# frozen_string_literal: true

require 'spec_helper'
require 'securerandom'

# Round trip with the issuing half of the pair: tokens minted by
# jwt_auth_client's TokenIssuer / Issuable / HttpClient are verified by this
# middleware. Needs the jwt_auth_client gem (see the Gemfile); skipped otherwise.
begin
  require 'jwt_auth_client'
rescue LoadError
  # handled below
end

RSpec.describe 'interop with jwt_auth_client' do
  if !defined?(JwtAuthClient::VERSION)
    it 'is skipped', skip: 'jwt_auth_client is not available (see the Gemfile)' do
      # placeholder so the skip is visible in the output
    end
    next
  elsif Gem::Version.new(JwtAuthClient::VERSION) < Gem::Version.new('0.2.0')
    it 'is skipped', skip: "jwt_auth_client #{JwtAuthClient::VERSION} is older than 0.2.0" do
      # placeholder so the skip is visible in the output
    end
    next
  end

  include Rack::Test::Methods

  let(:secret) { SecureRandom.hex(32) } # 64 bytes: enough for HS512 too
  let(:issuer) { 'main_app_sso' }
  let(:audience) { 'my_api' }
  let(:api_url) { 'https://my-api.internal' }
  let(:issuer_algorithm) { 'HS256' }

  # What the application behind the middleware sees.
  let(:seen) { [] }
  let(:inner_app) do
    lambda do |env|
      seen << env['rack_jwt_verifier.payload']
      [200, { 'content-type' => 'text/plain' }, ['ok']]
    end
  end

  let(:verifier_options) do
    {
      shared_secret: secret,
      algorithms: [issuer_algorithm],
      decode_options: { iss: issuer, aud: audience },
      logger: NULL_LOGGER
    }
  end
  let(:app) { Rack::Lint.new(RackJwtVerifier::Middleware.new(inner_app, verifier_options)) }

  before do
    JwtAuthClient.reset_configuration!
    JwtAuthClient.configure do |config|
      config.shared_secret = secret
      config.issuer = issuer
      config.algorithm = issuer_algorithm
      config.default_expiry_seconds = 300
      config.service_urls = { my_api: api_url, other_api: 'https://other.internal' }
    end
  end

  after { JwtAuthClient.reset_configuration! }

  def issue(user_id: 'service-account-etl', target_service: :my_api, **args)
    JwtAuthClient::TokenIssuer.call(user_id: user_id, target_service: target_service, **args)
  end

  def get_with(token, path = '/')
    get path, {}, { 'HTTP_AUTHORIZATION' => "Bearer #{token}" }
  end

  describe 'TokenIssuer -> Middleware' do
    it 'verifies an HS256 token and exposes sub, scopes and jti to the application' do
      get_with(issue(scopes: %w[read:invoices]))

      expect(last_response.status).to eq(200)
      expect(seen.last).to include('iss' => issuer, 'sub' => 'service-account-etl', 'aud' => audience,
                                   'scopes' => ['read:invoices'])
      expect(seen.last['jti']).to match(/\A\h{8}-\h{4}-\h{4}-\h{4}-\h{12}\z/)
      expect(seen.last).to include('iat', 'nbf', 'exp')
      expect(RackJwtVerifier::Scopes.from(seen.last)).to eq(['read:invoices'])
    end

    %w[HS384 HS512].each do |alg|
      context "with #{alg}" do
        let(:issuer_algorithm) { alg }

        it 'round-trips' do
          get_with(issue)
          expect(last_response.status).to eq(200)
          expect(JWT.decode(issue, nil, false).last['alg']).to eq(alg)
        end
      end
    end

    it 'rejects a token for another audience' do
      get_with(issue(target_service: :other_api))
      expect(last_response.status).to eq(401)
      expect(last_response.headers['www-authenticate']).to include('Invalid audience')
    end

    it 'rejects a token from another issuer' do
      JwtAuthClient.configuration.issuer = 'someone-else'
      get_with(issue)
      expect(last_response.status).to eq(401)
      expect(last_response.headers['www-authenticate']).to include('Invalid issuer')
    end

    it 'rejects a token signed with a different secret' do
      JwtAuthClient.configuration.shared_secret = SecureRandom.hex(32)
      get_with(issue)
      expect(last_response.status).to eq(401)
      expect(last_response.headers['www-authenticate']).to include('Signature verification failed')
    end

    it 'rejects a token signed with an HS algorithm the verifier does not list' do
      JwtAuthClient.configuration.algorithm = 'HS512'
      get_with(issue)
      expect(last_response.status).to eq(401)
      expect(last_response.headers['www-authenticate']).to include('Expected a different algorithm')
    end

    context 'exp / nbf with the default 60 s leeway' do
      let(:token) { issue(expiry_seconds: 60) }

      it 'accepts a token up to 60 s past exp and rejects it after' do
        token # issued now
        Timecop.travel(Time.now + 60 + 30) { get_with(token) }
        expect(last_response.status).to eq(200)

        Timecop.travel(Time.now + 60 + 90) { get_with(token) }
        expect(last_response.status).to eq(401)
        expect(last_response.headers['www-authenticate']).to include('Signature has expired')
      end

      it 'tolerates the issuer clock being up to 60 s ahead (nbf) and no more' do
        ahead = Timecop.travel(Time.now + 30) { issue }
        get_with(ahead)
        expect(last_response.status).to eq(200)

        far_ahead = Timecop.travel(Time.now + 120) { issue }
        get_with(far_ahead)
        expect(last_response.status).to eq(401)
        expect(last_response.headers['www-authenticate']).to include('Signature nbf has not been reached')
      end
    end

    context 'with require_scopes' do
      let(:verifier_options) { super().merge(require_scopes: %w[read:invoices]) }

      it 'lets a token with the scope through and answers 403 otherwise' do
        get_with(issue(scopes: %w[read:invoices write:invoices]))
        expect(last_response.status).to eq(200)

        get_with(issue(scopes: %w[write:invoices]))
        expect(last_response.status).to eq(403)
        expect(last_response.headers['www-authenticate'])
          .to include('error="insufficient_scope"').and include('scope="read:invoices"')

        get_with(issue) # jwt_auth_client omits the claim entirely when there are no scopes
        expect(last_response.status).to eq(403)
      end
    end

    context 'with replay_cache' do
      let(:verifier_options) { super().merge(replay_cache: true) }

      it 'accepts each fresh token once' do
        token = issue
        get_with(token)
        expect(last_response.status).to eq(200)

        get_with(token)
        expect(last_response.status).to eq(401)
        expect(last_response.headers['www-authenticate']).to include('already been used')

        get_with(issue) # fresh jti
        expect(last_response.status).to eq(200)
      end
    end
  end

  describe 'Issuable -> Middleware' do
    let(:model_class) do
      Class.new do
        include JwtAuthClient::Issuable

        def id
          42
        end

        def jwt_claims
          { user_id: 'sso-42', email: 'ada@example.com' }
        end
      end
    end

    it 'delivers the custom claims and uses user_id as sub' do
      get_with(model_class.new.to_jwt(target_service: :my_api, scopes: ['profile']))

      expect(last_response.status).to eq(200)
      expect(seen.last).to include('sub' => 'sso-42', 'user_id' => 'sso-42', 'email' => 'ada@example.com',
                                   'scopes' => ['profile'])
    end
  end

  describe 'HttpClient -> Middleware' do
    it 'sends a Bearer token the middleware accepts, freshly minted per request' do
      # The stubbed "server" is the middleware itself.
      tokens = []
      stub_request(:get, "#{api_url}/v1/invoices").to_return do |request|
        tokens << request.headers['Authorization'].delete_prefix('Bearer ')
        authorization = request.headers['Authorization']
        response = Rack::MockRequest.new(app).get('/v1/invoices', 'HTTP_AUTHORIZATION' => authorization)
        { status: response.status, headers: response.headers, body: response.body }
      end

      client = JwtAuthClient::HttpClient.call(user_id: 'etl', target_service: :my_api, scopes: ['read:invoices'])
      2.times { expect(client.get('/v1/invoices').status).to eq(200) }

      expect(seen.map { |p| p['sub'] }).to eq(%w[etl etl])
      expect(tokens.uniq.size).to eq(2) # token_reuse_seconds = 0: a fresh jti per request
    end
  end

  # jwt_auth_client 0.3.0 will sign with RS256/ES256 and a kid. Until then the
  # exact payload TokenIssuer produces is re-signed here with asymmetric keys
  # and verified through a JWKS, so the kid matching and algorithm paths are
  # proven against the real claim shape. Switch the signer to TokenIssuer once
  # 0.3.0 ships.
  describe 'asymmetric tokens with the jwt_auth_client payload (0.3.0 preview)' do
    let(:jwks_url) { 'https://sso.example.com/.well-known/jwks.json' }
    let(:rsa) { OpenSSL::PKey::RSA.generate(2048) }
    let(:ec) { OpenSSL::PKey::EC.generate('prime256v1') }
    let(:jwks) { JWT::JWK::Set.new([JWT::JWK.new(rsa, kid: 'rsa-2026'), JWT::JWK.new(ec, kid: 'ec-2026')]) }
    let(:verifier_options) do
      { jwks_url: jwks_url, algorithms: %w[RS256 ES256], decode_options: { iss: issuer, aud: audience },
        logger: NULL_LOGGER, cache_store: RackJwtVerifier::InProcessCache.new }
    end

    before { stub_request(:get, jwks_url).to_return(status: 200, body: JSON.generate(jwks.export)) }

    # The payload jwt_auth_client would sign, taken from a real HS token.
    def issuer_payload(**args)
      JWT.decode(issue(**args), nil, false).first
    end

    def resign(payload, key, alg, kid)
      JWT.encode(payload, key, alg, kid: kid)
    end

    it 'verifies an RS256 token matched by kid' do
      get_with(resign(issuer_payload(scopes: ['read:invoices']), rsa, 'RS256', 'rsa-2026'))
      expect(last_response.status).to eq(200)
      expect(seen.last).to include('iss' => issuer, 'aud' => audience, 'scopes' => ['read:invoices'])
    end

    it 'verifies an ES256 token matched by kid' do
      get_with(resign(issuer_payload, ec, 'ES256', 'ec-2026'))
      expect(last_response.status).to eq(200)
    end

    it 'rejects a token whose kid is unknown, after a rate-limited refetch' do
      get_with(resign(issuer_payload, rsa, 'RS256', 'rotated-away'))
      expect(last_response.status).to eq(401)
      expect(WebMock).to have_requested(:get, jwks_url).twice
    end

    it 'rejects a token whose kid names a key of another type' do
      get_with(resign(issuer_payload, rsa, 'RS256', 'ec-2026'))
      expect(last_response.status).to eq(401)
    end

    it 'rejects an HS256 token signed with the JWKS public key material (algorithm confusion)' do
      confused = JWT.encode(issuer_payload, rsa.public_key.to_pem, 'HS256', kid: 'rsa-2026')
      get_with(confused)
      expect(last_response.status).to eq(401)
      expect(last_response.headers['www-authenticate']).to include('Expected a different algorithm')
    end
  end
end
