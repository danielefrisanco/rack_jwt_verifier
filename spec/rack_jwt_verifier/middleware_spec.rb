# frozen_string_literal: true

require 'spec_helper'
require 'openssl'
require 'jwt'
require 'webmock/rspec'
require 'rack_jwt_verifier/middleware' # Require the Middleware under test
require 'stringio'

RSpec.describe RackJwtVerifier::Middleware do
  include Rack::Test::Methods

  # --- Key and Token Helpers ---

  # Helper variables for signing and verifying tokens
  let(:key_pair) { OpenSSL::PKey::RSA.generate(2048) }
  let(:public_key_pem) { key_pair.public_key.to_pem }
  let(:private_key_signer) { key_pair }
  let(:payload) { { 'user_id' => 101, 'iss' => TEST_ISSUER, 'aud' => TEST_AUDIENCE } }

  # The key URL defined in spec_helper's verifier_options
  let(:key_url) { verifier_options[:public_key_url] }

  # A valid token, signed to expire in 5 minutes
  let(:valid_token) { token_expiring_in(300) }

  def token_expiring_in(seconds)
    JWT.encode(payload.merge({ exp: Time.now.to_i + seconds }), private_key_signer, 'RS256')
  end

  # A token created in the past to ensure it's expired when the test runs
  let(:expired_token) do
    Timecop.freeze(Time.now - 3600) do # Freeze time far in the past
      # Token expires 5 minutes from the frozen time, meaning it's expired now
      JWT.encode(payload.merge({ exp: Time.now.to_i + 300 }), private_key_signer, 'RS256')
    end
  end

  # A token signed by a key the verifier won't recognize
  let(:evil_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:bad_signature_token) { JWT.encode(payload, evil_key, 'RS256') }

  # A string that is not a valid JWT format
  let(:invalid_token) { "this.is.not.a.jwt" }

  # --- WebMock Stubbing ---

  before do
    # STUB: Prevent the verifier from making a real network call for the public key
    stub_request(:get, key_url).to_return(status: 200, body: public_key_pem)
    Timecop.return # Ensure time is unfrozen before each test context
  end

  # NOTE: The 'app' method used here is defined in spec/spec_helper.rb,
  # which sets up the Middleware wrapping the MockApp.

  # --- Test Contexts ---

  context 'when no token is present in the Authorization header' do
    it 'passes the request to the application successfully' do
      get '/'
      expect(last_response.status).to eq(200)
      # Checks that the payload was not set
      expect(last_response.body).to include("User ID in env: ")
    end
  end

  context 'when a token is present' do
    context 'with a valid Bearer token' do
      let(:auth_header) { { 'HTTP_AUTHORIZATION' => "Bearer #{valid_token}" } }

      it 'verifies the token and adds the payload to the environment' do
        get '/', {}, auth_header
        expect(last_response.status).to eq(200)
        # Check that the mock app received the user_id from the environment
        expect(last_response.body).to include("User ID in env: 101")
      end

      it 'fetches the key once and serves subsequent requests from the cache' do
        3.times { get '/', {}, auth_header }
        expect(last_response.status).to eq(200)
        expect(WebMock).to have_requested(:get, key_url).once
      end

      it 'refetches the key once the cache TTL has elapsed' do
        expiring = build_app(verifier_options.merge(cache_ttl: 0)) # every entry expires at once
        2.times { Rack::MockRequest.new(expiring).get('/', auth_header) }
        expect(WebMock).to have_requested(:get, key_url).twice
      end
    end

    context 'with an expired JWT' do
      let(:auth_header_expired) { { 'HTTP_AUTHORIZATION' => "Bearer #{expired_token}" } }

      # Freeze time to ensure the token is definitively expired when the middleware runs
      around do |ex|
        Timecop.freeze { ex.run }
      end

      it 'returns 401 Unauthorized' do
        get '/', {}, auth_header_expired
        expect(last_response.status).to eq(401)
        # FIX: Expect the generic error message
        expect(last_response.body).to eq('Unauthorized: Invalid or expired JWT.')
      end
    end

    context 'with a JWT that fails verification (bad signature)' do
      let(:auth_header_bad) { { 'HTTP_AUTHORIZATION' => "Bearer #{bad_signature_token}" } }

      it 'returns 401 Unauthorized' do
        get '/', {}, auth_header_bad
        expect(last_response.status).to eq(401)
        # FIX: Expect the generic error message
        expect(last_response.body).to eq('Unauthorized: Invalid or expired JWT.')
      end
    end

    context 'with a structurally invalid JWT' do
      let(:auth_header_invalid) { { 'HTTP_AUTHORIZATION' => "Bearer #{invalid_token}" } }

      it 'returns 401 Unauthorized' do
        get '/', {}, auth_header_invalid
        expect(last_response.status).to eq(401)
        # FIX: Expect the generic error message
        expect(last_response.body).to eq('Unauthorized: Invalid or expired JWT.')
      end
    end

    context 'issuer and audience enforcement' do
      let(:wrong_issuer_token) do
        JWT.encode(payload.merge('iss' => 'someone-else', 'exp' => Time.now.to_i + 300), private_key_signer, 'RS256')
      end
      let(:wrong_audience_token) do
        JWT.encode(payload.merge('aud' => 'other_app', 'exp' => Time.now.to_i + 300), private_key_signer, 'RS256')
      end

      it 'returns 401 for a token from a different issuer' do
        get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{wrong_issuer_token}" }
        expect(last_response.status).to eq(401)
        expect(last_response.headers['www-authenticate']).to include('Invalid issuer')
      end

      it 'returns 401 for a token meant for a different audience' do
        get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{wrong_audience_token}" }
        expect(last_response.status).to eq(401)
        expect(last_response.headers['www-authenticate']).to include('Invalid audience')
      end

      it 'accepts a token from the configured issuer for the configured audience' do
        get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{valid_token}" }
        expect(last_response.status).to eq(200)
        expect(last_response.body).to include("User ID in env: 101")
      end
    end

    context 'when the downstream application itself raises JWT::DecodeError' do
      let(:raising_app) { ->(_env) { raise JWT::DecodeError, 'unrelated failure inside the app' } }
      let(:app) { RackJwtVerifier::Middleware.new(raising_app, verifier_options) }

      it 'lets the error propagate instead of masking it as a 401' do
        expect { get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{valid_token}" } }
          .to raise_error(JWT::DecodeError, /unrelated failure inside the app/)
      end
    end
  end

  context 'with a valid token but an unreachable key endpoint' do
    let(:log_io) { StringIO.new }
    let(:app) { build_app(verifier_options.merge(logger: Logger.new(log_io))) }

    before { stub_request(:get, key_url).to_return(status: 503) }

    it 'returns 503 with a retry-after header rather than 401 or a crash' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{valid_token}" }
      expect(last_response.status).to eq(503)
      expect(last_response.headers['retry-after']).to eq(RackJwtVerifier::Middleware::RETRY_AFTER_SECONDS.to_s)
      expect(last_response.body).to include('could not fetch the token verification key')
    end

    it 'logs the failure at error level' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{valid_token}" }
      expect(log_io.string).to include('ERROR').and include('Failed to fetch public key')
    end
  end

  context 'Authorization header parsing' do
    it 'accepts a lowercase "bearer" scheme' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "bearer #{valid_token}" }
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include("User ID in env: 101")
    end

    it 'accepts an uppercase "BEARER" scheme' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "BEARER #{valid_token}" }
      expect(last_response.body).to include("User ID in env: 101")
    end

    it 'tolerates surrounding and repeated whitespace' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "  Bearer    #{valid_token}  " }
      expect(last_response.body).to include("User ID in env: 101")
    end

    it 'ignores a non-Bearer scheme and passes the request through' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => 'Basic dXNlcjpwYXNz' }
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include("User ID in env: NONE")
    end

    it 'treats "Bearer" with no token as no token' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => 'Bearer ' }
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include("User ID in env: NONE")
    end
  end

  context 'with require_token: true' do
    let(:app) { build_app(verifier_options.merge(require_token: true)) }

    it 'rejects a request with no Authorization header with a bare Bearer challenge' do
      get '/'
      expect(last_response.status).to eq(401)
      expect(last_response.headers['www-authenticate']).to eq('Bearer')
      expect(last_response.body).to eq('Unauthorized: Bearer token required.')
    end

    it 'still accepts a valid token' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{valid_token}" }
      expect(last_response.status).to eq(200)
    end
  end

  context 'response format' do
    it 'sets www-authenticate with an error code and description, and a content-length, on 401' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{invalid_token}" }
      expect(last_response.headers['www-authenticate'])
        .to eq('Bearer error="invalid_token", error_description="Not enough or too many segments"')
      expect(last_response.headers['content-type']).to eq('text/plain')
      expect(last_response.headers['content-length']).to eq(last_response.body.bytesize.to_s)
    end

    it 'strips characters that are not allowed inside a quoted-string from error_description' do
      token = JWT.encode(payload.merge('iss' => 'x"y\\z', 'exp' => Time.now.to_i + 300), private_key_signer, 'RS256')
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{token}" }
      description = last_response.headers['www-authenticate'][/error_description="([^"]*)"/, 1]
      expect(description).to include('Invalid issuer').and match(/\A[\x20-\x21\x23-\x5B\x5D-\x7E]*\z/)
    end

    context 'with json_errors: true' do
      let(:app) { build_app(verifier_options.merge(json_errors: true, require_token: true)) }

      it 'renders a 401 for an invalid token as JSON' do
        get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{expired_token}" }
        expect(last_response.status).to eq(401)
        expect(last_response.headers['content-type']).to eq('application/json')
        expect(JSON.parse(last_response.body))
          .to eq('error' => 'invalid_token', 'error_description' => 'Signature has expired')
      end

      it 'renders a 401 for a missing token as JSON' do
        get '/'
        expect(JSON.parse(last_response.body))
          .to eq('error' => 'missing_token', 'error_description' => 'Unauthorized: Bearer token required.')
        expect(last_response.headers['www-authenticate']).to eq('Bearer')
      end

      it 'renders a 503 as JSON' do
        stub_request(:get, key_url).to_return(status: 503)
        get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{valid_token}" }
        expect(last_response.status).to eq(503)
        expect(JSON.parse(last_response.body)['error']).to eq('key_unavailable')
        expect(last_response.headers['retry-after']).to eq('5')
      end
    end

    context 'with an on_error hook' do
      let(:calls) { [] }
      let(:hook) do
        lambda do |env, reason, error|
          calls << [env['PATH_INFO'], reason, error]
          reason == :invalid_token ? [418, { 'content-type' => 'text/plain' }, ['teapot']] : nil
        end
      end
      let(:app) { build_app(verifier_options.merge(on_error: hook, require_token: true)) }

      it 'uses the response the hook returns' do
        get '/secret', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{invalid_token}" }
        expect(last_response.status).to eq(418)
        expect(last_response.body).to eq('teapot')
        expect(calls.size).to eq(1)
        expect(calls.first[0..1]).to eq(['/secret', :invalid_token])
        expect(calls.first[2]).to be_a(JWT::DecodeError)
      end

      it 'falls back to the default response when the hook returns nil' do
        get '/'
        expect(last_response.status).to eq(401)
        expect(last_response.body).to eq('Unauthorized: Bearer token required.')
        expect(calls).to eq([['/', :missing_token, nil]])
      end
    end
  end

  context 'with skip rules' do
    let(:app) do
      build_app(verifier_options.merge(
                  require_token: true,
                  skip: ['/health', %r{\A/public/}, ->(env) { env['REQUEST_METHOD'] == 'OPTIONS' }]
                ))
    end

    it 'bypasses verification for an exact path match' do
      get '/health'
      expect(last_response.status).to eq(200)
    end

    it 'bypasses verification for a regexp match' do
      get '/public/anything/here'
      expect(last_response.status).to eq(200)
    end

    it 'bypasses verification when a callable rule matches' do
      options '/secret'
      expect(last_response.status).to eq(200)
    end

    it 'still verifies everything else' do
      get '/healthz'
      expect(last_response.status).to eq(401)
    end

    it 'does not verify a token on a skipped path even if one is present' do
      get '/health', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{invalid_token}" }
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('User ID in env: NONE')
    end

    it 'matches against SCRIPT_NAME + PATH_INFO for mounted apps' do
      mounted = build_app(verifier_options.merge(require_token: true, skip: ['/api/health']))
      response = Rack::MockRequest.new(mounted).get('/health', 'SCRIPT_NAME' => '/api')
      expect(response.status).to eq(200)
    end

    it 'rejects an unusable rule at boot' do
      expect { RackJwtVerifier::Middleware.new(MockApp.new, verifier_options.merge(skip: [42])) }
        .to raise_error(RackJwtVerifier::ConfigurationError, /skip: entries must be/)
    end
  end

  context 'with require_scopes' do
    let(:app) { build_app(verifier_options.merge(require_scopes: %w[read:invoices write:invoices])) }

    def scoped_token(scopes)
      JWT.encode(payload.merge('scopes' => scopes, 'exp' => Time.now.to_i + 300), private_key_signer, 'RS256')
    end

    it 'lets a token carrying every required scope through' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{scoped_token(%w[read:invoices write:invoices admin])}" }
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include('User ID in env: 101')
    end

    it 'answers 403 with an insufficient_scope challenge naming the required scopes' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{scoped_token(%w[read:invoices])}" }
      expect(last_response.status).to eq(403)
      expect(last_response.headers['www-authenticate']).to eq(
        'Bearer error="insufficient_scope", ' \
        'error_description="Token lacks required scope(s): write:invoices", ' \
        'scope="read:invoices write:invoices"'
      )
      expect(last_response.body).to eq('Forbidden: the token does not grant the required scope.')
    end

    it 'answers 403 for a token with no scopes at all' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{valid_token}" }
      expect(last_response.status).to eq(403)
    end

    it 'accepts the OAuth-style space-delimited scope claim too' do
      token = JWT.encode(payload.merge('scope' => 'write:invoices read:invoices', 'exp' => Time.now.to_i + 300),
                         private_key_signer, 'RS256')
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{token}" }
      expect(last_response.status).to eq(200)
    end

    it 'implies require_token' do
      get '/'
      expect(last_response.status).to eq(401)
      expect(last_response.headers['www-authenticate']).to eq('Bearer')
    end

    it 'still answers 401, not 403, for an invalid token' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{invalid_token}" }
      expect(last_response.status).to eq(401)
    end

    it 'renders the 403 as JSON when json_errors is on' do
      app = build_app(verifier_options.merge(require_scopes: ['admin'], json_errors: true))
      response = Rack::MockRequest.new(app).get('/', 'HTTP_AUTHORIZATION' => "Bearer #{valid_token}")
      expect(response.status).to eq(403)
      expect(JSON.parse(response.body))
        .to eq('error' => 'insufficient_scope', 'error_description' => 'Token lacks required scope(s): admin')
    end

    it 'hands an InsufficientScopeError to the on_error hook' do
      seen = nil
      hook = lambda { |_env, reason, error|
        seen = [reason, error]
        nil
      }
      app = build_app(verifier_options.merge(require_scopes: %w[a b], on_error: hook))
      Rack::MockRequest.new(app).get('/', 'HTTP_AUTHORIZATION' => "Bearer #{scoped_token(['a'])}")
      expect(seen[0]).to eq(:insufficient_scope)
      expect(seen[1]).to be_a(RackJwtVerifier::InsufficientScopeError)
      expect(seen[1].required).to eq(%w[a b])
      expect(seen[1].missing).to eq(['b'])
    end

    it 'accepts a single scope string' do
      app = build_app(verifier_options.merge(require_scopes: 'read:invoices'))
      token = scoped_token(['read:invoices'])
      response = Rack::MockRequest.new(app).get('/', 'HTTP_AUTHORIZATION' => "Bearer #{token}")
      expect(response.status).to eq(200)
    end

    it 'refuses require_token: false alongside require_scopes at boot' do
      expect { build_app(verifier_options.merge(require_scopes: ['a'], require_token: false)) }
        .to raise_error(RackJwtVerifier::ConfigurationError, /drop require_token: false/)
    end

    it 'refuses blank scopes at boot' do
      expect { build_app(verifier_options.merge(require_scopes: ['a', ''])) }
        .to raise_error(RackJwtVerifier::ConfigurationError, /non-empty strings/)
    end
  end

  context 'with replay_cache' do
    let(:store) { RackJwtVerifier::InProcessCache.new }
    let(:app) { build_app(verifier_options.merge(replay_cache: store)) }
    let(:jti_token) do
      JWT.encode(payload.merge('jti' => 'once', 'exp' => Time.now.to_i + 300), private_key_signer, 'RS256')
    end

    it 'accepts a token once and answers 401 invalid_token on the second presentation' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{jti_token}" }
      expect(last_response.status).to eq(200)

      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{jti_token}" }
      expect(last_response.status).to eq(401)
      expect(last_response.headers['www-authenticate'])
        .to include('error="invalid_token"').and include('already been used')
    end

    it 'answers 401 for a token without a jti' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{valid_token}" }
      expect(last_response.status).to eq(401)
      expect(last_response.headers['www-authenticate']).to include('Missing jti')
    end

    it 'answers 503 when the replay store is down' do
      broken = instance_double(RackJwtVerifier::InProcessCache, write: nil)
      allow(broken).to receive(:read).and_raise(IOError, 'connection refused')
      log_io = StringIO.new
      app = build_app(verifier_options.merge(replay_cache: broken, logger: Logger.new(log_io), json_errors: true))
      response = Rack::MockRequest.new(app).get('/', 'HTTP_AUTHORIZATION' => "Bearer #{jti_token}")
      expect(response.status).to eq(503)
      expect(response.headers['retry-after']).to eq('5')
      expect(JSON.parse(response.body)['error']).to eq('replay_cache_unavailable')
      expect(log_io.string).to include('ERROR').and include('replay cache unavailable')
    end
  end

  context 'with a custom env_key' do
    let(:captured) { {} }
    let(:capturing_app) do
      lambda { |env|
        captured.merge!(env.select do |k, _|
          k.start_with?('rack_jwt', 'my.')
        end)
        [200, {}, ['ok']]
      }
    end
    let(:app) { build_app(verifier_options.merge(env_key: 'my.claims'), capturing_app) }

    it 'stores the payload under the given key only' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{valid_token}" }
      expect(captured.keys).to eq(['my.claims'])
      expect(captured['my.claims']).to include('user_id' => 101)
    end
  end

  context 'logging' do
    let(:log_io) { StringIO.new }
    let(:logger) { Logger.new(log_io) }

    it 'uses the :logger option for rejected tokens' do
      opts = verifier_options.merge(logger: logger)
      RackJwtVerifier::Middleware.new(MockApp.new, opts).call(
        Rack::MockRequest.env_for('/', 'HTTP_AUTHORIZATION' => "Bearer #{invalid_token}")
      )
      expect(log_io.string).to include('WARN').and include('token rejected')
    end

    it 'falls back to env["rack.logger"] when no :logger option is given' do
      opts = verifier_options.merge(logger: nil)
      RackJwtVerifier::Middleware.new(MockApp.new, opts).call(
        Rack::MockRequest.env_for('/', 'HTTP_AUTHORIZATION' => "Bearer #{invalid_token}", 'rack.logger' => logger)
      )
      expect(log_io.string).to include('token rejected')
    end

    it 'stays silent when neither is available' do
      opts = verifier_options.merge(logger: nil)
      expect do
        RackJwtVerifier::Middleware.new(MockApp.new, opts).call(
          Rack::MockRequest.env_for('/', 'HTTP_AUTHORIZATION' => "Bearer #{invalid_token}")
        )
      end.not_to output.to_stderr
    end
  end

  context 'with a jwks_url instead of a public_key_url' do
    let(:jwks_url) { 'https://sso.example.com/.well-known/jwks.json' }
    let(:app) { build_app(verifier_options.merge(public_key_url: nil, jwks_url: jwks_url)) }
    let(:kid_token) { JWT.encode(payload.merge(exp: Time.now.to_i + 300), private_key_signer, 'RS256', kid: 'k1') }

    before do
      set = JWT::JWK::Set.new([JWT::JWK.new(key_pair, kid: 'k1')])
      stub_request(:get, jwks_url).to_return(status: 200, body: JSON.generate(set.export))
    end

    it 'verifies a token against the key set' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{kid_token}" }
      expect(last_response.status).to eq(200)
      expect(last_response.body).to include("User ID in env: 101")
    end

    it 'returns 401 for an unknown kid' do
      other = JWT.encode(payload.merge(exp: Time.now.to_i + 300), private_key_signer, 'RS256', kid: 'zz')
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{other}" }
      expect(last_response.status).to eq(401)
    end
  end

  context 'with a static public_key' do
    let(:app) { build_app(verifier_options.merge(public_key_url: nil, public_key: public_key_pem)) }

    it 'verifies without any network access' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{valid_token}" }
      expect(last_response.status).to eq(200)
      expect(WebMock).not_to have_requested(:get, key_url)
    end
  end

  context 'configuration' do
    it 'refuses a plain http:// public_key_url at boot' do
      expect { RackJwtVerifier::Middleware.new(MockApp.new, verifier_options.merge(public_key_url: 'http://sso.example.com/certs')) }
        .to raise_error(RackJwtVerifier::ConfigurationError, /https/)
    end

    context 'iss/aud policy' do
      it 'refuses to boot when neither iss nor aud is configured' do
        expect { RackJwtVerifier::Middleware.new(MockApp.new, public_key_url: key_url, logger: NULL_LOGGER) }
          .to raise_error(RackJwtVerifier::ConfigurationError, /must set :iss and :aud/)
      end

      it 'refuses to boot when only iss is configured' do
        expect { RackJwtVerifier::Middleware.new(MockApp.new, public_key_url: key_url, decode_options: { iss: 'x' }) }
          .to raise_error(RackJwtVerifier::ConfigurationError, /must set :aud/)
      end

      it 'treats a blank value as unset' do
        expect { RackJwtVerifier::Middleware.new(MockApp.new, public_key_url: key_url, decode_options: { iss: ' ', aud: 'a' }) }
          .to raise_error(RackJwtVerifier::ConfigurationError, /must set :iss/)
      end

      it 'accepts an array of issuers' do
        expect do
          RackJwtVerifier::Middleware.new(MockApp.new, public_key_url: key_url,
                                                       decode_options: { iss: %w[a b], aud: 'a' })
        end.not_to raise_error
      end

      it 'warns via the logger instead when require_iss_aud is false' do
        log_io = StringIO.new
        RackJwtVerifier::Middleware.new(MockApp.new, public_key_url: key_url, require_iss_aud: false,
                                                     logger: Logger.new(log_io))
        expect(log_io.string).to include(':iss and :aud not set')
      end

      it 'warns on stderr when require_iss_aud is false and no logger is configured' do
        expect { RackJwtVerifier::Middleware.new(MockApp.new, public_key_url: key_url, require_iss_aud: false) }
          .to output(/:iss and :aud not set/).to_stderr
      end

      it 'stays quiet when both are configured' do
        log_io = StringIO.new
        RackJwtVerifier::Middleware.new(MockApp.new, verifier_options.merge(logger: Logger.new(log_io)))
        expect(log_io.string).to be_empty
      end
    end
  end
end
