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
  let(:payload) { { 'user_id' => 101, 'aud' => 'my_app' } }
  
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
        get '/', {}, auth_header
        Timecop.travel(Time.now + RackJwtVerifier::Verifier::CACHE_TTL_SECONDS + 1) do
          get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{token_expiring_in(300)}" }
        end
        expect(last_response.status).to eq(200)
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

    context 'with an issuer configured via decode_options' do
      let(:app) { build_app(verifier_options.merge(decode_options: { iss: 'trusted-sso' })) }
      let(:wrong_issuer_token) do
        JWT.encode(payload.merge(iss: 'someone-else', exp: Time.now.to_i + 300), private_key_signer, 'RS256')
      end
      let(:right_issuer_token) do
        JWT.encode(payload.merge(iss: 'trusted-sso', exp: Time.now.to_i + 300), private_key_signer, 'RS256')
      end

      it 'returns 401 for a token from a different issuer' do
        get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{wrong_issuer_token}" }
        expect(last_response.status).to eq(401)
      end

      it 'accepts a token from the configured issuer' do
        get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{right_issuer_token}" }
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
    it 'sets www-authenticate with an error code and a content-length on 401' do
      get '/', {}, { 'HTTP_AUTHORIZATION' => "Bearer #{invalid_token}" }
      expect(last_response.headers['www-authenticate']).to eq('Bearer error="invalid_token"')
      expect(last_response.headers['content-type']).to eq('text/plain')
      expect(last_response.headers['content-length']).to eq(last_response.body.bytesize.to_s)
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
      opts = verifier_options.merge(logger: nil, decode_options: { iss: 'x' })
      RackJwtVerifier::Middleware.new(MockApp.new, opts).call(
        Rack::MockRequest.env_for('/', 'HTTP_AUTHORIZATION' => "Bearer #{invalid_token}", 'rack.logger' => logger)
      )
      expect(log_io.string).to include('token rejected')
    end

    it 'stays silent when neither is available' do
      opts = verifier_options.merge(logger: nil, decode_options: { iss: 'x' })
      expect {
        RackJwtVerifier::Middleware.new(MockApp.new, opts).call(
          Rack::MockRequest.env_for('/', 'HTTP_AUTHORIZATION' => "Bearer #{invalid_token}")
        )
      }.not_to output.to_stderr
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
        .to raise_error(ArgumentError, /https/)
    end

    it 'warns via the logger at boot when neither iss nor aud is configured' do
      log_io = StringIO.new
      RackJwtVerifier::Middleware.new(MockApp.new, verifier_options.merge(logger: Logger.new(log_io)))
      expect(log_io.string).to include('neither :iss nor :aud')
    end

    it 'warns on stderr at boot when no logger is configured' do
      expect { RackJwtVerifier::Middleware.new(MockApp.new, public_key_url: key_url) }
        .to output(/neither :iss nor :aud/).to_stderr
    end

    it 'does not warn when an issuer is configured' do
      log_io = StringIO.new
      RackJwtVerifier::Middleware.new(MockApp.new, verifier_options.merge(logger: Logger.new(log_io), decode_options: { iss: 'x' }))
      expect(log_io.string).to be_empty
    end
  end
end
