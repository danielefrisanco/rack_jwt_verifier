# frozen_string_literal: true

require 'spec_helper'
require 'openssl'
require 'jwt'
require 'webmock/rspec'
require 'rack_jwt_verifier/middleware' # Require the Middleware under test

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
  let(:valid_token) { JWT.encode(payload.merge({ exp: Time.now.to_i + 300 }), private_key_signer, 'RS256') }
  
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

      it 'calls the Verifier and fetches the key once' do
        get '/', {}, auth_header
        # This confirms the verification step happened without crashing the network.
        expect(WebMock).to have_requested(:get, key_url).once
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
      let(:app) do
        RackJwtVerifier::Middleware.new(MockApp.new, verifier_options.merge(decode_options: { iss: 'trusted-sso' }))
      end
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

  context 'configuration' do
    it 'refuses a plain http:// public_key_url at boot' do
      expect { RackJwtVerifier::Middleware.new(MockApp.new, public_key_url: 'http://sso.example.com/certs') }
        .to raise_error(ArgumentError, /https/)
    end
  end
end
