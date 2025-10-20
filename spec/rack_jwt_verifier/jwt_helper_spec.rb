# frozen_string_literal: true

require 'spec_helper'
require 'openssl'
require 'jwt'
require 'rack_jwt_verifier/jwt_helper'

RSpec.describe RackJwtVerifier::JwtHelper do
  # Helper method to generate a new key pair for each test run
  def generate_key_pair
    # Generate a new 2048-bit RSA key pair
    OpenSSL::PKey::RSA.generate(2048)
  end

  # Setup keys and the helper instance for all tests in this context
  let(:key_pair) { generate_key_pair }
  let(:private_key_pem) { key_pair.to_pem }
  let(:helper) { described_class.new(private_key_pem) }

  let(:payload) do
    {
      'user_id' => 42,
      'email' => 'test@example.com',
      'role' => 'member'
    }
  end

  # --- Initialization and Basic Properties ---

  describe '#initialize' do
    it 'loads the private key and derives the public key' do
      expect(helper.private_key).to be_a(OpenSSL::PKey::RSA)
      expect(helper.public_key).to be_a(OpenSSL::PKey::RSA)
      # Ensure the public key derived from the helper's private key matches the key pair's public key
      expect(helper.public_key.to_pem).to eq(key_pair.public_key.to_pem)
    end
  end

  # --- Encoding and Decoding ---

  describe '#encode and #decode' do
    it 'successfully encodes and decodes the payload' do
      token = helper.encode(payload)
      decoded_payload = helper.decode(token)

      # Check that the decoded payload contains all original data
      expect(decoded_payload['user_id']).to eq(payload['user_id'])
      expect(decoded_payload['email']).to eq(payload['email'])
      expect(decoded_payload['role']).to eq(payload['role'])

      # Check for standard claims added by the helper
      expect(decoded_payload).to include('exp', 'iat')
    end

    it 'uses the RS256 algorithm for encoding' do
      token = helper.encode(payload)
      _payload, header = JWT.decode(token, nil, false) # Decode without verification to inspect header
      expect(header['alg']).to eq('RS256')
    end
  end

  # --- Security and Validation Tests ---

  describe 'Token Validation' do
    context 'when the token has an expired signature' do
      it 'raises a JWT::ExpiredSignature error' do
        expired_payload = payload.merge({ 'exp' => Time.now.to_i - 10 }) # Set expiration 10 seconds in the past
        
        # Use key_pair directly as it is the private key object
        expired_token = JWT.encode(expired_payload, key_pair, 'RS256')

        expect { helper.decode(expired_token) }.to raise_error(JWT::ExpiredSignature)
      end
    end

    context 'when the token is signed by a different key' do
      it 'raises a JWT::VerificationError' do
        # Create a completely different key pair to simulate an attacker's key
        evil_key_pair = generate_key_pair
        # Use evil_key_pair directly as it is the private key object
        evil_token = JWT.encode(payload, evil_key_pair, 'RS256')

        # Try to decode the evil token using the legitimate helper's public key
        expect { helper.decode(evil_token) }.to raise_error(JWT::VerificationError)
      end
    end

    context 'when the token is structurally invalid' do
      it 'raises a JWT::DecodeError' do
        invalid_token = 'header.payload.signature_that_is_malformed'
        expect { helper.decode(invalid_token) }.to raise_error(JWT::DecodeError)
      end
    end
  end
end
