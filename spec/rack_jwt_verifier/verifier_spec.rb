# frozen_string_literal: true

require 'spec_helper'
require 'openssl'
require 'jwt'
require 'webmock/rspec'
require 'rack_jwt_verifier/verifier'
require 'timecop'

RSpec.describe RackJwtVerifier::Verifier do
  # Alias the Verifier class for cleaner code
  let(:described_class) { RackJwtVerifier::Verifier }

  # Helper to generate keys and tokens for testing
  let(:key_pair) { OpenSSL::PKey::RSA.generate(2048) }
  let(:public_key_pem) { key_pair.public_key.to_pem }
  let(:private_key_signer) { key_pair } 
  
  let(:key_url) { 'https://sso.example.com/api/v1/public_key' }
  let(:payload) { { 'iss' => 'test_issuer', 'user_id' => 123 } }
  
  # Mock cache object that responds to #read and #write
  let(:mock_cache) { instance_double(RackJwtVerifier::InProcessCache) }
  
  # Token expires in 5 minutes (300 seconds)
  let(:valid_token) { JWT.encode(payload.merge({ exp: Time.now.to_i + 300 }), private_key_signer, 'RS256') }

  # The Verifier instance we are testing (using the mock cache)
  let(:verifier) do
    described_class.new(public_key_url: key_url, cache_store: mock_cache) 
  end

  # Set up a successful key fetch stub before each test
  before do
    # This ensures WebMock knows what to return when the Verifier requests the key
    stub_request(:get, key_url).to_return(status: 200, body: public_key_pem)
  end

  # --- Initialization ---

  describe '#initialize' do
    # Simple verifier without explicit cache
    let(:default_verifier) { described_class.new(public_key_url: key_url) }

    it 'sets the public key URL' do
      expect(verifier.instance_variable_get(:@public_key_url)).to eq(key_url)
    end
    
    it 'uses InProcessCache if no cache_store is provided' do
      cache = default_verifier.instance_variable_get(:@cache)
      expect(cache).to be_a(RackJwtVerifier::InProcessCache)
    end
    
    it 'uses the provided cache_store if one is passed' do
      cache = verifier.instance_variable_get(:@cache)
      expect(cache).to eq(mock_cache)
    end

    it 'merges default decode options with provided options' do
      custom_verifier = described_class.new(
        public_key_url: key_url,
        decode_options: { leeway: 10, iss: 'custom-issuer' }
      )
      options = custom_verifier.instance_variable_get(:@decode_options)
      expect(options[:leeway]).to eq(10) # Custom value is used
      expect(options[:algorithm]).to eq('RS256') # Default value is kept
      expect(options[:iss]).to eq('custom-issuer')
    end

    context 'claim enforcement flags' do
      def decode_options_for(decode_options)
        described_class.new(public_key_url: key_url, decode_options: decode_options)
                       .instance_variable_get(:@decode_options)
      end

      it 'enables verify_iss when an iss value is given' do
        expect(decode_options_for(iss: 'issuer')[:verify_iss]).to be(true)
      end

      it 'enables verify_aud when an aud value is given' do
        expect(decode_options_for(aud: 'my-app')[:verify_aud]).to be(true)
      end

      it 'enables verify_sub when a sub value is given' do
        expect(decode_options_for(sub: 'user-1')[:verify_sub]).to be(true)
      end

      it 'leaves an explicit verify_iss: false untouched' do
        expect(decode_options_for(iss: 'issuer', verify_iss: false)[:verify_iss]).to be(false)
      end

      it 'does not add verify flags for claims that were not given' do
        options = decode_options_for({})
        expect(options).not_to include(:verify_iss, :verify_aud, :verify_sub)
      end
    end

    context 'public_key_url validation' do
      it 'rejects a plain http:// URL by default' do
        expect { described_class.new(public_key_url: 'http://sso.example.com/key') }
          .to raise_error(ArgumentError, /must be an https:\/\/ URL/)
      end

      it 'accepts a plain http:// URL when allow_insecure_http is true' do
        expect { described_class.new(public_key_url: 'http://sso.example.com/key', allow_insecure_http: true) }
          .not_to raise_error
      end

      it 'rejects a non-HTTP scheme even with allow_insecure_http' do
        expect { described_class.new(public_key_url: 'ftp://sso.example.com/key', allow_insecure_http: true) }
          .to raise_error(ArgumentError, /must be an https:\/\/ URL/)
      end

      it 'rejects a string that is not a URL' do
        expect { described_class.new(public_key_url: 'not a url at all') }
          .to raise_error(ArgumentError, /not a valid URL/)
      end
    end

    it 'defaults the HTTP timeout and allows overriding it' do
      expect(verifier.instance_variable_get(:@http_timeout)).to eq(described_class::DEFAULT_HTTP_TIMEOUT)
      custom = described_class.new(public_key_url: key_url, http_timeout: 1.5)
      expect(custom.instance_variable_get(:@http_timeout)).to eq(1.5)
    end
  end

  describe 'standalone require' do
    it 'can be required and instantiated without the top-level entry point' do
      lib = File.expand_path('../../lib', __dir__)
      script = 'require "rack_jwt_verifier/verifier"; ' \
               'RackJwtVerifier::Verifier.new(public_key_url: "https://sso.example.com/key"); ' \
               'print "ok"'
      output = IO.popen([RbConfig.ruby, '-I', lib, '-e', script], err: [:child, :out], &:read)
      expect(output).to eq('ok')
    end
  end

  # --- Key Fetching and Caching (using the mock) ---

  describe '#fetch_public_key (private)' do
    let(:cache_key) { RackJwtVerifier::Verifier::PUBLIC_KEY_CACHE_KEY }

    it 'fetches the key from the remote URL on cache miss and writes to cache' do
      # 1. Setup: Cache read returns nil (miss)
      expect(mock_cache).to receive(:read).with(cache_key).and_return(nil)
      # 2. Expect: Network hit occurs, and the key is written back
      expect(mock_cache).to receive(:write).with(cache_key, public_key_pem, expires_in: RackJwtVerifier::Verifier::CACHE_TTL_SECONDS)
      
      key = verifier.send(:fetch_public_key)
      expect(key).to be_a(OpenSSL::PKey::RSA)
      expect(WebMock).to have_requested(:get, key_url).once
    end

    it 'reads the key from cache on cache hit and avoids network hit' do
      # 1. Setup: Cache read returns the PEM string (hit)
      expect(mock_cache).to receive(:read).with(cache_key).and_return(public_key_pem).twice # FIX 1: Expect two reads since we call fetch_public_key twice
      # 2. Expect: Cache write is NOT called, network is NOT hit
      expect(mock_cache).not_to receive(:write)
      
      verifier.send(:fetch_public_key)
      verifier.send(:fetch_public_key) # Call twice to confirm caching works

      expect(WebMock).not_to have_requested(:get, key_url)
    end
    
    context 'when the key fetch fails' do
      it 'raises a KeyFetchError on non-200 response' do
        expect(mock_cache).to receive(:read).and_return(nil)
        stub_request(:get, key_url).to_return(status: 404)
        expect { verifier.send(:fetch_public_key) }.to raise_error(RackJwtVerifier::Verifier::KeyFetchError, /Failed to fetch public key/)
      end

      it 'raises a KeyFetchError on invalid key format and does not cache the bad body' do
        expect(mock_cache).to receive(:read).and_return(nil)
        # A 200 that is not a key must never be cached, or every request would
        # fail for the whole TTL even after the SSO recovers.
        expect(mock_cache).not_to receive(:write)
        
        # Simulate an error by returning invalid data
        stub_request(:get, key_url).to_return(status: 200, body: 'Not a valid PEM key format')
        expect { verifier.send(:fetch_public_key) }.to raise_error(RackJwtVerifier::Verifier::KeyFetchError, /Error processing public key/)
      end

      it 'recovers on the next call once the endpoint serves a real key again' do
        cache = RackJwtVerifier::InProcessCache.new
        recovering = described_class.new(public_key_url: key_url, cache_store: cache)

        stub_request(:get, key_url).to_return(status: 200, body: '<html>maintenance</html>')
        expect { recovering.verify(valid_token) }.to raise_error(RackJwtVerifier::Verifier::KeyFetchError)

        stub_request(:get, key_url).to_return(status: 200, body: public_key_pem)
        expect(recovering.verify(valid_token)).to include('user_id' => 123)
      end

      it 'raises a KeyFetchError when the request times out' do
        expect(mock_cache).to receive(:read).and_return(nil)
        stub_request(:get, key_url).to_timeout
        expect { verifier.send(:fetch_public_key) }
          .to raise_error(RackJwtVerifier::Verifier::KeyFetchError, /Timed out fetching public key/)
      end

      it 'raises a KeyFetchError when the response body exceeds the size cap' do
        expect(mock_cache).to receive(:read).and_return(nil)
        expect(mock_cache).not_to receive(:write)
        oversized = 'A' * (RackJwtVerifier::Verifier::MAX_KEY_RESPONSE_BYTES + 1)
        stub_request(:get, key_url).to_return(status: 200, body: oversized)
        expect { verifier.send(:fetch_public_key) }
          .to raise_error(RackJwtVerifier::Verifier::KeyFetchError, /exceeds/)
      end
    end

    it 'identifies itself with a User-Agent and an Accept header' do
      expect(mock_cache).to receive(:read).and_return(nil)
      allow(mock_cache).to receive(:write)

      verifier.send(:fetch_public_key)

      expect(WebMock).to have_requested(:get, key_url).with(
        headers: {
          'User-Agent' => "rack_jwt_verifier/#{RackJwtVerifier::VERSION}",
          'Accept' => 'application/x-pem-file, text/plain, */*'
        }
      )
    end
  end

  # --- Token Verification ---

  describe '#verify' do
    # Use the mock cache, but ensure read returns a hit so we can verify the token
    before do
      allow(mock_cache).to receive(:read).and_return(public_key_pem)
    end
    
    it 'successfully verifies a valid, signed token and returns the payload' do
      decoded_payload = verifier.verify(valid_token)
      # Must compare the decoded payload without the dynamically generated exp
      expected_payload = payload.map { |k, v| [k.to_s, v] }.to_h
      
      expect(decoded_payload).to include(expected_payload)
      expect(decoded_payload).to have_key('exp')
    end

    it 'raises JWT::ExpiredSignature for an expired token' do
      # Set up a Verifier instance that specifically overrides the default 60-second leeway
      verifier_no_leeway = described_class.new(
        public_key_url: key_url, 
        cache_store: mock_cache,
        decode_options: { leeway: 0 } # Crucial for clean expiration testing
      )
      
      # Use Timecop to guarantee the expiration test works correctly.
      Timecop.freeze(Time.now) do
        # 1. Create a token that expires 10 seconds in the future (from frozen time)
        exp_time = Time.now.to_i + 10
        expired_token = JWT.encode(payload.merge({ exp: exp_time }), private_key_signer, 'RS256')
        
        # 2. Travel forward past the expiration time
        Timecop.travel(Time.now + 11) do
          # 3. Verification should now fail with ExpiredSignature
          expect { verifier_no_leeway.verify(expired_token) }.to raise_error(JWT::ExpiredSignature)
        end
      end
    end

    it 'raises JWT::VerificationError for a token signed by a different key' do
      evil_key = OpenSSL::PKey::RSA.generate(2048)
      # Token is signed by the attacker's key (the evil_key object)
      evil_token = JWT.encode(payload.merge({ exp: Time.now.to_i + 300 }), evil_key, 'RS256')
      expect { verifier.verify(evil_token) }.to raise_error(JWT::VerificationError)
    end

    it 'raises an error if the key fetch fails before verification' do
      # 1. Force a cache miss
      allow(mock_cache).to receive(:read).and_return(nil)
      # 2. Force network failure
      stub_request(:get, key_url).to_return(status: 500)
      
      expect { verifier.verify(valid_token) }.to raise_error(RackJwtVerifier::Verifier::KeyFetchError)
    end

    context 'claim enforcement' do
      def verifier_with(decode_options)
        described_class.new(public_key_url: key_url, cache_store: mock_cache, decode_options: decode_options)
      end

      def token_with(claims)
        JWT.encode(claims.merge(exp: Time.now.to_i + 300), private_key_signer, 'RS256')
      end

      it 'rejects a token whose iss does not match the configured issuer' do
        expect { verifier_with(iss: 'expected-issuer').verify(token_with(iss: 'other-issuer')) }
          .to raise_error(JWT::InvalidIssuerError)
      end

      it 'rejects a token with no iss when an issuer is configured' do
        expect { verifier_with(iss: 'expected-issuer').verify(token_with({})) }
          .to raise_error(JWT::InvalidIssuerError)
      end

      it 'accepts a token whose iss matches the configured issuer' do
        payload = verifier_with(iss: 'expected-issuer').verify(token_with(iss: 'expected-issuer'))
        expect(payload['iss']).to eq('expected-issuer')
      end

      it 'rejects a token whose aud does not match the configured audience' do
        expect { verifier_with(aud: 'my-app').verify(token_with(aud: 'other-app')) }
          .to raise_error(JWT::InvalidAudError)
      end

      it 'accepts a token whose aud matches the configured audience' do
        payload = verifier_with(aud: 'my-app').verify(token_with(aud: 'my-app'))
        expect(payload['aud']).to eq('my-app')
      end
    end
  end
end
