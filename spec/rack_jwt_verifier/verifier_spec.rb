# frozen_string_literal: true

require 'spec_helper'
require 'stringio'

RSpec.describe RackJwtVerifier::Verifier do
  # Helper to generate keys and tokens for testing
  let(:key_pair) { OpenSSL::PKey::RSA.generate(2048) }
  let(:public_key_pem) { key_pair.public_key.to_pem }

  let(:key_url) { 'https://sso.example.com/api/v1/public_key' }
  let(:cache_key) { described_class::PUBLIC_KEY_CACHE_KEY }
  let(:payload) { { 'iss' => 'test_issuer', 'user_id' => 123 } }

  # A cache that always misses unless an example says otherwise, so every
  # verify goes to the (stubbed) network by default.
  let(:mock_cache) { instance_double(RackJwtVerifier::InProcessCache, read: nil, write: nil) }
  let(:verifier) { described_class.new(public_key_url: key_url, cache_store: mock_cache) }

  # Token expires in 5 minutes (300 seconds) unless the claims say otherwise
  let(:valid_token) { token_with }

  def token_with(signer: key_pair, **claims)
    base = payload.merge('exp' => Time.now.to_i + 300)
    JWT.encode(base.merge(claims.transform_keys(&:to_s)), signer, 'RS256')
  end

  def verifier_with(**options)
    described_class.new(public_key_url: key_url, cache_store: mock_cache, **options)
  end

  # A self-signed X.509 certificate carrying the given RSA key's public half.
  def certificate_pem_for(rsa)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse('/CN=sso.example.com')
    cert.public_key = rsa.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 3600
    cert.sign(rsa, OpenSSL::Digest.new('SHA256'))
    cert.to_pem
  end

  def jwks_json(kids_to_keys)
    set = JWT::JWK::Set.new(kids_to_keys.map { |kid, key| JWT::JWK.new(key, kid: kid) })
    JSON.generate(set.export)
  end

  # Set up a successful key fetch stub before each test
  before do
    stub_request(:get, key_url).to_return(status: 200, body: public_key_pem)
  end

  # --- Configuration ---

  describe 'configuration' do
    it 'requires exactly one key source' do
      expect { described_class.new({}) }
        .to raise_error(ArgumentError, /exactly one of :public_key, :public_key_url, :jwks_url/)
      expect { described_class.new(public_key_url: key_url, jwks_url: key_url) }
        .to raise_error(ArgumentError, /got :public_key_url and :jwks_url/)
    end

    context 'public_key_url validation' do
      it 'rejects a plain http:// URL by default' do
        expect { described_class.new(public_key_url: 'http://sso.example.com/key') }
          .to raise_error(ArgumentError, %r{must be an https:// URL})
      end

      it 'accepts a plain http:// URL when allow_insecure_http is true' do
        expect { described_class.new(public_key_url: 'http://sso.example.com/key', allow_insecure_http: true) }
          .not_to raise_error
      end

      it 'rejects a non-HTTP scheme even with allow_insecure_http' do
        expect { described_class.new(public_key_url: 'ftp://sso.example.com/key', allow_insecure_http: true) }
          .to raise_error(ArgumentError, %r{must be an https:// URL})
      end

      it 'rejects a string that is not a URL' do
        expect { described_class.new(public_key_url: 'not a url at all') }
          .to raise_error(ArgumentError, /not a valid URL/)
      end
    end

    it 'validates jwks_url the same way' do
      expect { described_class.new(jwks_url: 'http://sso.example.com/jwks') }
        .to raise_error(ArgumentError, %r{jwks_url must be an https:// URL})
    end

    context 'algorithms' do
      let(:ec_key) { OpenSSL::PKey::EC.generate('prime256v1') }
      let(:es256_token) { JWT.encode(payload.merge('exp' => Time.now.to_i + 300), ec_key, 'ES256') }

      it 'rejects anything but RS256 by default' do
        expect { described_class.new(public_key: ec_key).verify(es256_token) }
          .to raise_error(JWT::IncorrectAlgorithm)
      end

      it 'accepts an ES256 token when algorithms includes it' do
        v = described_class.new(public_key: ec_key, algorithms: %w[RS256 ES256])
        expect(v.verify(es256_token)).to include('user_id' => 123)
      end

      it 'does not let the RS256 default override an algorithms list given in decode_options' do
        v = described_class.new(public_key: ec_key, decode_options: { algorithms: ['ES256'] })
        expect(v.verify(es256_token)).to include('user_id' => 123)
      end

      it 'lets an explicit decode_options algorithm win over the list' do
        v = described_class.new(public_key: ec_key, algorithms: ['ES256'], decode_options: { algorithm: 'RS256' })
        expect { v.verify(es256_token) }.to raise_error(JWT::IncorrectAlgorithm)
      end
    end

    context 'http timeout' do
      def expect_connection_with(timeout)
        expect(Net::HTTP).to receive(:start)
          .with('sso.example.com', 443, hash_including(use_ssl: true, open_timeout: timeout, read_timeout: timeout))
          .and_call_original
      end

      it 'applies the default timeout to the key fetch' do
        expect_connection_with(described_class::DEFAULT_HTTP_TIMEOUT)
        verifier.verify(valid_token)
      end

      it 'applies a custom http_timeout to the key fetch' do
        expect_connection_with(1.5)
        verifier_with(http_timeout: 1.5).verify(valid_token)
      end
    end
  end

  describe 'standalone require' do
    it 'can be required and instantiated without the top-level entry point' do
      lib = File.expand_path('../../lib', __dir__)
      script = 'require "rack_jwt_verifier/verifier"; ' \
               'RackJwtVerifier::Verifier.new(public_key_url: "https://sso.example.com/key"); ' \
               'print "ok"'
      output = IO.popen([RbConfig.ruby, '-I', lib, '-e', script], err: %i[child out], &:read)
      expect(output).to eq('ok')
    end
  end

  # --- Static key ---

  describe 'static public_key' do
    it 'verifies with a PEM public key and never touches the network' do
      v = described_class.new(public_key: public_key_pem)
      expect(v.verify(valid_token)).to include('user_id' => 123)
      expect(WebMock).not_to have_requested(:get, key_url)
    end

    it 'accepts an X.509 certificate PEM' do
      v = described_class.new(public_key: certificate_pem_for(key_pair))
      expect(v.verify(valid_token)).to include('user_id' => 123)
    end

    it 'accepts an OpenSSL::PKey object' do
      v = described_class.new(public_key: key_pair.public_key)
      expect(v.verify(valid_token)).to include('user_id' => 123)
    end

    it 'rejects a token signed by a different key' do
      v = described_class.new(public_key: public_key_pem)
      expect { v.verify(token_with(signer: OpenSSL::PKey::RSA.generate(2048))) }
        .to raise_error(JWT::VerificationError)
    end

    it 'raises ArgumentError at boot for a key that does not parse' do
      expect { described_class.new(public_key: 'not a key') }
        .to raise_error(ArgumentError, /public_key is not a valid PEM/)
    end
  end

  # --- Key Fetching and Caching ---

  describe 'public key retrieval' do
    it 'fetches the key from the remote URL on a cache miss and writes it to the cache' do
      expect(mock_cache).to receive(:read).with(a_string_starting_with(cache_key)).and_return(nil)
      expect(mock_cache).to receive(:write)
        .with(a_string_starting_with(cache_key), public_key_pem, expires_in: described_class::CACHE_TTL_SECONDS)

      expect(verifier.verify(valid_token)).to include('user_id' => 123)
      expect(WebMock).to have_requested(:get, key_url).once
    end

    it 'uses the cached key and never touches the network on a cache hit' do
      expect(mock_cache).to receive(:read).with(a_string_starting_with(cache_key)).and_return(public_key_pem).twice
      expect(mock_cache).not_to receive(:write)

      2.times { verifier.verify(valid_token) }

      expect(WebMock).not_to have_requested(:get, key_url)
    end

    it 'defaults to an in-process cache that holds the key across calls' do
      default_verifier = described_class.new(public_key_url: key_url)

      3.times { default_verifier.verify(valid_token) }

      expect(WebMock).to have_requested(:get, key_url).once
    end

    it 'identifies itself with a User-Agent and an Accept header' do
      verifier.verify(valid_token)

      expect(WebMock).to have_requested(:get, key_url).with(
        headers: {
          'User-Agent' => "rack_jwt_verifier/#{RackJwtVerifier::VERSION}",
          'Accept' => 'application/x-pem-file, text/plain, */*'
        }
      )
    end

    it 'accepts an X.509 certificate PEM served at the URL' do
      stub_request(:get, key_url).to_return(status: 200, body: certificate_pem_for(key_pair))
      expect(verifier.verify(valid_token)).to include('user_id' => 123)
    end

    it 'honours a custom cache_ttl' do
      expect(mock_cache).to receive(:write).with(anything, public_key_pem, expires_in: 42)
      verifier_with(cache_ttl: 42).verify(valid_token)
    end

    it 'scopes the cache key to the URL so verifiers sharing a store do not collide' do
      other_url = 'https://other-sso.example.com/key'
      other_key = OpenSSL::PKey::RSA.generate(2048)
      stub_request(:get, other_url).to_return(status: 200, body: other_key.public_key.to_pem)
      shared = RackJwtVerifier::InProcessCache.new

      first  = described_class.new(public_key_url: key_url, cache_store: shared)
      second = described_class.new(public_key_url: other_url, cache_store: shared)

      expect(first.verify(valid_token)).to include('user_id' => 123)
      expect(second.verify(token_with(signer: other_key))).to include('user_id' => 123)
      expect(WebMock).to have_requested(:get, other_url).once
    end

    it 'fetches only once when many threads miss the cache simultaneously' do
      shared = described_class.new(public_key_url: key_url, cache_store: RackJwtVerifier::InProcessCache.new)
      results = Array.new(8) { Thread.new { shared.verify(valid_token)['user_id'] } }.map(&:value)

      expect(results).to all(eq(123))
      expect(WebMock).to have_requested(:get, key_url).once
    end

    context 'when the cache store is broken' do
      let(:log_io) { StringIO.new }
      let(:broken_cache) { instance_double(RackJwtVerifier::InProcessCache) }
      let(:resilient) do
        described_class.new(public_key_url: key_url, cache_store: broken_cache, logger: Logger.new(log_io))
      end

      it 'treats a failing read as a miss and still verifies' do
        allow(broken_cache).to receive(:read).and_raise(IOError, 'connection refused')
        allow(broken_cache).to receive(:write)
        expect(resilient.verify(valid_token)).to include('user_id' => 123)
        expect(log_io.string).to include('cache read failed').and include('connection refused')
      end

      it 'ignores a failing write and still verifies' do
        allow(broken_cache).to receive(:read).and_return(nil)
        allow(broken_cache).to receive(:write).and_raise(IOError, 'connection refused')
        expect(resilient.verify(valid_token)).to include('user_id' => 123)
        expect(log_io.string).to include('cache write failed')
      end

      it 'falls back to one fetch per call until the store recovers' do
        allow(broken_cache).to receive(:read).and_raise(IOError)
        allow(broken_cache).to receive(:write)
        2.times { resilient.verify(valid_token) }
        expect(WebMock).to have_requested(:get, key_url).twice
      end
    end

    context 'key rotation' do
      let(:rotating) { described_class.new(public_key_url: key_url, cache_store: RackJwtVerifier::InProcessCache.new) }
      let(:new_key) { OpenSSL::PKey::RSA.generate(2048) }

      before do
        rotating.verify(valid_token) # warm the cache with the old key
        stub_request(:get, key_url).to_return(status: 200, body: new_key.public_key.to_pem)
      end

      it 'refetches the key and retries when a signature does not verify' do
        expect(rotating.verify(token_with(signer: new_key))).to include('user_id' => 123)
        expect(WebMock).to have_requested(:get, key_url).twice
      end

      it 'still rejects a token that does not verify against the refetched key' do
        expect { rotating.verify(token_with(signer: OpenSSL::PKey::RSA.generate(2048))) }
          .to raise_error(JWT::VerificationError)
        expect(WebMock).to have_requested(:get, key_url).twice
      end

      it 'does not refetch again within refetch_interval' do
        rotating.verify(token_with(signer: new_key))
        expect { rotating.verify(token_with(signer: OpenSSL::PKey::RSA.generate(2048))) }
          .to raise_error(JWT::VerificationError)
        expect(WebMock).to have_requested(:get, key_url).twice
      end

      it 'refetches again once refetch_interval allows it' do
        eager = described_class.new(public_key_url: key_url, cache_store: RackJwtVerifier::InProcessCache.new,
                                    refetch_interval: 0)
        eager.verify(token_with(signer: new_key))
        expect { eager.verify(token_with(signer: OpenSSL::PKey::RSA.generate(2048))) }
          .to raise_error(JWT::VerificationError)
        # cold fetch + one refetch per bad signature
        expect(WebMock).to have_requested(:get, key_url).times(3)
      end
    end

    context 'when the key fetch fails' do
      it 'raises a KeyFetchError on a non-200 response' do
        stub_request(:get, key_url).to_return(status: 404)
        expect { verifier.verify(valid_token) }
          .to raise_error(described_class::KeyFetchError, /Failed to fetch public key.*404/)
      end

      it 'raises a KeyFetchError on an invalid key body and does not cache it' do
        # A 200 that is not a key must never be cached, or every request would
        # fail for the whole TTL even after the SSO recovers.
        expect(mock_cache).not_to receive(:write)
        stub_request(:get, key_url).to_return(status: 200, body: 'Not a valid PEM key format')

        expect { verifier.verify(valid_token) }
          .to raise_error(described_class::KeyFetchError, /Error processing public key/)
      end

      it 'recovers on the next call once the endpoint serves a real key again' do
        recovering = described_class.new(public_key_url: key_url, cache_store: RackJwtVerifier::InProcessCache.new)

        stub_request(:get, key_url).to_return(status: 200, body: '<html>maintenance</html>')
        expect { recovering.verify(valid_token) }.to raise_error(described_class::KeyFetchError)

        stub_request(:get, key_url).to_return(status: 200, body: public_key_pem)
        expect(recovering.verify(valid_token)).to include('user_id' => 123)
      end

      it 'raises a KeyFetchError when the request times out' do
        stub_request(:get, key_url).to_timeout
        expect { verifier.verify(valid_token) }
          .to raise_error(described_class::KeyFetchError, /Timed out fetching public key/)
      end

      it 'raises a KeyFetchError when the response body exceeds the size cap' do
        expect(mock_cache).not_to receive(:write)
        oversized = 'A' * (described_class::MAX_KEY_RESPONSE_BYTES + 1)
        stub_request(:get, key_url).to_return(status: 200, body: oversized)

        expect { verifier.verify(valid_token) }
          .to raise_error(described_class::KeyFetchError, /exceeds/)
      end
    end
  end

  # --- JWKS ---

  describe 'jwks_url' do
    let(:jwks_url) { 'https://sso.example.com/.well-known/jwks.json' }
    let(:second_key) { OpenSSL::PKey::RSA.generate(2048) }
    let(:jwks_verifier) { described_class.new(jwks_url: jwks_url, cache_store: RackJwtVerifier::InProcessCache.new) }

    def kid_token(kid, key)
      JWT.encode(payload.merge('exp' => Time.now.to_i + 300), key, 'RS256', kid: kid)
    end

    before { stub_request(:get, jwks_url).to_return(status: 200, body: jwks_json('k1' => key_pair)) }

    it 'verifies a token whose kid is in the set' do
      expect(jwks_verifier.verify(kid_token('k1', key_pair))).to include('user_id' => 123)
      expect(WebMock).to have_requested(:get, jwks_url).once
    end

    it 'caches the JWKS body under its own namespace' do
      expect(mock_cache).to receive(:write)
        .with(a_string_starting_with(described_class::JWKS_CACHE_KEY), jwks_json('k1' => key_pair),
              expires_in: anything)
      described_class.new(jwks_url: jwks_url, cache_store: mock_cache).verify(kid_token('k1', key_pair))
    end

    it 'sends a JSON Accept header' do
      jwks_verifier.verify(kid_token('k1', key_pair))
      expect(WebMock).to have_requested(:get, jwks_url)
        .with(headers: { 'Accept' => 'application/jwk-set+json, application/json, */*' })
    end

    it 'rejects a token whose kid is not in the set, after one refetch' do
      expect { jwks_verifier.verify(kid_token('nope', key_pair)) }
        .to raise_error(JWT::DecodeError, /Could not find public key for kid nope/)
      expect(WebMock).to have_requested(:get, jwks_url).twice
    end

    it 'picks up a newly rotated key on an unknown kid' do
      jwks_verifier.verify(kid_token('k1', key_pair))
      stub_request(:get, jwks_url).to_return(status: 200, body: jwks_json('k1' => key_pair, 'k2' => second_key))

      expect(jwks_verifier.verify(kid_token('k2', second_key))).to include('user_id' => 123)
      expect(WebMock).to have_requested(:get, jwks_url).twice
    end

    it 'rate-limits refetches triggered by unknown kids' do
      expect { jwks_verifier.verify(kid_token('nope', key_pair)) }.to raise_error(JWT::DecodeError)
      expect { jwks_verifier.verify(kid_token('nope2', key_pair)) }.to raise_error(JWT::DecodeError)
      expect(WebMock).to have_requested(:get, jwks_url).twice
    end

    it 'rejects a token signed by a different key even when the kid matches' do
      expect { jwks_verifier.verify(kid_token('k1', second_key)) }.to raise_error(JWT::VerificationError)
    end

    it 'rejects a token with no kid by default' do
      expect { jwks_verifier.verify(valid_token) }.to raise_error(JWT::DecodeError, /kid/)
    end

    it 'accepts a token with no kid when allow_nil_kid is set' do
      lenient = described_class.new(jwks_url: jwks_url, cache_store: RackJwtVerifier::InProcessCache.new,
                                    decode_options: { allow_nil_kid: true })
      expect(lenient.verify(valid_token)).to include('user_id' => 123)
    end

    it 'verifies an ES256 token from an EC JWK when algorithms allows it' do
      ec_key = OpenSSL::PKey::EC.generate('prime256v1')
      stub_request(:get, jwks_url).to_return(status: 200, body: jwks_json('ec1' => ec_key))
      v = described_class.new(jwks_url: jwks_url, algorithms: ['ES256'], cache_store: RackJwtVerifier::InProcessCache.new)
      token = JWT.encode(payload.merge('exp' => Time.now.to_i + 300), ec_key, 'ES256', kid: 'ec1')
      expect(v.verify(token)).to include('user_id' => 123)
    end

    context 'when the JWKS is unusable' do
      let(:strict) { described_class.new(jwks_url: jwks_url, cache_store: mock_cache) }

      it 'raises KeyFetchError and does not cache a set with no keys' do
        expect(mock_cache).not_to receive(:write)
        stub_request(:get, jwks_url).to_return(status: 200, body: '{"keys":[]}')
        expect { strict.verify(kid_token('k1', key_pair)) }
          .to raise_error(described_class::KeyFetchError, /contains no keys/)
      end

      it 'raises KeyFetchError and does not cache a body that is not JSON' do
        expect(mock_cache).not_to receive(:write)
        stub_request(:get, jwks_url).to_return(status: 200, body: '<html>maintenance</html>')
        expect { strict.verify(kid_token('k1', key_pair)) }
          .to raise_error(described_class::KeyFetchError, /Error processing public key/)
      end

      it 'raises KeyFetchError when the endpoint is down' do
        stub_request(:get, jwks_url).to_return(status: 502)
        expect { strict.verify(kid_token('k1', key_pair)) }
          .to raise_error(described_class::KeyFetchError, /502/)
      end
    end
  end

  # --- Token Verification ---

  describe '#verify' do
    it 'returns the payload of a valid, correctly signed token' do
      decoded = verifier.verify(valid_token)
      expect(decoded).to include(payload)
      expect(decoded).to have_key('exp')
    end

    it 'raises JWT::VerificationError for a token signed by a different key' do
      evil_token = token_with(signer: OpenSSL::PKey::RSA.generate(2048))
      expect { verifier.verify(evil_token) }.to raise_error(JWT::VerificationError)
    end

    it 'raises JWT::IncorrectAlgorithm for a token signed with a different algorithm' do
      hmac_token = JWT.encode(payload.merge('exp' => Time.now.to_i + 300), 'shared-secret', 'HS256')
      expect { verifier.verify(hmac_token) }.to raise_error(JWT::IncorrectAlgorithm)
    end

    it 'raises JWT::DecodeError for a malformed token' do
      expect { verifier.verify('this.is.not.a.jwt') }.to raise_error(JWT::DecodeError)
    end

    it 'raises KeyFetchError if the key cannot be fetched' do
      stub_request(:get, key_url).to_return(status: 500)
      expect { verifier.verify(valid_token) }.to raise_error(described_class::KeyFetchError)
    end

    context 'expiration, not-before and leeway' do
      let(:now) { Time.now }

      around { |example| Timecop.freeze(now) { example.run } }

      it 'accepts a token that expired within the default 60-second leeway' do
        expect(verifier.verify(token_with(exp: now.to_i - 30))).to include('user_id' => 123)
      end

      it 'rejects a token that expired beyond the default leeway' do
        expect { verifier.verify(token_with(exp: now.to_i - 61)) }.to raise_error(JWT::ExpiredSignature)
      end

      it 'rejects a token that expired one second ago when leeway is 0' do
        strict = verifier_with(decode_options: { leeway: 0 })
        expect { strict.verify(token_with(exp: now.to_i - 1)) }.to raise_error(JWT::ExpiredSignature)
      end

      it 'accepts a token whose nbf is in the future but within leeway' do
        expect(verifier.verify(token_with(nbf: now.to_i + 30))).to include('user_id' => 123)
      end

      it 'rejects a token whose nbf is in the future beyond leeway' do
        expect { verifier.verify(token_with(nbf: now.to_i + 120)) }.to raise_error(JWT::ImmatureSignature)
      end
    end

    context 'claim enforcement' do
      it 'rejects a token whose iss does not match the configured issuer' do
        expect { verifier_with(decode_options: { iss: 'expected-issuer' }).verify(token_with(iss: 'other-issuer')) }
          .to raise_error(JWT::InvalidIssuerError)
      end

      it 'rejects a token with no iss when an issuer is configured' do
        no_iss = JWT.encode({ 'user_id' => 1, 'exp' => Time.now.to_i + 300 }, key_pair, 'RS256')
        expect { verifier_with(decode_options: { iss: 'expected-issuer' }).verify(no_iss) }
          .to raise_error(JWT::InvalidIssuerError)
      end

      it 'accepts a token whose iss matches the configured issuer' do
        decoded = verifier_with(decode_options: { iss: 'expected-issuer' }).verify(token_with(iss: 'expected-issuer'))
        expect(decoded['iss']).to eq('expected-issuer')
      end

      it 'accepts any issuer when none is configured' do
        expect(verifier.verify(token_with(iss: 'whoever'))['iss']).to eq('whoever')
      end

      it 'rejects a token whose aud does not match the configured audience' do
        expect { verifier_with(decode_options: { aud: 'my-app' }).verify(token_with(aud: 'other-app')) }
          .to raise_error(JWT::InvalidAudError)
      end

      it 'accepts a token whose aud matches the configured audience' do
        decoded = verifier_with(decode_options: { aud: 'my-app' }).verify(token_with(aud: 'my-app'))
        expect(decoded['aud']).to eq('my-app')
      end

      it 'rejects a token whose sub does not match the configured subject' do
        expect { verifier_with(decode_options: { sub: 'user-1' }).verify(token_with(sub: 'user-2')) }
          .to raise_error(JWT::InvalidSubError)
      end

      it 'honours an explicit verify_iss: false alongside iss' do
        lenient = verifier_with(decode_options: { iss: 'expected-issuer', verify_iss: false })
        expect(lenient.verify(token_with(iss: 'other-issuer'))['iss']).to eq('other-issuer')
      end

      it 'keeps the RS256 default when other decode options are customised' do
        hmac_token = JWT.encode(payload.merge('exp' => Time.now.to_i + 300), 'shared-secret', 'HS256')
        expect { verifier_with(decode_options: { leeway: 10 }).verify(hmac_token) }
          .to raise_error(JWT::IncorrectAlgorithm)
      end
    end
  end
end
