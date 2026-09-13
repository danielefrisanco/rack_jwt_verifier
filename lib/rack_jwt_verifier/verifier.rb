# frozen_string_literal: true

require "jwt"
require_relative "errors"
require_relative "in_process_cache"
require_relative "key_source"
require_relative "replay_guard"

module RackJwtVerifier
  # Decodes and verifies JWTs against key material from a configured source:
  # a static PEM, a PEM served at a URL, a JWKS endpoint, or a shared HMAC
  # secret. Handles caching, key rotation, claim enforcement and optional jti
  # replay protection so the middleware does not have to.
  class Verifier
    # Kept under the old constant so existing `rescue Verifier::KeyFetchError`
    # code keeps working.
    KeyFetchError = RackJwtVerifier::KeyFetchError

    # Cache namespace for a fetched PEM; the full key also carries a digest of the URL.
    PUBLIC_KEY_CACHE_KEY = KeySource::RemotePem::CACHE_KEY_PREFIX
    # Cache namespace for a fetched JWKS; the full key also carries a digest of the URL.
    JWKS_CACHE_KEY = KeySource::RemoteJwks::CACHE_KEY_PREFIX
    # The default TTL for cached key material (5 minutes)
    CACHE_TTL_SECONDS = KeySource::Remote::DEFAULT_CACHE_TTL
    # Default open/read timeout (seconds) for fetching key material
    DEFAULT_HTTP_TIMEOUT = KeySource::Remote::DEFAULT_HTTP_TIMEOUT
    # Largest response body (bytes) accepted as key material
    MAX_KEY_RESPONSE_BYTES = KeySource::Remote::MAX_RESPONSE_BYTES
    # Minimum gap (seconds) between rotation-triggered refetches
    DEFAULT_REFETCH_INTERVAL = KeySource::Remote::DEFAULT_REFETCH_INTERVAL

    # Exactly one of these tells the Verifier where its key comes from. Having
    # shared_secret in the same exclusive set is what rules out "a secret next
    # to a public key" — the classic RS256/HS256 confusion setup.
    KEY_SOURCE_OPTIONS = %i[public_key public_key_url jwks_url shared_secret].freeze

    # The HMAC family, only ever enabled by shared_secret.
    HMAC_ALGORITHMS = %w[HS256 HS384 HS512].freeze

    # RFC 7518 §3.2: an HMAC key must be at least as long as the hash output.
    # Same numbers jwt_auth_client enforces on the signing side.
    MIN_SECRET_BYTES = { "HS256" => 32, "HS384" => 48, "HS512" => 64 }.freeze

    # Default accepted algorithms per key-source family.
    DEFAULT_ASYMMETRIC_ALGORITHMS = %w[RS256].freeze
    DEFAULT_HMAC_ALGORITHMS = %w[HS256].freeze

    # ruby-jwt only validates an expected claim value (e.g. `iss: "..."`) when
    # the matching `verify_*` flag is also set. Map each claim to its flag so we
    # can switch the flag on automatically whenever a value is supplied.
    CLAIM_VERIFY_FLAGS = {
      iss: :verify_iss,
      aud: :verify_aud,
      sub: :verify_sub
    }.freeze

    # Default options for JWT decoding to ensure strict security compliance.
    # ruby-jwt only checks exp/nbf when the claim is present, so `exp` is also
    # listed as required: a token with no expiry would otherwise be valid forever.
    DEFAULT_DECODE_OPTIONS = {
      verify_expiration: true,
      verify_not_before: true,
      required_claims: %w[exp].freeze,
      leeway: 60 # Allow a 60-second clock skew for "exp" and "nbf" claims
    }.freeze

    # @param options [Hash] Configuration options.
    # @option options [String, OpenSSL::PKey] :public_key A static PEM public key or X.509 certificate.
    # @option options [String] :public_key_url The https:// URL serving a PEM public key or certificate.
    # @option options [String] :jwks_url The https:// URL serving a JSON Web Key Set.
    # @option options [String, Hash] :shared_secret An HMAC secret (String) or `{ env: "VAR" }`.
    #   Enables the HS* algorithms; mutually exclusive with the public-key sources.
    # @option options [Array<String>] :algorithms Accepted signing algorithms
    #   (default: ["RS256"], or ["HS256"] with :shared_secret).
    # @option options [Boolean] :allow_insecure_http Permit a plain http:// URL (development only).
    # @option options [Numeric] :http_timeout Open/read/write timeout in seconds for the key fetch.
    # @option options [Integer] :cache_ttl Seconds to cache fetched key material.
    # @option options [Numeric] :refetch_interval Minimum seconds between rotation-triggered refetches.
    # @option options [Object] :cache_store Optional custom cache object (must respond to #read and #write).
    # @option options [Boolean, Object] :replay_cache `true` to track `jti` in :cache_store (or a fresh
    #   InProcessCache), or a cache store to track it in. Tokens are then required to carry a `jti`
    #   and a second presentation before `exp` is rejected.
    # @option options [Logger] :logger Where cache-store failures are reported (default: silent).
    # @option options [Hash] :decode_options Custom options for JWT.decode.
    # @raise [ConfigurationError] for an unusable option set.
    def initialize(options = {})
      source_name = key_source_name(options)
      @key_source = build_key_source(source_name, options)
      @algorithms = build_algorithms(source_name, options)
      @decode_options = build_decode_options(options.fetch(:decode_options, {}), replay: replay_wanted?(options))
      @replay_guard = build_replay_guard(options, @decode_options[:leeway])
    end

    # The algorithms this verifier accepts, after defaults and policy.
    # @return [Array<String>]
    attr_reader :algorithms

    # Decodes and verifies the JWT.
    # @param token [String] The JWT string from the Authorization header.
    # @return [Hash] The decoded payload (the user claims).
    # @raise [JWT::DecodeError] If the token is invalid, expired, replayed, or signature fails.
    # @raise [KeyFetchError] If the key material could not be obtained.
    # @raise [ReplayCacheError] If replay protection is on and its store is unavailable.
    def verify(token)
      payload = decode_with_rotation(token)
      # Only a token that passed every other check is recorded: an expired or
      # mis-signed token must not be able to "burn" a jti.
      @replay_guard&.check!(payload)
      payload
    end

    private

    def decode_with_rotation(token)
      decode(token)
    rescue JWT::VerificationError
      # A signature mismatch may mean the provider rotated its key. Refresh
      # once (rate-limited) and retry; if nothing was refreshed, or the retry
      # fails too, the token is simply bad.
      raise unless @key_source.refresh!

      decode(token)
    end

    # Performs the cryptographic verification and claim validation. The `true`
    # is required to enable verification checks; only the payload is returned.
    def decode(token)
      payload, _header =
        if @key_source.jwks?
          JWT.decode(token, nil, true, @decode_options.merge(jwks: @key_source.jwks_loader))
        else
          JWT.decode(token, @key_source.verification_key, true, @decode_options)
        end
      payload
    end

    def key_source_name(options)
      given = KEY_SOURCE_OPTIONS.select { |name| options[name] }
      return given.first if given.size == 1

      raise ConfigurationError,
            "exactly one of #{KEY_SOURCE_OPTIONS.map(&:inspect).join(', ')} must be given" \
            "#{" (got #{given.map(&:inspect).join(' and ')})" unless given.empty?}"
    end

    def build_key_source(name, options)
      case name
      when :public_key
        KeySource::Static.new(options[:public_key])
      when :public_key_url
        KeySource::RemotePem.new(url: options[:public_key_url], **remote_options(options))
      when :jwks_url
        KeySource::RemoteJwks.new(url: options[:jwks_url], **remote_options(options))
      when :shared_secret
        KeySource::Secret.new(options[:shared_secret])
      end
    end

    def remote_options(options)
      {
        # Inject cache store, defaulting to the simple InProcessCache. This
        # allows users to pass in a cache store that responds to #read and #write.
        cache: options.fetch(:cache_store) { InProcessCache.new },
        cache_ttl: options.fetch(:cache_ttl, CACHE_TTL_SECONDS),
        http_timeout: options.fetch(:http_timeout, DEFAULT_HTTP_TIMEOUT),
        refetch_interval: options.fetch(:refetch_interval, DEFAULT_REFETCH_INTERVAL),
        allow_insecure_http: options.fetch(:allow_insecure_http, false),
        logger: options[:logger]
      }
    end

    # The effective algorithm list, from (in order of precedence) a
    # decode_options :algorithm, the top-level :algorithms, a decode_options
    # :algorithms, or the family default — then checked against the policy:
    # never "none", and HS* only with a shared secret, never mixed with
    # asymmetric algorithms. ruby-jwt would happily verify an RS256 token's
    # public key as an HMAC secret otherwise.
    def build_algorithms(source_name, options)
      decode_options = options.fetch(:decode_options, {})
      hmac = source_name == :shared_secret

      list = decode_options[:algorithm] || options[:algorithms] || decode_options[:algorithms] ||
             (hmac ? DEFAULT_HMAC_ALGORITHMS : DEFAULT_ASYMMETRIC_ALGORITHMS)
      list = Array(list).map { |alg| alg.to_s.strip }.reject(&:empty?)
      raise ConfigurationError, "algorithms must list at least one algorithm" if list.empty?

      if list.any? { |alg| alg.casecmp?("none") }
        raise ConfigurationError, '"none" is not an acceptable algorithm: it disables signature verification'
      end

      hmac_algs, other_algs = list.partition { |alg| HMAC_ALGORITHMS.include?(alg.upcase) }
      if hmac
        unless other_algs.empty?
          raise ConfigurationError,
                "shared_secret only works with #{HMAC_ALGORITHMS.join('/')}; " \
                "remove #{other_algs.join(', ')} from algorithms or use a public key source"
        end
        check_secret_length!(hmac_algs.map(&:upcase))
      elsif hmac_algs.any?
        raise ConfigurationError,
              "#{hmac_algs.join(', ')} require shared_secret; they cannot be mixed with public-key algorithms " \
              "(a public key would be accepted as the HMAC secret)"
      end

      list.freeze
    end

    def check_secret_length!(hmac_algs)
      needed = hmac_algs.map { |alg| MIN_SECRET_BYTES.fetch(alg) }.max
      actual = @key_source.verification_key.bytesize
      return if actual >= needed

      raise ConfigurationError,
            "shared_secret must be at least #{needed} bytes for #{hmac_algs.join('/')} (got #{actual}); " \
            "generate one with: openssl rand -hex #{needed}"
    end

    def replay_wanted?(options)
      store = options[:replay_cache]
      !(store.nil? || store == false)
    end

    def build_replay_guard(options, leeway)
      return nil unless replay_wanted?(options)

      store = options[:replay_cache]
      store = options.fetch(:cache_store) { InProcessCache.new } if store == true
      unless store.respond_to?(:read) && store.respond_to?(:write)
        raise ConfigurationError, "replay_cache must be true or a cache store responding to #read and #write"
      end

      ReplayGuard.new(store, leeway: leeway)
    end

    # Merge default options over any user-provided options, then:
    # - install the policy-checked algorithm list and drop any :algorithm so
    #   ruby-jwt (which consults :algorithm first) sees exactly that list;
    # - make sure an expected claim value is actually enforced: `iss: "x"` on
    #   its own is a no-op in ruby-jwt unless `verify_iss: true` accompanies
    #   it. An explicit `verify_*: false` from the user is left untouched;
    # - require a jti when replay protection is on.
    def build_decode_options(user_options, replay:)
      merged = DEFAULT_DECODE_OPTIONS.merge(user_options)
      merged.delete(:algorithm)
      merged[:algorithms] = @algorithms

      CLAIM_VERIFY_FLAGS.each do |claim, flag|
        merged[flag] = true if merged.key?(claim) && !merged.key?(flag)
      end
      merged[:verify_jti] = true if replay && !merged.key?(:verify_jti)

      leeway = merged[:leeway]
      unless leeway.is_a?(Numeric) && leeway >= 0
        raise ConfigurationError, "decode_options[:leeway] must be a non-negative number of seconds"
      end

      merged
    end
  end
end
