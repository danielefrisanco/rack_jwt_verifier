# frozen_string_literal: true

require "jwt"
require_relative "errors"
require_relative "in_process_cache"
require_relative "key_source"

module RackJwtVerifier
  # Decodes and verifies JWTs against key material from a configured source:
  # a static PEM, a PEM served at a URL, or a JWKS endpoint. Handles caching,
  # key rotation and claim enforcement so the middleware does not have to.
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

    # Exactly one of these tells the Verifier where its key comes from.
    KEY_SOURCE_OPTIONS = %i[public_key public_key_url jwks_url].freeze

    # ruby-jwt only validates an expected claim value (e.g. `iss: "..."`) when
    # the matching `verify_*` flag is also set. Map each claim to its flag so we
    # can switch the flag on automatically whenever a value is supplied.
    CLAIM_VERIFY_FLAGS = {
      iss: :verify_iss,
      aud: :verify_aud,
      sub: :verify_sub
    }.freeze

    # Default options for JWT decoding to ensure strict security compliance
    DEFAULT_DECODE_OPTIONS = {
      algorithm: "RS256", # Must match your SSO provider's algorithm
      # THIS MUST BE TRUE: Ensures the 'exp' claim is checked during decoding
      verify_expiration: true,
      verify_not_before: true,
      leeway: 60 # Allow a 60-second clock skew for "exp" and "nbf" claims
    }.freeze

    # @param options [Hash] Configuration options.
    # @option options [String, OpenSSL::PKey] :public_key A static PEM public key or X.509 certificate.
    # @option options [String] :public_key_url The https:// URL serving a PEM public key or certificate.
    # @option options [String] :jwks_url The https:// URL serving a JSON Web Key Set.
    # @option options [Array<String>] :algorithms Accepted signing algorithms (default: ["RS256"]).
    # @option options [Boolean] :allow_insecure_http Permit a plain http:// URL (development only).
    # @option options [Numeric] :http_timeout Open/read timeout in seconds for the key fetch.
    # @option options [Integer] :cache_ttl Seconds to cache fetched key material.
    # @option options [Numeric] :refetch_interval Minimum seconds between rotation-triggered refetches.
    # @option options [Object] :cache_store Optional custom cache object (must respond to #read and #write).
    # @option options [Hash] :decode_options Custom options for JWT.decode.
    def initialize(options = {})
      @key_source = build_key_source(options)
      @decode_options = build_decode_options(options.fetch(:decode_options, {}), options[:algorithms])
    end

    # Decodes and verifies the JWT.
    # @param token [String] The JWT string from the Authorization header.
    # @return [Hash] The decoded payload (the user claims).
    # @raise [JWT::DecodeError] If the token is invalid, expired, or signature fails.
    # @raise [KeyFetchError] If the key material could not be obtained.
    def verify(token)
      decode(token)
    rescue JWT::VerificationError
      # A signature mismatch may mean the provider rotated its key. Refresh
      # once (rate-limited) and retry; if nothing was refreshed, or the retry
      # fails too, the token is simply bad.
      raise unless @key_source.refresh!

      decode(token)
    end

    private

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

    def build_key_source(options)
      given = KEY_SOURCE_OPTIONS.select { |name| options[name] }
      unless given.size == 1
        raise ArgumentError,
              "exactly one of #{KEY_SOURCE_OPTIONS.map(&:inspect).join(', ')} must be given" \
              "#{given.empty? ? '' : " (got #{given.map(&:inspect).join(' and ')})"}"
      end

      case given.first
      when :public_key
        KeySource::Static.new(options[:public_key])
      when :public_key_url
        KeySource::RemotePem.new(url: options[:public_key_url], **remote_options(options))
      when :jwks_url
        KeySource::RemoteJwks.new(url: options[:jwks_url], **remote_options(options))
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
        allow_insecure_http: options.fetch(:allow_insecure_http, false)
      }
    end

    # Merge default options over any user-provided options, then:
    # - apply a top-level :algorithms list, and drop our :algorithm default
    #   whenever a list is in play — ruby-jwt consults :algorithm first, so the
    #   default would otherwise silently override the user's list;
    # - make sure an expected claim value is actually enforced: `iss: "x"` on
    #   its own is a no-op in ruby-jwt unless `verify_iss: true` accompanies
    #   it. An explicit `verify_*: false` from the user is left untouched.
    def build_decode_options(user_options, algorithms)
      merged = DEFAULT_DECODE_OPTIONS.merge(user_options)
      merged[:algorithms] = Array(algorithms) if algorithms
      merged.delete(:algorithm) if merged.key?(:algorithms) && !user_options.key?(:algorithm)

      CLAIM_VERIFY_FLAGS.each do |claim, flag|
        merged[flag] = true if merged.key?(claim) && !merged.key?(flag)
      end
      merged
    end
  end
end
