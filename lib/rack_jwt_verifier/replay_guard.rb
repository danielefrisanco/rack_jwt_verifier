# frozen_string_literal: true

require "digest"
require_relative "errors"

module RackJwtVerifier
  # Records each verified token's `jti` in a cache store until the token
  # expires, and rejects a token whose `jti` is already there.
  #
  # The store is the same read/write abstraction used for key material
  # (InProcessCache, Rails.cache, ...). An in-process store only detects
  # replays within one worker; use a shared store for real protection.
  #
  # Failure mode is closed: a store that raises turns into ReplayCacheError
  # (a 503 in the middleware). The operator asked for replay protection, so a
  # request whose jti cannot be checked is not waved through.
  class ReplayGuard
    CACHE_KEY_PREFIX = "rack_jwt_verifier:jti"

    # Used when a payload has no numeric `exp` to derive the TTL from (only
    # possible when the operator removed `exp` from required_claims).
    FALLBACK_TTL = 24 * 60 * 60

    attr_reader :store, :leeway

    # @param store [#read, #write] the cache store holding seen jtis.
    # @param leeway [Numeric] clock-skew leeway; a jti is remembered for exp + leeway.
    def initialize(store, leeway: 0)
      @store = store
      @leeway = leeway
    end

    # @param payload [Hash] the verified claims.
    # @raise [ReplayedTokenError] if this jti has been seen before.
    # @raise [JWT::InvalidJtiError] if the payload carries no usable jti.
    # @raise [ReplayCacheError] if the store cannot be read or written.
    def check!(payload)
      jti = payload["jti"].to_s
      raise JWT::InvalidJtiError, "Missing jti" if jti.strip.empty?

      key = cache_key(jti)
      ttl = ttl_for(payload)

      # Read first so stores that ignore unless_exist still catch the common
      # case; the conditional write then closes the window for stores that
      # honour it (ActiveSupport stores return false when the key exists).
      seen, stored = store_access(key, ttl)
      raise ReplayedTokenError, "Token has already been used (jti #{jti})" if seen || stored == false

      nil
    end

    # @param jti [String]
    # @return [String] the cache key; jti is hashed so an attacker-chosen value
    #   cannot produce an unbounded or store-hostile key.
    def cache_key(jti)
      "#{CACHE_KEY_PREFIX}:#{Digest::SHA256.hexdigest(jti)}"
    end

    private

    def store_access(key, ttl)
      seen = @store.read(key)
      return [true, nil] if seen

      [false, @store.write(key, 1, expires_in: ttl, unless_exist: true)]
    rescue StandardError => e
      raise ReplayCacheError, "replay cache unavailable (#{e.class}: #{e.message})"
    end

    def ttl_for(payload)
      exp = payload["exp"]
      return FALLBACK_TTL unless exp.is_a?(Numeric)

      [(exp - Time.now.to_i + @leeway).ceil, 1].max
    end
  end
end
