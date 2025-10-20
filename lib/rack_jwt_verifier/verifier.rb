# frozen_string_literal: true

require "jwt"
require "net/http"
require "json"

module RackJwtVerifier
  # This class handles the cryptographic heavy lifting: fetching and caching
  # public keys from the SSO provider, and performing the actual JWT decoding
  # and signature verification.
  class Verifier
    # Error raised if we fail to fetch keys from the remote URL
    class KeyFetchError < StandardError; end
    
    # The cache key used to store the public key PEM string
    PUBLIC_KEY_CACHE_KEY = 'rack_jwt_verifier:public_key'.freeze
    # The TTL for the cache (5 minutes, must match the default in InProcessCache)
    CACHE_TTL_SECONDS = 300

    # Default options for JWT decoding to ensure strict security compliance
    DEFAULT_DECODE_OPTIONS = {
      algorithm: "RS256", # Must match your SSO provider's algorithm
      # THIS MUST BE TRUE: Ensures the 'exp' claim is checked during decoding
      verify_expiration: true,
      verify_not_before: true,
      leeway: 60, # Allow a 60-second clock skew for "exp" and "nbf" claims
      # 'iss' validation will be added later when we configure the Verifier.
      # verify_iss: true
    }.freeze

    # @param options [Hash] Configuration options.
    # @option options [String] :public_key_url The URL to fetch the public key.
    # @option options [Object] :cache_store Optional custom cache object (must respond to #read and #write).
    # @option options [Hash] :decode_options Custom options for JWT.decode.
    def initialize(options = {})
      @public_key_url = options.fetch(:public_key_url)
      
      # Inject cache store, defaulting to the simple InProcessCache.
      # This allows users to pass in a Redis/Memcached client that responds to #read and #write.
      @cache = options.fetch(:cache_store, InProcessCache.new)
      
      # Merge default options over any user-provided options
      @decode_options = DEFAULT_DECODE_OPTIONS.merge(options.fetch(:decode_options, {}))
    end

    # Decodes and verifies the JWT.
    # @param token [String] The JWT string from the Authorization header.
    # @return [Hash] The decoded payload (the user claims).
    # @raise [JWT::DecodeError] If the token is invalid, expired, or signature fails.
    def verify(token)
      # 1. Fetch the key from cache or network
      key = fetch_public_key

      # 2. Perform the cryptographic verification and claim validation
      # The `true` is required to enable verification checks.
      payload, _header = JWT.decode(token, key, true, @decode_options)
      
      # For standard usage, we only need the payload hash
      payload
    end

    private

    # Handles fetching the public key from the remote URL, using the injected cache.
    def fetch_public_key
      # 1. Try to read the PEM string from the cache
      cached_pem = @cache.read(PUBLIC_KEY_CACHE_KEY)
      
      if cached_pem
        # Found in cache, convert PEM to OpenSSL object and return
        return OpenSSL::PKey::RSA.new(cached_pem)
      end

      # 2. Key is missing or expired, fetch it from the network
      uri = URI(@public_key_url)
      response = Net::HTTP.get_response(uri)

      unless response.is_a?(Net::HTTPSuccess)
        raise KeyFetchError, "Failed to fetch public key from #{@public_key_url}: #{response.code}"
      end

      # 3. Process response
      public_key_pem = response.body
      
      # 4. Cache the new key PEM string
      @cache.write(PUBLIC_KEY_CACHE_KEY, public_key_pem, expires_in: CACHE_TTL_SECONDS)
      
      # 5. Return the OpenSSL object for verification
      OpenSSL::PKey::RSA.new(public_key_pem)

    rescue KeyFetchError
      # Re-raise explicit KeyFetchError for easier debugging/rescue in middleware
      raise
    rescue StandardError => e
      # Catch all other network/parsing/OpenSSL errors
      raise KeyFetchError, "Error processing public key: #{e.message}"
    end
  end
end
