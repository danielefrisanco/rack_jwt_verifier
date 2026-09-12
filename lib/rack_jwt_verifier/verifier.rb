# frozen_string_literal: true

require "jwt"
require "net/http"
require "uri"
require "json"
require_relative "version"

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

    # Default timeout (seconds) applied separately to opening the connection
    # and to reading the response when fetching the public key. Kept short so a
    # slow SSO endpoint cannot pin every request thread on a cache miss.
    DEFAULT_HTTP_TIMEOUT = 5
    # Largest response body (bytes) we are willing to read as a public key.
    # A PEM-encoded RSA key is well under 1 KB; anything bigger is not a key.
    MAX_KEY_RESPONSE_BYTES = 64 * 1024

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
    # @option options [String] :public_key_url The https:// URL to fetch the public key.
    # @option options [Boolean] :allow_insecure_http Permit a plain http:// URL (development only).
    # @option options [Numeric] :http_timeout Open/read timeout in seconds for the key fetch.
    # @option options [Object] :cache_store Optional custom cache object (must respond to #read and #write).
    # @option options [Hash] :decode_options Custom options for JWT.decode.
    def initialize(options = {})
      @public_key_url = options.fetch(:public_key_url)
      @public_key_uri = parse_public_key_url(
        @public_key_url,
        allow_insecure_http: options.fetch(:allow_insecure_http, false)
      )
      @http_timeout = options.fetch(:http_timeout, DEFAULT_HTTP_TIMEOUT)
      
      # Inject cache store, defaulting to the simple InProcessCache.
      # This allows users to pass in a cache store that responds to #read and #write.
      @cache = options.fetch(:cache_store, InProcessCache.new)
      
      @decode_options = build_decode_options(options.fetch(:decode_options, {}))
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

    # The public key must travel over TLS: an attacker who can tamper with a
    # plaintext fetch can substitute their own key and mint arbitrary tokens.
    def parse_public_key_url(url, allow_insecure_http:)
      uri = URI.parse(url.to_s)
      return uri if uri.is_a?(URI::HTTPS)
      return uri if uri.is_a?(URI::HTTP) && allow_insecure_http

      raise ArgumentError,
            "public_key_url must be an https:// URL (got #{url.inspect}). " \
            "Pass allow_insecure_http: true to permit http:// in development."
    rescue URI::InvalidURIError
      raise ArgumentError, "public_key_url is not a valid URL: #{url.inspect}"
    end

    # Merge default options over any user-provided options, then make sure an
    # expected claim value is actually enforced: `iss: "x"` on its own is a
    # no-op in ruby-jwt unless `verify_iss: true` accompanies it. An explicit
    # `verify_*: false` from the user is left untouched.
    def build_decode_options(user_options)
      merged = DEFAULT_DECODE_OPTIONS.merge(user_options)
      CLAIM_VERIFY_FLAGS.each do |claim, flag|
        merged[flag] = true if merged.key?(claim) && !merged.key?(flag)
      end
      merged
    end

    # Handles fetching the public key from the remote URL, using the injected cache.
    def fetch_public_key
      # 1. Try to read the PEM string from the cache
      cached_pem = @cache.read(PUBLIC_KEY_CACHE_KEY)
      
      if cached_pem
        # Found in cache, convert PEM to OpenSSL object and return
        return OpenSSL::PKey::RSA.new(cached_pem)
      end

      # 2. Key is missing or expired, fetch it from the network
      public_key_pem = fetch_public_key_pem
      
      # 3. Cache the new key PEM string
      @cache.write(PUBLIC_KEY_CACHE_KEY, public_key_pem, expires_in: CACHE_TTL_SECONDS)
      
      # 4. Return the OpenSSL object for verification
      OpenSSL::PKey::RSA.new(public_key_pem)

    rescue KeyFetchError
      # Re-raise explicit KeyFetchError for easier debugging/rescue in middleware
      raise
    rescue StandardError => e
      # Catch all other network/parsing/OpenSSL errors
      raise KeyFetchError, "Error processing public key: #{e.message}"
    end

    # Performs the HTTP GET for the key with strict timeouts and a size cap.
    # The body is streamed so an oversized response is abandoned early rather
    # than buffered in full.
    def fetch_public_key_pem
      uri = @public_key_uri
      body = +""

      Net::HTTP.start(uri.host, uri.port,
                      use_ssl: uri.scheme == "https",
                      open_timeout: @http_timeout,
                      read_timeout: @http_timeout) do |http|
        request = Net::HTTP::Get.new(uri)
        request["User-Agent"] = "rack_jwt_verifier/#{VERSION}"
        request["Accept"] = "application/x-pem-file, text/plain, */*"

        http.request(request) do |response|
          unless response.is_a?(Net::HTTPSuccess)
            raise KeyFetchError, "Failed to fetch public key from #{@public_key_url}: #{response.code}"
          end

          response.read_body do |chunk|
            body << chunk
            if body.bytesize > MAX_KEY_RESPONSE_BYTES
              raise KeyFetchError,
                    "Public key response from #{@public_key_url} exceeds #{MAX_KEY_RESPONSE_BYTES} bytes"
            end
          end
        end
      end

      body
    rescue Net::OpenTimeout, Net::ReadTimeout
      raise KeyFetchError, "Timed out fetching public key from #{@public_key_url} after #{@http_timeout}s"
    end
  end
end
