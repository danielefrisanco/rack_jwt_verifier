# frozen_string_literal: true

require "digest"
require "json"
require "jwt"
require "net/http"
require "openssl"
require "uri"
require_relative "errors"
require_relative "version"

module RackJwtVerifier
  # Where the verification key material comes from.
  #
  # Every source answers #jwks? and #refresh!. A single-key source (Static,
  # RemotePem) also answers #verification_key; a JWKS source answers
  # #jwks_loader, in the shape ruby-jwt's :jwks decode option expects.
  module KeySource
    # Turns PEM text into an OpenSSL public key. Accepts a bare public key
    # (RSA, EC, Ed25519, ...) or an X.509 certificate, which is what many SSO
    # providers serve at their ".pem" endpoints. An OpenSSL::PKey passes through.
    def self.parse_public_key(pem)
      return pem if pem.is_a?(OpenSSL::PKey::PKey)

      text = pem.to_s
      if text.include?("-----BEGIN CERTIFICATE-----")
        OpenSSL::X509::Certificate.new(text).public_key
      else
        OpenSSL::PKey.read(text)
      end
    end

    # A key handed over directly: a PEM string, a certificate PEM, or an
    # OpenSSL::PKey. Nothing to fetch, cache or refresh.
    class Static
      attr_reader :verification_key

      def initialize(key)
        @verification_key = KeySource.parse_public_key(key)
      rescue OpenSSL::PKey::PKeyError, OpenSSL::X509::CertificateError => e
        raise ArgumentError, "public_key is not a valid PEM public key or certificate: #{e.message}"
      end

      def jwks?
        false
      end

      def refresh!
        false
      end
    end

    # Shared machinery for key material fetched over HTTPS: caching, strict
    # timeouts, a size cap, single-flight fetching within the process, and a
    # rate-limited refresh for key rotation. Subclasses say how to parse the
    # body and which cache namespace to use.
    class Remote
      # Timeout (seconds) applied separately to opening the connection and to
      # reading the response. Kept short so a slow endpoint cannot pin every
      # request thread on a cache miss.
      DEFAULT_HTTP_TIMEOUT = 5
      # Largest response body (bytes) we are willing to read. A PEM key is well
      # under 1 KB and a JWKS with a handful of keys a few KB.
      MAX_RESPONSE_BYTES = 64 * 1024
      # How long (seconds) fetched material is served from the cache.
      DEFAULT_CACHE_TTL = 300
      # Minimum gap (seconds) between two rotation-triggered refetches, so a
      # flood of tokens with bad signatures or unknown kids cannot turn into a
      # flood of requests to the provider.
      DEFAULT_REFETCH_INTERVAL = 60

      attr_reader :url, :cache_key

      def initialize(url:, cache:, cache_ttl: DEFAULT_CACHE_TTL, http_timeout: DEFAULT_HTTP_TIMEOUT,
                     refetch_interval: DEFAULT_REFETCH_INTERVAL, allow_insecure_http: false)
        @url = url.to_s
        @uri = parse_url(@url, allow_insecure_http: allow_insecure_http)
        @cache = cache
        @cache_ttl = cache_ttl
        @http_timeout = http_timeout
        @refetch_interval = refetch_interval
        # Scoped to the URL so two verifiers sharing one cache store (two SSO
        # providers behind one Redis) never read each other's key.
        @cache_key = "#{cache_key_prefix}:#{Digest::SHA256.hexdigest(@url)[0, 16]}"

        @fetch_lock = Mutex.new # single-flight: one network fetch per process on a cold cache
        @state_lock = Mutex.new # guards @parsed and @last_refetch_at
        @parsed = nil           # [body, parsed material] of the last body parsed
        @last_refetch_at = nil  # monotonic clock
      end

      # Refetches the material unless a refresh happened less than
      # refetch_interval seconds ago. Returns true if it actually refetched.
      def refresh!
        @state_lock.synchronize do
          now = monotonic_now
          return false if @last_refetch_at && now - @last_refetch_at < @refetch_interval

          @last_refetch_at = now
        end
        fetch_and_store
        true
      end

      private

      # Parsed material, from the cache or (on a miss) the network.
      def material
        body = @cache.read(cache_key) || fetch_once
        parsed_for(body)
      end

      # Only one thread per process performs the fetch on a cold cache; the
      # others wait for it and then find the body in the cache.
      def fetch_once
        @fetch_lock.synchronize do
          @cache.read(cache_key) || fetch_and_store
        end
      end

      def fetch_and_store
        body = fetch_body
        # Parse *before* caching so a 200 that is not key material (an HTML
        # maintenance page, say) is never stored and served for the TTL.
        parse!(body)
        @cache.write(cache_key, body, expires_in: @cache_ttl)
        body
      end

      # Parsing is not free (and JWKS parsing less so), so the result for a
      # given body is memoised until the body changes.
      def parsed_for(body)
        @state_lock.synchronize do
          @parsed = [body, parse!(body)] unless @parsed && @parsed[0] == body
          @parsed[1]
        end
      end

      def parse!(body)
        parse(body)
      rescue KeyFetchError
        raise
      rescue StandardError => e
        raise KeyFetchError, "Error processing public key: #{e.message}"
      end

      # The material must travel over TLS: an attacker who can tamper with a
      # plaintext fetch can substitute their own key and mint arbitrary tokens.
      def parse_url(url, allow_insecure_http:)
        uri = URI.parse(url)
        return uri if uri.is_a?(URI::HTTPS)
        return uri if uri.is_a?(URI::HTTP) && allow_insecure_http

        raise ArgumentError,
              "#{url_option_name} must be an https:// URL (got #{url.inspect}). " \
              "Pass allow_insecure_http: true to permit http:// in development."
      rescue URI::InvalidURIError
        raise ArgumentError, "#{url_option_name} is not a valid URL: #{url.inspect}"
      end

      # Performs the HTTP GET with strict timeouts and a size cap. The body is
      # streamed so an oversized response is abandoned early rather than
      # buffered in full.
      def fetch_body
        uri = @uri
        body = +""

        Net::HTTP.start(uri.host, uri.port,
                        use_ssl: uri.scheme == "https",
                        open_timeout: @http_timeout,
                        read_timeout: @http_timeout) do |http|
          request = Net::HTTP::Get.new(uri)
          request["User-Agent"] = "rack_jwt_verifier/#{VERSION}"
          request["Accept"] = accept_header

          http.request(request) do |response|
            unless response.is_a?(Net::HTTPSuccess)
              raise KeyFetchError, "Failed to fetch public key from #{@url}: #{response.code}"
            end

            response.read_body do |chunk|
              body << chunk
              if body.bytesize > MAX_RESPONSE_BYTES
                raise KeyFetchError, "Public key response from #{@url} exceeds #{MAX_RESPONSE_BYTES} bytes"
              end
            end
          end
        end

        body
      rescue Net::OpenTimeout, Net::ReadTimeout
        raise KeyFetchError, "Timed out fetching public key from #{@url} after #{@http_timeout}s"
      rescue KeyFetchError
        raise
      rescue StandardError => e
        raise KeyFetchError, "Error fetching public key from #{@url}: #{e.message}"
      end

      def monotonic_now
        Process.clock_gettime(Process::CLOCK_MONOTONIC)
      end
    end

    # A single PEM public key (or X.509 certificate) served at a URL.
    class RemotePem < Remote
      CACHE_KEY_PREFIX = "rack_jwt_verifier:public_key"

      def verification_key
        material
      end

      def jwks?
        false
      end

      private

      def cache_key_prefix
        CACHE_KEY_PREFIX
      end

      def url_option_name
        "public_key_url"
      end

      def accept_header
        "application/x-pem-file, text/plain, */*"
      end

      def parse(body)
        KeySource.parse_public_key(body)
      end
    end

    # A JSON Web Key Set served at a URL (typically /.well-known/jwks.json).
    class RemoteJwks < Remote
      CACHE_KEY_PREFIX = "rack_jwt_verifier:jwks"

      def jwks?
        true
      end

      # ruby-jwt calls the loader once, and again with kid_not_found: true when
      # the token's kid is absent from the set it got — the rotation signal for
      # JWKS. Refresh (rate-limited) on that signal, then hand back the set.
      def jwks_loader
        lambda do |options|
          refresh! if options[:kid_not_found] || options[:invalidate]
          material
        end
      end

      private

      def cache_key_prefix
        CACHE_KEY_PREFIX
      end

      def url_option_name
        "jwks_url"
      end

      def accept_header
        "application/jwk-set+json, application/json, */*"
      end

      def parse(body)
        set = JWT::JWK::Set.new(JSON.parse(body))
        raise KeyFetchError, "JWKS from #{@url} contains no keys" if set.size.zero?

        set
      end
    end
  end
end
