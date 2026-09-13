# frozen_string_literal: true

require 'jwt'
require 'openssl'

module RackJwtVerifier
  # @deprecated Will be removed in 0.4.0. Issues (and, for round-trip checks,
  #   decodes) RS256 tokens from an RSA private key.
  #
  # This is a second token issuer living inside the verifier: it sets neither
  # `iss`, `aud`, `nbf` nor `jti`, so what it mints does not pass the claim
  # policy the middleware now enforces. Issue tokens with the `jwt_auth_client`
  # gem instead (HMAC today, RS256/ES256 from its 0.3.0); in a test suite,
  # sign with `JWT.encode` directly — see spec/support/token_factory.rb in this
  # repository for a helper you can copy.
  class JwtHelper
    ALGORITHM = 'RS256'

    DEPRECATION = 'RackJwtVerifier::JwtHelper is deprecated and will be removed in 0.4.0: issue tokens with the ' \
                  'jwt_auth_client gem, or sign test tokens with JWT.encode. Set ' \
                  'RACK_JWT_VERIFIER_SILENCE_DEPRECATIONS=1 to silence this warning.'

    @warned = false
    @warn_lock = Mutex.new

    class << self
      # Emits the deprecation warning once per process.
      def warn_deprecated
        return if ENV['RACK_JWT_VERIFIER_SILENCE_DEPRECATIONS'] == '1'

        @warn_lock.synchronize do
          return if @warned

          @warned = true
        end
        Kernel.warn(DEPRECATION, uplevel: 2)
      end

      # Forget that the warning was emitted. Intended for test suites.
      def reset_deprecation_warning!
        @warn_lock.synchronize { @warned = false }
      end
    end

    attr_reader :private_key, :public_key

    # @param private_key_pem [String, OpenSSL::PKey::RSA] The RSA private key used for signing.
    def initialize(private_key_pem)
      self.class.warn_deprecated
      @private_key = private_key_pem.is_a?(OpenSSL::PKey::RSA) ? private_key_pem : OpenSSL::PKey::RSA.new(private_key_pem)
      @public_key = @private_key.public_key
    end

    # Encodes a payload into a JWT, adding `iat` and `exp`.
    #
    # @param payload [Hash] Claims (string or symbol keys; an explicit `exp` in the payload wins).
    # @param expires_in [Integer] Seconds until the token expires (default: 1 hour).
    # @return [String] The signed JWT string.
    def encode(payload, expires_in = 3600)
      now = Time.now.to_i
      # Normalise to string keys first so a caller's 'exp' and our :exp cannot
      # both end up in the JSON as duplicate "exp" members.
      claims = { 'iat' => now, 'exp' => now + expires_in }.merge(payload.transform_keys(&:to_s))
      JWT.encode(claims, @private_key, ALGORITHM)
    end

    # Decodes and verifies a JWT with the public key. Meant for self-checks;
    # the middleware's verification lives in Verifier.
    #
    # @param token [String] The JWT string to decode.
    # @param options [Hash] Extra options for JWT.decode (leeway, iss, verify_iss, ...).
    # @return [Hash] The decoded payload if verification is successful.
    # @raise [JWT::DecodeError] If the token is invalid or expired.
    def decode(token, options = {})
      payload, _header = JWT.decode(token, @public_key, true, { algorithm: ALGORITHM }.merge(options))
      payload
    end
  end
end
