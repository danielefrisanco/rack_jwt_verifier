# frozen_string_literal: true

require 'jwt'
require 'openssl'

module RackJwtVerifier
  # Issues (and, for round-trip checks, decodes) RS256 tokens from an RSA
  # private key. This is the *signing* side: use it in tests, or in the service
  # that mints tokens. The middleware itself only ever needs the public key.
  class JwtHelper
    ALGORITHM = 'RS256'

    attr_reader :private_key, :public_key

    # @param private_key_pem [String, OpenSSL::PKey::RSA] The RSA private key used for signing.
    def initialize(private_key_pem)
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
