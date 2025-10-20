# frozen_string_literal: true

require 'jwt'
require 'openssl'

# A helper class for handling JWT creation and verification using RSA keys (RS256).
# This is typically used by the application or a separate service to *create* tokens.
module RackJwtVerifier
  class JwtHelper
    # The private_key must be an OpenSSL::PKey::RSA object (or similar).
    attr_reader :private_key, :public_key

    # Initializes the helper with the RSA Private Key used for signing.
    #
    # @param private_key_pem [String] The PEM string of the RSA Private Key.
    def initialize(private_key_pem)
      # !! IMPORTANT !!
      # This key signs the tokens.
      @private_key = OpenSSL::PKey::RSA.new(private_key_pem)
      @public_key = @private_key.public_key
    end

    # Encodes a payload into a JWT.
    #
    # @param payload [Hash] The data to be encoded in the JWT (e.g., user ID, roles).
    # @param expires_in [Integer] Time in seconds until the token expires (default: 1 hour).
    # @return [String] The signed JWT string.
    def encode(payload, expires_in = 3600)
      # Set standard expiration time (exp) and issued-at time (iat) claims
      time = Time.now.to_i
      payload_with_claims = payload.merge({
        iat: time,
        exp: time + expires_in
      })

      JWT.encode(payload_with_claims, @private_key, 'RS256')
    end

    # Decodes and verifies a JWT using the public key.
    #
    # NOTE: This method is used primarily for self-testing in the application
    # but the primary verification logic for the middleware is in the Verifier class.
    #
    # @param token [String] The JWT string to decode.
    # @return [Hash] The decoded payload if verification is successful.
    # @raise [JWT::VerificationError, JWT::DecodeError] If the token is invalid or expired.
    def decode(token)
      # Decodes using the public key, performs signature verification (true),
      # and restricts the algorithm to 'RS256'.
      decoded = JWT.decode(token, @public_key, true, { algorithm: 'RS256' })
      # Returns only the payload (the first element of the array).
      decoded.first
    end
  end
end
