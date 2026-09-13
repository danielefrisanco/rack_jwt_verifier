# frozen_string_literal: true

require 'jwt'
require 'securerandom'

# Signs test tokens in the shape jwt_auth_client emits (iss, sub, aud, scopes,
# iat, nbf, exp, jti + custom claims), with any key and algorithm ruby-jwt
# supports. This replaces RackJwtVerifier::JwtHelper in the suite; copy it into
# your own spec/support if you need one.
module TokenFactory
  module_function

  # @param key [String, OpenSSL::PKey::PKey] HMAC secret or private key.
  # @param algorithm [String] e.g. 'HS256', 'RS256', 'ES256'.
  # @param claims [Hash] claims to add or override (String or Symbol keys).
  # @param kid [String, nil] key id for the JOSE header.
  # @param expires_in [Integer] seconds until exp.
  # @return [String] the signed token.
  def sign(key:, algorithm:, claims: {}, kid: nil, expires_in: 300, iss: TEST_ISSUER, aud: TEST_AUDIENCE)
    now = Time.now.to_i
    payload = {
      'iss' => iss, 'sub' => 'user-1', 'aud' => aud,
      'iat' => now, 'nbf' => now, 'exp' => now + expires_in, 'jti' => SecureRandom.uuid
    }.merge(claims.transform_keys(&:to_s)).compact
    headers = kid ? { kid: kid } : {}
    JWT.encode(payload, key, algorithm, headers)
  end
end
