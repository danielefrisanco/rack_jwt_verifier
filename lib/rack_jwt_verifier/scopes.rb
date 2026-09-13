# frozen_string_literal: true

module RackJwtVerifier
  # Reads the scopes granted by a verified token.
  #
  # Two claim shapes are understood: `scopes`, an Array of Strings (what
  # jwt_auth_client emits), and `scope`, a space-delimited String (the OAuth 2
  # convention, RFC 8693 §4.2 / RFC 9068 §2.2.3). Both are normalised to an
  # Array of Strings.
  #
  #   claims = env["rack_jwt_verifier.payload"]
  #   RackJwtVerifier::Scopes.from(claims)                     # => ["read:invoices"]
  #   RackJwtVerifier::Scopes.include?(claims, "read:invoices") # => true
  #   RackJwtVerifier::Scopes.missing(claims, %w[read:x write:x]) # => ["write:x"]
  module Scopes
    module_function

    # @param payload [Hash, nil] the verified claims.
    # @return [Array<String>] granted scopes; empty when there are none.
    def from(payload)
      return [] unless payload.is_a?(Hash)

      raw = payload["scopes"] || payload[:scopes]
      raw = payload["scope"] || payload[:scope] if raw.nil?

      case raw
      when Array then raw.map(&:to_s).reject(&:empty?)
      when String then raw.split
      else []
      end
    end

    # @return [Array<String>] the required scopes the payload does not grant.
    def missing(payload, required)
      Array(required).map(&:to_s) - from(payload)
    end

    # @return [Boolean] true when every given scope is granted.
    def include?(payload, *scopes)
      missing(payload, scopes.flatten).empty?
    end
  end
end
