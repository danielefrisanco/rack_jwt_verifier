# frozen_string_literal: true

require "jwt"

module RackJwtVerifier
  # Base class for every error this gem raises on its own behalf. Token
  # verification failures keep raising ruby-jwt's JWT::DecodeError family.
  class Error < StandardError; end

  # Raised at boot for an unusable option set: no key source, a shared secret
  # next to a public key, HS* mixed with RS*/ES*, a too-short secret, missing
  # iss/aud, ... Raised from Middleware.new / Verifier.new, never per request.
  class ConfigurationError < Error; end

  # Raised when the verification key material cannot be obtained or parsed:
  # the remote endpoint is down or slow, returned something that is not a
  # key, or the configured static key does not parse.
  class KeyFetchError < Error; end

  # Raised when the replay cache (jti store) cannot be read or written. The
  # middleware answers 503: the operator asked for replay protection, so a
  # request whose jti cannot be checked is refused rather than waved through.
  class ReplayCacheError < Error; end

  # Raised when a token's jti has already been seen. Subclasses ruby-jwt's
  # InvalidJtiError so it travels the same 401 path as any other bad claim.
  class ReplayedTokenError < JWT::InvalidJtiError; end

  # Handed to the :on_error hook when a token lacks a scope listed in
  # require_scopes. Carries what was required and what was missing.
  class InsufficientScopeError < Error
    attr_reader :required, :missing

    def initialize(required:, missing:)
      @required = required
      @missing = missing
      super("Token lacks required scope(s): #{missing.join(' ')}")
    end
  end
end
