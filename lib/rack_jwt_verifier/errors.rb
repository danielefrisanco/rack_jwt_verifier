# frozen_string_literal: true

module RackJwtVerifier
  # Raised when the verification key material cannot be obtained or parsed:
  # the remote endpoint is down or slow, returned something that is not a
  # key, or the configured static key does not parse.
  class KeyFetchError < StandardError; end
end
