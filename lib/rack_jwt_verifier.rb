# frozen_string_literal: true

# Entry point for the gem: `require "rack_jwt_verifier"` loads everything.
# (`require "rack-jwt-verifier"`, the gem's name, works too.)

require_relative "rack_jwt_verifier/version"
require_relative "rack_jwt_verifier/errors"
require_relative "rack_jwt_verifier/in_process_cache"
require_relative "rack_jwt_verifier/key_source"
require_relative "rack_jwt_verifier/replay_guard"
require_relative "rack_jwt_verifier/scopes"
require_relative "rack_jwt_verifier/verifier"
require_relative "rack_jwt_verifier/middleware"
require_relative "rack_jwt_verifier/jwt_helper"

# Namespace for the gem: Middleware, Verifier, KeySource, Scopes, ReplayGuard,
# InProcessCache and the deprecated JwtHelper.
module RackJwtVerifier
end
