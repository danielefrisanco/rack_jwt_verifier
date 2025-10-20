# frozen_string_literal: true

# This file serves as the main entry point for the rack_jwt_verifier gem.
# When a user calls `require 'rack_jwt_verifier'`, this file is loaded.

require_relative "rack_jwt_verifier/version"

# Require core component files so they are available under the RackJwtVerifier module.
# IMPORTANT: These paths rely on you moving `jwt_helper.rb` into the
# `lib/rack_jwt_verifier/` directory.
require_relative "rack_jwt_verifier/jwt_helper"
require_relative "rack_jwt_verifier/verifier"
require_relative "rack_jwt_verifier/middleware"
require_relative "rack_jwt_verifier/in_process_cache"


# The main namespace module for the gem. All classes (JwtHelper, Verifier,
# Middleware) are now accessible via RackJwtVerifier::ClassName.
module RackJwtVerifier
end
