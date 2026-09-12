# frozen_string_literal: true

# Bundler auto-requires a gem by its name, so `gem "rack-jwt-verifier"` looks
# for this file. The real entry point lives under the underscore name.
require_relative "rack_jwt_verifier"
