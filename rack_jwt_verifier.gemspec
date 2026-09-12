# frozen_string_literal: true

require_relative "lib/rack_jwt_verifier/version"

Gem::Specification.new do |spec|
  spec.name          = "rack-jwt-verifier"
  spec.version       = RackJwtVerifier::VERSION
  spec.authors       = ["Daniele Frisanco"]
  spec.email         = ["daniele.frisanco@gmail.com"]

  spec.summary       = "Rack middleware that authenticates requests with JWTs from an external identity provider."
  spec.description   = "Verifies JWT signatures against a JWKS endpoint, a PEM URL or a static key, enforces " \
                       "exp/nbf/iss/aud claims, caches key material, handles key rotation, and exposes the " \
                       "verified claims to the application through the Rack environment."
  spec.homepage      = "https://github.com/danielefrisanco/rack_jwt_verifier"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  # Ship only what a user needs; no git required to build.
  spec.files         = Dir["lib/**/*.rb"] + %w[README.md CHANGELOG.md LICENSE.md]
  spec.require_paths = ["lib"]

  spec.add_dependency "jwt", "~> 2.8"
  # Default gem until Ruby 3.4; a bundled gem from Ruby 4.0, so it must be declared.
  spec.add_dependency "logger", ">= 1.4"
  spec.add_dependency "rack", ">= 2.2", "< 4"
end
