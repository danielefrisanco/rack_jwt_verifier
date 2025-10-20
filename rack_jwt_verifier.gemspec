# frozen_string_literal: true

require_relative "lib/rack_jwt_verifier/version"

Gem::Specification.new do |spec|
  spec.name          = "rack-jwt-verifier"
  spec.version       = RackJwtVerifier::VERSION
  spec.authors       = ["Daniele Frisanco"]
  spec.email         = ["daniele.frisanco@gmail.com"]

  spec.summary       = "A Rack middleware for authenticating requests using JWTs (JSON Web Tokens) and injecting user data into the Rack environment."
  spec.description   = "Verifies JWT signature, validates claims (expiration, issuer), and handles public key retrieval to ensure requests are securely authenticated by an external SSO provider."
  spec.homepage      = "https://github.com/danielefrisanco/rack_jwt_verifier"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 2.6.6"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    %x{git ls-files -z}.split("\x0").reject do |f|
      (f == "rack_jwt_verifier.gemspec") ||
        f.match(%r{^(test|spec|features)/})
    end
  end
  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Production Dependencies
  spec.add_dependency "jwt", "~> 2.8"
  spec.add_dependency "rack", ">= 2.0"

  # Development Dependencies
  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.0"
  spec.add_development_dependency "webmock", "~> 3.0"
  spec.add_development_dependency "timecop", "~> 0.9"

  spec.add_development_dependency "rack-test"
end
