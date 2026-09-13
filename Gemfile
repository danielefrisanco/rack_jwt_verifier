# frozen_string_literal: true

source "https://rubygems.org"

# Runtime dependencies live in the gemspec.
gemspec

group :development, :test do
  gem "rack-test", "~> 2.1"
  gem "rake", "~> 13.0"
  gem "rspec", "~> 3.12"
  gem "rubocop", "~> 1.60", require: false
  gem "timecop", "~> 0.9"
  gem "webmock", "~> 3.18"
end

# The issuing half of the pair, for the round-trip interop specs
# (spec/rack_jwt_verifier/interop_spec.rb). Optional: those specs skip when
# the gem is not around. Point JWT_AUTH_CLIENT_PATH at a checkout, or keep one
# next to this repository. jwt_auth_client needs Ruby >= 3.1.
jwt_auth_client_path = ENV.fetch("JWT_AUTH_CLIENT_PATH", File.expand_path("../jwt_auth_client", __dir__))
if RUBY_VERSION >= "3.1" && File.exist?(File.join(jwt_auth_client_path, "jwt_auth_client.gemspec"))
  gem "jwt_auth_client", path: jwt_auth_client_path, group: %i[development test]
end
