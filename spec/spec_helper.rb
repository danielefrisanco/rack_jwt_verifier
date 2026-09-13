# frozen_string_literal: true

require "bundler/setup"
require "logger"
require "rack/test"
require "rack/lint"
require "rack_jwt_verifier"
require "webmock/rspec" # New dependency for mocking HTTP requests
require 'timecop' # Required for testing time-dependent logic (caching, expiration)

Dir[File.join(__dir__, "support", "**", "*.rb")].each { |f| require f }

# WebMock configuration: Ensure no real network connections are made during tests.
WebMock.disable_net_connect!(allow_localhost: true)

# Mock Rack Application for testing middleware
class MockApp
  # Stores the expected user ID for retrieval in tests
  def call(env)
    # FIX: Safely access the payload. If it's nil, use 'NONE' for the user ID.
    payload = env['rack_jwt_verifier.payload']
    user_id = payload ? payload['user_id'] : 'NONE'

    # The actual application will use the verified user data from the environment
    [200, { "content-type" => "text/plain" }, ["User ID in env: #{user_id}"]]
  end
end

# Swallows log output so the suite stays quiet; tests that care about logging
# pass their own logger.
NULL_LOGGER = Logger.new(IO::NULL)

# Issuer and audience every test token carries and every middleware expects.
TEST_ISSUER = "trusted-sso"
TEST_AUDIENCE = "my_app"

module MiddlewareSpecHelpers
  # Builds the middleware under test. Rack::Lint makes every response prove it
  # satisfies the Rack SPEC (lowercase headers etc.).
  def build_app(options = verifier_options, inner = MockApp.new)
    Rack::Lint.new(RackJwtVerifier::Middleware.new(inner, options))
  end

  # The app Rack::Test drives by default; contexts override with `let(:app)`.
  # Memoised per example so consecutive requests hit the same middleware
  # instance — and therefore the same key cache.
  def app
    @app ||= build_app
  end

  # Default options used in tests
  def verifier_options
    {
      public_key_url: "https://sso.example.com/certs",
      logger: NULL_LOGGER,
      decode_options: { iss: TEST_ISSUER, aud: TEST_AUDIENCE }
    }
  end

  # Default options plus extra decode options, keeping iss/aud in place.
  def options_with_decode(extra, base = verifier_options)
    base.merge(decode_options: base[:decode_options].merge(extra))
  end
end

RSpec.configure do |config|
  # Enable flags like --only-failures and --next-failure
  config.example_status_persistence_file_path = ".rspec_status"

  # Disable RSpec exposing methods globally on `Module` and `main`
  config.disable_monkey_patching!

  config.expect_with :rspec do |c|
    c.syntax = :expect
  end

  # Include Rack::Test helpers
  config.include Rack::Test::Methods
  config.include MiddlewareSpecHelpers
end
