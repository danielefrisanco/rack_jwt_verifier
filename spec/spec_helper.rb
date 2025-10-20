# frozen_string_literal: true

require "bundler/setup"
require "rack/test"
require "rack_jwt_verifier"
require "webmock/rspec" # New dependency for mocking HTTP requests
require 'timecop' # Required for testing time-dependent logic (caching, expiration)

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
    [200, { "Content-Type" => "text/plain" }, ["User ID in env: #{user_id}"]]
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

  # Helper method to create a Rack app instance for testing
  def app(options = verifier_options)
    RackJwtVerifier::Middleware.new(MockApp.new, options)
  end

  # Placeholder for options used in tests
  def verifier_options
    { public_key_url: "https://sso.example.com/certs" }
  end
end
