# frozen_string_literal: true

require "rack_jwt_verifier/verifier"

module RackJwtVerifier
  # The primary middleware class responsible for intercepting requests,
  # extracting the JWT, verifying it, and injecting the user's details
  # into the Rack environment.
  class Middleware
    # The default key in the Rack environment used to store the verified JWT payload.
    # This can be accessed by downstream applications (e.g., Rails controllers)
    # to retrieve the authenticated user's details.
    RACK_ENV_PAYLOAD_KEY = "rack_jwt_verifier.payload".freeze

    def initialize(app, options = {})
      @app = app
      @options = options
      
      # The Verifier instance is initialized with options (like public_key_url)
      # and is responsible for all crypto and key management.
      @verifier = Verifier.new(options)
    end

    def call(env)
      token = extract_token(env)
      
      # If no token is found, we immediately pass the request down the stack
      # and the application is responsible for handling the unauthenticated state.
      return @app.call(env) unless token

      # Only the verification step is guarded: a JWT::DecodeError raised by the
      # downstream application must propagate, not be turned into a 401 here.
      begin
        # Use the Verifier to handle the complex crypto and validation logic
        payload = @verifier.verify(token)
      rescue JWT::DecodeError => e
        # If verification fails (invalid signature, expired, invalid claim),
        # log the error and return an unauthenticated response.
        warn "JWT Verification Failed: #{e.message}"
        
        # Return a 401 Unauthorized response
        return unauthorized_response
      end

      # On successful verification, store the payload in the Rack environment
      env[RACK_ENV_PAYLOAD_KEY] = payload
      
      @app.call(env)
    end

    private

    # Extracts the JWT from the standard Authorization header format: "Bearer <token>"
    def extract_token(env)
      # Rack converts HTTP_AUTHORIZATION header to ENV['HTTP_AUTHORIZATION']
      auth_header = env["HTTP_AUTHORIZATION"]
      
      return nil unless auth_header
      
      scheme, token = auth_header.split(" ", 2)
      
      # Only process if the scheme is "Bearer" and a token is present
      (scheme == "Bearer") ? token : nil
    end

    # Standard 401 Unauthorized Rack response
    def unauthorized_response
      # Status, Headers, Body (Array of strings)
      [401, { "Content-Type" => "text/plain", "WWW-Authenticate" => "Bearer error=\"invalid_token\"" }, ["Unauthorized: Invalid or expired JWT."]]
    end
  end
end
