# frozen_string_literal: true

require "logger"
require_relative "verifier"

module RackJwtVerifier
  # The primary middleware class responsible for intercepting requests,
  # extracting the JWT, verifying it, and injecting the user's details
  # into the Rack environment.
  class Middleware
    # The default key in the Rack environment used to store the verified JWT payload.
    # This can be accessed by downstream applications (e.g., Rails controllers)
    # to retrieve the authenticated user's details.
    RACK_ENV_PAYLOAD_KEY = "rack_jwt_verifier.payload"

    # Seconds a client is told to wait before retrying after a 503.
    RETRY_AFTER_SECONDS = 5

    # Used when neither a :logger option nor env["rack.logger"] is available.
    NULL_LOGGER = Logger.new(IO::NULL)

    # @param app [#call] The downstream Rack application.
    # @param options [Hash] Middleware options; everything else is forwarded to Verifier.
    # @option options [Boolean] :require_token Reject requests that carry no Bearer token (default: false, pass through).
    # @option options [Logger] :logger Logger for verification failures (default: env["rack.logger"], else silent).
    def initialize(app, options = {})
      @app = app
      @require_token = options.fetch(:require_token, false)
      @logger = options[:logger]
      
      # The Verifier instance is initialized with options (like public_key_url)
      # and is responsible for all crypto and key management.
      @verifier = Verifier.new(options)

      warn_if_claims_unrestricted(options.fetch(:decode_options, {}))
    end

    def call(env)
      token = extract_token(env)
      
      # With no token the request is passed down the stack and the application
      # decides how to treat the unauthenticated state — unless require_token
      # is set, in which case it is rejected here.
      unless token
        return unauthorized_response(missing_token: true) if @require_token

        return @app.call(env)
      end

      # Only the verification step is guarded: a JWT::DecodeError raised by the
      # downstream application must propagate, not be turned into a 401 here.
      begin
        # Use the Verifier to handle the complex crypto and validation logic
        payload = @verifier.verify(token)
      rescue JWT::DecodeError => e
        # Invalid signature, expired, bad claim: the client's problem.
        logger(env).warn { "rack_jwt_verifier: token rejected: #{e.message}" }
        return unauthorized_response
      rescue KeyFetchError => e
        # We could not obtain the key to check the token: our problem, not the
        # client's, so answer 503 rather than 401.
        logger(env).error { "rack_jwt_verifier: #{e.message}" }
        return service_unavailable_response
      end

      # On successful verification, store the payload in the Rack environment
      env[RACK_ENV_PAYLOAD_KEY] = payload
      
      @app.call(env)
    end

    private

    # Extracts the JWT from the standard Authorization header format: "Bearer <token>".
    # The scheme is matched case-insensitively (RFC 7235 §2.1).
    def extract_token(env)
      # Rack converts HTTP_AUTHORIZATION header to ENV['HTTP_AUTHORIZATION']
      auth_header = env["HTTP_AUTHORIZATION"]
      
      return nil unless auth_header
      
      scheme, token = auth_header.strip.split(/\s+/, 2)
      return nil unless scheme&.casecmp?("bearer")

      token = token&.strip
      token.nil? || token.empty? ? nil : token
    end

    def logger(env)
      @logger || env["rack.logger"] || NULL_LOGGER
    end

    # A key alone proves who signed the token, not who it was meant for. Nudge
    # the operator once at boot if neither iss nor aud is being checked.
    def warn_if_claims_unrestricted(decode_options)
      return if decode_options.key?(:iss) || decode_options.key?(:aud)

      (@logger || Kernel).warn(
        "rack_jwt_verifier: neither :iss nor :aud is set in decode_options, so any " \
        "token signed by the configured key is accepted. Set decode_options: { iss: ..., aud: ... }."
      )
    end

    # 401 Unauthorized. Per RFC 6750 §3 a request that carried no credentials
    # at all gets the bare challenge, without an error code.
    def unauthorized_response(missing_token: false)
      if missing_token
        text_response(401, "Unauthorized: Bearer token required.", "www-authenticate" => "Bearer")
      else
        text_response(401, "Unauthorized: Invalid or expired JWT.",
                      "www-authenticate" => 'Bearer error="invalid_token"')
      end
    end

    # 503 Service Unavailable, for when the verification key could not be fetched.
    def service_unavailable_response
      text_response(503, "Service Unavailable: could not fetch the token verification key.",
                    "retry-after" => RETRY_AFTER_SECONDS.to_s)
    end

    # Rack 3 requires lowercase header names; they are equally valid on Rack 2.
    def text_response(status, body, extra_headers = {})
      headers = {
        "content-type" => "text/plain",
        "content-length" => body.bytesize.to_s
      }.merge(extra_headers)
      [status, headers, [body]]
    end
  end
end
