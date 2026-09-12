# frozen_string_literal: true

require "json"
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

    # Status and default plain-text body for each way a request can be refused.
    # The reason symbol doubles as the `error` code in JSON bodies.
    ERROR_RESPONSES = {
      missing_token: [401, "Unauthorized: Bearer token required."],
      invalid_token: [401, "Unauthorized: Invalid or expired JWT."],
      key_unavailable: [503, "Service Unavailable: could not fetch the token verification key."]
    }.freeze

    # @param app [#call] The downstream Rack application.
    # @param options [Hash] Middleware options; everything else is forwarded to Verifier.
    # @option options [Boolean] :require_token Reject requests that carry no Bearer token
    #   (default: false, pass through).
    # @option options [Logger] :logger Logger for verification failures
    #   (default: env["rack.logger"], else silent).
    # @option options [String] :env_key Rack env key that receives the payload
    #   (default: RACK_ENV_PAYLOAD_KEY).
    # @option options [Array<String, Regexp, #call>] :skip Paths (exact string, regexp) or
    #   predicates on env that bypass the middleware.
    # @option options [Boolean] :json_errors Render 401/503 bodies as JSON
    #   `{"error", "error_description"}` (default: plain text).
    # @option options [#call] :on_error `->(env, reason, exception) { rack_response or nil }`
    #   to customise refusals.
    def initialize(app, options = {})
      @app = app
      @require_token = options.fetch(:require_token, false)
      @logger = options[:logger]
      @env_key = options.fetch(:env_key, RACK_ENV_PAYLOAD_KEY)
      @skip = validate_skip_rules(Array(options[:skip]))
      @json_errors = options.fetch(:json_errors, false)
      @on_error = options[:on_error]

      # The Verifier instance is initialized with options (like public_key_url)
      # and is responsible for all crypto and key management.
      @verifier = Verifier.new(options)

      warn_if_claims_unrestricted(options.fetch(:decode_options, {}))
    end

    def call(env)
      return @app.call(env) if skip?(env)

      token = extract_token(env)

      # With no token the request is passed down the stack and the application
      # decides how to treat the unauthenticated state — unless require_token
      # is set, in which case it is rejected here.
      unless token
        return error_response(env, :missing_token, nil) if @require_token

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
        return error_response(env, :invalid_token, e)
      rescue KeyFetchError => e
        # We could not obtain the key to check the token: our problem, not the
        # client's, so answer 503 rather than 401.
        logger(env).error { "rack_jwt_verifier: #{e.message}" }
        return error_response(env, :key_unavailable, e)
      end

      # On successful verification, store the payload in the Rack environment
      env[@env_key] = payload

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

    # A skip rule is an exact path string, a regexp matched against the path,
    # or a callable given the whole env.
    def skip?(env)
      return false if @skip.empty?

      path = "#{env['SCRIPT_NAME']}#{env['PATH_INFO']}"
      @skip.any? do |rule|
        case rule
        when String then rule == path
        when Regexp then rule.match?(path)
        else rule.call(env)
        end
      end
    end

    def validate_skip_rules(rules)
      rules.each do |rule|
        next if rule.is_a?(String) || rule.is_a?(Regexp) || rule.respond_to?(:call)

        raise ArgumentError, "skip: entries must be a String, a Regexp or respond to #call (got #{rule.inspect})"
      end
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

    # Builds the refusal for `reason`, letting an :on_error hook take over
    # first. Returning nil from the hook falls back to the default response.
    def error_response(env, reason, error)
      custom = @on_error&.call(env, reason, error)
      return custom if custom

      status, default_text = ERROR_RESPONSES.fetch(reason)
      description = error && sanitize_description(error.message)

      headers = {}
      headers["www-authenticate"] = challenge(reason, description) if status == 401
      headers["retry-after"] = RETRY_AFTER_SECONDS.to_s if status == 503

      if @json_errors
        body = JSON.generate(error: reason, error_description: description || default_text)
        respond(status, body, "application/json", headers)
      else
        respond(status, default_text, "text/plain", headers)
      end
    end

    # RFC 6750 §3: a request that carried no credentials at all gets the bare
    # challenge, without an error code; otherwise the code and a description.
    def challenge(reason, description)
      return "Bearer" if reason == :missing_token

      value = +'Bearer error="invalid_token"'
      value << ", error_description=\"#{description}\"" if description && !description.empty?
      value
    end

    # error_description is a quoted-string: keep it to the characters RFC 6750
    # allows inside one (printable ASCII minus `"` and `\`) and a sane length.
    def sanitize_description(message)
      message.to_s.gsub(/[^\x20-\x21\x23-\x5B\x5D-\x7E]/, "")[0, 200]
    end

    # Rack 3 requires lowercase header names; they are equally valid on Rack 2.
    def respond(status, body, content_type, extra_headers = {})
      headers = {
        "content-type" => content_type,
        "content-length" => body.bytesize.to_s
      }.merge(extra_headers)
      [status, headers, [body]]
    end
  end
end
