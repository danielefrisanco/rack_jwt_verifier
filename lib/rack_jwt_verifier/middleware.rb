# frozen_string_literal: true

require "json"
require "logger"
require_relative "errors"
require_relative "scopes"
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
      insufficient_scope: [403, "Forbidden: the token does not grant the required scope."],
      key_unavailable: [503, "Service Unavailable: could not fetch the token verification key."],
      replay_cache_unavailable: [503, "Service Unavailable: could not check the token for replay."]
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
    # @option options [Array<String>] :require_scopes Scopes every token must grant; a token
    #   lacking one gets a 403 with an `insufficient_scope` challenge. Implies :require_token.
    # @option options [Boolean] :require_iss_aud Refuse to boot unless decode_options carries
    #   both :iss and :aud (default: true). `false` logs a warning instead.
    # @raise [ConfigurationError] for an unusable option set.
    def initialize(app, options = {})
      @app = app
      @logger = options[:logger]
      @env_key = options.fetch(:env_key, RACK_ENV_PAYLOAD_KEY)
      @skip = validate_skip_rules(Array(options[:skip]))
      @json_errors = options.fetch(:json_errors, false)
      @on_error = options[:on_error]
      @require_scopes = validate_required_scopes(options[:require_scopes])
      @require_token = resolve_require_token(options)

      # The Verifier instance is initialized with options (like public_key_url)
      # and is responsible for all crypto and key management.
      @verifier = Verifier.new(options)

      enforce_claim_policy(options)
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
      rescue ReplayCacheError => e
        logger(env).error { "rack_jwt_verifier: #{e.message}" }
        return error_response(env, :replay_cache_unavailable, e)
      end

      missing = Scopes.missing(payload, @require_scopes)
      unless missing.empty?
        error = InsufficientScopeError.new(required: @require_scopes, missing: missing)
        logger(env).warn { "rack_jwt_verifier: #{error.message}" }
        return error_response(env, :insufficient_scope, error)
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

        raise ConfigurationError, "skip: entries must be a String, a Regexp or respond to #call (got #{rule.inspect})"
      end
    end

    def validate_required_scopes(scopes)
      list = Array(scopes).map(&:to_s)
      if list.any?(&:empty?)
        raise ConfigurationError, "require_scopes: entries must be non-empty strings (got #{scopes.inspect})"
      end

      list.uniq.freeze
    end

    # A required scope can only be checked on a token, so require_scopes
    # implies require_token; saying otherwise explicitly is a contradiction.
    def resolve_require_token(options)
      return options.fetch(:require_token, false) if @require_scopes.empty?

      if options.key?(:require_token) && !options[:require_token]
        raise ConfigurationError, "require_scopes: needs a token to check; drop require_token: false"
      end

      true
    end

    def logger(env)
      @logger || env["rack.logger"] || NULL_LOGGER
    end

    # A key alone proves who signed the token, not who it was meant for — and
    # a shared secret proves even less. Both iss and aud must be checked
    # unless the operator explicitly opts out, in which case they get the
    # warning instead.
    def enforce_claim_policy(options)
      decode_options = options.fetch(:decode_options, {})
      missing = %i[iss aud].reject { |claim| present?(decode_options[claim]) }
      return if missing.empty?

      if options.fetch(:require_iss_aud, true)
        raise ConfigurationError,
              "decode_options must set #{missing.map(&:inspect).join(' and ')} so only tokens issued by " \
              "your provider, for this application, are accepted. Pass require_iss_aud: false to opt out."
      end

      (@logger || Kernel).warn(
        "rack_jwt_verifier: #{missing.map(&:inspect).join(' and ')} not set in decode_options, so any " \
        "token signed by the configured key is accepted. Set decode_options: { iss: ..., aud: ... }."
      )
    end

    def present?(value)
      case value
      when nil then false
      when String then !value.strip.empty?
      when Array then value.any? { |v| present?(v) }
      else true
      end
    end

    # Builds the refusal for `reason`, letting an :on_error hook take over
    # first. Returning nil from the hook falls back to the default response.
    def error_response(env, reason, error)
      custom = @on_error&.call(env, reason, error)
      return custom if custom

      status, default_text = ERROR_RESPONSES.fetch(reason)
      description = error && sanitize_description(error.message)

      headers = {}
      headers["www-authenticate"] = challenge(reason, description) if [401, 403].include?(status)
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
    # An insufficient_scope challenge also names the scopes required (§3.1).
    def challenge(reason, description)
      return "Bearer" if reason == :missing_token

      code = reason == :insufficient_scope ? "insufficient_scope" : "invalid_token"
      value = "Bearer error=\"#{code}\""
      value << ", error_description=\"#{description}\"" if description && !description.empty?
      value << ", scope=\"#{sanitize_description(@require_scopes.join(' '))}\"" if reason == :insufficient_scope
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
