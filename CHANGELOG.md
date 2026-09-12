# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- `iss`, `aud` and `sub` values in `decode_options` are now actually enforced. Previously the
  underlying `jwt` gem silently ignored them unless `verify_iss`/`verify_aud`/`verify_sub` was
  also set — a token from any issuer was accepted even with `iss:` configured. The matching
  `verify_*` flag is now enabled automatically whenever a value is supplied.
- `public_key_url` must be an `https://` URL. A plaintext `http://` URL is rejected at boot
  unless `allow_insecure_http: true` is passed, since a key fetched over HTTP can be
  substituted by an on-path attacker.
- The public key fetch now has a 5-second open/read timeout (configurable via `http_timeout:`)
  and refuses response bodies over 64 KB, so a slow or misbehaving SSO endpoint cannot pin
  request threads.
- `JWT::DecodeError` raised by the downstream application is no longer caught by the
  middleware and turned into a 401; only the middleware's own verification step is guarded.

### Fixed
- Response headers are lowercase (`content-type`, `www-authenticate`), as Rack 3 requires;
  `Rack::Lint` previously rejected the 401 response.
- A `200` response whose body is not a valid key (e.g. an HTML maintenance page) is no longer
  written to the cache. Previously it poisoned the cache for the full TTL, failing every
  request for five minutes after the SSO had recovered.
- A key-fetch failure (endpoint down, timeout, bad key) now yields `503 Service Unavailable`
  with `Retry-After: 5` instead of an unhandled `KeyFetchError` (a 500).
- `require "rack_jwt_verifier/verifier"` on its own no longer raises `NameError` for
  `InProcessCache`; the file requires its own dependencies.
- `gem "rack-jwt-verifier"` now loads without a `require:` override: a `lib/rack-jwt-verifier.rb`
  shim matches the gem name. The README install snippet pointed at a non-existent gem name.
- The `Bearer` scheme is matched case-insensitively (RFC 7235) and whitespace around the token
  is tolerated. `bearer <token>` was previously treated as "no token" and passed through.
- `InProcessCache#delete` returns the deleted value, as documented, rather than the internal
  `[value, expires_at]` pair.

### Added
- `require_token:` middleware option — reject requests that carry no token with a bare
  `WWW-Authenticate: Bearer` challenge instead of passing them through.
- `logger:` middleware option; falls back to `env["rack.logger"]`, then to silence. Rejected
  tokens log at `warn`, key-fetch failures at `error`. Replaces the unconditional `Kernel#warn`.
- A one-time boot warning when neither `iss` nor `aud` is configured.
- `content-length` on the middleware's own responses.
- `allow_insecure_http:` and `http_timeout:` middleware options.
- The key fetch sends `User-Agent: rack_jwt_verifier/<version>` and an `Accept` header.

## [0.1.0]

### Added
- Initial release: `RackJwtVerifier::Middleware`, `Verifier` with pluggable cache store,
  `InProcessCache`, and `JwtHelper`.
