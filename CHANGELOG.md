# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-09-12

A security and correctness release. **Read the *Security* section before upgrading**: an
`http://` key URL now fails at boot, `iss`/`aud` are enforced when set (they silently were not
before), and a key outage answers `503` instead of `500`.

### Added
- **`jwks_url:`** — verify against a JSON Web Key Set, matching tokens by `kid`. An unknown `kid`
  triggers a rate-limited refetch so rotated keys are picked up immediately. A set with no keys,
  or a body that is not JSON, is rejected before it can be cached.
- **`public_key:`** — a static PEM public key, X.509 certificate PEM, or `OpenSSL::PKey`; no
  network access.
- X.509 certificate PEMs are accepted from `public_key_url` (what Keycloak/Auth0 `.pem` endpoints
  serve). EC and Ed keys parse too.
- Key rotation for `public_key_url`: on a signature mismatch the key is refetched once and the
  token retried. `refetch_interval:` (default 60 s) rate-limits rotation-triggered refetches.
- `algorithms:` option (default `["RS256"]`). A list given in `decode_options` is no longer
  silently overridden by the `RS256` default (ruby-jwt reads `:algorithm` before `:algorithms`).
- `cache_ttl:` option.
- Middleware: `skip:` (exact path, regexp or callable), `env_key:`, `json_errors:` and an
  `on_error:` hook receiving `(env, reason, exception)`.
- The `401` challenge now carries `error_description` (sanitised to RFC 6750's quoted-string
  alphabet).
- Cache keys are scoped to the URL, so two verifiers sharing one cache store no longer read each
  other's key.
- Single-flight fetching on a cold cache; parsed key material is memoised per body instead of
  re-parsing the PEM on every request.
- `require_token:` middleware option — reject requests that carry no token with a bare
  `WWW-Authenticate: Bearer` challenge instead of passing them through.
- `logger:` middleware option; falls back to `env["rack.logger"]`, then to silence. Rejected
  tokens log at `warn`, key-fetch failures at `error`. Replaces the unconditional `Kernel#warn`.
- A one-time boot warning when neither `iss` nor `aud` is configured.
- `content-length` on the middleware's own responses.
- `allow_insecure_http:` and `http_timeout:` middleware options.
- The key fetch sends `User-Agent: rack_jwt_verifier/<version>` and an `Accept` header.

### Changed
- Requires Ruby >= 3.0 and Rack >= 2.2 (< 4).
- A failing cache store (Redis down) no longer breaks authentication: reads are treated as
  misses and writes as no-ops, logged at `warn`; key material is fetched per request until the
  store recovers.
- `InProcessCache` measures expiry on the monotonic clock, so wall-clock jumps cannot extend or
  cut short an entry; the clock is injectable for tests.
- `JwtHelper#encode` normalises claim keys so a caller's `'exp'` and the generated `:exp` cannot
  both land in the JSON; `#decode` accepts extra `JWT.decode` options; an `OpenSSL::PKey::RSA` is
  accepted in place of a PEM.
- `KeyFetchError` is now `RackJwtVerifier::KeyFetchError`; `Verifier::KeyFetchError` still
  resolves to the same class.
- Giving none, or more than one, of `public_key`, `public_key_url`, `jwks_url` raises
  `ArgumentError` at boot (previously a `KeyError` for the missing URL).

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

## [0.1.0] - 2025-10-20

### Added
- Initial release: `RackJwtVerifier::Middleware`, `Verifier` with pluggable cache store,
  `InProcessCache`, and `JwtHelper`.

[Unreleased]: https://github.com/danielefrisanco/rack_jwt_verifier/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/danielefrisanco/rack_jwt_verifier/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/danielefrisanco/rack_jwt_verifier/releases/tag/v0.1.0
