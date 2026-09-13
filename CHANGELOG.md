# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-09-13

Interop with [`jwt_auth_client`](https://github.com/danielefrisanco/jwt_auth_client) 0.2.0 and a
stricter claim policy. **Breaking**: `iss` and `aud` must now be configured, tokens must carry
`exp`, and boot-time option errors raise `ConfigurationError` instead of `ArgumentError`. See the
upgrade notes.

### Added
- **`shared_secret:`** key source — a `String` or `{ env: "VAR_NAME" }` — enabling `HS256`/`HS384`/
  `HS512`. This is what `jwt_auth_client` 0.2.x signs with. Guardrails, all at boot: the secret must
  be at least 32/48/64 bytes (RFC 7518 §3.2, matching the issuer's rule); a secret cannot be given
  alongside `public_key`/`public_key_url`/`jwks_url`; `HS*` cannot be listed without a secret nor
  next to `RS*`/`ES*`/`PS*`; `none` is refused in any spelling, including via `decode_options`.
  Asymmetric keys remain the default and the recommended path; HMAC is documented as the mode for a
  small trusted set of internal services.
- **`require_scopes:`** middleware option: a token lacking a listed scope gets `403` with an RFC
  6750 `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"` challenge (reason
  `:insufficient_scope` for `on_error`/JSON bodies, carrying an `InsufficientScopeError` with
  `#required`/`#missing`). Implies `require_token: true`.
- **`RackJwtVerifier::Scopes`** helper (`.from`, `.include?`, `.missing`) reading a `scopes` Array
  (jwt_auth_client) or an OAuth-style space-delimited `scope` String, for per-route checks.
- **`replay_cache:`** option (default off): `true` records each `jti` in `cache_store` (or a fresh
  `InProcessCache`); a store object records it there. A token is accepted once until `exp` +
  leeway; a second presentation is `401`; a token with no `jti` is `401`; an unavailable replay
  store answers `503` (reason `:replay_cache_unavailable`) — fail closed.
- **`require_iss_aud:`** option (default `true`); `false` restores the 0.2.0 boot warning.
- `decode_options[:required_claims]` (default `["exp"]`).
- `Verifier#algorithms` exposes the effective, policy-checked algorithm list.
- Error hierarchy: `RackJwtVerifier::Error` > `ConfigurationError`, `KeyFetchError`,
  `ReplayCacheError`, `InsufficientScopeError`; `ReplayedTokenError < JWT::InvalidJtiError`.
- `InProcessCache`: `write(..., unless_exist: true)` (returns `false` when a live entry exists),
  `#clear`, `#size`, and amortised eviction of expired entries so a jti-per-request workload cannot
  grow it without bound.
- Round-trip interop specs driving `jwt_auth_client`'s `TokenIssuer`, `Issuable` and `HttpClient`
  output through the middleware (HS256/384/512, iss/aud, leeway, scopes, replay), plus the same
  payload shape re-signed with RS256/ES256 + `kid` through a JWKS as a preview of jwt_auth_client
  0.3.0. `jwt_auth_client` is an optional path development dependency (`JWT_AUTH_CLIENT_PATH`).
- CI: Ruby 4.0 and a ruby-jwt 3 leg (`gemfiles/jwt_3.gemfile`); the gemspec allows `jwt >= 2.8, < 4`.
- The key fetch applies `write_timeout` as well as open/read; a spec pins down that redirects are
  never followed.

### Changed
- **`iss` and `aud` are required.** `Middleware.new` raises `ConfigurationError` unless
  `decode_options` sets both (non-blank; `iss` may be an Array), or `require_iss_aud: false` is
  passed. Previously a warning was logged when *neither* was set.
- **`exp` is required.** ruby-jwt only checks `exp` when the claim is present, so a token without
  one was previously valid forever. Override with `decode_options: { required_claims: [] }`.
- Boot-time option errors (no/several key sources, bad URL, unparsable key, bad `skip:` rule) raise
  `RackJwtVerifier::ConfigurationError` (was `ArgumentError`).
- `decode_options[:algorithm]`/`[:algorithms]` are folded into the same algorithm policy as the
  top-level `algorithms:` instead of bypassing it.
- `decode_options[:leeway]` is validated at boot (non-negative Numeric).
- README: `EdDSA` is no longer listed as supported — ruby-jwt 2.x only provides it through the
  native `rbnacl` gem (3.x through `jwt-eddsa`), neither of which is a dependency.

### Deprecated
- **`RackJwtVerifier::JwtHelper`** — a second token issuer inside the verifier, minting tokens
  without `iss`/`aud`/`nbf`/`jti` that no longer pass the claim policy. Issue tokens with
  `jwt_auth_client`; in test suites sign with `JWT.encode` (see `spec/support/token_factory.rb`
  for a helper to copy). It warns once per process (`RACK_JWT_VERIFIER_SILENCE_DEPRECATIONS=1`
  silences it) and will be removed in 0.4.0.

### Security
- Algorithm confusion is ruled out at boot: HMAC and asymmetric algorithms can never be enabled
  on the same verifier, a shared secret can never sit next to a public key, and `none` is refused
  everywhere. ruby-jwt 2.x itself accepts any non-empty String as an HMAC key, so the RFC 7518
  minimum length is enforced by this gem.
- Tokens without `exp` are refused (see *Changed*).

### Upgrade notes (0.2.0 → 0.3.0)
1. Set `decode_options: { iss: "...", aud: "..." }` on every middleware. If you truly cannot check
   one of them, pass `require_iss_aud: false` and accept the boot warning.
2. Tokens must carry `exp`. If your provider omits it, pass
   `decode_options: { required_claims: [] }` — and reconsider the provider.
3. Code rescuing `ArgumentError` around `Middleware.new`/`Verifier.new` should rescue
   `RackJwtVerifier::ConfigurationError` (or `RackJwtVerifier::Error`).
4. Replace `RackJwtVerifier::JwtHelper` with `jwt_auth_client` (or `JWT.encode` in tests) before
   0.4.0.
5. To verify `jwt_auth_client` tokens: `shared_secret: { env: "JWT_SERVICE_SECRET" }`,
   `algorithms: ["HS256"]` (the issuer's `config.algorithm`), `iss:` = the issuer's
   `config.issuer`, `aud:` = the `target_service` name. See the README's *Pairing with
   jwt_auth_client*.

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
- Requires Ruby >= 3.0 and Rack >= 2.2 (< 4). Depends on the `logger` gem explicitly, as it leaves
  Ruby's default gems in 4.0.
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

[Unreleased]: https://github.com/danielefrisanco/rack_jwt_verifier/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/danielefrisanco/rack_jwt_verifier/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/danielefrisanco/rack_jwt_verifier/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/danielefrisanco/rack_jwt_verifier/releases/tag/v0.1.0
