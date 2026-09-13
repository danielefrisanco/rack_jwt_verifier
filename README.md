RackJwtVerifier
===============

A Rack middleware that authenticates requests with JSON Web Tokens (JWT) signed by an external identity provider (SSO / OIDC) or by your own internal services.

It verifies the signature against the provider's public key — from a **JWKS endpoint**, a **PEM URL** or a **static key** — or, as an explicit opt-in for internal services, against a **shared HMAC secret**; validates the standard claims, caches key material, handles key rotation, and puts the verified claims into the Rack environment for your application. Works with any Rack application, including Ruby on Rails.

It is the verifying half of a pair: [`jwt_auth_client`](https://github.com/danielefrisanco/jwt_auth_client) issues the tokens on the calling side. See [Pairing with jwt_auth_client](#pairing-with-jwt_auth_client).

Features
--------

*   **Key sources:** `jwks_url` (what Keycloak, Auth0, Okta, Entra ID, Cognito, Google… publish), `public_key_url` (a PEM public key or X.509 certificate), a static `public_key`, or — opt-in — a `shared_secret` for HMAC.
*   **Algorithms:** `RS256` by default; `RS*`, `PS*`, `ES*` via `algorithms:`; `HS256`/`HS384`/`HS512` only with `shared_secret`. HS and RS/ES can never be enabled together, and `none` is always refused — at boot.
*   **Claim validation:** `exp` (required), `nbf`, and `iss`/`aud` — which you must configure, or opt out of explicitly.
*   **Scopes:** `require_scopes:` answers `403` with an RFC 6750 `insufficient_scope` challenge; `RackJwtVerifier::Scopes` reads scopes for per-route checks.
*   **Replay protection:** optional `replay_cache:` remembers each `jti` until the token expires.
*   **Key rotation:** unknown `kid` or a signature mismatch triggers a rate-limited refetch, so rotated keys are picked up without waiting for the cache TTL.
*   **Caching:** in-process by default; plug in any `read`/`write` cache store (e.g. `ActiveSupport::Cache`) so all workers share one fetched key.
*   **Hardened fetch:** HTTPS enforced, redirects never followed, 5 s timeouts, 64 KB size cap, bad responses never cached.
*   **Rack 2 and 3**, `Rack::Lint`-clean responses, RFC 6750 `WWW-Authenticate` challenges, optional JSON error bodies, path skipping, custom error hook.

Installation
------------

```ruby
gem 'rack-jwt-verifier'
```

```bash
$ bundle install
```

Requires Ruby 3.1+, Rack 2.2 or 3.x, and ruby-jwt 2.8+ or 3.x.

Quick start
-----------

```ruby
# config/application.rb (Rails) or config.ru (plain Rack)
Rails.application.config.middleware.use RackJwtVerifier::Middleware,
  jwks_url: "https://sso.example.com/.well-known/jwks.json",
  decode_options: {
    iss: "https://sso.example.com",   # who must have issued the token
    aud: "my-api"                     # who the token must be for
  }
```

`iss` and `aud` are required: the middleware refuses to boot without them (see [Claim validation](#claim-validation-decode_options)).

Then, in your application:

```ruby
claims = request.env["rack_jwt_verifier.payload"]  # Hash of claims, or nil if no token was sent
claims["sub"]                                       # the subject
RackJwtVerifier::Scopes.from(claims)                # => ["read:invoices", ...]
```

Key sources
-----------

Exactly one of these must be given.

| Option | What it serves | Notes |
| -- | -- | -- |
| `:jwks_url` | A JSON Web Key Set (`{"keys":[…]}`) | Tokens are matched by their `kid` header. Recommended — this is what nearly every provider publishes. |
| `:public_key_url` | A single PEM public key **or** an X.509 certificate | Fine for providers that expose one key. |
| `:public_key` | A PEM string, certificate PEM, or `OpenSSL::PKey` | No network access at all. Handy for `ENV["SSO_PUBLIC_KEY"]`. |
| `:shared_secret` | An HMAC secret: a `String`, or `{ env: "VAR_NAME" }` | Enables `HS256`/`HS384`/`HS512`. For a small trusted set of internal services only — see below. |

URLs must be `https://`. Pass `allow_insecure_http: true` to permit `http://` **in development only** — over plaintext HTTP an attacker on the network path can swap the key and mint arbitrary tokens.

```ruby
# Static key from the environment
use RackJwtVerifier::Middleware,
  public_key: ENV.fetch("SSO_PUBLIC_KEY"),
  decode_options: { iss: "https://sso.example.com", aud: "my-api" }

# EC keys need the algorithm list widened
use RackJwtVerifier::Middleware,
  jwks_url: "https://sso.example.com/.well-known/jwks.json",
  algorithms: %w[RS256 ES256],
  decode_options: { iss: "https://sso.example.com", aud: "my-api" }
```

Tokens without a `kid` header are rejected when using `jwks_url`. If your provider does not set one, add `decode_options: { allow_nil_kid: true }` — the first key in the set is then used.

`EdDSA` is not in scope: ruby-jwt 2.x only provides it through the native `rbnacl` gem and 3.x through `jwt-eddsa`; neither is a dependency here.

### Shared secret (HMAC) — internal services only

Asymmetric keys are the default and the recommended path: the verifier only ever holds a *public* key, so a compromised API cannot mint tokens. A shared secret is different — **every service holding it can mint tokens for every audience**. Use `shared_secret` for a small, trusted set of internal services that you control on both ends (this is what `jwt_auth_client` 0.2.x needs), keep the set of holders small, and move to asymmetric keys when the issuer supports them.

```ruby
use RackJwtVerifier::Middleware,
  shared_secret: { env: "JWT_SERVICE_SECRET" },     # or the String itself: ENV.fetch("JWT_SERVICE_SECRET")
  algorithms: ["HS256"],                           # default with shared_secret; HS384/HS512 also allowed
  decode_options: { iss: "main_app_sso", aud: "billing_api" }
```

Guardrails, all enforced at boot with a `RackJwtVerifier::ConfigurationError`:

*   The secret must be at least **32 / 48 / 64 bytes** for HS256 / HS384 / HS512 (RFC 7518 §3.2) — the same rule `jwt_auth_client` applies when signing. `openssl rand -hex 32` produces a 64-byte hex string that satisfies all three.
*   `shared_secret` cannot be combined with `public_key`, `public_key_url` or `jwks_url`, and `HS*` cannot appear in `algorithms` without it, nor next to `RS*`/`ES*`/`PS*`. This closes the classic algorithm-confusion attack in which an attacker signs a token with `HS256` using the *public* key as the secret.
*   `none` is refused everywhere, in any spelling, including through `decode_options`.

Caching and key rotation
------------------------

Fetched key material is cached for `cache_ttl` seconds (default 300). The default store is a per-process `InProcessCache`; for multi-process or multi-host deployments pass any object with the standard cache-store interface — `read(key)` and `write(key, value, expires_in: seconds)` — so the provider is contacted once per TTL rather than once per worker:

```ruby
# config/initializers/rack_jwt_verifier.rb
Rails.application.config.middleware.use RackJwtVerifier::Middleware,
  jwks_url: ENV.fetch("SSO_JWKS_URL"),
  cache_store: Rails.cache,               # any ActiveSupport::Cache::Store works
  decode_options: { iss: ENV.fetch("SSO_ISSUER"), aud: "my-api" }
```

The object must be a cache **store**, not a raw client — a `redis-rb` connection does not respond to `read`/`write`; wrap it in `ActiveSupport::Cache::RedisCacheStore`. Cache keys are namespaced (`rack_jwt_verifier:jwks:<url digest>`) so several middlewares can share one store.

**Rotation.** When a token's `kid` is not in the cached set (JWKS), or its signature does not verify against the cached key (PEM), the middleware refetches once and retries. Refetches are rate-limited to one per `refetch_interval` seconds (default 60) so a flood of forged tokens cannot become a flood of requests to your provider.

Within one process only one thread performs a fetch on a cold cache; the others wait for it.

Options
-------

### Middleware

| Option | Default | Purpose |
| -- | -- | -- |
| `:require_token` | `false` | `true`: a request with no `Bearer` token gets a `401`. `false`: it is passed through with no payload set, and your application decides. |
| `:skip` | `[]` | Paths that bypass the middleware entirely: exact strings (`"/health"`), regexps (`%r{\A/public/}`), or callables on the env (`->(env) { env["REQUEST_METHOD"] == "OPTIONS" }`). Matched against `SCRIPT_NAME + PATH_INFO`. |
| `:env_key` | `"rack_jwt_verifier.payload"` | Rack env key that receives the verified claims. |
| `:json_errors` | `false` | Render `401`/`503` bodies as `{"error": "...", "error_description": "..."}` with `content-type: application/json`. |
| `:on_error` | — | `->(env, reason, exception) { … }` returning a Rack response to use instead of the default, or `nil` to keep the default. `reason` is `:missing_token`, `:invalid_token` or `:key_unavailable`. |
| `:logger` | `env["rack.logger"]` | Rejected tokens log at `warn`, key-fetch failures at `error`. Falls back to the request's `rack.logger` (`Rails.logger` in Rails), then to silence. |
| `:require_scopes` | `[]` | Scopes every token must grant. A token lacking one gets `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"`. Implies `require_token: true`. See *Scopes*. |
| `:require_iss_aud` | `true` | Refuse to boot unless `decode_options` sets both `iss` and `aud`. `false` logs a warning instead. |
| `:replay_cache` | off | `true` to record each `jti` in `cache_store`, or a cache store to record it in. See *Replay protection*. |

### Key fetching

| Option | Default | Purpose |
| -- | -- | -- |
| `:algorithms` | `["RS256"]` (`["HS256"]` with `shared_secret`) | Accepted signing algorithms. `HS*` only with `shared_secret`; never mixed. |
| `:cache_store` | `InProcessCache.new` | See *Caching* above. |
| `:cache_ttl` | `300` | Seconds to cache fetched key material. |
| `:refetch_interval` | `60` | Minimum seconds between rotation-triggered refetches. |
| `:http_timeout` | `5` | Open and read timeout, in seconds, for the key fetch. |
| `:allow_insecure_http` | `false` | Permit a plain `http://` URL. Development only. |

Responses over 64 KB are refused — a PEM key is under 1 KB and a JWKS a few KB.

### Claim validation (`:decode_options`)

Everything here is handed to `JWT.decode`.

| Option | Default | Purpose |
| -- | -- | -- |
| `:iss` | — | **Required.** The issuer the token must carry (a String, or an Array of accepted issuers). |
| `:aud` | — | **Required.** The audience the token must carry. |
| `:sub` | — | The subject the token must carry. |
| `:leeway` | `60` | Clock-skew tolerance, in seconds, for `exp` and `nbf`. `0` for strict timing. |
| `:required_claims` | `["exp"]` | Claims that must be present. ruby-jwt only *checks* `exp` when it is there; requiring it means a token without an expiry is refused rather than valid forever. |
| `:verify_expiration` | `true` | Check `exp`. Leave on. |
| `:verify_not_before` | `true` | Check `nbf`. Leave on. |
| `:allow_nil_kid` | `false` | JWKS only: accept tokens without a `kid`. |

> The `jwt` gem only checks `iss`/`aud`/`sub` when the matching `verify_iss`/`verify_aud`/`verify_sub` flag is also `true`. This middleware switches the flag on automatically whenever you supply a value, so `iss: "…"` really is enforced. An explicit `verify_iss: false` next to `iss:` is respected.

**`iss` and `aud` are required.** A key proves who *signed* a token, not who it was *for* — and a shared secret proves even less. `Middleware.new` raises `ConfigurationError` when either is missing. If you genuinely cannot check them (a provider that sets no `aud`, say), pass `require_iss_aud: false`; the middleware then logs a warning at boot instead.

Scopes
------

The verified claims are in `env["rack_jwt_verifier.payload"]`, `sub` included. Scopes are read from a `scopes` claim (an Array of Strings, what `jwt_auth_client` emits) or, failing that, an OAuth-style space-delimited `scope` String.

Require scopes globally on the middleware:

```ruby
use RackJwtVerifier::Middleware, jwks_url: "…", decode_options: { … },
  require_scopes: ["read:invoices"]
```

A token lacking any of them is refused with `403` and

```
WWW-Authenticate: Bearer error="insufficient_scope", error_description="Token lacks required scope(s): read:invoices", scope="read:invoices"
```

(`reason` is `:insufficient_scope` for `on_error` and JSON bodies; the hook receives a `RackJwtVerifier::InsufficientScopeError` with `#required` and `#missing`). `require_scopes` implies `require_token: true`.

For per-route checks, use the helper in your application:

```ruby
claims = request.env["rack_jwt_verifier.payload"]
RackJwtVerifier::Scopes.from(claims)                            # => ["read:invoices"]
RackJwtVerifier::Scopes.include?(claims, "write:invoices")      # => false
RackJwtVerifier::Scopes.missing(claims, %w[read:x write:x])     # => ["write:x"]
```

Replay protection
-----------------

Off by default. With `replay_cache:` each verified token's `jti` is remembered until the token's `exp` (plus leeway), and a second presentation is refused with `401 invalid_token`. Tokens without a `jti` are refused too.

```ruby
use RackJwtVerifier::Middleware, …,
  cache_store: Rails.cache,
  replay_cache: true              # record jtis in cache_store …
  # replay_cache: Rails.cache     # … or in a store of their own
```

*   The store is the same `read`/`write` abstraction as `cache_store`. `true` uses `cache_store` (or a fresh `InProcessCache` when none was given). An **in-process store only detects replays within one worker**; use a shared store (`Rails.cache` on Redis/Memcached) for real protection.
*   `jwt_auth_client` mints a fresh `jti` per request by default (`token_reuse_seconds = 0`), so replay protection works out of the box; with `token_reuse_seconds > 0` on the issuer, do not enable it here.
*   The check runs only after every other check passed, so an expired or mis-signed token cannot "burn" a `jti`.
*   A replay store that raises makes the request fail **closed**: `503` with `Retry-After`, reason `:replay_cache_unavailable`. You asked for the guarantee; skipping it silently would be worse than a retryable error. (The key cache, by contrast, fails open — a fetch still verifies the signature.)
*   Keys are `rack_jwt_verifier:jti:<sha256 of jti>`, written with `unless_exist: true` so stores that support it (ActiveSupport's do) close the check-then-write window.

Request flow
------------

1.  If the path matches a `:skip` rule, the request goes straight through.
2.  The token is read from `Authorization: Bearer <token>` (scheme matched case-insensitively).
    *   No token: passed through with no payload — or `401` with `WWW-Authenticate: Bearer` if `require_token: true`.
3.  Key material is read from the cache, or fetched on a miss.
4.  Signature and claims are verified.
    *   Success: the claims are stored in `env["rack_jwt_verifier.payload"]` and the request continues.
    *   Invalid token (expired, bad signature, wrong issuer/audience, unknown `kid`, replayed `jti`): `401` with `WWW-Authenticate: Bearer error="invalid_token", error_description="…"`.
    *   Valid token without a required scope: `403` with `WWW-Authenticate: Bearer error="insufficient_scope", scope="…"`.
    *   Key material unavailable (endpoint down, timeout, not a key), or the replay store down: `503` with `Retry-After: 5` — the failure is on our side, not the client's.

`JWT::DecodeError`s raised by *your* application are never intercepted; only the middleware's own verification step is guarded.

Errors
------

| Class | Raised when |
| -- | -- |
| `RackJwtVerifier::ConfigurationError` | An unusable option set, at boot (`Middleware.new` / `Verifier.new`): no or several key sources, `HS*` mixed with `RS*`, a short secret, missing `iss`/`aud`, an `http://` URL, … |
| `RackJwtVerifier::KeyFetchError` | Key material could not be fetched or parsed. The middleware turns it into a `503`. |
| `RackJwtVerifier::ReplayCacheError` | The replay store could not be read or written. `503`. |
| `RackJwtVerifier::ReplayedTokenError` (`< JWT::InvalidJtiError`) | A `jti` was presented twice. `401`. |
| `RackJwtVerifier::InsufficientScopeError` | Handed to `on_error` for a `403`; carries `#required` and `#missing`. |

All but `ReplayedTokenError` inherit from `RackJwtVerifier::Error`. Token verification failures are ruby-jwt's `JWT::DecodeError` family.

Pairing with jwt_auth_client
----------------------------

[`jwt_auth_client`](https://github.com/danielefrisanco/jwt_auth_client) is the issuing half: it mints `{ iss, sub, aud, scopes, iat, nbf, exp, jti, … }` tokens and sends them as `Bearer` tokens from one internal service to another. Today (0.2.x) it signs with `HS256`/`HS384`/`HS512` and a shared secret; asymmetric signing with a `kid` is planned for its 0.3.0, at which point the verifier side below becomes a `jwks_url`.

Issuer (`config/initializers/jwt_auth_client.rb` in the *calling* service):

```ruby
JwtAuthClient.configure do |config|
  config.shared_secret = ENV.fetch("JWT_SERVICE_SECRET")   # >= 32 bytes; openssl rand -hex 32
  config.issuer = "main_app_sso"
  config.algorithm = "HS256"
  config.service_urls = { billing_api: "https://billing.internal" }
end

BILLING = JwtAuthClient::HttpClient.call(user_id: "etl", target_service: :billing_api, scopes: ["read:invoices"])
```

Verifier (in the *receiving* service, `billing_api`):

```ruby
Rails.application.config.middleware.use RackJwtVerifier::Middleware,
  shared_secret: { env: "JWT_SERVICE_SECRET" },   # the same secret
  algorithms: ["HS256"],                          # the same algorithm
  decode_options: {
    iss: "main_app_sso",                          # jwt_auth_client's config.issuer
    aud: "billing_api"                            # the target_service the caller names
  },
  require_scopes: ["read:invoices"],              # optional
  replay_cache: true, cache_store: Rails.cache    # optional
```

The claims then arrive as `env["rack_jwt_verifier.payload"]`: `sub` is the caller's `user_id`, `scopes` its scopes, and any custom claims from `Issuable#jwt_claims` (`user_id`, `email`, …) come through unchanged. The [interop spec](spec/rack_jwt_verifier/interop_spec.rb) exercises exactly this round trip against the real gem.

Security considerations
-----------------------

*   **`iss` and `aud` are mandatory** for a reason: without them any token signed by the provider — for any application — is accepted. Opt out only when you cannot check them, and know what that means.
*   **Use HTTPS for key URLs.** `allow_insecure_http` exists for local development only. Redirects are never followed.
*   **Prefer `jwks_url`.** It supports multiple keys and `kid`-based rotation; a single PEM URL cannot express an overlap period.
*   **Keep `leeway` small.** 60 s covers real clock skew; larger values extend the life of expired tokens.
*   **Prefer asymmetric algorithms.** With a public key the verifier cannot mint tokens; with a shared secret it can. `HS*` and `RS*`/`ES*` are never accepted together — the middleware refuses to boot if you try — so a public key can never be reinterpreted as an HMAC secret.
*   **Replay protection needs a shared store** to mean anything across workers or hosts.

Design notes
------------

A few choices that are not obvious from the code:

*   **The gem is `rack-jwt-verifier`, the require path `rack_jwt_verifier`.** The hyphenated name was published first and is what users already depend on, so it stays; `lib/rack-jwt-verifier.rb` is a one-line shim so Bundler's auto-require works.
*   **Options are a positional hash, not keyword arguments.** `middleware.use Klass, hash` hands the hash over positionally, so a keyword signature would break Rails users on Ruby 3.
*   **`iss`/`aud` switch their `verify_*` flag on automatically.** ruby-jwt ignores an expected claim value unless the flag is set; requiring users to pass both is how the 0.1.0 README ended up recommending a configuration that enforced nothing.
*   **Key-fetch failures answer 503, not 401.** The client did nothing wrong; a 401 would make it discard a valid token and re-authenticate.
*   **Rotation refetches are rate-limited** (`refetch_interval`) so a stream of forged tokens cannot be turned into a stream of requests to the provider.
*   **The HMAC key-length rule lives here, not in ruby-jwt.** ruby-jwt 2.x verifies with any non-empty String; the RFC 7518 minimum is enforced by this gem so both halves of the pair agree.
*   **The replay store fails closed, the key cache fails open.** A key-cache miss still ends in a verified signature; a skipped replay check silently drops a guarantee the operator asked for.
*   **`JwtHelper` is deprecated** (removal in 0.4.0). It was a second token issuer inside the verifier, signing without `iss`/`aud`/`nbf`/`jti`. Issue with `jwt_auth_client`; in test suites sign with `JWT.encode` (see `spec/support/token_factory.rb`). It warns once per process; `RACK_JWT_VERIFIER_SILENCE_DEPRECATIONS=1` silences it.

Development
-----------

RSpec, WebMock (no real network in tests), Timecop and RuboCop. CI runs the suite on Ruby 3.1–4.0 against Rack 2, Rack 3 and ruby-jwt 2/3.

```bash
$ bundle install
$ bundle exec rake            # specs + rubocop
$ bundle exec rspec
$ BUNDLE_GEMFILE=gemfiles/rack_2.gemfile bundle exec rspec   # the Rack 2 leg
$ BUNDLE_GEMFILE=gemfiles/jwt_3.gemfile bundle exec rspec    # the ruby-jwt 3 leg
```

The interop specs need a checkout of `jwt_auth_client` next to this repository (or `JWT_AUTH_CLIENT_PATH=/path/to/it`); they skip otherwise.

License
-------

MIT — see [LICENSE.md](LICENSE.md).
