RackJwtVerifier
===============

A Rack middleware that authenticates requests with JSON Web Tokens (JWT) signed by an external identity provider (SSO / OIDC).

It verifies the signature against the provider's public key — from a **JWKS endpoint**, a **PEM URL** or a **static key** — validates the standard claims, caches key material, handles key rotation, and puts the verified claims into the Rack environment for your application. Works with any Rack application, including Ruby on Rails.

Features
--------

*   **Three key sources:** `jwks_url` (what Keycloak, Auth0, Okta, Entra ID, Cognito, Google… publish), `public_key_url` (a PEM public key or X.509 certificate), or a static `public_key`.
*   **Algorithms:** `RS256` by default; any algorithm ruby-jwt supports (`RS*`, `PS*`, `ES*`, `EdDSA`) via `algorithms:`.
*   **Claim validation:** `exp` and `nbf` always; `iss`, `aud` and `sub` as soon as you configure them.
*   **Key rotation:** unknown `kid` or a signature mismatch triggers a rate-limited refetch, so rotated keys are picked up without waiting for the cache TTL.
*   **Caching:** in-process by default; plug in any `read`/`write` cache store (e.g. `ActiveSupport::Cache`) so all workers share one fetched key.
*   **Hardened fetch:** HTTPS enforced, 5 s timeouts, 64 KB size cap, bad responses never cached.
*   **Rack 2 and 3**, `Rack::Lint`-clean responses, RFC 6750 `WWW-Authenticate` challenges, optional JSON error bodies, path skipping, custom error hook.

Installation
------------

```ruby
gem 'rack-jwt-verifier'
```

```bash
$ bundle install
```

Requires Ruby 3.0+ and Rack 2.2 or 3.x.

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

Then, in your application:

```ruby
claims = request.env["rack_jwt_verifier.payload"]  # Hash of claims, or nil if no token was sent
```

Key sources
-----------

Exactly one of these must be given.

| Option | What it serves | Notes |
| -- | -- | -- |
| `:jwks_url` | A JSON Web Key Set (`{"keys":[…]}`) | Tokens are matched by their `kid` header. Recommended — this is what nearly every provider publishes. |
| `:public_key_url` | A single PEM public key **or** an X.509 certificate | Fine for providers that expose one key. |
| `:public_key` | A PEM string, certificate PEM, or `OpenSSL::PKey` | No network access at all. Handy for `ENV["SSO_PUBLIC_KEY"]`. |

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

### Key fetching

| Option | Default | Purpose |
| -- | -- | -- |
| `:algorithms` | `["RS256"]` | Accepted signing algorithms. |
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
| `:iss` | — | **Recommended.** The issuer the token must carry. |
| `:aud` | — | **Recommended.** The audience the token must carry. |
| `:sub` | — | The subject the token must carry. |
| `:leeway` | `60` | Clock-skew tolerance, in seconds, for `exp` and `nbf`. `0` for strict timing. |
| `:verify_expiration` | `true` | Check `exp`. Leave on. |
| `:verify_not_before` | `true` | Check `nbf`. Leave on. |
| `:allow_nil_kid` | `false` | JWKS only: accept tokens without a `kid`. |

> The `jwt` gem only checks `iss`/`aud`/`sub` when the matching `verify_iss`/`verify_aud`/`verify_sub` flag is also `true`. This middleware switches the flag on automatically whenever you supply a value, so `iss: "…"` really is enforced. An explicit `verify_iss: false` next to `iss:` is respected.

The middleware logs a warning at boot if neither `iss` nor `aud` is configured: a key alone proves who *signed* a token, not who it was *for*.

Request flow
------------

1.  If the path matches a `:skip` rule, the request goes straight through.
2.  The token is read from `Authorization: Bearer <token>` (scheme matched case-insensitively).
    *   No token: passed through with no payload — or `401` with `WWW-Authenticate: Bearer` if `require_token: true`.
3.  Key material is read from the cache, or fetched on a miss.
4.  Signature and claims are verified.
    *   Success: the claims are stored in `env["rack_jwt_verifier.payload"]` and the request continues.
    *   Invalid token (expired, bad signature, wrong issuer/audience, unknown `kid`): `401` with `WWW-Authenticate: Bearer error="invalid_token", error_description="…"`.
    *   Key material unavailable (endpoint down, timeout, not a key): `503` with `Retry-After: 5` — the failure is on our side, not the client's.

`JWT::DecodeError`s raised by *your* application are never intercepted; only the middleware's own verification step is guarded.

Security considerations
-----------------------

*   **Always set `iss` and `aud`.** Without them any token signed by the provider — for any application — is accepted.
*   **Use HTTPS for key URLs.** `allow_insecure_http` exists for local development only.
*   **Prefer `jwks_url`.** It supports multiple keys and `kid`-based rotation; a single PEM URL cannot express an overlap period.
*   **Keep `leeway` small.** 60 s covers real clock skew; larger values extend the life of expired tokens.
*   **Stick to asymmetric algorithms.** The middleware only ever holds public keys; do not add `HS*` to `algorithms`.

Design notes
------------

A few choices that are not obvious from the code:

*   **The gem is `rack-jwt-verifier`, the require path `rack_jwt_verifier`.** The hyphenated name was published first and is what users already depend on, so it stays; `lib/rack-jwt-verifier.rb` is a one-line shim so Bundler's auto-require works.
*   **Options are a positional hash, not keyword arguments.** `middleware.use Klass, hash` hands the hash over positionally, so a keyword signature would break Rails users on Ruby 3.
*   **`iss`/`aud` switch their `verify_*` flag on automatically.** ruby-jwt ignores an expected claim value unless the flag is set; requiring users to pass both is how the 0.1.0 README ended up recommending a configuration that enforced nothing.
*   **Key-fetch failures answer 503, not 401.** The client did nothing wrong; a 401 would make it discard a valid token and re-authenticate.
*   **Rotation refetches are rate-limited** (`refetch_interval`) so a stream of forged tokens cannot be turned into a stream of requests to the provider.

Development
-----------

RSpec, WebMock (no real network in tests), Timecop and RuboCop. CI runs the suite on Ruby 3.0–3.4 against both Rack 2 and Rack 3.

```bash
$ bundle install
$ bundle exec rake            # specs + rubocop
$ bundle exec rspec
$ BUNDLE_GEMFILE=gemfiles/rack_2.gemfile bundle exec rspec   # the Rack 2 leg
```

License
-------

MIT — see [LICENSE.md](LICENSE.md).
