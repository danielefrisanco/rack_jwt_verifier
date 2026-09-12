# rack_jwt_verifier — Review Findings & Action Plan

Reviewed 2026-09-12 against Ruby 3.1.4, rack 3.2.3, jwt 2.8.2. Current suite: 24 examples, 0 failures.
Every "confirmed" item below was reproduced with a probe script, not inferred from reading.

Priority order: Phase 1 (security) → Phase 2 (bugs) → Phase 3 (tests) → Phase 4 (features) → Phase 5 (hygiene).
Phases 1–3 are small, mechanical changes and should ship together as **0.2.0**. Phase 4 items are each a minor release.

---

## Phase 1 — Security

### 1.1 `iss:` / `aud:` in `decode_options` do not enforce anything  ⚠ confirmed
- **Where:** `lib/rack_jwt_verifier/verifier.rb:43`, README "Customizing JWT Decoding" table
- **Problem:** ruby-jwt only checks a claim when `verify_iss: true` / `verify_aud: true` is set. Passing `iss: "x"` alone is a no-op — a token with `iss: "EVIL"` is accepted. The README recommends exactly this misconfiguration.
- **Fix:**
  - [x] In `Verifier#initialize`, when `decode_options[:iss]` is present, force `verify_iss: true`; same for `:aud` → `verify_aud: true` (and `:sub` → `verify_sub`, `:jti` → `verify_jti` if we want to be thorough).
  - [x] Fix the README table and example; state explicitly that `iss` and `aud` are enforced when given.
  - [x] Log a warning at boot when neither `iss` nor `aud` is configured (done with 2.8's logger).
- **Test:** token with wrong `iss` → `JWT::InvalidIssuerError`; wrong `aud` → `JWT::InvalidAudError`.

### 1.2 Plaintext `http://` key URL accepted silently
- **Where:** `verifier.rb:36`, `verifier.rb:75`
- **Problem:** Fetching the verification key over HTTP lets an on-path attacker substitute their own key and mint arbitrary tokens — total auth bypass, no error, no warning.
- **Fix:**
  - [x] Validate `public_key_url` in `#initialize`: must parse as `URI::HTTPS`; raise `ArgumentError` otherwise.
  - [x] Add `allow_insecure_http: true` opt-out (for local dev only), documented as such.
- **Test:** `http://` URL raises `ArgumentError` unless `allow_insecure_http: true`.

### 1.3 No HTTP timeouts / size cap on key fetch
- **Where:** `verifier.rb:76`
- **Problem:** `Net::HTTP.get_response` defaults to 60 s open + 60 s read. On a cache miss with a slow SSO every request thread blocks up to two minutes — self-inflicted DoS. No response size cap either.
- **Fix:**
  - [x] Replace `Net::HTTP.get_response` with an explicit `Net::HTTP.start(host, port, use_ssl:, open_timeout:, read_timeout:)` block.
  - [x] Defaults: `open_timeout: 5`, `read_timeout: 5`; expose `http_timeout:` option.
  - [x] Reject bodies larger than ~64 KB before caching/parsing.
  - [x] Set a `User-Agent` and `Accept` header.
- **Test:** WebMock `to_timeout` → `KeyFetchError`.

### 1.4 Downstream `JWT::DecodeError` swallowed by the middleware  ⚠ confirmed
- **Where:** `lib/rack_jwt_verifier/middleware.rb:38-46`
- **Problem:** `@app.call(env)` runs inside the `rescue JWT::DecodeError`. If the application itself raises `JWT::DecodeError` (apps commonly decode other tokens), this middleware converts it into a 401 and masks the real error.
- **Fix:**
  - [x] Move `@app.call(env)` out of the `begin/rescue`; only `@verifier.verify(token)` should be guarded.
- **Test:** inner app raises `JWT::DecodeError` with a valid bearer token → error propagates (not 401).

---

## Phase 2 — Bugs

### 2.1 Rack 3 header-name violation  ⚠ confirmed
- **Where:** `middleware.rb:67`
- **Problem:** Rack 3 requires lowercase header names. `Rack::Lint` fails with `uppercase character in header name: Content-Type`. Gemspec allows `rack >= 2.0`; lockfile is rack 3.2.3.
- **Fix:**
  - [x] Use `"content-type"` and `"www-authenticate"` (valid on Rack 2 too).
  - [x] Add `content-length`.
- **Test:** wrap the middleware in `Rack::Lint` in the middleware spec for every path (pass-through, 200, 401, 503).

### 2.2 Cache poisoning by non-PEM 200 response  ⚠ confirmed
- **Where:** `verifier.rb:83-89`
- **Problem:** Response body is written to the cache *before* it is parsed. A 200 with an HTML maintenance page is cached for 5 min; every request fails with `KeyFetchError` even after the SSO recovers. `spec/rack_jwt_verifier/verifier_spec.rb:110` ("FIX 2") works around the bug instead of exposing it.
- **Fix:**
  - [x] Parse with `OpenSSL::PKey::RSA.new` first; write to cache only on success.
  - [x] Remove the `allow(mock_cache).to receive(:write)` workaround in the spec and assert `write` is *not* called on bad body.
- **Test:** bad body → `KeyFetchError` and cache untouched; next call with a good body succeeds.

### 2.3 `KeyFetchError` never rescued in the middleware  ⚠ confirmed
- **Where:** `middleware.rb:39`, `verifier.rb:91-93`
- **Problem:** SSO outage → unhandled exception → 500 on every request that carries a token. The verifier comment claims it re-raises "for rescue in middleware", but nothing rescues it.
- **Fix:**
  - [x] Rescue `Verifier::KeyFetchError` in `Middleware#call` → `503 Service Unavailable` with `retry-after: 5` and a log line at `error` level.
  - [x] Decided: 503 (the problem is ours, not the client's). Documented in README.
- **Test:** stub 5xx / timeout → 503.

### 2.4 `verifier.rb` doesn't require its own dependencies  ⚠ confirmed
- **Where:** `verifier.rb:3-5`, `lib/rack_jwt_verifier.rb:11-14`
- **Problem:** `require "rack_jwt_verifier/verifier"` alone → `NameError: uninitialized constant InProcessCache`. Also uses `OpenSSL` without `require "openssl"`. Works from the top-level file only because `in_process_cache` is required last and the constant resolves lazily.
- **Fix:**
  - [x] `require_relative "in_process_cache"` and `require "openssl"` in `verifier.rb`.
  - [x] Use `require_relative` in `middleware.rb` too (currently a bare `require`).
  - [x] Drop the explicit `require 'rack_jwt_verifier/in_process_cache'` workaround from `verifier_spec.rb:9`.

### 2.5 Gem name / require-path mismatch
- **Where:** `rack_jwt_verifier.gemspec:6`, README "Installation"
- **Problem:** Gemspec name is `rack-jwt-verifier`; README says `gem 'rack_jwt_verifier'`. Bundler auto-requires a hyphenated gem as `rack-jwt-verifier`, which doesn't exist under `lib/` → `LoadError` on `Bundler.require` in Rails unless the user adds `require: 'rack_jwt_verifier'`.
- **Decision:** `rack-jwt-verifier` 0.1.0 is already on rubygems.org (357 downloads as of 2026-09-12), so renaming would strand existing users. Option B it is.
  - [x] ~~Option A: rename gem~~ — ruled out, gem is published under the hyphenated name.
  - [x] Option B: keep the hyphen and add `lib/rack-jwt-verifier.rb` containing `require_relative "rack_jwt_verifier"`.
  - [x] Update README install snippet to match; delete the stray `rack-jwt-verifier-0.1.0.gem` from the repo root.

### 2.6 `Bearer` scheme match is case-sensitive  ⚠ confirmed
- **Where:** `middleware.rb:58-61`
- **Problem:** RFC 7235 auth-schemes are case-insensitive. `bearer <token>` is treated as "no token" and passes through unauthenticated.
- **Fix:**
  - [x] `scheme&.casecmp?("bearer")`; `token&.strip`; treat empty token as absent.
- **Test:** `bearer`, `BEARER`, `Bearer` all verified; `Basic xyz` and empty `Bearer ` are ignored.

### 2.7 README contradicts code on missing token
- **Where:** `middleware.rb:29`, README "How it Works" §5
- **Problem:** README says a missing token → 401; code passes the request through.
- **Fix:**
  - [x] Added `require_token: false` option (default keeps current pass-through behaviour; consider flipping in 1.0).
  - [x] Document both modes.
- **Test:** `require_token: true` + no header → 401 with `www-authenticate: Bearer`.

### 2.8 `warn` used as the logger
- **Where:** `middleware.rb:42`
- **Problem:** Unconditional stderr write on every bad token; not silenceable, not structured.
- **Fix:**
  - [x] Accept `logger:` option; fall back to `env['rack.logger']`, then a null logger.
  - [x] Log at `info`/`warn` for token failures, `error` for key-fetch failures. Never log the token itself.

---

## Phase 3 — Test coverage (add alongside Phases 1–2)

- [x] **`InProcessCache` spec** (currently none): read/write/delete, TTL expiry (Timecop), `expires_in` override, thread-safety smoke test.
- [x] Middleware spec: reuse **one** middleware instance across requests so caching is actually exercised (currently `app` in `spec_helper.rb:40` builds a fresh middleware + cache per request; "fetches the key once" passes trivially).
- [x] Middleware spec: `Rack::Lint` wrapper on all responses.
- [x] Verifier spec: `iss` / `aud` / `sub` enforcement, `nbf`, leeway boundaries, http URL rejection. (cert-PEM input: with 4.3.)
- [x] Middleware spec: `KeyFetchError` → 503; case-insensitive scheme; downstream error not swallowed; `require_token`.
- [x] Stop testing via `instance_variable_get` / `send(:fetch_public_key)`; test observable behaviour (cache `read`/`write` calls + WebMock).
- [x] Remove the `let(:described_class)` override in `verifier_spec.rb:14` (shadows RSpec's built-in).
- [x] Silence the `warn` noise in the test run (follows from 2.8).

---
- [x] Fixed in passing: `InProcessCache#delete` returned the internal `[value, expires_at]` pair instead of the value its doc promised.

---

## Phase 4 — Missing features (by impact)

### 4.1 JWKS support with `kid` (biggest gap)
Nearly every SSO (Keycloak, Auth0, Okta, Entra ID, Cognito, Google) publishes `/.well-known/jwks.json`, not a raw PEM. ruby-jwt has a built-in `jwks:` option that takes a loader lambda receiving `{ kid:, invalidate: }`.
- [x] Add `jwks_url:` option (mutually exclusive with `public_key_url:` / `public_key:`).
- [x] Loader: read JWKS JSON from cache; on `invalidate: true` or unknown `kid`, refetch (rate-limited via `refetch_interval:`, default 60 s).
- [x] Cache the raw JWKS JSON, build `JWT::JWK::Set` per process (memoised per body).

### 4.2 Key-rotation handling for the PEM path
- [x] On `JWT::VerificationError`, delete the cached key and retry **once** with a fresh fetch (rate-limited so a flood of bad tokens can't hammer the SSO).

### 4.3 Accept X.509 certificate PEMs
Keycloak / Auth0 `.pem` endpoints return `-----BEGIN CERTIFICATE-----`; `OpenSSL::PKey::RSA.new` rejects it.
- [x] Detect `BEGIN CERTIFICATE` → `OpenSSL::X509::Certificate.new(pem).public_key`.
- [x] Use `OpenSSL::PKey.read` instead of `PKey::RSA.new` so EC/Ed keys work too.

### 4.4 Static key option
- [x] `public_key:` (PEM string, e.g. from ENV) as an alternative to any URL; skips cache & network entirely.

### 4.5 Configuration surface
- [x] `cache_ttl:` (currently hard-coded 300 in two places — `verifier.rb:18` and `in_process_cache.rb:9`).
- [x] `algorithms:` array (`RS256` default; allow `RS384/512`, `PS*`, `ES*`, `EdDSA`).
- [x] `env_key:` to rename `rack_jwt_verifier.payload`.
- [x] `http_timeout:` (from 1.3), `allow_insecure_http:` (from 1.2), `require_token:` (from 2.7), `logger:` (from 2.8), `refetch_interval:` (new, 4.2).

### 4.6 Middleware ergonomics
- [x] `skip:` — array of strings / regexps / lambdas for paths that bypass the middleware (`/health`, `/assets`).
- [x] `on_unauthorized:` callback / custom response builder; JSON 401 body option (`{"error":"invalid_token"}`).
- [x] Put the failure reason in `www-authenticate` per RFC 6750 (`error="invalid_token", error_description="..."`) — sanitised to the quoted-string alphabet, never the token.

---

**Design note (2026-09-12):** done as one refactor rather than piecemeal — key retrieval moved into `KeySource::{Static,RemotePem,RemoteJwks}` (`lib/rack_jwt_verifier/key_source.rb`) sharing fetch/cache/timeout/single-flight/refresh code in `KeySource::Remote`; `Verifier` picks one source and decodes. Found and fixed along the way: cache keys were not scoped to the URL, so two verifiers sharing a Redis store would have read each other's key.

---

## Phase 5 — Improvements & hygiene

### Code
- [x] Memoize the parsed `OpenSSL::PKey` per PEM string — `verifier.rb:71` re-parses the PEM on **every request**. (done in 4a: `KeySource::Remote#parsed_for`)
- [x] Mutex around the network fetch in `fetch_public_key` to prevent a thundering herd on cold cache. (done in 4a: single-flight `@fetch_lock`)
- [ ] `rescue StandardError` at `verifier.rb:94` also wraps cache-store failures (Redis down) as "Error processing public key". Split: cache read failure → log + fall through to network; only wrap HTTP/OpenSSL errors as `KeyFetchError`.
- [x] Remove unused `@options` in `Middleware#initialize` (`middleware.rb:17`). (Verifier still receives the full hash and ignores what it does not know — fine.)
- [ ] `InProcessCache`: use `Process.clock_gettime(Process::CLOCK_MONOTONIC)` instead of `Time.now.to_i` (wall-clock jumps). Note: Timecop-based specs will need adjusting.
- [ ] `JwtHelper`: it ships the *signing* side inside a verifier gem — consider moving it to `spec/support/` or documenting it as a test helper only. If kept: `payload.merge(iat:, exp:)` with symbol keys produces duplicate JSON keys when the caller passes `'exp'`; normalise keys first. `decode` should accept options (leeway, iss…).
- [ ] Remove leftover scaffolding comments (`lib/rack_jwt_verifier.rb:9-10`, "IMPORTANT: These paths rely on you moving…").
- [ ] Bump `required_ruby_version` to `>= 3.0` (2.6/2.7 are EOL) and switch option hashes to keyword arguments.

### Repo
- [ ] Add `.gitignore`: `*.gem`, `.rspec_status`, `.bundle/`, `coverage/`, `pkg/`, `tmp/`.
- [ ] `git rm --cached .rspec_status`.
- [x] Delete `rack-jwt-verifier-0.1.0.gem` from the root (build into `pkg/`).
- [ ] Gemfile: drop the duplicated deps (`rack`, `rspec`, `rack-test`, `webmock`) — they conflict with the gemspec constraints (`rspec ~> 3.12` vs `~> 3.0`, `webmock ~> 3.14` vs `~> 3.0`). `gemspec` alone is enough.
- [ ] Add `Rakefile` (`rake` is already a dev dep) with `spec` as default task, plus `.rspec` (`--require spec_helper --color`).
- [ ] Add CI (GitHub Actions matrix: Ruby 3.0–3.3 × rack 2/3).
- [ ] Add RuboCop with a minimal config.
- [x] Fill in `CHANGELOG.md` (Keep-a-Changelog format) starting with 0.1.0 and the 0.2.0 entries from this plan. (Needs a version heading + date at release time.)

### README
- [x] Fix install snippet to match the final gem name (2.5).
- [x] Fix the `iss`/`aud` table & example (1.1); remove the leaked markdown link inside the code sample (`iss: "[https://…](https://…)"`).
- [x] Un-escape `cache\_store`, `decode\_options`, `public\_key\_url`, `expires\_in` in prose.
- [x] LICENSE link currently points to a Google search → link to `LICENSE.md`.
- [x] "pass in a Redis/Memcached client" is wrong — it must be a cache **store** responding to `read(key)` / `write(key, value, expires_in:)` (e.g. `ActiveSupport::Cache::Store`), not a `redis-rb` client. Say so, and document the exact interface (`delete` too, once 4.2 lands).
- [x] Document the missing-token behaviour and `require_token` (2.7), the 503 behaviour (2.3), https enforcement (1.2), and timeouts (1.3).
- [x] Add a "Security considerations" section: enforce `iss`/`aud`, use HTTPS, keep leeway small, prefer JWKS.

---

## Suggested execution order

1. Phase 1.4, 2.1, 2.4, 2.6 — pure mechanical fixes, no API change.
2. Phase 1.1, 2.2, 2.3, 2.8 — small behaviour changes; add specs from Phase 3 as you go.
3. Phase 1.2, 1.3, 2.7 — new options with safe defaults.
4. Phase 2.5 + README + repo hygiene → tag **0.2.0**.
5. Phase 4.3, 4.4, 4.5 → **0.3.0**.
6. Phase 4.1, 4.2, 4.6 → **0.4.0** / **1.0.0**.
