# rack_jwt_verifier 0.3.0 — interop with jwt_auth_client, claim policy, review

Context: `jwt_auth_client` 0.2.0 (the issuing half) emits

```
{ iss, sub, aud (String), scopes (Array<String>, optional), iat, nbf, exp, jti (UUID),
  + optional custom claims (user_id, email, ...) }
```

signed with `HS256`/`HS384`/`HS512` and a shared secret of >= 32/48/64 bytes. Asymmetric
signing (RS256/ES256 + `kid`) arrives in jwt_auth_client 0.3.0. This gem is asymmetric-only
today, so nothing jwt_auth_client produces can be verified. Goal: 0.3.0 of this gem verifies
HS* tokens as an explicit opt-in, enforces the claim policy the issuer relies on, exposes
`scopes`/`sub` usefully, and is ready for the asymmetric tokens when they land.

Facts established while analysing (they drive several decisions below):

- ruby-jwt 2.10.3 accepts *any* non-empty String as an HMAC key (a 5-byte key verifies), so the
  RFC 7518 §3.2 minimum-length guard has to be enforced by this gem.
- ruby-jwt 2.x only supports `EdDSA` when the native `rbnacl` gem is loaded, and deprecates it
  (3.x moves it to `jwt-eddsa`). The README's "EdDSA" claim is not something the gem can deliver
  on its own.
- `verify_expiration: true` in ruby-jwt only checks `exp` **when the claim is present**: a token
  with no `exp` is accepted forever today.
- Claim verification in ruby-jwt runs *after* the signature check; `verify_jti: true` rejects a
  missing/blank `jti`; `required_claims:` rejects missing claims.
- `JSON.parse` is only ever called with one positional argument (`key_source.rb`); ruby-jwt's own
  `JWT::JSON.parse` likewise. json 3.x is already installed locally (3.0.2) and the suite passes.
- `InProcessCache` never evicts expired entries. Fine for one key body; unbounded for jti storage.
- jwt_auth_client 0.2.0 exists only on the local `harden-0.2.0` branch; `origin/main` is 0.1.0.

## 0. Ground rules

- Run `bundle exec rspec` and `bundle exec rubocop` after every step; nothing lands red.
- Work on branch `interop-0.3.0`; one commit per step; CHANGELOG/README/version updated in the
  step that changes behaviour, not at the end.
- 0.3.0 is **breaking**: `iss`/`aud` become required, `exp` becomes required, boot errors get a
  new class. Everything else is additive.

## 1. Interop now — HMAC as an explicit opt-in

New key-source option `shared_secret:` (fourth member of the "exactly one of" set alongside
`public_key`, `public_key_url`, `jwks_url` — which by construction forbids a secret next to a
public key).

- Value: a `String` (the secret itself, e.g. `ENV.fetch("JWT_SERVICE_SECRET")`) or
  `{ env: "JWT_SERVICE_SECRET" }` to have the middleware read the variable at boot. A literal
  String is never interpreted as an ENV name — that would make a real secret ambiguous.
- `KeySource::Secret`: static, nothing to fetch; `refresh!` is `false`; `verification_key` is
  the String. Rotation is out of scope (a shared secret has no `kid`; rotate by redeploying).
- `algorithms:` defaults to `["HS256"]` when `shared_secret` is given (`["RS256"]` otherwise).
- Boot-time validation (`ConfigurationError`, never per request):
  - `"none"` (any case) is rejected in every configuration.
  - With `shared_secret`: every algorithm must be `HS256|HS384|HS512`; the secret must be at
    least 32/48/64 bytes for the *longest* HS algorithm listed; empty/nil secret rejected;
    `{ env: }` pointing at an unset variable rejected with the variable name in the message.
  - With a public-key source: no `HS*` may appear in `algorithms`.
  - `decode_options[:algorithm]` / `[:algorithms]` are folded into the same check so they cannot
    smuggle an `HS*` past the top-level `algorithms:` (today they bypass it entirely).
- Docs: asymmetric stays the default and the recommended path. HMAC is documented as the
  "small trusted set of internal services" mode: every holder of the secret can mint tokens for
  every audience, so keep the set small, and switch to jwt_auth_client 0.3.0's asymmetric mode
  when it ships. README "Security considerations" is updated (the "never add HS*" bullet becomes
  "never mix HS* and RS*/ES*; the middleware refuses to boot if you try").

## 2. Claim policy matching the issuer

- **`iss` and `aud` required at boot.** `Middleware.new` raises `ConfigurationError` unless
  `decode_options` carries a non-blank `iss` and `aud`, or the operator passes
  `require_iss_aud: false` (in which case the existing one-time warning is logged instead).
  This replaces the 0.2.0 warning. Rationale: a key/secret alone proves who *signed* a token,
  not who it was *for*; with a shared secret it does not even prove that much.
- **`exp` required.** `required_claims: ["exp"]` goes into the default decode options
  (operator-overridable through `decode_options[:required_claims]`). `nbf` stays optional
  (jwt_auth_client sends it; SSO providers often don't). `leeway` stays at 60 s via
  `decode_options[:leeway]`, validated at boot as a non-negative Numeric.
- **Scopes.** Verified claims already land in `env["rack_jwt_verifier.payload"]`, so `sub` and
  `scopes` are available. Added:
  - `RackJwtVerifier::Scopes` helper: `.from(payload)` returns the granted scopes as
    `Array<String>` reading `scopes` (Array, what jwt_auth_client emits) or `scope`
    (space-delimited String, RFC 8693/9068 style); `.missing(payload, required)`;
    `.include?(payload, *scopes)`. Apps use it for per-route checks.
  - `require_scopes: [...]` middleware option: every listed scope must be present, otherwise
    `403` with `WWW-Authenticate: Bearer error="insufficient_scope", error_description="...",
    scope="a b"` (RFC 6750 §3.1), reason `:insufficient_scope` for `on_error`/JSON bodies.
    A required scope implies a required token, so `require_scopes` sets `require_token`;
    passing an explicit `require_token: false` alongside it is a `ConfigurationError`.
- **Replay protection** (`replay_cache:`, default off):
  - `replay_cache: true` uses the `cache_store` given to the middleware (or a fresh
    `InProcessCache`); `replay_cache: some_store` uses that store (any `read`/`write` store,
    `Rails.cache` included). Per-process `InProcessCache` only protects within one worker —
    documented; use a shared store for real protection.
  - When on, `verify_jti: true` is added (a token with no `jti` is rejected) and after a
    successful decode the verifier does check-then-`write(..., unless_exist: true)` on
    `rack_jwt_verifier:jti:<sha256(jti)>` with `expires_in = exp - now + leeway`. A hit raises
    `ReplayedTokenError < JWT::InvalidJtiError` → `401 invalid_token`.
  - A replay store that raises makes the request fail **closed** (`503`, reason
    `:replay_cache_unavailable`): the operator turned the guarantee on; silently skipping it
    would be worse than a retryable error. Contrast with the key cache, which fails open
    because the fetch still verifies the signature.
  - `InProcessCache` gains `unless_exist:` support and amortised eviction of expired entries so
    a jti-per-request workload cannot grow it without bound; also `#clear`.

## 3. Consolidate issuing: deprecate `JwtHelper`

`JwtHelper` is a second token issuer living inside the verifier, RS256-only, no `iss`/`aud`/
`nbf`/`jti`. Decision: **deprecate in favour of jwt_auth_client** (which will do RS256 in
0.3.0), rather than keep a shrunken copy — two issuers would drift again.

- Not removed in this pass. `JwtHelper.new` emits a one-time deprecation warning (via
  `Kernel#warn` with `uplevel`, opt-out with `RACK_JWT_VERIFIER_SILENCE_DEPRECATIONS=1` for
  test suites) pointing at jwt_auth_client and at the spec support helper.
- The test suite stops using it: a `spec/support/token_factory.rb` signs test tokens directly
  with `JWT.encode`, so removing `JwtHelper` in 0.4.0 touches no spec.
- CHANGELOG "Deprecated" entry; README section replaced by a short deprecation note.

## 4. Prepare for jwt_auth_client 0.3.0 asymmetric tokens

- Round-trip spec `spec/rack_jwt_verifier/interop_spec.rb` using jwt_auth_client's
  `TokenIssuer` as the signer:
  - HS256/HS384/HS512 tokens with `iss`/`aud`/`scopes`/`jti` through the middleware; `scopes`
    and `sub` reach the app; `require_scopes` and `replay_cache` behave against real issuer
    output; `Issuable` custom claims (`user_id`, `email`) arrive intact.
  - Asymmetric: jwt_auth_client cannot sign RS256/ES256 yet, so the spec builds the *same
    payload shape* (via `TokenIssuer` where a payload is obtainable, else the documented shape)
    and signs it with `JWT.encode(..., kid:)` for RS256 and ES256, verified through `jwks_url`
    with `kid` matching. It is tagged so it is the one to switch to `TokenIssuer` when 0.3.0
    ships.
  - EdDSA: documented as requiring `rbnacl` on ruby-jwt 2.x (`jwt-eddsa` on 3.x); not part of
    the default algorithm set and not claimed in the README any more.
- Development dependency: `gem "jwt_auth_client", path: ENV.fetch("JWT_AUTH_CLIENT_PATH",
  "../jwt_auth_client")` in the Gemfile, guarded by the directory existing and Ruby >= 3.1
  (jwt_auth_client's floor). The interop spec `skip`s with a clear message when the gem is not
  loadable or older than 0.2.0. CI checks the sibling repo out into `vendor/jwt_auth_client`;
  until `harden-0.2.0` is merged to its `main`, that leg skips the interop examples.

## 5. General review — findings and fixes

Security
- `exp` not required (see §2) — fixed.
- `decode_options[:algorithm(s)]` bypass the top-level algorithm policy — fixed (§1).
- `none` never rejected explicitly — fixed (§1).
- Key fetch: no `write_timeout`; add it. Redirects are (correctly) not followed; TLS
  verification is Net::HTTP's default `VERIFY_PEER` — keep, add a spec that an `http://`
  redirect target is never fetched.
- `error_description` echoes ruby-jwt messages which can include token claim values (e.g. the
  received `iss`/`aud`) — acceptable (it is the client's own token) and already sanitised.

Correctness / bugs
- README claims EdDSA — fixed in docs.
- `Verifier` constants `PUBLIC_KEY_CACHE_KEY` etc. are kept for compatibility.
- `Middleware#warn_if_claims_unrestricted` falls back to `Kernel.warn` — superseded by §2.

Performance / thread safety
- `InProcessCache`: unbounded growth — fixed (§2). Locking is correct (single mutex).
- `KeySource::Remote`: `@fetch_lock` single-flight and `@state_lock` for memo/rate-limit are
  correct; `refresh!` deliberately runs outside `@fetch_lock`. No change.
- The replay check adds one cache read+write per request only when enabled.

Error hierarchy
- Add `RackJwtVerifier::Error < StandardError`; `ConfigurationError < Error` (boot-time
  option problems; replaces the bare `ArgumentError`s); `KeyFetchError < Error`;
  `ReplayCacheError < Error`; `ReplayedTokenError < JWT::InvalidJtiError` (so the
  middleware's `rescue JWT::DecodeError` path handles it as a 401);
  `InsufficientScopeError < Error` handed to `on_error`. `Verifier::KeyFetchError` alias kept.

Compatibility
- json >= 3.0: no positional-options `JSON.parse` calls exist; json 3.0.2 is what the local
  bundle resolves to and the suite passes. Add a comment/spec guard so it stays that way.
- CI: add a `gemfiles/jwt_3.gemfile` leg (ruby-jwt 3.x) if the suite passes against it
  locally; otherwise keep `~> 2.8` and record why. Add Ruby 4.0 to the matrix (the `logger`
  dependency was added for it). Keep Ruby 3.0 as the floor (breaking enough already); the
  jwt_auth_client path dependency is skipped on 3.0.

README accuracy
- Remove EdDSA claim; document `shared_secret`, `require_iss_aud`, `require_scopes`,
  `replay_cache`, `required_claims`, the new error classes, the `JwtHelper` deprecation, and
  the "pairs with jwt_auth_client" interop section with a copy-pasteable config for each side.

## 6. Release bookkeeping

- `VERSION = "0.3.0"`, CHANGELOG `[0.3.0]` with Added/Changed/Deprecated/Security/Fixed and
  explicit upgrade notes (set `iss`/`aud` or `require_iss_aud: false`; tokens must carry `exp`;
  rescue `ConfigurationError` instead of `ArgumentError` at boot).
- Commit on `interop-0.3.0`.
