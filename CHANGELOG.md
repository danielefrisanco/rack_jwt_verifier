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

### Added
- `allow_insecure_http:` and `http_timeout:` middleware options.
- The key fetch sends `User-Agent: rack_jwt_verifier/<version>` and an `Accept` header.

## [0.1.0]

### Added
- Initial release: `RackJwtVerifier::Middleware`, `Verifier` with pluggable cache store,
  `InProcessCache`, and `JwtHelper`.
