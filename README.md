RackJwtVerifier
===============

A robust and production-ready Rack middleware for authenticating requests using JSON Web Tokens (JWT) signed by an external Single Sign-On (SSO) provider.

This gem handles the cryptographic verification, caching of public keys, and integration into any Rack application (including Ruby on Rails).

Features
--------

*   **Cryptographic Verification:** Verifies the JWT signature using the `RS256` algorithm and public keys fetched from a remote URL.
    
*   **Flexible Caching:** Uses a configurable cache store for public keys, defaulting to in-memory caching but easily upgradable to **Redis** or **Memcached** for multi-process environments.
    
*   **Claim Validation:** Enforces standard JWT claims, including expiration (`exp`) and not-before (`nbf`).
    
*   **Rack Middleware:** Protects application routes by halting unauthorized requests with a `401 Unauthorized` response.
    

Installation
------------

Add this line to your application's `Gemfile`:

```ruby
gem 'rack_jwt_verifier'
```

And then execute:

```bash
$ bundle install
```

Usage and Integration
---------------------

### 1\. Basic Setup (In-Memory Caching)

The simplest way to integrate is by providing the URL where your SSO provider exposes its public key (usually a PEM-encoded RSA key). The public key will be cached in memory for **5 minutes** per worker process.

**In `config/application.rb` (for Rails) or `config.ru` (for generic Rack):**

```ruby
# Requires `rack_jwt_verifier` implicitly in Rails, or explicitly in config.ru
# Replace the URL with your actual SSO Public Key endpoint
PUBLIC_KEY_URL = "https://sso.example.com/api/v1/public_key"
Rails.application.config.middleware.use RackJwtVerifier::Middleware,
                                        public_key_url: PUBLIC_KEY_URL
```
### 2\. Production Setup with Redis Caching

For horizontally scaled applications (e.g., using Puma or multiple Docker containers), the default in-memory cache is inefficient. To prevent a "cache stampede" where all workers simultaneously fetch the key, you must use a distributed cache like Redis.

**Prerequisites:** You need a Redis client library installed (e.g., `redis-rails` or `connection\_pool`).

#### Example: Using Redis as the Cache Store

The `RackJwtVerifier` expects a cache object that responds to the standard Ruby cache interface: `#read(key)` and `#write(key, value, expires\_in: ttl)`.

**Example using `ActiveSupport::Cache::RedisCacheStore` (Common in Rails apps):**

```ruby
# In config/initializers/rack_jwt_verifier.rb

# 1. Configure your Redis cache client
# This example assumes you have Redis configured via Rails:
REDIS_CACHE_CLIENT = ActiveSupport::Cache.lookup_store(:redis_cache_store, {
    url: ENV.fetch("REDIS_URL", "redis://localhost:6379/1"),
    reconnect_attempts: 1  })
# 2. Configure the Verifier with the Redis client
Rails.application.config.middleware.use RackJwtVerifier::Middleware,
  public_key_url: ENV.fetch("SSO_PUBLIC_KEY_URL"),
  cache_store: REDIS_CACHE_CLIENT
```

By passing the Redis cache client via the `cache\_store` option, all your application workers will share a single cache, ensuring the public key is fetched from the network only once every 5 minutes (or whatever TTL is configured internally).

### 3\. Middleware Options

| Option | Default | Purpose |
| -- | -- | -- |
| `:public_key_url` | (required) | The **`https://`** URL that serves the SSO provider's PEM-encoded public key. |
| `:allow_insecure_http` | `false` | Permit a plain `http://` URL. **Development only** — over plaintext HTTP an attacker on the network path can swap the key and mint arbitrary tokens. |
| `:http_timeout` | `5` seconds | Open and read timeout for the key fetch. Keeps a slow SSO endpoint from tying up request threads on a cache miss. |
| `:cache_store` | `InProcessCache` | Cache for the fetched key (see section 2). |
| `:decode_options` | see below | Options passed to `JWT.decode`. |

The key fetch also refuses response bodies larger than 64 KB — a PEM public key is well under 1 KB.

### 4\. Customizing JWT Decoding

You can pass a `:decode_options` hash to the middleware to override the default settings for the JWT gem.

| Option | Default Value | Purpose |
| -- | -- | -- |
| `:leeway` | `60` seconds | Sets clock skew tolerance for `exp` and `nbf` checks. Set to `0` for strict timing. |
| `:algorithm` | `"RS256"` | The expected signing algorithm. |
| `:iss` | (None) | **RECOMMENDED**: The issuer the token must carry. Enforced as soon as it is set. |
| `:aud` | (None) | **RECOMMENDED**: The audience the token must carry. Enforced as soon as it is set. |
| `:sub` | (None) | The subject the token must carry. Enforced as soon as it is set. |

> **Note:** the underlying `jwt` gem only checks `iss`/`aud`/`sub` when the matching `verify_iss`/`verify_aud`/`verify_sub` flag is also `true`. This middleware switches the flag on automatically whenever you supply a value, so `iss: "..."` really is enforced. If you explicitly pass `verify_iss: false` alongside `iss:`, your setting wins.

**Example: Strict Expiration, Issuer and Audience Check:**

```ruby
Rails.application.config.middleware.use RackJwtVerifier::Middleware,
  public_key_url: ENV.fetch("SSO_PUBLIC_KEY_URL"),
  decode_options: {
    # No clock skew tolerance
    leeway: 0,
    # Ensure the token was issued by our expected SSO provider ...
    iss: "https://my-sso.com/token-service",
    # ... and minted for this application
    aud: "my-app"
  }
```

How it Works
------------

1.  **Request Flow:** On every incoming HTTP request, the middleware intercepts the call.
    
2.  **Token Extraction:** It looks for a token in the `Authorization: Bearer <token>` header.
    
3.  **Key Retrieval:** The Verifier attempts to read the public key PEM string from the configured `cache\_store` (Redis or In-Memory).
    *   If the key is present, it's used immediately.
    *   If the key is missing or expired, a network request is made to the `public\_key\_url`, and the key is written back to the cache for 5 minutes.
        
4.  **Verification:** The public key is used to cryptographically verify the JWT's signature and validate its claims (`exp`, `nbf`, `iss`, etc.).
    
5.  **Authorization:**
    *   If verification succeeds, the request passes to your application.
    *   If verification fails (e.g., token expired, bad signature, or missing token), the request is halted, and a `401 Unauthorized` response is immediately returned.
        

Development
-----------

The testing setup uses RSpec, WebMock for network request mocking, and Timecop for robust time-dependent testing (like expiration checks).

To run the full suite:

```bash
$ bundle install
$ bundle exec rspec
```

License
-------

The gem is available as open source under the terms of the [MIT License](https://www.google.com/search?q=LICENSE.txt).