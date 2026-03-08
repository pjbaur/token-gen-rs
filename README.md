# token-gen

A cryptographically secure, type-safe token generation library for Rust.

## Features

- **Type-safe tokens**: Distinct types for auth tokens, API keys, and CSRF tokens
- **Builder pattern**: Ergonomic configuration with compile-time guarantees
- **Secure defaults**: OS-backed CSPRNG, constant-time comparison, HMAC-SHA256 signatures
- **Flexible hashing**: SHA-256 or scrypt for API key storage
- **Zero runtime dependencies** (aside from well-vetted crypto crates)

## Installation

```bash
cargo add token-gen
```

### CLI Installation

To install the command-line tool:

```bash
cargo install token-gen --features cli
```

## Library Usage

### Auth Tokens

Simple tokens for authentication flows:

```rust
use token_gen::{AuthToken, Format};

// Generate a simple token
let token = AuthToken::generate(32, Format::Base64Url)?;
println!("{}", token);
```

Expiring tokens with HMAC signatures:

```rust
use token_gen::{AuthToken, SecretKey};
use std::time::Duration;

let secret = SecretKey::from_string("your-secret-key");

let token = AuthToken::builder()
    .length(32)
    .expires_in(Duration::from_secs(3600)) // 1 hour
    .secret_key(&secret)
    .generate()?;

// Verify later
token.verify(&secret)?;
assert!(!token.is_expired()?);
```

### API Keys

Generate prefixed keys with hashes for database storage:

```rust
use token_gen::{ApiKey, ApiKeyType, Environment, HashAlgorithm};

let generated = ApiKey::builder()
    .key_type(ApiKeyType::Secret)
    .environment(Environment::Test)
    .hash_algorithm(HashAlgorithm::Scrypt)
    .generate_with_hash()?;

// Give the key to the user
println!("Key: {}", generated.key);      // sk_test_xxx

// Store the hash in your database
println!("Hash: {}", generated.key_hash); // scrypt:14:8:1:...
```

| Key Type | Prefix | Example |
|----------|--------|---------|
| `Api` | `api` | `api_live_xxx` |
| `Secret` | `sk` | `sk_test_xxx` |
| `Public` | `pk` | `pk_staging_xxx` |

Verify a key against stored hash:

```rust
let key: ApiKey = "sk_test_abc123".parse()?;
let valid = key.verify(&stored_hash);
```

### CSRF Tokens

HMAC-signed tokens bound to session IDs:

```rust
use token_gen::{CsrfToken, SecretKey};

let secret = SecretKey::from_string("csrf-secret");
let session_id = "user-session-123";

// Generate token for form
let token = CsrfToken::generate(&secret, session_id, 32)?;

// Verify on submission
let claims = token.verify(&secret, session_id, 3600)?;
println!("Token age: {:?}", claims.age);
```

## CLI Usage

```bash
# Generate auth token
token-gen auth
token-gen auth -l 64 -f hex
token-gen auth -x 3600 -s "secret-key"  # expiring token

# Check if token is expired
token-gen auth --check-expiry "token-string"

# Generate API key
token-gen api
token-gen api -t sk -e test
token-gen api -n 5 -o json  # generate 5 keys as JSON

# Hash an existing key
token-gen api --hash "api_live_xxx"

# Verify key against hash
token-gen api --verify "api_live_xxx" "sha256:..."

# Generate CSRF token (requires secret)
token-gen csrf -s "csrf-secret"
TOKEN_GEN_SECRET="csrf-secret" token-gen csrf

# Verify CSRF token
token-gen csrf -s "csrf-secret" --verify "token-string"
```

## API Reference

| Type | Description |
|------|-------------|
| [`AuthToken`] | Simple or expiring authentication tokens |
| [`ApiKey`] | Prefixed API keys with hashing support |
| [`CsrfToken`] | Session-bound HMAC-signed tokens |
| [`SecretKey`] | Key material for signing operations |
| [`Format`] | Output encoding (Base64Url, Hex) |
| [`TokenError`] | Error type for all operations |

## Security Notes

- **Randomness**: Uses `rand::rngs::OsRng` (platform-specific CSPRNG)
- **Timing attacks**: Constant-time comparison via the `subtle` crate
- **Minimum entropy**: 16 bytes (128 bits) enforced for all tokens
- **Key storage**: Never store raw API keys; always store hashes
- **Secrets**: Use strong, randomly-generated secret keys in production

## License

MIT

## Documentation

Full API documentation: [docs.rs/token-gen](https://docs.rs/token-gen)
