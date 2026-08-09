# token-gen

A cryptographically secure, type-safe token generation library for Rust.

## Features

- **Type-safe tokens**: Distinct types for auth tokens, API keys, and CSRF tokens
- **Builder pattern**: Ergonomic configuration with validation when `generate()` runs
- **Secure defaults**: OS-backed CSPRNG, constant-time comparison, HMAC-SHA256 signatures
- **Flexible hashing**: SHA-256 or scrypt for API key storage
- **Explicit dependency surface**: Crypto, time, and error-handling crates, with CLI dependencies behind the optional `cli` feature

## Requirements

Minimum supported Rust version (MSRV): **Rust 1.85**.

## Feature Flags

| Flag | Description |
|------|-------------|
| `cli` | Enables the `token-gen` command-line binary and its Clap/Serde dependencies |

## Installation

`token-gen` is not currently published on crates.io. From a local checkout, add it by path:

```bash
cargo add token-gen --path /path/to/token-gen-rs
```

Or add it directly to `Cargo.toml`:

```toml
[dependencies]
token-gen = { path = "/path/to/token-gen-rs" }
```

### CLI Installation

Install the command-line tool from a local clone:

```bash
cargo install --path /path/to/token-gen-rs --features cli
```

## Library Usage

### Auth Tokens

Simple tokens for authentication flows:

```rust
use token_gen::{AuthToken, Format};

let token = AuthToken::generate(32, Format::Base64Url)?;
println!("{token}");

# Ok::<(), token_gen::TokenError>(())
```

Expiring tokens with HMAC signatures:

```rust
use std::time::Duration;
use token_gen::{AuthToken, SecretKey};

let secret = SecretKey::from_string("replace-with-a-random-secret-at-least-32-bytes")?;

let token = AuthToken::builder()
    .length(32)
    .expires_in(Duration::from_secs(3600)) // 1 hour
    .secret_key(&secret)
    .generate()?;

token.verify(&secret)?;
assert!(!token.is_expired()?);

# Ok::<(), token_gen::TokenError>(())
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

println!("Key: {}", generated.key);      // sk_test_xxx; give to the user once
println!("Hash: {}", generated.key_hash); // scrypt:...; store in the database

# Ok::<(), token_gen::TokenError>(())
```

| Key Type | Prefix | Example |
|----------|--------|---------|
| `Api` | `api` | `api_live_xxx` |
| `Secret` | `sk` | `sk_test_xxx` |
| `Public` | `pk` | `pk_staging_xxx` |

Verify a key against its stored hash:

```rust
use token_gen::{ApiKey, ApiKeyType, Environment};

let generated = ApiKey::builder()
    .key_type(ApiKeyType::Secret)
    .environment(Environment::Test)
    .generate_with_hash()?;
let key: ApiKey = generated.key.to_string().parse()?;

assert!(key.verify(&generated.key_hash));

# Ok::<(), token_gen::TokenError>(())
```

### CSRF Tokens

HMAC-signed tokens bound to session IDs:

```rust
use token_gen::{CsrfToken, SecretKey};

let secret = SecretKey::from_string("replace-with-a-random-secret-at-least-32-bytes")?;
let session_id = "user-session-123";

let token = CsrfToken::generate(&secret, session_id, 32)?;
let claims = token.verify(&secret, session_id, 3600)?;
assert_eq!(claims.session_id, session_id);

# Ok::<(), token_gen::TokenError>(())
```

## CLI Usage

The CLI accepts an inline `--secret` for development, but command-line secrets can leak through shell history and process listings. For normal use, load `TOKEN_GEN_SECRET` from a password manager or prompt without echoing it:

```bash
read -r -s TOKEN_GEN_SECRET
export TOKEN_GEN_SECRET
```

Then run the documented workflows:

<!-- readme-cli-smoke:start -->
```bash
# Generate auth tokens
token-gen auth
token-gen auth -l 64 -f hex
SIGNED_TOKEN="$(token-gen auth -x 3600)"
token-gen auth --check-expiry "$SIGNED_TOKEN"

# Generate API keys
token-gen api
token-gen api -t sk -e test
token-gen api -n 5 -o json

# Hash and verify an API key
API_RESULT="$(token-gen api)"
API_KEY="$(printf '%s\n' "$API_RESULT" | awk '/^key: / {print $2}')"
API_HASH="$(printf '%s\n' "$API_RESULT" | awk '/^key_hash: / {print $2}')"
token-gen api --hash "$API_KEY"
token-gen api --verify "$API_KEY" "$API_HASH"

# Generate and verify a CSRF token bound to the same application session
SESSION_ID="user-session-123"
CSRF_TOKEN="$(token-gen csrf --session-id "$SESSION_ID")"
token-gen csrf --session-id "$SESSION_ID" --verify "$CSRF_TOKEN"
```
<!-- readme-cli-smoke:end -->

`--session-id` is required for CSRF generation and verification. Verification fails when the supplied session ID differs from the one used to sign the token.

## API Reference

Until the crate is published, API entries link to usage documentation in this README. Build the full generated API reference locally as described below.

| Type | Description |
|------|-------------|
| [`AuthToken`](#auth-tokens) | Simple or expiring authentication tokens |
| [`ApiKey`](#api-keys) | Prefixed API keys with hashing support |
| [`CsrfToken`](#csrf-tokens) | Session-bound HMAC-signed tokens |
| [`SecretKey`](#csrf-tokens) | Key material for signing operations |
| [`Format`](#auth-tokens) | Output encoding (`Base64Url`, `Hex`) |
| [`TokenError`](#error-handling) | Error type for all fallible operations |

## Error Handling

Fallible library operations return `Result<_, TokenError>`. Propagate errors with `?`, as in the examples above, or match individual `TokenError` variants when callers need specialized handling.

## Security Notes

- **Randomness**: Uses `rand::rngs::SysRng` (platform-specific CSPRNG)
- **Timing attacks**: Uses constant-time comparison via the `subtle` crate
- **Signatures**: Uses HMAC-SHA256 for expiry-bearing auth and CSRF tokens
- **Password hashing**: Supports configurable scrypt parameters for API key storage
- **Minimum entropy**: Enforces at least 16 bytes (128 bits) for tokens and signing secrets
- **Key storage**: Never store raw API keys; store their hashes
- **Secrets**: Use strong, randomly generated secret keys in production; avoid command-line literals

## Documentation

The crate is unpublished, so docs.rs does not host its API documentation. Build and open the current API documentation locally:

```bash
cargo doc --all-features --no-deps --open
```

## License

MIT
