# Security Policy

## Security Considerations

This document outlines the security architecture, considerations, and best practices for the `token-gen` library.

### Cryptographic Primitives

#### Random Number Generation

- **CSPRNG**: Uses `rand::rngs::SysRng` for all random number generation
- **Minimum entropy**: All tokens require a minimum of 16 bytes (128 bits) of entropy
- **No fallbacks**: The library will fail rather than use weak randomness

#### HMAC Signatures

- **Algorithm**: HMAC-SHA256 for all signed tokens (CSRF, expiring auth)
- **Key requirement**: Secret keys must be at least 16 bytes (128 bits)
- **Constant-time comparison**: All signature verification uses constant-time comparison via the `subtle` crate to prevent timing attacks

#### API Key Hashing

Two hashing options are available:

1. **SHA-256** (default, fast):
   - Suitable for API keys due to their high entropy (128+ bits)
   - Deterministic: same key always produces the same hash
   - Format: `sha256:<hex-encoded-hash>`

2. **Scrypt** (slower, more resistant):
   - Parameters: N=14 (16384), r=8, p=1, output=32 bytes
   - Random 16-byte salt per hash
   - Suitable for additional security requirements
   - Format: `scrypt:N:r:p:<salt>:<hash>`

**Note**: These parameters are designed for API keys which have high entropy. For password hashing, use stronger parameters (N=17+) or a dedicated password hashing library like `argon2`.

### Secret Key Handling

#### Minimum Length

Secret keys for signing must be at least 16 bytes (128 bits). Shorter keys will be rejected with an error.

```rust
// This will fail:
let key = SecretKey::from_string("short").unwrap_err();

// This is the minimum:
let key = SecretKey::from_string("1234567890123456").unwrap();
```

#### Debug Output Protection

`SecretKey` and `ApiKey` implement custom `Debug` that redacts sensitive values:

```rust
let key = SecretKey::from_string("super-secret-value-here").unwrap();
println!("{:?}", key);
// Output: SecretKey { len: 22, redacted: "[REDACTED]" }
```

### Token Types Security Properties

| Token Type | Security Properties | Use Case |
|------------|---------------------|----------|
| `AuthToken` | Random entropy, optional HMAC signature with expiration | Session tokens, password reset |
| `ApiKey` | Prefixed, hashable for storage | API authentication |
| `CsrfToken` | HMAC-signed, session-bound, expiring | CSRF protection |

### Threat Model

#### Protected Against

- **Timing attacks**: Constant-time comparison for all signature verification
- **Rainbow tables**: Scrypt uses per-hash random salts
- **Replay attacks**: CSRF tokens include timestamps and are session-bound
- **Key confusion**: Different token types have different formats
- **Entropy exhaustion**: Minimum 128-bit entropy enforced
- **Debug leakage**: Sensitive values redacted in debug output

#### Not Protected Against

- **Compromised secrets**: If your secret key is leaked, tokens can be forged
- **Side-channel attacks**: Beyond timing attacks (e.g., power analysis)
- **Memory dumps**: Secrets are not zeroized in memory (consider your threat model)

### Best Practices

#### Secret Key Management

1. **Generate strong keys**: Use at least 32 bytes (256 bits) of entropy
2. **Store securely**: Use environment variables or secret management systems
3. **Rotate regularly**: Implement key rotation for long-lived applications
4. **Never log**: Secret keys are redacted in debug output, but avoid logging them explicitly

```rust
// Good: Use a strong random key
let secret = SecretKey::new(generate_bytes(32)?);

// Bad: Using weak or predictable keys
let secret = SecretKey::from_string("password123").unwrap();
```

#### Token Storage

1. **API Keys**: Store only the hash, never the plaintext key
2. **Auth Tokens**: Can be stored in sessions or transmitted to clients
3. **CSRF Tokens**: Store in server-side session, validate on form submission

#### Token Lifecycle

1. **Generation**: Always use the minimum recommended length (32 bytes)
2. **Transmission**: Use HTTPS for all token transmission
3. **Validation**: Always verify tokens before trusting them
4. **Expiration**: Use appropriate expiration times for your use case

```rust
// Example: Short-lived CSRF token
let csrf = CsrfToken::generate(&secret, session_id, 32)?;
let claims = csrf.verify(&secret, session_id, 3600)?; // 1 hour max

// Example: API key with secure scrypt storage
let generated = ApiKey::builder()
    .key_type(ApiKeyType::Secret)
    .environment(Environment::Live)
    .length(32)
    .hash_algorithm(HashAlgorithm::Scrypt)
    .generate_with_hash()?;
```

### Reporting Security Vulnerabilities

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Email security concerns to the maintainers
3. Include detailed reproduction steps
4. Allow time for investigation and fix before disclosure

### Security Audit

This library was designed with security in mind, but has not undergone formal security audit. For critical applications, consider:

1. Independent security review
2. Fuzzing the cryptographic implementations
3. Integration testing in your specific threat model

### Dependencies

Key cryptographic dependencies:

| Crate | Version | Purpose |
|-------|---------|---------|
| `rand` | 0.10 | CSPRNG (SysRng) |
| `sha2` | 0.10 | SHA-256 hashing |
| `hmac` | 0.12 | HMAC signatures |
| `scrypt` | 0.11 | Key derivation |
| `subtle` | 2.5 | Constant-time comparison |

Keep dependencies updated to receive security fixes.
