//! # token-gen
//!
//! A cryptographically secure, type-safe token generation library for Rust.
//!
//! ## Overview
//!
//! `token-gen` provides three distinct token types for common authentication and security use cases:
//!
//! - **[`AuthToken`]**: Simple or expiring tokens for authentication flows (password reset, email verification, session tokens)
//! - **[`ApiKey`]**: Prefixed API keys with optional SHA-256 or scrypt hashing for secure database storage
//! - **[`CsrfToken`]**: HMAC-signed tokens bound to session IDs for CSRF protection
//!
//! Each token type uses the builder pattern for configuration and provides type-safe operations.
//!
//! ## Feature Flags
//!
//! | Flag | Description |
//! |------|-------------|
//! | `cli` | Enables the `token-gen` command-line binary |
//!
//! ## Quick Examples
//!
//! ### Simple Auth Token
//!
//! ```rust
//! use token_gen::{AuthToken, Format};
//!
//! // Generate a 32-byte token encoded as base64url
//! let token = AuthToken::generate(32, Format::Base64Url)?;
//! println!("Token: {}", token);
//! # Ok::<(), token_gen::TokenError>(())
//! ```
//!
//! ### Expiring Auth Token
//!
//! ```rust
//! use token_gen::{AuthToken, SecretKey, Format};
//! use std::time::Duration;
//!
//! let secret = SecretKey::from_string("your-secret-key-min-16-chars")?;
//! let token = AuthToken::builder()
//!     .length(32)
//!     .expires_in(Duration::from_secs(3600)) // 1 hour
//!     .secret_key(&secret)
//!     .generate()?;
//!
//! // Later, verify the token
//! token.verify(&secret)?;
//! assert!(!token.is_expired()?);
//! # Ok::<(), token_gen::TokenError>(())
//! ```
//!
//! ### API Key with Hash for Storage
//!
//! ```rust
//! use token_gen::{ApiKey, ApiKeyType, Environment};
//!
//! // Generate a live API key
//! let generated = ApiKey::builder()
//!     .key_type(ApiKeyType::Api)
//!     .environment(Environment::Live)
//!     .generate_with_hash()?;
//!
//! println!("Key (give to user): {}", generated.key);
//! println!("Hash (store in DB): {}", generated.key_hash);
//!
//! // Verify later
//! assert!(generated.verify());
//! # Ok::<(), token_gen::TokenError>(())
//! ```
//!
//! ### CSRF Token
//!
//! ```rust
//! use token_gen::{CsrfToken, SecretKey};
//!
//! let secret = SecretKey::from_string("your-secret-key-min-16-chars")?;
//! let session_id = "user-session-123";
//!
//! // Generate token for form
//! let token = CsrfToken::generate(&secret, session_id, 32)?;
//!
//! // Verify submitted token
//! let claims = token.verify(&secret, session_id, 3600)?;
//! println!("Token age: {:?}", claims.age);
//! # Ok::<(), token_gen::TokenError>(())
//! ```
//!
//! ## Security
//!
//! - Uses [`rand::rngs::OsRng`] for cryptographically secure random number generation
//! - Constant-time comparison for signature verification via the [`subtle`] crate
//! - HMAC-SHA256 signatures for expiring tokens
//! - Configurable scrypt parameters for API key hashing
//!
//! ## Minimum Entropy
//!
//! All token types enforce a minimum of 16 bytes (128 bits) of entropy to ensure cryptographic security.

pub mod crypto;
pub mod encoding;
pub mod error;
pub mod token;

pub use crypto::{TokenRng, SystemRng, MIN_ENTROPY_BYTES};
pub use encoding::{Base64Url, Format, Hex};
pub use error::TokenError;
pub use token::{
    ApiKey, ApiKeyBuilder, ApiKeyType, AuthToken, AuthTokenBuilder, CsrfClaims, CsrfToken,
    CsrfTokenBuilder, Environment, GeneratedApiKey, HashAlgorithm, SecretKey,
};
