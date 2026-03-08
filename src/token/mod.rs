//! Token generation types.
//!
//! This module contains the three main token types:
//! - [`AuthToken`] - Authentication tokens (simple or expiring)
//! - [`ApiKey`] - Prefixed API keys with hashing support
//! - [`CsrfToken`] - HMAC-signed CSRF tokens with session binding

mod api_key;
mod auth;
mod csrf;

pub use api_key::{ApiKey, ApiKeyBuilder, ApiKeyType, Environment, GeneratedApiKey, HashAlgorithm};
pub use auth::{AuthToken, AuthTokenBuilder};
pub use csrf::{CsrfClaims, CsrfToken, CsrfTokenBuilder, SecretKey};
