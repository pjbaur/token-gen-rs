//! Error types for token generation.
//!
//! This module defines the `TokenError` enum which represents all possible
//! errors that can occur during token operations.

use thiserror::Error;

/// Errors that can occur during token operations.
#[derive(Debug, Error)]
pub enum TokenError {
    #[error("insufficient entropy: requested {requested} bytes, minimum is {minimum}")]
    InsufficientEntropy { requested: usize, minimum: usize },

    #[error("token has expired")]
    Expired,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid format: {0}")]
    InvalidFormat(String),

    #[error("invalid length: {0}")]
    InvalidLength(String),

    #[error("cryptographic error: {0}")]
    CryptoError(String),

    #[error("parse error: {0}")]
    ParseError(String),
}
