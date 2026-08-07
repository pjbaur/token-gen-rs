//! Encoding utilities for token generation.
//!
//! Provides URL-safe Base64 and hexadecimal encoding with newtype wrappers
//! for type safety.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::fmt;
use std::str::FromStr;

/// Minimum entropy in bytes (128 bits).
pub const MIN_ENTROPY_BYTES: usize = 16;

/// URL-safe Base64 encoded string (no padding).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Base64Url(String);

impl Base64Url {
    /// Encode bytes to URL-safe Base64.
    pub fn encode(bytes: &[u8]) -> Self {
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    /// Decode to bytes.
    pub fn decode(&self) -> Result<Vec<u8>, base64::DecodeError> {
        URL_SAFE_NO_PAD.decode(&self.0)
    }

    /// Get the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Base64Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Base64Url {
    type Err = base64::DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Validate by decoding
        URL_SAFE_NO_PAD.decode(s)?;
        Ok(Self(s.to_string()))
    }
}

impl AsRef<str> for Base64Url {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Hexadecimal encoded string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Hex(String);

impl Hex {
    /// Encode bytes to hexadecimal.
    pub fn encode(bytes: &[u8]) -> Self {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            write!(s, "{:02x}", b).unwrap();
        }
        Self(s)
    }

    /// Decode to bytes.
    pub fn decode(&self) -> Result<Vec<u8>, String> {
        (0..self.0.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&self.0[i..i + 2], 16).map_err(|e| e.to_string()))
            .collect()
    }

    /// Get the inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Hex {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() % 2 != 0 {
            return Err("hex string must have even length".to_string());
        }
        // Validate by decoding
        let hex = Self(s.to_string());
        hex.decode()?;
        Ok(hex)
    }
}

impl AsRef<str> for Hex {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Output format for tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Format {
    /// URL-safe Base64 (no padding).
    #[default]
    Base64Url,
    /// Lowercase hexadecimal.
    Hex,
}

impl Format {
    /// Encode bytes using this format.
    pub fn encode(&self, bytes: &[u8]) -> String {
        match self {
            Format::Base64Url => Base64Url::encode(bytes).to_string(),
            Format::Hex => Hex::encode(bytes).to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_roundtrip() {
        let bytes = b"hello world";
        let encoded = Base64Url::encode(bytes);
        let decoded = encoded.decode().unwrap();
        assert_eq!(bytes.to_vec(), decoded);
    }

    #[test]
    fn hex_roundtrip() {
        let bytes = b"hello world";
        let encoded = Hex::encode(bytes);
        let decoded = encoded.decode().unwrap();
        assert_eq!(bytes.to_vec(), decoded);
    }

    #[test]
    fn format_encode_base64() {
        let bytes = b"test data";
        let encoded = Format::Base64Url.encode(bytes);
        assert!(encoded.contains('-') || !encoded.contains('+')); // URL-safe
    }

    #[test]
    fn format_encode_hex() {
        let bytes = b"\xff\x00";
        let encoded = Format::Hex.encode(bytes);
        assert_eq!(encoded, "ff00");
    }
}
