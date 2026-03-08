//! Auth token generation.
//!
//! Provides simple and expiring authentication tokens with builder pattern support.

use crate::crypto::{generate_bytes, generate_bytes_with_rng, constant_time_compare, TokenRng};
use crate::encoding::{Base64Url, Format};
use crate::error::TokenError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::csrf::SecretKey;

type HmacSha256 = Hmac<Sha256>;

/// Default token length in bytes.
const DEFAULT_LENGTH: usize = 32;

/// Authentication token.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthToken {
    /// The token string.
    inner: String,
    /// Whether this token is expiring (has timestamp/signature).
    expiring: bool,
}

impl AuthToken {
    /// Generate a new auth token.
    ///
    /// # Errors
    ///
    /// Returns an error if the length is less than 16 bytes or RNG fails.
    pub fn generate(length: usize, format: Format) -> Result<Self, TokenError> {
        let bytes = generate_bytes(length)?;
        let encoded = format.encode(&bytes);
        Ok(Self {
            inner: encoded,
            expiring: false,
        })
    }

    /// Generate a new auth token with a custom RNG.
    pub fn generate_with_rng<R: TokenRng>(
        rng: &mut R,
        length: usize,
        format: Format,
    ) -> Result<Self, TokenError> {
        let bytes = generate_bytes_with_rng(rng, length)?;
        let encoded = format.encode(&bytes);
        Ok(Self {
            inner: encoded,
            expiring: false,
        })
    }

    /// Create a builder for configuring token generation.
    pub fn builder() -> AuthTokenBuilder<'static> {
        AuthTokenBuilder::new()
    }

    /// Get the token as a string slice.
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Check if this token is an expiring token.
    pub fn is_expiring(&self) -> bool {
        self.expiring
    }

    /// Check if an expiring token has expired.
    ///
    /// For non-expiring tokens, this always returns `false`.
    ///
    /// # Errors
    ///
    /// Returns an error if the token format is invalid or time operations fail.
    pub fn is_expired(&self) -> Result<bool, TokenError> {
        if !self.expiring {
            return Ok(false);
        }

        let parts: Vec<&str> = self.inner.split('.').collect();
        if parts.len() != 3 {
            return Err(TokenError::InvalidFormat("expected 3 parts".to_string()));
        }

        // Decode timestamp
        let ts_bytes = Base64Url::from_str(parts[0])
            .map_err(|e| TokenError::ParseError(e.to_string()))?
            .decode()
            .map_err(|e| TokenError::ParseError(e.to_string()))?;

        if ts_bytes.len() != 8 {
            return Err(TokenError::InvalidFormat("invalid timestamp length".to_string()));
        }

        let timestamp = u64::from_be_bytes([
            ts_bytes[0], ts_bytes[1], ts_bytes[2], ts_bytes[3],
            ts_bytes[4], ts_bytes[5], ts_bytes[6], ts_bytes[7],
        ]);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| TokenError::CryptoError(e.to_string()))?
            .as_secs();

        Ok(now > timestamp)
    }

    /// Verify an expiring token against a secret key.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid, expired, or the signature doesn't match.
    pub fn verify(&self, secret: &SecretKey) -> Result<(), TokenError> {
        if !self.expiring {
            return Err(TokenError::InvalidFormat("token is not expiring".to_string()));
        }

        let parts: Vec<&str> = self.inner.split('.').collect();
        if parts.len() != 3 {
            return Err(TokenError::InvalidFormat("expected 3 parts".to_string()));
        }

        // Decode timestamp
        let ts_bytes = Base64Url::from_str(parts[0])
            .map_err(|e| TokenError::ParseError(e.to_string()))?
            .decode()
            .map_err(|e| TokenError::ParseError(e.to_string()))?;

        if ts_bytes.len() != 8 {
            return Err(TokenError::InvalidFormat("invalid timestamp".to_string()));
        }

        let timestamp = u64::from_be_bytes([
            ts_bytes[0], ts_bytes[1], ts_bytes[2], ts_bytes[3],
            ts_bytes[4], ts_bytes[5], ts_bytes[6], ts_bytes[7],
        ]);

        // Decode nonce
        let nonce = Base64Url::from_str(parts[1])
            .map_err(|e| TokenError::ParseError(e.to_string()))?
            .decode()
            .map_err(|e| TokenError::ParseError(e.to_string()))?;

        // Decode expected signature
        let expected_sig = Base64Url::from_str(parts[2])
            .map_err(|e| TokenError::ParseError(e.to_string()))?
            .decode()
            .map_err(|e| TokenError::ParseError(e.to_string()))?;

        // Compute actual signature
        let actual_sig = Self::compute_signature(secret, timestamp, &nonce)?;

        // Constant-time comparison
        if !constant_time_compare(&expected_sig, &actual_sig) {
            return Err(TokenError::InvalidSignature);
        }

        // Check expiry
        if self.is_expired()? {
            return Err(TokenError::Expired);
        }

        Ok(())
    }

    fn compute_signature(
        secret: &SecretKey,
        timestamp: u64,
        nonce: &[u8],
    ) -> Result<Vec<u8>, TokenError> {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| TokenError::CryptoError(e.to_string()))?;

        mac.update(&timestamp.to_be_bytes());
        mac.update(nonce);

        Ok(mac.finalize().into_bytes().to_vec())
    }
}

impl std::fmt::Display for AuthToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl AsRef<str> for AuthToken {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

impl FromStr for AuthToken {
    type Err = TokenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(TokenError::InvalidFormat("token cannot be empty".to_string()));
        }

        // Check if this looks like an expiring token (3 base64url parts)
        let parts: Vec<&str> = s.split('.').collect();
        let expiring = if parts.len() == 3 {
            // Validate that each part is valid base64url
            let valid = parts.iter().all(|p| Base64Url::from_str(p).is_ok());
            // Additional validation: first part should be 8 bytes when decoded (timestamp)
            if valid {
                if let Ok(ts) = Base64Url::from_str(parts[0]) {
                    if let Ok(decoded) = ts.decode() {
                        decoded.len() == 8
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        Ok(Self {
            inner: s.to_string(),
            expiring,
        })
    }
}

/// Builder for `AuthToken` generation.
///
/// # Example
///
/// ```
/// use token_gen::{AuthToken, SecretKey, Format};
/// use std::time::Duration;
///
/// let secret = SecretKey::from_string("my-secret-key-min-16-chars").unwrap();
/// let token = AuthToken::builder()
///     .length(32)
///     .format(Format::Base64Url)
///     .expires_in(Duration::from_secs(3600))
///     .secret_key(&secret)
///     .generate()
///     .unwrap();
///
/// assert!(token.is_expiring());
/// assert!(!token.is_expired().unwrap());
/// ```
#[derive(Debug)]
pub struct AuthTokenBuilder<'a> {
    length: usize,
    format: Format,
    expires_in: Option<Duration>,
    secret_key: Option<&'a SecretKey>,
}

impl<'a> AuthTokenBuilder<'a> {
    /// Create a new builder with default values.
    fn new() -> Self {
        Self {
            length: DEFAULT_LENGTH,
            format: Format::Base64Url,
            expires_in: None,
            secret_key: None,
        }
    }

    /// Set the token length in bytes.
    ///
    /// Minimum is 16 bytes (128 bits).
    pub fn length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }

    /// Set the output format.
    pub fn format(mut self, format: Format) -> Self {
        self.format = format;
        self
    }

    /// Set the expiration duration.
    ///
    /// When set, the token will include a timestamp and HMAC signature.
    pub fn expires_in(mut self, duration: Duration) -> Self {
        self.expires_in = Some(duration);
        self
    }

    /// Set the secret key for signing expiring tokens.
    ///
    /// Required when `expires_in` is set.
    pub fn secret_key(mut self, key: &'a SecretKey) -> Self {
        self.secret_key = Some(key);
        self
    }

    /// Generate the auth token.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Length is less than 16 bytes
    /// - `expires_in` is set but `secret_key` is not
    /// - RNG or cryptographic operations fail
    pub fn generate(self) -> Result<AuthToken, TokenError> {
        let bytes = generate_bytes(self.length)?;

        if let Some(duration) = self.expires_in {
            let secret = self.secret_key.ok_or_else(|| {
                TokenError::InvalidFormat("secret_key is required for expiring tokens".to_string())
            })?;

            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| TokenError::CryptoError(e.to_string()))?
                .as_secs()
                .checked_add(duration.as_secs())
                .ok_or_else(|| TokenError::CryptoError("timestamp overflow".to_string()))?;

            let signature = AuthToken::compute_signature(secret, timestamp, &bytes)?;

            let ts_encoded = Base64Url::encode(&timestamp.to_be_bytes());
            let nonce_encoded = Base64Url::encode(&bytes);
            let sig_encoded = Base64Url::encode(&signature);

            Ok(AuthToken {
                inner: format!("{}.{}.{}", ts_encoded, nonce_encoded, sig_encoded),
                expiring: true,
            })
        } else {
            let encoded = self.format.encode(&bytes);
            Ok(AuthToken {
                inner: encoded,
                expiring: false,
            })
        }
    }
}

impl Default for AuthTokenBuilder<'_> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_auth_token_base64() {
        let token = AuthToken::generate(32, Format::Base64Url).unwrap();
        assert!(!token.as_str().is_empty());
        assert!(!token.is_expiring());
        assert!(!token.is_expired().unwrap());
    }

    #[test]
    fn generate_auth_token_hex() {
        let token = AuthToken::generate(32, Format::Hex).unwrap();
        assert_eq!(token.as_str().len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn builder_simple_token() {
        let token = AuthToken::builder()
            .length(32)
            .format(Format::Hex)
            .generate()
            .unwrap();

        assert_eq!(token.as_str().len(), 64);
        assert!(!token.is_expiring());
    }

    #[test]
    fn builder_expiring_token() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let token = AuthToken::builder()
            .length(32)
            .format(Format::Base64Url)
            .expires_in(Duration::from_secs(3600))
            .secret_key(&secret)
            .generate()
            .unwrap();

        assert!(token.is_expiring());
        assert!(!token.is_expired().unwrap());

        // Token should have 3 parts
        let parts: Vec<&str> = token.as_str().split('.').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn builder_expiring_requires_secret() {
        let result = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .generate();

        assert!(result.is_err());
        assert!(matches!(result, Err(TokenError::InvalidFormat(_))));
    }

    #[test]
    fn verify_valid_token() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let token = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .secret_key(&secret)
            .generate()
            .unwrap();

        assert!(token.verify(&secret).is_ok());
    }

    #[test]
    fn verify_wrong_secret_fails() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let wrong_secret = SecretKey::from_string("wrong-secret-12345").unwrap();
        let token = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .secret_key(&secret)
            .generate()
            .unwrap();

        assert!(token.verify(&wrong_secret).is_err());
    }

    #[test]
    fn from_str_simple_token() {
        let token_str = "aBcDeFgHiJkLmNoPqRsTuVwXyZ123456";
        let token: AuthToken = token_str.parse().unwrap();

        assert_eq!(token.as_str(), token_str);
        assert!(!token.is_expiring());
    }

    #[test]
    fn from_str_expiring_token() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let original = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .secret_key(&secret)
            .generate()
            .unwrap();

        let parsed: AuthToken = original.as_str().parse().unwrap();
        assert!(parsed.is_expiring());
        assert_eq!(parsed.as_str(), original.as_str());
    }

    #[test]
    fn from_str_empty_fails() {
        let result: Result<AuthToken, _> = "".parse();
        assert!(result.is_err());
    }

    #[test]
    fn verify_non_expiring_token_fails() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let token = AuthToken::generate(32, Format::Base64Url).unwrap();

        // Non-expiring tokens can't be verified
        assert!(token.verify(&secret).is_err());
    }

    #[test]
    fn display_and_as_ref() {
        let token = AuthToken::generate(32, Format::Base64Url).unwrap();
        let display = format!("{}", token);
        let as_ref: &str = token.as_ref();

        assert_eq!(display, token.as_str());
        assert_eq!(as_ref, token.as_str());
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_generate_length(
            length in 16usize..128,
        ) {
            let token = AuthToken::generate(length, Format::Base64Url).unwrap();
            // Base64url encodes to ~1.33x the byte length
            let min_encoded_len = (length * 4) / 3;
            assert!(token.as_str().len() >= min_encoded_len);
        }

        #[test]
        fn prop_unique_tokens(
            length in 16usize..64,
        ) {
            let token1 = AuthToken::generate(length, Format::Base64Url).unwrap();
            let token2 = AuthToken::generate(length, Format::Base64Url).unwrap();
            prop_assert_ne!(token1, token2);
        }

        #[test]
        fn prop_hex_length(
            length in 16usize..64,
        ) {
            let token = AuthToken::generate(length, Format::Hex).unwrap();
            // Hex encoding doubles the length
            prop_assert_eq!(token.as_str().len(), length * 2);
        }

        #[test]
        fn prop_from_str_roundtrip(s in "[a-zA-Z0-9]{16,64}") {
            let token: AuthToken = s.parse().unwrap();
            prop_assert_eq!(token.as_str(), s);
            prop_assert!(!token.is_expiring());
        }

        #[test]
        fn prop_builder_expiring_format(
            length in 16usize..64,
            expires_secs in 60u64..86400,
            key in "[a-zA-Z0-9]{16,32}",
        ) {
            let secret = SecretKey::from_string(&key).expect("key should be valid");
            let token = AuthToken::builder()
                .length(length)
                .expires_in(Duration::from_secs(expires_secs))
                .secret_key(&secret)
                .generate()
                .unwrap();

            // Should have 3 parts
            let parts: Vec<&str> = token.as_str().split('.').collect();
            prop_assert_eq!(parts.len(), 3);
            prop_assert!(token.is_expiring());
            prop_assert!(!token.is_expired().unwrap());
        }

        #[test]
        fn prop_verify_roundtrip(
            length in 16usize..64,
            expires_secs in 60u64..86400,
            key in "[a-zA-Z0-9]{16,32}",
        ) {
            let secret = SecretKey::from_string(&key).expect("key should be valid");
            let token = AuthToken::builder()
                .length(length)
                .expires_in(Duration::from_secs(expires_secs))
                .secret_key(&secret)
                .generate()
                .unwrap();

            let parsed: AuthToken = token.as_str().parse().unwrap();
            prop_assert!(parsed.verify(&secret).is_ok());
        }
    }
}
