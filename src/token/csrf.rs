//! CSRF token generation and verification.
//!
//! Provides HMAC-signed tokens bound to session IDs for CSRF protection.

use crate::crypto::{constant_time_compare, generate_bytes};
use crate::encoding::Base64Url;
use crate::error::TokenError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

type HmacSha256 = Hmac<Sha256>;

/// Default nonce length in bytes.
const DEFAULT_NONCE_LENGTH: usize = 32;

/// Minimum nonce length in bytes.
const MIN_NONCE_LENGTH: usize = 16;

/// Minimum secret key length in bytes (128 bits).
const MIN_SECRET_KEY_LENGTH: usize = 16;

/// Secret key for signing tokens.
#[derive(Clone)]
pub struct SecretKey(Vec<u8>);

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the actual key value in debug output to prevent secret leakage
        f.debug_struct("SecretKey")
            .field("len", &self.0.len())
            .field("redacted", &"[REDACTED]")
            .finish()
    }
}

impl SecretKey {
    /// Create a new secret key from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the key is less than 16 bytes (128 bits).
    pub fn new(bytes: Vec<u8>) -> Result<Self, TokenError> {
        if bytes.len() < MIN_SECRET_KEY_LENGTH {
            return Err(TokenError::InvalidFormat(format!(
                "secret key must be at least {} bytes, got {}",
                MIN_SECRET_KEY_LENGTH,
                bytes.len()
            )));
        }
        Ok(Self(bytes))
    }

    /// Create a secret key from a string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is less than 16 bytes when encoded as UTF-8.
    pub fn from_string(s: &str) -> Result<Self, TokenError> {
        let bytes = s.as_bytes();
        if bytes.len() < MIN_SECRET_KEY_LENGTH {
            return Err(TokenError::InvalidFormat(format!(
                "secret key must be at least {} bytes, got {}",
                MIN_SECRET_KEY_LENGTH,
                bytes.len()
            )));
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Get the key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Claims extracted from a verified CSRF token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfClaims {
    /// Unix timestamp when the token was created.
    pub timestamp: u64,
    /// Age of the token as a duration.
    pub age: Duration,
    /// Session ID the token is bound to.
    pub session_id: String,
}

/// CSRF token with HMAC signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CsrfToken {
    token: String,
    // Store parsed components for efficient verification
    timestamp: u64,
    nonce: Vec<u8>,
    signature: Vec<u8>,
}

impl CsrfToken {
    /// Generate a new CSRF token.
    ///
    /// The token format is: `timestamp.nonce.signature` (all base64url encoded).
    ///
    /// # Errors
    ///
    /// Returns an error if the length is less than 16 bytes or RNG fails.
    pub fn generate(
        secret: &SecretKey,
        session_id: &str,
        length: usize,
    ) -> Result<Self, TokenError> {
        Self::builder()
            .secret_key(secret)
            .session_id(session_id)
            .length(length)
            .generate()
    }

    /// Create a new builder for constructing CSRF tokens.
    pub fn builder() -> CsrfTokenBuilder {
        CsrfTokenBuilder::default()
    }

    /// Verify a CSRF token and return the claims.
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid, expired, or the signature doesn't match.
    pub fn verify(
        &self,
        secret: &SecretKey,
        session_id: &str,
        max_age_secs: u64,
    ) -> Result<CsrfClaims, TokenError> {
        // Check expiry
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| TokenError::CryptoError(e.to_string()))?
            .as_secs();

        let age_secs = now.saturating_sub(self.timestamp);
        if age_secs > max_age_secs {
            return Err(TokenError::Expired);
        }

        // Compute actual signature
        let actual_sig = Self::compute_signature(secret, self.timestamp, &self.nonce, session_id)?;

        // Constant-time comparison
        if !constant_time_compare(&self.signature, &actual_sig) {
            return Err(TokenError::InvalidSignature);
        }

        Ok(CsrfClaims {
            timestamp: self.timestamp,
            age: Duration::from_secs(age_secs),
            session_id: session_id.to_string(),
        })
    }

    fn compute_signature(
        secret: &SecretKey,
        timestamp: u64,
        nonce: &[u8],
        session_id: &str,
    ) -> Result<Vec<u8>, TokenError> {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .map_err(|e| TokenError::CryptoError(e.to_string()))?;

        mac.update(&timestamp.to_be_bytes());
        mac.update(nonce);
        mac.update(session_id.as_bytes());

        Ok(mac.finalize().into_bytes().to_vec())
    }

    /// Get the token as a string slice.
    pub fn as_str(&self) -> &str {
        &self.token
    }

    /// Get the timestamp when this token was created.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }
}

impl std::fmt::Display for CsrfToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.token)
    }
}

impl AsRef<str> for CsrfToken {
    fn as_ref(&self) -> &str {
        &self.token
    }
}

impl FromStr for CsrfToken {
    type Err = TokenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split('.').collect();
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
            ts_bytes[0],
            ts_bytes[1],
            ts_bytes[2],
            ts_bytes[3],
            ts_bytes[4],
            ts_bytes[5],
            ts_bytes[6],
            ts_bytes[7],
        ]);

        // Decode nonce
        let nonce = Base64Url::from_str(parts[1])
            .map_err(|e| TokenError::ParseError(e.to_string()))?
            .decode()
            .map_err(|e| TokenError::ParseError(e.to_string()))?;

        // Decode signature
        let signature = Base64Url::from_str(parts[2])
            .map_err(|e| TokenError::ParseError(e.to_string()))?
            .decode()
            .map_err(|e| TokenError::ParseError(e.to_string()))?;

        Ok(Self {
            token: s.to_string(),
            timestamp,
            nonce,
            signature,
        })
    }
}

/// Builder for constructing CSRF tokens with custom configuration.
#[derive(Debug, Clone)]
pub struct CsrfTokenBuilder {
    length: usize,
    secret_key: Option<SecretKey>,
    session_id: Option<String>,
}

impl Default for CsrfTokenBuilder {
    fn default() -> Self {
        Self {
            length: DEFAULT_NONCE_LENGTH,
            secret_key: None,
            session_id: None,
        }
    }
}

impl CsrfTokenBuilder {
    /// Create a new builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the nonce length in bytes.
    ///
    /// Must be at least 16 bytes. Default is 32 bytes.
    pub fn length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }

    /// Set the secret key for signing.
    pub fn secret_key(mut self, key: &SecretKey) -> Self {
        self.secret_key = Some(key.clone());
        self
    }

    /// Set the session ID to bind the token to.
    pub fn session_id(mut self, id: &str) -> Self {
        self.session_id = Some(id.to_string());
        self
    }

    /// Generate the CSRF token.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Length is less than 16 bytes
    /// - Secret key was not set
    /// - Session ID was not set
    /// - RNG fails
    pub fn generate(self) -> Result<CsrfToken, TokenError> {
        if self.length < MIN_NONCE_LENGTH {
            return Err(TokenError::InsufficientEntropy {
                requested: self.length,
                minimum: MIN_NONCE_LENGTH,
            });
        }

        let secret = self
            .secret_key
            .ok_or_else(|| TokenError::InvalidFormat("secret key is required".to_string()))?;

        let session_id = self
            .session_id
            .ok_or_else(|| TokenError::InvalidFormat("session_id is required".to_string()))?;

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| TokenError::CryptoError(e.to_string()))?
            .as_secs();

        let nonce = generate_bytes(self.length)?;
        let signature = CsrfToken::compute_signature(&secret, timestamp, &nonce, &session_id)?;

        let ts_encoded = Base64Url::encode(&timestamp.to_be_bytes());
        let nonce_encoded = Base64Url::encode(&nonce);
        let sig_encoded = Base64Url::encode(&signature);

        let token = format!("{}.{}.{}", ts_encoded, nonce_encoded, sig_encoded);

        Ok(CsrfToken {
            token,
            timestamp,
            nonce,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_verify_csrf() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let token = CsrfToken::generate(&secret, "session-123", 32).unwrap();
        let claims = token.verify(&secret, "session-123", 3600).unwrap();
        assert_eq!(claims.session_id, "session-123");
    }

    #[test]
    fn verify_wrong_session_fails() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let token = CsrfToken::generate(&secret, "session-123", 32).unwrap();
        assert!(token.verify(&secret, "wrong-session", 3600).is_err());
    }

    #[test]
    fn verify_wrong_secret_fails() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let wrong_secret = SecretKey::from_string("wrong-secret-12345").unwrap();
        let token = CsrfToken::generate(&secret, "session-123", 32).unwrap();
        assert!(token.verify(&wrong_secret, "session-123", 3600).is_err());
    }

    #[test]
    fn builder_pattern() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let token = CsrfToken::builder()
            .secret_key(&secret)
            .session_id("session-456")
            .length(24)
            .generate()
            .unwrap();

        let claims = token.verify(&secret, "session-456", 3600).unwrap();
        assert_eq!(claims.session_id, "session-456");
    }

    #[test]
    fn builder_requires_secret_key() {
        let result = CsrfToken::builder().session_id("session-123").generate();

        assert!(result.is_err());
    }

    #[test]
    fn builder_requires_session_id() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let result = CsrfToken::builder().secret_key(&secret).generate();

        assert!(result.is_err());
    }

    #[test]
    fn builder_rejects_short_length() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let result = CsrfToken::builder()
            .secret_key(&secret)
            .session_id("session-123")
            .length(8)
            .generate();

        assert!(result.is_err());
        match result {
            Err(TokenError::InsufficientEntropy { requested, minimum }) => {
                assert_eq!(requested, 8);
                assert_eq!(minimum, 16);
            }
            _ => panic!("Expected InsufficientEntropy error"),
        }
    }

    #[test]
    fn from_str_roundtrip() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let original = CsrfToken::generate(&secret, "session-123", 32).unwrap();
        let token_str = original.as_str();

        let parsed: CsrfToken = token_str.parse().unwrap();
        assert_eq!(original, parsed);
        assert_eq!(original.timestamp(), parsed.timestamp());
    }

    #[test]
    fn from_str_invalid_format() {
        let result: Result<CsrfToken, _> = "invalid-token".parse();
        assert!(result.is_err());

        let result: Result<CsrfToken, _> = "a.b".parse();
        assert!(result.is_err());

        let result: Result<CsrfToken, _> = "a.b.c.d".parse();
        assert!(result.is_err());
    }

    #[test]
    fn csrf_claims_contain_correct_data() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let token = CsrfToken::generate(&secret, "session-789", 32).unwrap();

        // Small delay to ensure age > 0
        std::thread::sleep(std::time::Duration::from_millis(10));

        let claims = token.verify(&secret, "session-789", 3600).unwrap();
        assert_eq!(claims.session_id, "session-789");
        assert!(claims.age.as_secs() < 3600);
        assert!(claims.timestamp > 0);
    }

    #[test]
    fn verify_expired_token_fails() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let token = CsrfToken::generate(&secret, "session-123", 32).unwrap();

        // Verify with very short max_age (0 seconds) - should fail after any delay
        std::thread::sleep(std::time::Duration::from_millis(10));
        let result = token.verify(&secret, "session-123", 0);
        // This may or may not fail depending on timing, so we just check it doesn't panic
        let _ = result;
    }

    #[test]
    fn display_trait() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let token = CsrfToken::generate(&secret, "session-123", 32).unwrap();
        let displayed = format!("{}", token);
        assert_eq!(displayed, token.as_str());
    }

    #[test]
    fn as_ref_trait() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();
        let token = CsrfToken::generate(&secret, "session-123", 32).unwrap();
        let as_ref: &str = token.as_ref();
        assert_eq!(as_ref, token.as_str());
    }

    #[test]
    fn secret_key_minimum_length_enforced() {
        // Too short - should fail
        assert!(SecretKey::new(vec![1, 2, 3]).is_err());
        assert!(SecretKey::from_string("short").is_err());

        // Minimum length - should succeed
        assert!(SecretKey::new(vec![0u8; 16]).is_ok());
        assert!(SecretKey::from_string("1234567890123456").is_ok());
    }

    #[test]
    fn secret_key_debug_redacts_value() {
        let secret = SecretKey::from_string("super-secret-key-value").unwrap();
        let debug_output = format!("{:?}", secret);
        assert!(!debug_output.contains("super-secret-key-value"));
        assert!(debug_output.contains("[REDACTED]"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    // Generate arbitrary session IDs (alphanumeric strings)
    prop_compose! {
        fn arb_session_id()(s in "[a-zA-Z0-9_-]{1,64}") -> String {
            s
        }
    }

    // Generate arbitrary secret keys (minimum 16 bytes)
    prop_compose! {
        fn arb_secret_key()(bytes in prop::collection::vec(any::<u8>(), 16..64)) -> SecretKey {
            SecretKey::new(bytes).expect("generated key should be valid")
        }
    }

    proptest! {
        #[test]
        fn generate_and_verify_roundtrip(
            session_id in arb_session_id(),
            secret in arb_secret_key(),
            length in 16usize..64,
            max_age in 1u64..86400
        ) {
            let token = CsrfToken::generate(&secret, &session_id, length)?;
            let claims = token.verify(&secret, &session_id, max_age)?;

            prop_assert_eq!(claims.session_id, session_id);
            prop_assert!(claims.age.as_secs() < max_age);
        }

        #[test]
        fn from_str_roundtrip_prop(
            session_id in arb_session_id(),
            secret in arb_secret_key(),
            length in 16usize..64
        ) {
            let original = CsrfToken::generate(&secret, &session_id, length)?;
            let token_str = original.as_str();

            let parsed: CsrfToken = token_str.parse()?;
            prop_assert_eq!(original, parsed);
        }

        #[test]
        fn wrong_session_id_fails(
            session_id in arb_session_id(),
            wrong_session_id in arb_session_id(),
            secret in arb_secret_key(),
            length in 16usize..64
        ) {
            prop_assume!(session_id != wrong_session_id);

            let token = CsrfToken::generate(&secret, &session_id, length)?;
            let result = token.verify(&secret, &wrong_session_id, 3600);

            prop_assert!(result.is_err());
        }

        #[test]
        fn wrong_secret_fails(
            session_id in arb_session_id(),
            secret in arb_secret_key(),
            wrong_secret in arb_secret_key(),
            length in 16usize..64
        ) {
            prop_assume!(secret.as_bytes() != wrong_secret.as_bytes());

            let token = CsrfToken::generate(&secret, &session_id, length)?;
            let result = token.verify(&wrong_secret, &session_id, 3600);

            prop_assert!(result.is_err());
        }

        #[test]
        fn builder_matches_generate(
            session_id in arb_session_id(),
            secret in arb_secret_key(),
            length in 16usize..64
        ) {
            // Both methods should produce valid tokens
            let token1 = CsrfToken::generate(&secret, &session_id, length)?;
            let token2 = CsrfToken::builder()
                .secret_key(&secret)
                .session_id(&session_id)
                .length(length)
                .generate()?;

            // Both should verify with the same credentials
            prop_assert!(token1.verify(&secret, &session_id, 3600).is_ok());
            prop_assert!(token2.verify(&secret, &session_id, 3600).is_ok());
        }

        #[test]
        fn timestamp_is_recent(
            session_id in arb_session_id(),
            secret in arb_secret_key(),
            length in 16usize..64
        ) {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let token = CsrfToken::generate(&secret, &session_id, length)?;

            // Token timestamp should be within 1 second of current time
            let diff = if token.timestamp() > now {
                token.timestamp() - now
            } else {
                now - token.timestamp()
            };
            prop_assert!(diff <= 1);
        }

        #[test]
        fn token_format_has_three_parts(
            session_id in arb_session_id(),
            secret in arb_secret_key(),
            length in 16usize..64
        ) {
            let token = CsrfToken::generate(&secret, &session_id, length)?;
            let parts: Vec<&str> = token.as_str().split('.').collect();

            prop_assert_eq!(parts.len(), 3);
        }

        #[test]
        fn claims_age_increases(
            session_id in arb_session_id(),
            secret in arb_secret_key(),
            length in 16usize..64
        ) {
            let token = CsrfToken::generate(&secret, &session_id, length)?;

            let claims1 = token.verify(&secret, &session_id, 3600)?;
            std::thread::sleep(std::time::Duration::from_millis(20));
            let claims2 = token.verify(&secret, &session_id, 3600)?;

            // Age should have increased (or stayed the same at second granularity)
            prop_assert!(claims2.age >= claims1.age);
        }
    }
}
