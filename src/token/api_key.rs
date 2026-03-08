//! API key generation and hashing.
//!
//! Provides prefixed API keys (e.g., `api_live_xxx`) with optional
//! SHA-256 or scrypt hashing for secure storage.

use crate::crypto::{constant_time_compare, generate_bytes};
use crate::encoding::Base64Url;
use crate::error::TokenError;
use scrypt::{scrypt, Params};
use sha2::{Digest, Sha256};
use std::fmt;

/// API key type prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ApiKeyType {
    /// Standard API key.
    #[default]
    Api,
    /// Secret key.
    Secret,
    /// Public key.
    Public,
}

impl ApiKeyType {
    /// Get the prefix string for this key type.
    pub fn prefix(&self) -> &'static str {
        match self {
            ApiKeyType::Api => "api",
            ApiKeyType::Secret => "sk",
            ApiKeyType::Public => "pk",
        }
    }
}

/// Environment for API keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Environment {
    /// Live/production environment.
    #[default]
    Live,
    /// Test environment.
    Test,
    /// Staging environment.
    Staging,
}

impl Environment {
    /// Get the prefix string for this environment.
    pub fn prefix(&self) -> &'static str {
        match self {
            Environment::Live => "live",
            Environment::Test => "test",
            Environment::Staging => "staging",
        }
    }
}

/// Hash algorithm for API key storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HashAlgorithm {
    /// SHA-256 hash (fast, suitable for most use cases).
    #[default]
    Sha256,
    /// Scrypt key derivation function (slower, more resistant to brute-force).
    Scrypt,
}

/// API key with prefix.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct ApiKey(String);

impl std::fmt::Debug for ApiKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the actual key value in debug output to prevent secret leakage
        f.debug_struct("ApiKey")
            .field("prefix", &self.key_type().map(|t| t.prefix()).unwrap_or("unknown"))
            .field("redacted", &"[REDACTED]")
            .finish()
    }
}

impl ApiKey {
    /// Generate a new API key.
    ///
    /// # Errors
    ///
    /// Returns an error if the length is less than 16 bytes or RNG fails.
    pub fn generate(
        key_type: ApiKeyType,
        environment: Environment,
        length: usize,
    ) -> Result<Self, TokenError> {
        let bytes = generate_bytes(length)?;
        let encoded = Base64Url::encode(&bytes);
        let key = format!("{}_{}_{}", key_type.prefix(), environment.prefix(), encoded);
        Ok(Self(key))
    }

    /// Create a builder for constructing API keys with custom options.
    pub fn builder() -> ApiKeyBuilder {
        ApiKeyBuilder::new()
    }

    /// Get the key as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hash this key using the specified algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if scrypt hashing fails.
    pub fn hash(&self, algorithm: HashAlgorithm) -> Result<String, TokenError> {
        match algorithm {
            HashAlgorithm::Sha256 => Ok(self.hash_sha256()),
            HashAlgorithm::Scrypt => self.hash_scrypt(),
        }
    }

    /// Hash this key using SHA-256.
    pub fn hash_sha256(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.0.as_bytes());
        let hash = hasher.finalize();
        format!("sha256:{}", hex::encode(hash))
    }

    /// Hash this key using scrypt.
    ///
    /// Uses parameters N=14 (16384 iterations), r=8, p=1, output=32 bytes.
    /// These parameters are suitable for API keys which have high entropy (128+ bits).
    /// For password hashing, consider using stronger parameters (N=17+).
    ///
    /// # Errors
    ///
    /// Returns an error if scrypt parameter creation or hashing fails.
    pub fn hash_scrypt(&self) -> Result<String, TokenError> {
        let params =
            Params::new(14, 8, 1, 32).map_err(|e| TokenError::CryptoError(e.to_string()))?;
        // Use CSPRNG (generate_bytes) for salt generation
        let salt_bytes = generate_bytes(16)?;
        let salt: [u8; 16] = salt_bytes.try_into().map_err(|_| {
            TokenError::CryptoError("failed to create salt array".to_string())
        })?;
        let mut derived = [0u8; 32];
        scrypt(self.0.as_bytes(), &salt, &params, &mut derived)
            .map_err(|e| TokenError::CryptoError(e.to_string()))?;
        Ok(format!(
            "scrypt:14:8:1:{}:{}",
            hex::encode(salt),
            hex::encode(derived)
        ))
    }

    /// Verify this key against a stored hash.
    pub fn verify(&self, stored_hash: &str) -> bool {
        if let Some(_hash_part) = stored_hash.strip_prefix("sha256:") {
            let expected = self.hash_sha256();
            constant_time_compare(expected.as_bytes(), stored_hash.as_bytes())
        } else if let Some(hash_part) = stored_hash.strip_prefix("scrypt:") {
            self.verify_scrypt(hash_part)
        } else {
            false
        }
    }

    fn verify_scrypt(&self, hash_part: &str) -> bool {
        let parts: Vec<&str> = hash_part.split(':').collect();
        if parts.len() != 5 {
            return false;
        }

        // Parse scrypt parameters
        let n: u8 = match parts[0].parse() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let r: u32 = match parts[1].parse() {
            Ok(v) => v,
            Err(_) => return false,
        };
        let p: u32 = match parts[2].parse() {
            Ok(v) => v,
            Err(_) => return false,
        };

        // Decode salt and expected hash
        let salt = match hex::decode(parts[3]) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let expected = match hex::decode(parts[4]) {
            Ok(h) => h,
            Err(_) => return false,
        };

        // Create params with output length matching expected hash length
        let params = match Params::new(n, r, p, expected.len()) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Derive key and compare
        let mut derived = vec![0u8; expected.len()];
        if scrypt(self.0.as_bytes(), &salt, &params, &mut derived).is_err() {
            return false;
        }

        constant_time_compare(&derived, &expected)
    }

    /// Get the key type from the prefix.
    pub fn key_type(&self) -> Option<ApiKeyType> {
        let prefix = self.0.split('_').next()?;
        match prefix {
            "api" => Some(ApiKeyType::Api),
            "sk" => Some(ApiKeyType::Secret),
            "pk" => Some(ApiKeyType::Public),
            _ => None,
        }
    }

    /// Get the environment from the prefix.
    pub fn environment(&self) -> Option<Environment> {
        let mut parts = self.0.split('_');
        parts.next()?; // Skip key type
        let env = parts.next()?;
        match env {
            "live" => Some(Environment::Live),
            "test" => Some(Environment::Test),
            "staging" => Some(Environment::Staging),
            _ => None,
        }
    }
}

impl fmt::Display for ApiKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for ApiKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for ApiKey {
    type Err = TokenError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(TokenError::InvalidFormat("API key cannot be empty".to_string()));
        }
        Ok(Self(s.to_string()))
    }
}

/// Builder for constructing API keys with custom options.
#[derive(Debug, Clone)]
pub struct ApiKeyBuilder {
    key_type: ApiKeyType,
    environment: Environment,
    length: usize,
    hash_algorithm: Option<HashAlgorithm>,
}

impl Default for ApiKeyBuilder {
    fn default() -> Self {
        Self {
            key_type: ApiKeyType::default(),
            environment: Environment::default(),
            length: 32,
            hash_algorithm: None,
        }
    }
}

impl ApiKeyBuilder {
    /// Create a new builder with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the key type.
    pub fn key_type(mut self, key_type: ApiKeyType) -> Self {
        self.key_type = key_type;
        self
    }

    /// Set the environment.
    pub fn environment(mut self, environment: Environment) -> Self {
        self.environment = environment;
        self
    }

    /// Set the key length in bytes.
    pub fn length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }

    /// Set the hash algorithm for generating a `GeneratedApiKey`.
    pub fn hash_algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.hash_algorithm = Some(algorithm);
        self
    }

    /// Generate the API key.
    ///
    /// # Errors
    ///
    /// Returns an error if the length is less than 16 bytes or RNG fails.
    pub fn generate(self) -> Result<ApiKey, TokenError> {
        ApiKey::generate(self.key_type, self.environment, self.length)
    }

    /// Generate the API key with its hash.
    ///
    /// # Errors
    ///
    /// Returns an error if the length is less than 16 bytes, RNG fails,
    /// or hashing fails (for scrypt).
    pub fn generate_with_hash(self) -> Result<GeneratedApiKey, TokenError> {
        let key = ApiKey::generate(self.key_type, self.environment, self.length)?;
        let key_hash = match self.hash_algorithm {
            Some(algorithm) => key.hash(algorithm)?,
            None => key.hash_sha256(),
        };
        Ok(GeneratedApiKey { key, key_hash })
    }
}

/// Generated API key with its hash.
#[derive(Debug, Clone)]
pub struct GeneratedApiKey {
    /// The generated key.
    pub key: ApiKey,
    /// The hash for storage.
    pub key_hash: String,
}

impl GeneratedApiKey {
    /// Generate a new API key with SHA-256 hash.
    ///
    /// # Errors
    ///
    /// Returns an error if the length is less than 16 bytes or RNG fails.
    pub fn generate_sha256(
        key_type: ApiKeyType,
        environment: Environment,
        length: usize,
    ) -> Result<Self, TokenError> {
        let key = ApiKey::generate(key_type, environment, length)?;
        let key_hash = key.hash_sha256();
        Ok(Self { key, key_hash })
    }

    /// Generate a new API key with scrypt hash.
    ///
    /// # Errors
    ///
    /// Returns an error if the length is less than 16 bytes, RNG fails,
    /// or scrypt hashing fails.
    pub fn generate_scrypt(
        key_type: ApiKeyType,
        environment: Environment,
        length: usize,
    ) -> Result<Self, TokenError> {
        let key = ApiKey::generate(key_type, environment, length)?;
        let key_hash = key.hash_scrypt()?;
        Ok(Self { key, key_hash })
    }

    /// Verify the key against the stored hash.
    pub fn verify(&self) -> bool {
        self.key.verify(&self.key_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_api_key() {
        let key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();
        assert!(key.as_str().starts_with("api_live_"));
        assert_eq!(key.key_type(), Some(ApiKeyType::Api));
        assert_eq!(key.environment(), Some(Environment::Live));
    }

    #[test]
    fn generate_all_key_types() {
        for (key_type, prefix) in [
            (ApiKeyType::Api, "api"),
            (ApiKeyType::Secret, "sk"),
            (ApiKeyType::Public, "pk"),
        ] {
            let key = ApiKey::generate(key_type, Environment::Live, 32).unwrap();
            assert!(key.as_str().starts_with(&format!("{}_live_", prefix)));
            assert_eq!(key.key_type(), Some(key_type));
        }
    }

    #[test]
    fn generate_all_environments() {
        for (env, prefix) in [
            (Environment::Live, "live"),
            (Environment::Test, "test"),
            (Environment::Staging, "staging"),
        ] {
            let key = ApiKey::generate(ApiKeyType::Api, env, 32).unwrap();
            assert!(key.as_str().starts_with(&format!("api_{}_", prefix)));
            assert_eq!(key.environment(), Some(env));
        }
    }

    #[test]
    fn hash_and_verify_sha256() {
        let key = ApiKey::generate(ApiKeyType::Api, Environment::Test, 32).unwrap();
        let hash = key.hash_sha256();
        assert!(hash.starts_with("sha256:"));
        assert!(key.verify(&hash));
    }

    #[test]
    fn hash_and_verify_scrypt() {
        let key = ApiKey::generate(ApiKeyType::Api, Environment::Test, 32).unwrap();
        let hash = key.hash_scrypt().unwrap();
        assert!(hash.starts_with("scrypt:"));
        assert!(key.verify(&hash));
    }

    #[test]
    fn hash_using_enum_sha256() {
        let key = ApiKey::generate(ApiKeyType::Api, Environment::Test, 32).unwrap();
        let hash = key.hash(HashAlgorithm::Sha256).unwrap();
        assert!(hash.starts_with("sha256:"));
        assert!(key.verify(&hash));
    }

    #[test]
    fn hash_using_enum_scrypt() {
        let key = ApiKey::generate(ApiKeyType::Api, Environment::Test, 32).unwrap();
        let hash = key.hash(HashAlgorithm::Scrypt).unwrap();
        assert!(hash.starts_with("scrypt:"));
        assert!(key.verify(&hash));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let key1 = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();
        let key2 = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();

        // SHA-256
        let hash_sha = key1.hash_sha256();
        assert!(!key2.verify(&hash_sha));

        // Scrypt
        let hash_scrypt = key1.hash_scrypt().unwrap();
        assert!(!key2.verify(&hash_scrypt));
    }

    #[test]
    fn verify_invalid_format_fails() {
        let key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();
        assert!(!key.verify("invalid_hash"));
        assert!(!key.verify("sha256:invalid_hex"));
        assert!(!key.verify("scrypt:invalid"));
    }

    #[test]
    fn builder_generate() {
        let key = ApiKey::builder()
            .key_type(ApiKeyType::Secret)
            .environment(Environment::Test)
            .length(32)
            .generate()
            .unwrap();
        assert!(key.as_str().starts_with("sk_test_"));
    }

    #[test]
    fn builder_generate_with_hash_sha256() {
        let generated = ApiKey::builder()
            .key_type(ApiKeyType::Api)
            .environment(Environment::Live)
            .length(32)
            .hash_algorithm(HashAlgorithm::Sha256)
            .generate_with_hash()
            .unwrap();

        assert!(generated.key.as_str().starts_with("api_live_"));
        assert!(generated.key_hash.starts_with("sha256:"));
        assert!(generated.verify());
    }

    #[test]
    fn builder_generate_with_hash_scrypt() {
        let generated = ApiKey::builder()
            .key_type(ApiKeyType::Api)
            .environment(Environment::Live)
            .length(32)
            .hash_algorithm(HashAlgorithm::Scrypt)
            .generate_with_hash()
            .unwrap();

        assert!(generated.key.as_str().starts_with("api_live_"));
        assert!(generated.key_hash.starts_with("scrypt:"));
        assert!(generated.verify());
    }

    #[test]
    fn builder_generate_with_hash_default() {
        // Without specifying hash_algorithm, it should default to SHA-256
        let generated = ApiKey::builder()
            .key_type(ApiKeyType::Api)
            .environment(Environment::Live)
            .length(32)
            .generate_with_hash()
            .unwrap();

        assert!(generated.key_hash.starts_with("sha256:"));
        assert!(generated.verify());
    }

    #[test]
    fn generated_api_key_sha256() {
        let generated =
            GeneratedApiKey::generate_sha256(ApiKeyType::Public, Environment::Staging, 32)
                .unwrap();
        assert!(generated.key.as_str().starts_with("pk_staging_"));
        assert!(generated.key_hash.starts_with("sha256:"));
        assert!(generated.verify());
    }

    #[test]
    fn generated_api_key_scrypt() {
        let generated =
            GeneratedApiKey::generate_scrypt(ApiKeyType::Secret, Environment::Test, 32).unwrap();
        assert!(generated.key.as_str().starts_with("sk_test_"));
        assert!(generated.key_hash.starts_with("scrypt:"));
        assert!(generated.verify());
    }

    #[test]
    fn minimum_length_enforced() {
        let result = ApiKey::generate(ApiKeyType::Api, Environment::Live, 8);
        assert!(result.is_err());
    }

    #[test]
    fn display_trait() {
        let key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();
        let display = format!("{}", key);
        assert_eq!(display, key.as_str());
    }

    #[test]
    fn as_ref_trait() {
        let key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();
        let ref_str: &str = key.as_ref();
        assert_eq!(ref_str, key.as_str());
    }

    #[test]
    fn debug_trait_redacts_key() {
        let key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();
        let debug_output = format!("{:?}", key);
        // Debug output should not contain the actual key value
        assert!(!debug_output.contains(key.as_str()));
        // But should indicate it's redacted
        assert!(debug_output.contains("[REDACTED]"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    prop_compose! {
        fn arb_api_key_type()(type_idx in 0..3usize) -> ApiKeyType {
            match type_idx {
                0 => ApiKeyType::Api,
                1 => ApiKeyType::Secret,
                _ => ApiKeyType::Public,
            }
        }
    }

    prop_compose! {
        fn arb_environment()(env_idx in 0..3usize) -> Environment {
            match env_idx {
                0 => Environment::Live,
                1 => Environment::Test,
                _ => Environment::Staging,
            }
        }
    }

    prop_compose! {
        fn arb_hash_algorithm()(algo_idx in 0..2usize) -> HashAlgorithm {
            match algo_idx {
                0 => HashAlgorithm::Sha256,
                _ => HashAlgorithm::Scrypt,
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn key_format_invariant(
            key_type in arb_api_key_type(),
            env in arb_environment(),
            length in 16usize..128
        ) {
            let key = ApiKey::generate(key_type, env, length).unwrap();
            let key_str = key.as_str();

            // Key should start with correct prefix
            let expected_prefix = format!("{}_{}_", key_type.prefix(), env.prefix());
            prop_assert!(key_str.starts_with(&expected_prefix));

            // Key should have at least 3 parts (prefix_env_random)
            // Note: the random portion can contain underscores from base64url encoding
            let parts: Vec<&str> = key_str.split('_').collect();
            prop_assert!(parts.len() >= 3);

            // First two parts should match key type and environment
            prop_assert_eq!(parts[0], key_type.prefix());
            prop_assert_eq!(parts[1], env.prefix());

            // Key type extraction should work
            prop_assert_eq!(key.key_type(), Some(key_type));

            // Environment extraction should work
            prop_assert_eq!(key.environment(), Some(env));
        }

        #[test]
        fn sha256_hash_verification(key_type in arb_api_key_type(), env in arb_environment()) {
            let key = ApiKey::generate(key_type, env, 32).unwrap();
            let hash = key.hash_sha256();

            // Hash should have correct format
            prop_assert!(hash.starts_with("sha256:"));
            prop_assert_eq!(hash.len(), 71); // "sha256:" (7) + 64 hex chars

            // Verification should succeed
            prop_assert!(key.verify(&hash));

            // Different key should not verify
            let other_key = ApiKey::generate(key_type, env, 32).unwrap();
            prop_assert!(!other_key.verify(&hash));
        }
    }

    // Separate proptest block for scrypt tests with fewer cases due to computational cost
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(5))]

        #[test]
        fn scrypt_hash_verification(key_type in arb_api_key_type(), env in arb_environment()) {
            let key = ApiKey::generate(key_type, env, 32).unwrap();
            let hash = key.hash_scrypt().unwrap();

            // Hash should have correct format
            prop_assert!(hash.starts_with("scrypt:"));

            // Parse scrypt format: scrypt:N:r:p:salt:hash
            let parts: Vec<&str> = hash.split(':').collect();
            prop_assert_eq!(parts.len(), 6);
            prop_assert_eq!(parts[0], "scrypt");
            prop_assert_eq!(parts[1], "14"); // N parameter
            prop_assert_eq!(parts[2], "8");  // r parameter
            prop_assert_eq!(parts[3], "1");  // p parameter
            prop_assert_eq!(parts[4].len(), 32); // salt (16 bytes = 32 hex chars)
            prop_assert_eq!(parts[5].len(), 64); // hash (32 bytes = 64 hex chars)

            // Verification should succeed
            prop_assert!(key.verify(&hash));

            // Different key should not verify
            let other_key = ApiKey::generate(key_type, env, 32).unwrap();
            prop_assert!(!other_key.verify(&hash));
        }

        #[test]
        fn hash_algorithm_enum(key_type in arb_api_key_type(), env in arb_environment(), algo in arb_hash_algorithm()) {
            let key = ApiKey::generate(key_type, env, 32).unwrap();
            let hash = key.hash(algo).unwrap();

            match algo {
                HashAlgorithm::Sha256 => {
                    prop_assert!(hash.starts_with("sha256:"));
                }
                HashAlgorithm::Scrypt => {
                    prop_assert!(hash.starts_with("scrypt:"));
                }
            }

            // Verification should always succeed
            prop_assert!(key.verify(&hash));
        }

        #[test]
        fn builder_produces_valid_keys(
            key_type in arb_api_key_type(),
            env in arb_environment(),
            length in 16usize..128,
            algo in arb_hash_algorithm()
        ) {
            let generated = ApiKey::builder()
                .key_type(key_type)
                .environment(env)
                .length(length)
                .hash_algorithm(algo)
                .generate_with_hash()
                .unwrap();

            // Key format should be correct
            let expected_prefix = format!("{}_{}_", key_type.prefix(), env.prefix());
            prop_assert!(generated.key.as_str().starts_with(&expected_prefix));

            // Hash should match algorithm
            match algo {
                HashAlgorithm::Sha256 => {
                    prop_assert!(generated.key_hash.starts_with("sha256:"));
                }
                HashAlgorithm::Scrypt => {
                    prop_assert!(generated.key_hash.starts_with("scrypt:"));
                }
            }

            // Verification should succeed
            prop_assert!(generated.verify());
        }

        #[test]
        fn scrypt_salts_are_unique(key_type in arb_api_key_type(), env in arb_environment()) {
            let key = ApiKey::generate(key_type, env, 32).unwrap();

            // Generate two scrypt hashes for the same key
            let hash1 = key.hash_scrypt().unwrap();
            let hash2 = key.hash_scrypt().unwrap();

            // Hashes should be different (due to random salt)
            prop_assert_ne!(&hash1, &hash2);

            // But both should verify
            prop_assert!(key.verify(&hash1));
            prop_assert!(key.verify(&hash2));
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn keys_are_unique(
            key_type in arb_api_key_type(),
            env in arb_environment(),
            length in 16usize..128
        ) {
            let key1 = ApiKey::generate(key_type, env, length).unwrap();
            let key2 = ApiKey::generate(key_type, env, length).unwrap();

            // Two keys with same parameters should be different
            prop_assert_ne!(key1.as_str(), key2.as_str());

            // Their hashes should also be different
            let hash1 = key1.hash_sha256();
            let hash2 = key2.hash_sha256();
            prop_assert_ne!(hash1, hash2);
        }
    }
}
