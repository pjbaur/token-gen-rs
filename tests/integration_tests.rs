//! Integration tests for token-gen.
//!
//! These tests verify the public API works correctly end-to-end with a focus on:
//! - Cross-module interoperability
//! - Real-world authentication workflows
//! - Edge cases and boundary conditions
//! - Error handling consistency

use std::collections::HashSet;
use std::time::Duration;
use token_gen::{
    ApiKey, ApiKeyType, AuthToken, CsrfToken, Environment, Format, GeneratedApiKey, HashAlgorithm,
    SecretKey, TokenError,
};

// =============================================================================
// Section 1: Token Interop Scenarios
// =============================================================================

mod token_interop {
    use super::*;

    /// Test that all token types can be generated and used together in a single context.
    #[test]
    fn all_token_types_coexist() {
        let secret = SecretKey::from_string("interop-secret-key").unwrap();

        // Generate all three token types
        let auth_token = AuthToken::generate(32, Format::Base64Url).unwrap();
        let api_key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();
        let csrf_token = CsrfToken::generate(&secret, "session-123", 32).unwrap();

        // All should have non-empty string representations
        assert!(!auth_token.as_str().is_empty());
        assert!(!api_key.as_str().is_empty());
        assert!(!csrf_token.as_str().is_empty());

        // Each should have distinct formats:
        // - AuthToken: base64url encoded (simple) or timestamp.nonce.signature (expiring)
        // - API keys: prefix_env_random (underscore-separated)
        // - CSRF tokens: timestamp.nonce.signature (dot-separated)
        assert!(api_key.as_str().contains('_')); // API keys have underscores
        assert!(csrf_token.as_str().contains('.')); // CSRF tokens have dots
    }

    /// Test using SecretKey across AuthToken and CsrfToken.
    #[test]
    fn shared_secret_key_for_signing() {
        let shared_secret = SecretKey::from_string("shared-application-secret").unwrap();

        // Generate an expiring auth token with the shared secret
        let auth_token = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .secret_key(&shared_secret)
            .generate()
            .unwrap();

        // Generate a CSRF token with the same secret
        let csrf_token = CsrfToken::generate(&shared_secret, "user-session", 32).unwrap();

        // Both should verify with the same secret
        assert!(auth_token.verify(&shared_secret).is_ok());

        let claims = csrf_token
            .verify(&shared_secret, "user-session", 3600)
            .unwrap();
        assert_eq!(claims.session_id, "user-session");
    }

    /// Test that different SecretKey instances produce incompatible signatures.
    #[test]
    fn secret_key_isolation() {
        let secret_a = SecretKey::from_string("secret-key-a-12345").unwrap();
        let secret_b = SecretKey::from_string("secret-key-b-12345").unwrap();

        // Generate tokens with secret A
        let auth_token = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .secret_key(&secret_a)
            .generate()
            .unwrap();

        let csrf_token = CsrfToken::generate(&secret_a, "session", 32).unwrap();

        // Tokens should NOT verify with secret B
        assert!(auth_token.verify(&secret_b).is_err());
        assert!(csrf_token.verify(&secret_b, "session", 3600).is_err());

        // But should verify with secret A
        assert!(auth_token.verify(&secret_a).is_ok());
        assert!(csrf_token.verify(&secret_a, "session", 3600).is_ok());
    }

    /// Test that all token types implement Display and AsRef<str>.
    #[test]
    fn string_representation_traits() {
        let secret = SecretKey::from_string("test-secret-12345").unwrap();

        let auth = AuthToken::generate(32, Format::Base64Url).unwrap();
        let api = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();
        let csrf = CsrfToken::generate(&secret, "session-id", 32).unwrap();

        // Display trait
        assert_eq!(format!("{}", auth), auth.as_str());
        assert_eq!(format!("{}", api), api.as_str());
        assert_eq!(format!("{}", csrf), csrf.as_str());

        // AsRef<str> trait
        let auth_ref: &str = auth.as_ref();
        let api_ref: &str = api.as_ref();
        let csrf_ref: &str = csrf.as_ref();

        assert_eq!(auth_ref, auth.as_str());
        assert_eq!(api_ref, api.as_str());
        assert_eq!(csrf_ref, csrf.as_str());
    }
}

// =============================================================================
// Section 2: Real-World Authentication Workflows
// =============================================================================

mod auth_workflows {
    use super::*;

    /// Simulate a complete user authentication flow:
    /// 1. User logs in → generate session-bound CSRF token
    /// 2. Generate API key for the user
    /// 3. Hash API key for storage
    /// 4. Later verify API key against stored hash
    #[test]
    fn user_authentication_flow() {
        // Step 1: User logs in - create session
        let session_id = "user-session-abc123";
        let app_secret = SecretKey::from_string("app-secret-key-12345").unwrap();

        // Generate CSRF token for the session
        let csrf_token = CsrfToken::generate(&app_secret, session_id, 32).unwrap();

        // Verify CSRF token is bound to the correct session
        let claims = csrf_token.verify(&app_secret, session_id, 3600).unwrap();
        assert_eq!(claims.session_id, session_id);

        // Step 2: Generate API key for the user
        let api_key = ApiKey::generate(ApiKeyType::Secret, Environment::Live, 32).unwrap();

        // Step 3: Hash API key for storage
        let stored_hash = api_key.hash_sha256();

        // Verify the hash format
        assert!(stored_hash.starts_with("sha256:"));
        assert_eq!(stored_hash.len(), 71); // "sha256:" (7) + 64 hex chars

        // Step 4: Later, verify API key against stored hash
        assert!(api_key.verify(&stored_hash));

        // A different key should not verify
        let wrong_key = ApiKey::generate(ApiKeyType::Secret, Environment::Live, 32).unwrap();
        assert!(!wrong_key.verify(&stored_hash));
    }

    /// Simulate API key registration and verification flow.
    #[test]
    fn api_key_registration_flow() {
        // Registration: Generate API key with hash
        let generated =
            GeneratedApiKey::generate_sha256(ApiKeyType::Api, Environment::Live, 32).unwrap();

        // Store the hash (simulating database storage)
        let stored_hash = generated.key_hash.clone();

        // Return the key to the user (only shown once!)
        let user_key = generated.key.clone();
        assert!(user_key.as_str().starts_with("api_live_"));

        // Later: User presents key for authentication
        // Parse the key and verify against stored hash
        let parsed_key: ApiKey = user_key.as_str().parse().unwrap();
        assert!(parsed_key.verify(&stored_hash));

        // Self-verification should also work
        assert!(generated.verify());
    }

    /// Simulate API key rotation workflow.
    #[test]
    fn api_key_rotation_flow() {
        // Old key
        let old_key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();
        let old_hash = old_key.hash(HashAlgorithm::Sha256).unwrap();

        // Generate new key (rotation)
        let new_key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();
        let new_hash = new_key.hash(HashAlgorithm::Sha256).unwrap();

        // Keys and hashes should be different
        assert_ne!(old_key.as_str(), new_key.as_str());
        assert_ne!(old_hash, new_hash);

        // Each key verifies only against its own hash
        assert!(old_key.verify(&old_hash));
        assert!(!old_key.verify(&new_hash));
        assert!(!new_key.verify(&old_hash));
        assert!(new_key.verify(&new_hash));
    }

    /// Simulate CSRF protection flow for form submission.
    #[test]
    fn csrf_protection_flow() {
        let secret = SecretKey::from_string("csrf-secret-12345").unwrap();
        let session_id = "user-session-xyz";

        // Server generates CSRF token for the session
        let csrf_token = CsrfToken::generate(&secret, session_id, 32).unwrap();

        // Token is embedded in form (as string)
        let token_string = csrf_token.as_str().to_string();

        // Later: Form submission includes the token
        let submitted_token: CsrfToken = token_string.parse().unwrap();

        // Server verifies the token
        let max_age_secs = 3600; // 1 hour
        let claims = submitted_token
            .verify(&secret, session_id, max_age_secs)
            .unwrap();

        // Verify session binding
        assert_eq!(claims.session_id, session_id);
        assert!(claims.age.as_secs() < max_age_secs);
    }

    /// Simulate expiring auth token for temporary access.
    #[test]
    fn expiring_auth_token_flow() {
        let secret = SecretKey::from_string("auth-secret-12345678").unwrap();

        // Generate short-lived token
        let token = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(300)) // 5 minutes
            .secret_key(&secret)
            .generate()
            .unwrap();

        // Token should not be expired
        assert!(!token.is_expired().unwrap());
        assert!(token.verify(&secret).is_ok());

        // Token can be serialized and deserialized
        let token_str = token.as_str();
        let parsed: AuthToken = token_str.parse().unwrap();

        // Parsed token should also verify
        assert!(parsed.verify(&secret).is_ok());
    }

    /// Simulate multi-environment API key management.
    #[test]
    fn multi_environment_api_keys() {
        let environments = [
            (Environment::Live, "live"),
            (Environment::Test, "test"),
            (Environment::Staging, "staging"),
        ];

        let mut keys_and_hashes = Vec::new();

        for (env, prefix) in &environments {
            let generated = ApiKey::builder()
                .key_type(ApiKeyType::Secret)
                .environment(*env)
                .length(32)
                .hash_algorithm(HashAlgorithm::Sha256)
                .generate_with_hash()
                .unwrap();

            // Verify prefix
            let expected_prefix = format!("sk_{}_", prefix);
            assert!(generated.key.as_str().starts_with(&expected_prefix));

            // Verify environment extraction
            assert_eq!(generated.key.environment(), Some(*env));

            keys_and_hashes.push((generated.key, generated.key_hash));
        }

        // Verify keys don't cross-authenticate
        for (i, (key_i, hash_i)) in keys_and_hashes.iter().enumerate() {
            for (j, (_key_j, hash_j)) in keys_and_hashes.iter().enumerate() {
                if i != j {
                    assert!(
                        !key_i.verify(hash_j),
                        "Key {} should not verify with hash {}",
                        i,
                        j
                    );
                } else {
                    assert!(
                        key_i.verify(hash_i),
                        "Key {} should verify with its own hash",
                        i
                    );
                }
            }
        }
    }

    /// Test scrypt hashing for high-security API keys.
    #[test]
    fn high_security_api_key_flow() {
        // Generate API key with scrypt (slower, more secure)
        let generated = ApiKey::builder()
            .key_type(ApiKeyType::Secret)
            .environment(Environment::Live)
            .length(32)
            .hash_algorithm(HashAlgorithm::Scrypt)
            .generate_with_hash()
            .unwrap();

        // Verify scrypt hash format
        assert!(generated.key_hash.starts_with("scrypt:"));

        // Parse scrypt format: scrypt:N:r:p:salt:hash
        let parts: Vec<&str> = generated.key_hash.split(':').collect();
        assert_eq!(parts.len(), 6);
        assert_eq!(parts[0], "scrypt");

        // Verify the key
        assert!(generated.verify());
    }

    /// Simulate session with both CSRF and auth tokens.
    #[test]
    fn session_with_multiple_token_types() {
        let secret = SecretKey::from_string("session-secret-12345").unwrap();
        let session_id = "user-session-123";

        // Create expiring auth token for API authentication
        let auth_token = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .secret_key(&secret)
            .generate()
            .unwrap();

        // Create CSRF token for form protection
        let csrf_token = CsrfToken::generate(&secret, session_id, 32).unwrap();

        // Create API key for long-term access
        let api_key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();
        let api_key_hash = api_key.hash_sha256();

        // Verify all tokens work correctly
        assert!(auth_token.verify(&secret).is_ok());
        assert!(csrf_token.verify(&secret, session_id, 3600).is_ok());
        assert!(api_key.verify(&api_key_hash));

        // All should have different formats:
        // - AuthToken expiring: timestamp.nonce.signature (dot-separated, base64url)
        // - API key: prefix_env_random (underscore-separated)
        // - CSRF token: timestamp.nonce.signature (dot-separated)
        assert!(auth_token.as_str().contains('.')); // Expiring auth has dots
        assert!(api_key.as_str().contains('_')); // API keys have underscores
        assert!(csrf_token.as_str().contains('.')); // CSRF tokens have dots

        // API keys should NOT contain dots (different from auth/CSRF tokens)
        assert!(!api_key.as_str().contains('.'));
    }
}

// =============================================================================
// Section 3: Edge Cases and Boundary Conditions
// =============================================================================

mod edge_cases {
    use super::*;

    /// Test minimum length enforcement across token types.
    #[test]
    fn minimum_length_enforcement() {
        // AuthToken: minimum 16 bytes
        let auth_result = AuthToken::generate(8, Format::Base64Url);
        assert!(auth_result.is_err());
        match auth_result {
            Err(TokenError::InsufficientEntropy { requested, minimum }) => {
                assert_eq!(requested, 8);
                assert_eq!(minimum, 16);
            }
            _ => panic!("Expected InsufficientEntropy error"),
        }

        // API Key: minimum 16 bytes
        let api_result = ApiKey::generate(ApiKeyType::Api, Environment::Live, 8);
        assert!(api_result.is_err());

        // CSRF Token: minimum 16 bytes
        let secret = SecretKey::from_string("test-secret-12345678").unwrap();
        let csrf_result = CsrfToken::generate(&secret, "session", 8);
        assert!(csrf_result.is_err());
    }

    /// Test exact minimum length works.
    #[test]
    fn exact_minimum_length_works() {
        // All token types should work with exactly 16 bytes
        let auth = AuthToken::generate(16, Format::Base64Url).unwrap();
        assert!(!auth.as_str().is_empty());

        let api = ApiKey::generate(ApiKeyType::Api, Environment::Live, 16).unwrap();
        assert!(api.as_str().starts_with("api_live_"));

        let secret = SecretKey::from_string("test-secret-12345678").unwrap();
        let csrf = CsrfToken::generate(&secret, "session", 16).unwrap();
        assert!(csrf.as_str().contains('.'));
    }

    /// Test large token lengths.
    #[test]
    fn large_token_lengths() {
        // 256 bytes should work
        let auth = AuthToken::generate(256, Format::Base64Url).unwrap();
        assert!(auth.as_str().len() > 256);

        let api = ApiKey::generate(ApiKeyType::Api, Environment::Live, 256).unwrap();
        assert!(api.as_str().starts_with("api_live_"));

        let secret = SecretKey::from_string("test-secret-12345678").unwrap();
        let csrf = CsrfToken::generate(&secret, "session", 256).unwrap();
        assert!(csrf.as_str().contains('.'));
    }

    /// Test empty and special session IDs for CSRF.
    #[test]
    fn csrf_special_session_ids() {
        let secret = SecretKey::from_string("test-secret-12345678").unwrap();

        // Empty session ID should work
        let csrf = CsrfToken::generate(&secret, "", 32).unwrap();
        let claims = csrf.verify(&secret, "", 3600).unwrap();
        assert_eq!(claims.session_id, "");

        // Session ID with special characters
        let special_id = "user@example.com::session-123";
        let csrf = CsrfToken::generate(&secret, special_id, 32).unwrap();
        let claims = csrf.verify(&secret, special_id, 3600).unwrap();
        assert_eq!(claims.session_id, special_id);

        // Session ID with unicode
        let unicode_id = "用户-セッション-𝄞";
        let csrf = CsrfToken::generate(&secret, unicode_id, 32).unwrap();
        let claims = csrf.verify(&secret, unicode_id, 3600).unwrap();
        assert_eq!(claims.session_id, unicode_id);
    }

    /// Test empty string handling.
    #[test]
    fn empty_string_handling() {
        // Empty auth token parse should fail
        let auth_result: Result<AuthToken, _> = "".parse();
        assert!(auth_result.is_err());

        // Empty API key parse should fail
        let api_result: Result<ApiKey, _> = "".parse();
        assert!(api_result.is_err());
    }

    /// Test very long session IDs.
    #[test]
    fn csrf_long_session_id() {
        let secret = SecretKey::from_string("test-secret-12345678").unwrap();

        // 1KB session ID
        let long_id = "x".repeat(1024);
        let csrf = CsrfToken::generate(&secret, &long_id, 32).unwrap();
        let claims = csrf.verify(&secret, &long_id, 3600).unwrap();
        assert_eq!(claims.session_id, long_id);
    }

    /// Test all format types for AuthToken.
    #[test]
    fn all_auth_token_formats() {
        let formats = [(Format::Base64Url, "base64url"), (Format::Hex, "hex")];

        for (format, _name) in formats {
            let token = AuthToken::generate(32, format).unwrap();

            match format {
                Format::Base64Url => {
                    // Base64url: no padding, URL-safe chars
                    assert!(!token.as_str().contains('='));
                    assert!(!token.as_str().contains('+'));
                    assert!(!token.as_str().contains('/'));
                }
                Format::Hex => {
                    // Hex: only 0-9, a-f
                    assert!(token.as_str().chars().all(|c| c.is_ascii_hexdigit()));
                    assert_eq!(token.as_str().len(), 64); // 32 bytes = 64 hex chars
                }
            }
        }
    }

    /// Test all API key types.
    #[test]
    fn all_api_key_types() {
        let key_types = [
            (ApiKeyType::Api, "api"),
            (ApiKeyType::Secret, "sk"),
            (ApiKeyType::Public, "pk"),
        ];

        for (key_type, prefix) in key_types {
            let key = ApiKey::generate(key_type, Environment::Live, 32).unwrap();
            assert!(key.as_str().starts_with(&format!("{}_live_", prefix)));
            assert_eq!(key.key_type(), Some(key_type));
        }
    }

    /// Test all environments.
    #[test]
    fn all_environments() {
        let environments = [
            (Environment::Live, "live"),
            (Environment::Test, "test"),
            (Environment::Staging, "staging"),
        ];

        for (env, prefix) in environments {
            let key = ApiKey::generate(ApiKeyType::Api, env, 32).unwrap();
            assert!(key.as_str().starts_with(&format!("api_{}_", prefix)));
            assert_eq!(key.environment(), Some(env));
        }
    }

    /// Test secret key from different sources.
    #[test]
    fn secret_key_sources() {
        // From string
        let from_str = SecretKey::from_string("my-secret-key-12345").unwrap();

        // From bytes
        let from_bytes = SecretKey::new(b"my-secret-key-12345".to_vec()).unwrap();

        // Both should produce the same signatures
        let auth1 = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .secret_key(&from_str)
            .generate()
            .unwrap();

        let auth2 = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .secret_key(&from_bytes)
            .generate()
            .unwrap();

        // Both should verify with either key
        assert!(auth1.verify(&from_str).is_ok());
        assert!(auth1.verify(&from_bytes).is_ok());
        assert!(auth2.verify(&from_str).is_ok());
        assert!(auth2.verify(&from_bytes).is_ok());
    }

    /// Test CSRF token parsing of malformed inputs.
    #[test]
    fn csrf_parse_malformed() {
        // Too few parts
        let result: Result<CsrfToken, _> = "abc".parse();
        assert!(result.is_err());

        // Too many parts
        let result: Result<CsrfToken, _> = "a.b.c.d".parse();
        assert!(result.is_err());

        // Invalid base64url in timestamp
        let result: Result<CsrfToken, _> = "invalid!!!.abc.def".parse();
        assert!(result.is_err());

        // Valid format but invalid timestamp (not 8 bytes)
        let result: Result<CsrfToken, _> = "YWJj.YWJj.YWJj".parse(); // "abc" in base64
        assert!(result.is_err());
    }

    /// Test API key verification with malformed hashes.
    #[test]
    fn api_key_verify_malformed_hash() {
        let key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();

        // Unknown hash format
        assert!(!key.verify("unknown:hash"));

        // Invalid sha256 format
        assert!(!key.verify("sha256:invalid_hex!@#"));

        // Invalid scrypt format - too few parts
        assert!(!key.verify("scrypt:14:8:1:salt"));

        // Invalid scrypt format - invalid hex
        assert!(!key.verify("scrypt:14:8:1:invalid!hex:alsoinvalid!"));
    }

    /// Test SecretKey minimum length requirement.
    #[test]
    fn secret_key_minimum_length() {
        // Too short - should fail
        let result = SecretKey::from_string("short");
        assert!(result.is_err());
        match result {
            Err(TokenError::InvalidFormat(msg)) => {
                assert!(msg.contains("16 bytes"));
            }
            _ => panic!("Expected InvalidFormat error"),
        }

        // Too short bytes
        let result = SecretKey::new(b"short".to_vec());
        assert!(result.is_err());

        // Exactly 16 bytes - should work
        let key = SecretKey::from_string("1234567890123456").unwrap();
        assert!(!key.as_bytes().is_empty());

        // More than 16 bytes - should work
        let key = SecretKey::from_string("this-is-a-long-secret-key").unwrap();
        assert!(!key.as_bytes().is_empty());
    }
}

// =============================================================================
// Section 4: Error Handling Consistency
// =============================================================================

mod error_handling {
    use super::*;

    /// Test that InsufficientEntropy error is consistent across types.
    #[test]
    fn insufficient_entropy_error_consistency() {
        // AuthToken
        let auth_err = AuthToken::generate(8, Format::Base64Url).unwrap_err();
        match auth_err {
            TokenError::InsufficientEntropy { requested, minimum } => {
                assert_eq!(requested, 8);
                assert_eq!(minimum, 16);
            }
            _ => panic!("Expected InsufficientEntropy"),
        }

        // API Key
        let api_err = ApiKey::generate(ApiKeyType::Api, Environment::Live, 8).unwrap_err();
        match api_err {
            TokenError::InsufficientEntropy { requested, minimum } => {
                assert_eq!(requested, 8);
                assert_eq!(minimum, 16);
            }
            _ => panic!("Expected InsufficientEntropy"),
        }

        // CSRF Token
        let secret = SecretKey::from_string("test-secret-12345678").unwrap();
        let csrf_err = CsrfToken::generate(&secret, "session", 8).unwrap_err();
        match csrf_err {
            TokenError::InsufficientEntropy { requested, minimum } => {
                assert_eq!(requested, 8);
                assert_eq!(minimum, 16);
            }
            _ => panic!("Expected InsufficientEntropy"),
        }
    }

    /// Test InvalidSignature error for auth tokens.
    #[test]
    fn invalid_signature_error_auth_token() {
        let secret_a = SecretKey::from_string("secret-key-a-12345").unwrap();
        let secret_b = SecretKey::from_string("secret-key-b-12345").unwrap();

        let token = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .secret_key(&secret_a)
            .generate()
            .unwrap();

        let err = token.verify(&secret_b).unwrap_err();
        assert!(matches!(err, TokenError::InvalidSignature));
    }

    /// Test InvalidSignature error for CSRF tokens.
    #[test]
    fn invalid_signature_error_csrf_token() {
        let secret_a = SecretKey::from_string("secret-key-a-12345").unwrap();
        let secret_b = SecretKey::from_string("secret-key-b-12345").unwrap();

        let token = CsrfToken::generate(&secret_a, "session", 32).unwrap();

        let err = token.verify(&secret_b, "session", 3600).unwrap_err();
        assert!(matches!(err, TokenError::InvalidSignature));
    }

    /// Test InvalidFormat error for builder missing required fields.
    #[test]
    fn invalid_format_missing_required_fields() {
        // AuthTokenBuilder missing secret_key for expiring token
        let err = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .generate()
            .unwrap_err();

        match err {
            TokenError::InvalidFormat(msg) => {
                assert!(msg.contains("secret_key"));
            }
            _ => panic!("Expected InvalidFormat"),
        }

        // CsrfTokenBuilder missing secret_key
        let err = CsrfToken::builder()
            .session_id("session")
            .length(32)
            .generate()
            .unwrap_err();

        match err {
            TokenError::InvalidFormat(msg) => {
                assert!(msg.contains("secret key"));
            }
            _ => panic!("Expected InvalidFormat"),
        }

        // CsrfTokenBuilder missing session_id
        let secret = SecretKey::from_string("test-secret-12345678").unwrap();
        let err = CsrfToken::builder()
            .secret_key(&secret)
            .length(32)
            .generate()
            .unwrap_err();

        match err {
            TokenError::InvalidFormat(msg) => {
                assert!(msg.contains("session_id"));
            }
            _ => panic!("Expected InvalidFormat"),
        }
    }

    /// Test InvalidFormat for non-expiring token verification.
    #[test]
    fn invalid_format_non_expiring_verify() {
        let secret = SecretKey::from_string("test-secret-12345678").unwrap();
        let token = AuthToken::generate(32, Format::Base64Url).unwrap();

        let err = token.verify(&secret).unwrap_err();
        match err {
            TokenError::InvalidFormat(msg) => {
                assert!(msg.contains("not expiring"));
            }
            _ => panic!("Expected InvalidFormat"),
        }
    }

    /// Test that all TokenError variants implement std::error::Error.
    #[test]
    fn token_error_is_std_error() {
        fn assert_error<E: std::error::Error>() {}

        assert_error::<TokenError>();
    }

    /// Test error Display for all variants.
    #[test]
    fn token_error_display() {
        let err = TokenError::InsufficientEntropy {
            requested: 8,
            minimum: 16,
        };
        let msg = format!("{}", err);
        assert!(msg.contains("8"));
        assert!(msg.contains("16"));

        let err = TokenError::Expired;
        assert!(format!("{}", err).contains("expired"));

        let err = TokenError::InvalidSignature;
        assert!(format!("{}", err).contains("signature"));

        let err = TokenError::InvalidFormat("test".to_string());
        assert!(format!("{}", err).contains("test"));

        let err = TokenError::InvalidLength("test".to_string());
        assert!(format!("{}", err).contains("test"));

        let err = TokenError::CryptoError("test".to_string());
        assert!(format!("{}", err).contains("test"));

        let err = TokenError::ParseError("test".to_string());
        assert!(format!("{}", err).contains("test"));
    }
}

// =============================================================================
// Section 5: Builder Pattern Tests
// =============================================================================

mod builder_patterns {
    use super::*;

    /// Test AuthTokenBuilder chaining.
    #[test]
    fn auth_token_builder_chaining() {
        let secret = SecretKey::from_string("test-secret-12345678").unwrap();

        let token = AuthToken::builder()
            .length(48)
            .format(Format::Hex)
            .expires_in(Duration::from_secs(7200))
            .secret_key(&secret)
            .generate()
            .unwrap();

        assert!(token.is_expiring());
        assert!(token.verify(&secret).is_ok());
    }

    /// Test ApiKeyBuilder chaining.
    #[test]
    fn api_key_builder_chaining() {
        let generated = ApiKey::builder()
            .key_type(ApiKeyType::Secret)
            .environment(Environment::Test)
            .length(48)
            .hash_algorithm(HashAlgorithm::Scrypt)
            .generate_with_hash()
            .unwrap();

        assert!(generated.key.as_str().starts_with("sk_test_"));
        assert!(generated.key_hash.starts_with("scrypt:"));
        assert!(generated.verify());
    }

    /// Test CsrfTokenBuilder chaining.
    #[test]
    fn csrf_token_builder_chaining() {
        let secret = SecretKey::from_string("test-secret-12345678").unwrap();

        let token = CsrfToken::builder()
            .secret_key(&secret)
            .session_id("my-session")
            .length(48)
            .generate()
            .unwrap();

        let claims = token.verify(&secret, "my-session", 3600).unwrap();
        assert_eq!(claims.session_id, "my-session");
    }

    /// Test builder defaults.
    #[test]
    fn builder_defaults() {
        // AuthTokenBuilder defaults
        let token = AuthToken::builder().generate().unwrap();
        assert!(!token.is_expiring());

        // ApiKeyBuilder defaults
        let key = ApiKey::builder().generate().unwrap();
        assert!(key.as_str().starts_with("api_live_"));

        // CsrfTokenBuilder requires explicit secret and session_id
        let secret = SecretKey::from_string("test-secret-12345678").unwrap();
        let token = CsrfToken::builder()
            .secret_key(&secret)
            .session_id("session")
            .generate()
            .unwrap();
        // Default length is 32
        assert!(token.as_str().contains('.'));
    }
}

// =============================================================================
// Section 6: Token Uniqueness and Randomness
// =============================================================================

mod uniqueness {
    use super::*;

    /// Verify that generated auth tokens are unique.
    #[test]
    fn auth_tokens_are_unique() {
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let token = AuthToken::generate(32, Format::Base64Url).unwrap();
            assert!(
                seen.insert(token.as_str().to_string()),
                "Duplicate token generated"
            );
        }
        assert_eq!(seen.len(), 100);
    }

    /// Verify that generated API keys are unique.
    #[test]
    fn api_keys_are_unique() {
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();
            assert!(
                seen.insert(key.as_str().to_string()),
                "Duplicate key generated"
            );
        }
        assert_eq!(seen.len(), 100);
    }

    /// Verify that generated CSRF tokens are unique.
    #[test]
    fn csrf_tokens_are_unique() {
        let secret = SecretKey::from_string("test-secret-12345678").unwrap();
        let mut seen = HashSet::new();

        for _ in 0..100 {
            let token = CsrfToken::generate(&secret, "session", 32).unwrap();
            assert!(
                seen.insert(token.as_str().to_string()),
                "Duplicate token generated"
            );
        }
        assert_eq!(seen.len(), 100);
    }

    /// Verify that scrypt hashes are unique due to random salt.
    #[test]
    fn scrypt_hashes_are_unique() {
        let key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();

        let hash1 = key.hash_scrypt().unwrap();
        let hash2 = key.hash_scrypt().unwrap();

        // Same key, different hashes due to salt
        assert_ne!(hash1, hash2);

        // But both should verify
        assert!(key.verify(&hash1));
        assert!(key.verify(&hash2));
    }

    /// Verify SHA-256 hashes are deterministic.
    #[test]
    fn sha256_hashes_are_deterministic() {
        let key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();

        let hash1 = key.hash_sha256();
        let hash2 = key.hash_sha256();

        // Same key, same hashes
        assert_eq!(hash1, hash2);
    }
}

// =============================================================================
// Section 7: Concurrent and Parallel Usage
// =============================================================================

mod concurrency {
    use super::*;
    use std::thread;

    /// Test that token generation is thread-safe.
    #[test]
    fn thread_safety() {
        let handles: Vec<_> = (0..10)
            .map(|_| {
                thread::spawn(|| {
                    let mut tokens = Vec::new();
                    for _ in 0..10 {
                        let token = AuthToken::generate(32, Format::Base64Url).unwrap();
                        tokens.push(token.as_str().to_string());
                    }
                    tokens
                })
            })
            .collect();

        let mut all_tokens: HashSet<String> = HashSet::new();
        for handle in handles {
            let tokens = handle.join().unwrap();
            for token in tokens {
                assert!(
                    all_tokens.insert(token),
                    "Duplicate token in concurrent generation"
                );
            }
        }

        // Should have 100 unique tokens
        assert_eq!(all_tokens.len(), 100);
    }

    /// Test that secret key can be shared across threads.
    #[test]
    fn shared_secret_thread_safety() {
        let secret = SecretKey::from_string("shared-secret-12345").unwrap();

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let secret = secret.clone();
                thread::spawn(move || {
                    let token = AuthToken::builder()
                        .length(32)
                        .expires_in(Duration::from_secs(3600))
                        .secret_key(&secret)
                        .generate()
                        .unwrap();

                    token.verify(&secret).is_ok()
                })
            })
            .collect();

        for handle in handles {
            assert!(handle.join().unwrap());
        }
    }
}

// =============================================================================
// Section 8: SecretKey Security Tests
// =============================================================================

mod secret_key_security {
    use super::*;

    /// Test that SecretKey debug output is redacted.
    #[test]
    fn secret_key_debug_redacted() {
        let secret = SecretKey::from_string("super-secret-key-12345").unwrap();
        let debug_output = format!("{:?}", secret);

        // Debug output should not contain the actual key
        assert!(!debug_output.contains("super-secret-key"));
        assert!(debug_output.contains("[REDACTED]"));
    }

    /// Test that SecretKey can be cloned.
    #[test]
    fn secret_key_clone() {
        let original = SecretKey::from_string("original-secret-key").unwrap();
        let cloned = original.clone();

        // Both should produce the same signatures
        let auth = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .secret_key(&original)
            .generate()
            .unwrap();

        assert!(auth.verify(&cloned).is_ok());
    }

    /// Test that SecretKey bytes are accessible.
    #[test]
    fn secret_key_bytes_access() {
        let key_str = "my-test-secret-key";
        let secret = SecretKey::from_string(key_str).unwrap();

        assert_eq!(secret.as_bytes(), key_str.as_bytes());
    }
}

// =============================================================================
// Section 9: Cross-Module Integration Tests
// =============================================================================

mod cross_module {
    use super::*;

    /// Test using AuthToken expiring format with CsrfToken-like pattern.
    #[test]
    fn expiring_auth_similar_to_csrf() {
        let secret = SecretKey::from_string("shared-app-secret-12").unwrap();

        // Both AuthToken and CsrfToken use similar format: timestamp.nonce.signature
        let auth = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .secret_key(&secret)
            .generate()
            .unwrap();

        let csrf = CsrfToken::generate(&secret, "session", 32).unwrap();

        // Both should have 3 parts separated by dots
        let auth_parts: Vec<&str> = auth.as_str().split('.').collect();
        let csrf_parts: Vec<&str> = csrf.as_str().split('.').collect();

        assert_eq!(auth_parts.len(), 3);
        assert_eq!(csrf_parts.len(), 3);

        // But the actual tokens should be different (different nonces)
        assert_ne!(auth.as_str(), csrf.as_str());
    }

    /// Test complete authentication workflow with all token types.
    #[test]
    fn complete_authentication_workflow() {
        // Application setup
        let app_secret = SecretKey::from_string("application-secret-16").unwrap();

        // User login - create session
        let session_id = "user-session-abc123";

        // Generate CSRF token for the session (for form submissions)
        let csrf_token = CsrfToken::generate(&app_secret, session_id, 32).unwrap();

        // Generate expiring auth token for API access
        let auth_token = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .secret_key(&app_secret)
            .generate()
            .unwrap();

        // Generate API key for long-term programmatic access
        let api_key = ApiKey::builder()
            .key_type(ApiKeyType::Secret)
            .environment(Environment::Live)
            .length(32)
            .hash_algorithm(HashAlgorithm::Sha256)
            .generate_with_hash()
            .unwrap();

        // Verify all tokens
        assert!(csrf_token.verify(&app_secret, session_id, 3600).is_ok());
        assert!(auth_token.verify(&app_secret).is_ok());
        assert!(api_key.verify());

        // Simulate later verification
        let stored_api_hash = api_key.key_hash.clone();

        // Later: verify API key from storage
        assert!(api_key.key.verify(&stored_api_hash));

        // Later: verify auth token hasn't expired
        assert!(!auth_token.is_expired().unwrap());

        // Later: verify CSRF token with session binding
        let claims = csrf_token.verify(&app_secret, session_id, 3600).unwrap();
        assert_eq!(claims.session_id, session_id);
    }

    /// Test token format consistency across modules.
    #[test]
    fn token_format_consistency() {
        let secret = SecretKey::from_string("format-test-secret-1").unwrap();

        // AuthToken expiring format
        let auth = AuthToken::builder()
            .length(32)
            .expires_in(Duration::from_secs(3600))
            .secret_key(&secret)
            .generate()
            .unwrap();

        // CsrfToken format
        let csrf = CsrfToken::generate(&secret, "session", 32).unwrap();

        // Both use base64url encoding for parts
        for token_str in [auth.as_str(), csrf.as_str()] {
            let parts: Vec<&str> = token_str.split('.').collect();
            assert_eq!(parts.len(), 3);

            // Each part should be valid base64url (no invalid chars)
            for part in &parts {
                assert!(!part.contains('+'), "Should not contain +");
                assert!(!part.contains('/'), "Should not contain /");
                // Note: padding may or may not be present depending on encoder
            }
        }
    }
}
