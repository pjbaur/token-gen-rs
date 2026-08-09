//! Integration tests for the token-gen CLI.
//!
//! These tests verify the CLI binary works correctly by running it as a subprocess.

use std::process::Command;

/// Path to the compiled CLI binary.
const CLI_PATH: &str = "./target/debug/token-gen";
const TEST_SECRET: &str = "test-secret-key-12345";
const OTHER_SECRET: &str = "other-secret-key-1234";
const TEST_SESSION_ID: &str = "test-session-123";

/// Helper to run the CLI with given arguments.
///
/// Returns (stdout, stderr, success).
fn run_cli(args: &[&str]) -> (String, String, bool) {
    let output = Command::new(CLI_PATH)
        .args(args)
        .output()
        .expect("Failed to run CLI");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.success(),
    )
}

/// Helper to run CLI with environment variable.
fn run_cli_with_env(args: &[&str], env_key: &str, env_value: &str) -> (String, String, bool) {
    let output = Command::new(CLI_PATH)
        .args(args)
        .env(env_key, env_value)
        .output()
        .expect("Failed to run CLI");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.success(),
    )
}

/// Run a CSRF command with the standard valid secret and session fixtures.
fn run_csrf(args: &[&str]) -> (String, String, bool) {
    let mut csrf_args = vec!["csrf", "-s", TEST_SECRET, "--session-id", TEST_SESSION_ID];
    csrf_args.extend_from_slice(args);
    run_cli(&csrf_args)
}

// =============================================================================
// AUTH COMMAND TESTS
// =============================================================================

mod auth_tests {
    use super::*;

    #[test]
    fn auth_generates_single_token_with_defaults() {
        let (stdout, stderr, success) = run_cli(&["auth"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(!stdout.trim().is_empty(), "Should output a token");
        // Base64url encoded 32 bytes should be ~43 characters (no padding)
        assert!(
            stdout.trim().len() >= 32,
            "Token should have reasonable length"
        );
    }

    #[test]
    fn auth_generates_multiple_tokens_with_count() {
        let (stdout, stderr, success) = run_cli(&["auth", "-n", "5"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        let lines: Vec<&str> = stdout.trim().lines().collect();
        assert_eq!(lines.len(), 5, "Should generate 5 tokens");
        // All tokens should be unique
        let unique: std::collections::HashSet<_> = lines.iter().collect();
        assert_eq!(unique.len(), 5, "All tokens should be unique");
    }

    #[test]
    fn auth_generates_hex_format_token() {
        let (stdout, stderr, success) = run_cli(&["auth", "-f", "hex"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        let token = stdout.trim();
        // 32 bytes = 64 hex characters
        assert_eq!(token.len(), 64, "Hex token should be 64 characters");
        assert!(
            token.chars().all(|c| c.is_ascii_hexdigit()),
            "Should be hex"
        );
    }

    #[test]
    fn auth_generates_expiring_token() {
        let (stdout, stderr, success) = run_cli(&["auth", "-x", "3600", "-s", TEST_SECRET]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        let token = stdout.trim();
        // Expiring tokens have format: timestamp.nonce.signature
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "Expiring token should have 3 parts");
    }

    #[test]
    fn auth_check_expiry_not_expired() {
        // First generate an expiring token
        let (token, _, _) = run_cli(&["auth", "-x", "3600", "-s", TEST_SECRET]);
        let token = token.trim();

        // Check it's not expired
        let (stdout, stderr, success) = run_cli(&["auth", "--check-expiry", token]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(
            stdout.contains("expired: false"),
            "Token should not be expired"
        );
    }

    #[test]
    fn auth_check_expiry_simple_token_never_expires() {
        // Generate a simple (non-expiring) token
        let (token, _, _) = run_cli(&["auth"]);
        let token = token.trim();

        // Simple tokens never expire
        let (stdout, stderr, success) = run_cli(&["auth", "--check-expiry", token]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(
            stdout.contains("expired: false"),
            "Simple token should never expire"
        );
    }

    #[test]
    fn auth_check_expiry_accepts_hyphen_leading_token() {
        // Base64URL tokens can begin with '-'; the value must not be
        // mistaken for a flag.
        let (stdout, stderr, success) = run_cli(&["auth", "--check-expiry", "-pXyZabc123_-foo"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(
            stdout.contains("expired: false"),
            "Hyphen-leading simple token should never expire"
        );
    }

    #[test]
    fn auth_requires_secret_for_expiring_token() {
        let (_stdout, stderr, success) = run_cli(&["auth", "-x", "3600"]);
        assert!(!success, "Should fail without secret");
        assert!(stderr.contains("Error"), "Should show error message");
        assert!(stderr.contains("secret"), "Error should mention secret");
    }

    #[test]
    fn auth_custom_length() {
        let (stdout, stderr, success) = run_cli(&["auth", "-l", "64", "-f", "hex"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        let token = stdout.trim();
        // 64 bytes = 128 hex characters
        assert_eq!(token.len(), 128, "Token should be 128 hex characters");
    }
}

// =============================================================================
// API COMMAND TESTS
// =============================================================================

mod api_tests {
    use super::*;

    #[test]
    fn api_generates_key_with_defaults() {
        let (stdout, stderr, success) = run_cli(&["api"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(stdout.contains("key:"), "Should output key");
        assert!(stdout.contains("key_hash:"), "Should output key hash");
        assert!(
            stdout.contains("api_live_"),
            "Default should be api_live prefix"
        );
    }

    #[test]
    fn api_generates_test_environment() {
        let (stdout, stderr, success) = run_cli(&["api", "-e", "test"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(stdout.contains("api_test_"), "Should have api_test prefix");
    }

    #[test]
    fn api_generates_staging_environment() {
        let (stdout, stderr, success) = run_cli(&["api", "-e", "staging"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(
            stdout.contains("api_staging_"),
            "Should have api_staging prefix"
        );
    }

    #[test]
    fn api_generates_secret_key_type() {
        let (stdout, stderr, success) = run_cli(&["api", "-t", "sk"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(stdout.contains("sk_live_"), "Should have sk_live prefix");
    }

    #[test]
    fn api_generates_public_key_type() {
        let (stdout, stderr, success) = run_cli(&["api", "-t", "pk"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(stdout.contains("pk_live_"), "Should have pk_live prefix");
    }

    #[test]
    fn api_hashes_existing_key() {
        let (stdout, stderr, success) = run_cli(&["api", "--hash", "api_test_abc123"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(stdout.contains("hash:"), "Should output hash");
        assert!(stdout.contains("sha256:"), "Hash should be SHA-256 format");
    }

    #[test]
    fn api_verify_valid_key_hash() {
        // First generate a key
        let (gen_stdout, _, success) = run_cli(&["api"]);
        assert!(success, "Generate should succeed");

        // Parse key and hash from output
        let key = gen_stdout
            .lines()
            .find(|l| l.starts_with("key:"))
            .and_then(|l| l.strip_prefix("key: "))
            .expect("Should have key")
            .trim()
            .to_string();
        let hash = gen_stdout
            .lines()
            .find(|l| l.starts_with("key_hash:"))
            .and_then(|l| l.strip_prefix("key_hash: "))
            .expect("Should have hash")
            .trim()
            .to_string();

        // Verify the key against the hash
        let (stdout, stderr, success) = run_cli(&["api", "--verify", &key, &hash]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(
            stdout.contains("valid: true"),
            "Key should verify successfully"
        );
    }

    #[test]
    fn api_verify_invalid_key_hash() {
        // Hash for one key
        let (_hash_stdout, _, _) = run_cli(&["api", "--hash", "api_test_abc123"]);

        // Try to verify with different key
        let (stdout, _stderr, success) =
            run_cli(&["api", "--verify", "api_test_different", "sha256:somehash"]);
        assert!(
            success,
            "CLI should succeed (verification returns result, not error)"
        );
        assert!(
            stdout.contains("valid: false"),
            "Wrong key should not verify"
        );
    }

    #[test]
    fn api_generates_multiple_keys() {
        let (stdout, stderr, success) = run_cli(&["api", "-n", "3"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        let lines: Vec<&str> = stdout.trim().lines().collect();
        // Each key generates 2 lines (key and hash), so 3 keys = 6 lines
        assert_eq!(lines.len(), 6, "Should have 6 lines for 3 keys");
    }
}

// =============================================================================
// CSRF COMMAND TESTS
// =============================================================================

mod csrf_tests {
    use super::*;

    #[test]
    fn csrf_generates_token_with_secret() {
        let (stdout, stderr, success) = run_csrf(&[]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        let token = stdout.trim();
        // CSRF tokens have format: timestamp.nonce.signature
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "CSRF token should have 3 parts");
    }

    #[test]
    fn csrf_generates_token_with_env_secret() {
        let (stdout, stderr, success) = run_cli_with_env(
            &["csrf", "--session-id", TEST_SESSION_ID],
            "TOKEN_GEN_SECRET",
            TEST_SECRET,
        );
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        let token = stdout.trim();
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3, "CSRF token should have 3 parts");
    }

    #[test]
    fn csrf_verify_valid_token() {
        // Generate a token
        let (token, _, success) = run_csrf(&[]);
        assert!(success, "Generate should succeed");
        let token = token.trim();

        // Verify it
        let (stdout, stderr, success) = run_csrf(&["--verify", token]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(stdout.contains("valid: true"), "Token should be valid");
    }

    #[test]
    fn csrf_rejects_wrong_session_id() {
        let (token, _, success) = run_csrf(&[]);
        assert!(success, "Generate should succeed");

        let (stdout, stderr, success) = run_cli(&[
            "csrf",
            "-s",
            TEST_SECRET,
            "--session-id",
            "other-session-456",
            "--verify",
            token.trim(),
        ]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(
            stdout.contains("valid: false"),
            "Token should be session-bound"
        );
    }

    #[test]
    fn csrf_rejects_wrong_secret() {
        // Generate with one secret
        let (token, _, _) = run_csrf(&[]);
        let token = token.trim();

        // Verify with different secret
        let (stdout, _stderr, success) = run_cli(&[
            "csrf",
            "-s",
            OTHER_SECRET,
            "--session-id",
            TEST_SESSION_ID,
            "--verify",
            token,
        ]);
        assert!(success, "CLI should succeed");
        assert!(
            stdout.contains("valid: false"),
            "Token should be invalid with wrong secret"
        );
    }

    #[test]
    fn csrf_requires_secret() {
        let (_stdout, stderr, success) = run_cli(&["csrf", "--session-id", TEST_SESSION_ID]);
        assert!(!success, "Should fail without secret");
        assert!(stderr.contains("Error"), "Should show error");
        assert!(stderr.contains("secret"), "Error should mention secret");
    }

    #[test]
    fn csrf_requires_non_empty_session_id() {
        let (_stdout, stderr, success) = run_cli(&["csrf", "-s", TEST_SECRET, "--session-id", ""]);
        assert!(!success, "Should fail with an empty session ID");
        assert!(
            stderr.contains("session-id"),
            "Error should mention session ID"
        );
    }

    #[test]
    fn csrf_custom_max_age() {
        // Generate token
        let (token, _, _) = run_csrf(&[]);
        let token = token.trim();

        // Verify with custom max age
        let (stdout, stderr, success) = run_csrf(&["--verify", token, "--max-age", "60"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(stdout.contains("valid: true"), "Token should be valid");
    }

    #[test]
    fn csrf_generates_multiple_tokens() {
        let (stdout, stderr, success) = run_csrf(&["-n", "5"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        let lines: Vec<&str> = stdout.trim().lines().collect();
        assert_eq!(lines.len(), 5, "Should generate 5 tokens");
        // All tokens should be unique
        let unique: std::collections::HashSet<_> = lines.iter().collect();
        assert_eq!(unique.len(), 5, "All tokens should be unique");
    }
}

// =============================================================================
// OUTPUT FORMAT TESTS
// =============================================================================

mod output_format_tests {
    use super::*;

    #[test]
    fn auth_plain_output_default() {
        let (stdout, stderr, success) = run_cli(&["auth"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        // Plain output should just be the token
        assert!(!stdout.trim().is_empty());
        assert!(
            !stdout.contains("token:"),
            "Plain output shouldn't have label"
        );
    }

    #[test]
    fn auth_json_output() {
        let (stdout, stderr, success) = run_cli(&["auth", "-o", "json"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        // Should be valid JSON with "token" field
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("Should be valid JSON");
        assert!(json.get("token").is_some(), "Should have token field");
    }

    #[test]
    fn auth_multiple_json_output() {
        let (stdout, stderr, success) = run_cli(&["auth", "-n", "3", "-o", "json"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("Should be valid JSON");
        assert!(json.get("tokens").is_some(), "Should have tokens field");
        let tokens = json.get("tokens").unwrap().as_array().unwrap();
        assert_eq!(tokens.len(), 3, "Should have 3 tokens");
    }

    #[test]
    fn api_plain_output() {
        let (stdout, stderr, success) = run_cli(&["api"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        assert!(
            stdout.contains("key:"),
            "Plain output should have key label"
        );
        assert!(
            stdout.contains("key_hash:"),
            "Plain output should have hash label"
        );
    }

    #[test]
    fn api_json_output() {
        let (stdout, stderr, success) = run_cli(&["api", "-o", "json"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("Should be valid JSON");
        assert!(json.get("key").is_some(), "Should have key field");
        assert!(json.get("key_hash").is_some(), "Should have key_hash field");
    }

    #[test]
    fn csrf_json_output() {
        let (stdout, stderr, success) = run_csrf(&["-o", "json"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("Should be valid JSON");
        assert!(json.get("token").is_some(), "Should have token field");
    }

    #[test]
    fn verify_json_output() {
        let (token, _, _) = run_csrf(&[]);
        let token = token.trim();

        let (stdout, stderr, success) = run_csrf(&["--verify", token, "-o", "json"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("Should be valid JSON");
        assert!(json.get("valid").is_some(), "Should have valid field");
        assert!(json["valid"].as_bool().unwrap(), "Token should be valid");
    }

    #[test]
    fn hash_json_output() {
        let (stdout, stderr, success) = run_cli(&["api", "--hash", "api_test_abc", "-o", "json"]);
        assert!(success, "CLI should succeed, stderr: {}", stderr);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("Should be valid JSON");
        assert!(json.get("hash").is_some(), "Should have hash field");
    }
}

// =============================================================================
// ERROR HANDLING TESTS
// =============================================================================

mod error_handling_tests {
    use super::*;

    #[test]
    fn missing_subcommand() {
        let (stdout, stderr, success) = run_cli(&[]);
        assert!(!success, "Should fail without subcommand");
        // Clap shows help or error
        assert!(!stdout.is_empty() || !stderr.is_empty());
    }

    #[test]
    fn invalid_subcommand() {
        let (stdout, stderr, success) = run_cli(&["invalid-command"]);
        assert!(!success, "Should fail with invalid command");
        assert!(
            !stderr.is_empty() || !stdout.is_empty(),
            "Should show error"
        );
    }

    #[test]
    fn csrf_missing_secret_error() {
        let (_stdout, stderr, success) = run_cli(&["csrf", "--session-id", TEST_SESSION_ID]);
        assert!(!success, "Should fail without secret");
        assert!(stderr.contains("Error"), "Should show error");
    }

    #[test]
    fn auth_expires_without_secret_error() {
        let (_stdout, stderr, success) = run_cli(&["auth", "-x", "3600"]);
        assert!(!success, "Should fail without secret for expiring token");
        assert!(stderr.contains("Error"), "Should show error");
    }

    #[test]
    fn invalid_length_too_small() {
        let (_stdout, stderr, success) = run_cli(&["auth", "-l", "8"]);
        assert!(!success, "Should fail with too small length");
        assert!(stderr.contains("Error"), "Should show error");
    }

    #[test]
    fn exit_code_success() {
        let (_, _, success) = run_cli(&["auth"]);
        assert!(success, "Successful command should have exit code 0");
    }

    #[test]
    fn exit_code_failure() {
        let (_, _, success) = run_cli(&["csrf", "--session-id", TEST_SESSION_ID]); // Missing secret
        assert!(!success, "Failed command should have non-zero exit code");
    }

    #[test]
    fn verify_missing_args() {
        // --verify requires 2 arguments (key and hash)
        let (_stdout, _stderr, success) = run_cli(&["api", "--verify", "only-one-arg"]);
        assert!(!success, "Should fail with missing verify argument");
    }
}

// =============================================================================
// HELP AND VERSION TESTS
// =============================================================================

mod help_version_tests {
    use super::*;

    #[test]
    fn help_flag() {
        let (stdout, stderr, success) = run_cli(&["--help"]);
        assert!(success, "Help should succeed");
        assert!(stdout.contains("token-gen") || stderr.contains("token-gen"));
        assert!(stdout.contains("auth") || stderr.contains("auth"));
        assert!(stdout.contains("api") || stderr.contains("api"));
        assert!(stdout.contains("csrf") || stderr.contains("csrf"));
    }

    #[test]
    fn version_flag() {
        let (stdout, stderr, success) = run_cli(&["--version"]);
        assert!(success, "Version should succeed");
        assert!(stdout.contains("token-gen") || stderr.contains("token-gen"));
    }

    #[test]
    fn subcommand_help() {
        let (stdout, stderr, success) = run_cli(&["auth", "--help"]);
        assert!(success, "Subcommand help should succeed");
        assert!(stdout.contains("length") || stderr.contains("length"));
        assert!(stdout.contains("format") || stderr.contains("format"));
        assert!(stdout.contains("expires") || stderr.contains("expires"));
    }
}
