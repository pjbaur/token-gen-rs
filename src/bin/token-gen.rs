//! Command-line interface for token generation.
//!
//! Binary entry point for the `token-gen` CLI tool.

use clap::{Parser, Subcommand, ValueEnum};
use serde::Serialize;
use std::process::ExitCode;
use std::time::Duration;
use std::{env, str::FromStr};
use token_gen::{ApiKey, ApiKeyType, AuthToken, CsrfToken, Environment, Format, SecretKey};

/// Generate cryptographically secure tokens.
#[derive(Parser)]
#[command(name = "token-gen")]
#[command(about = "Generate cryptographically secure tokens")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate auth/reset/invite token
    Auth(AuthArgs),
    /// Generate API key with prefix
    Api(ApiArgs),
    /// Generate HMAC-signed CSRF token
    Csrf(CsrfArgs),
}

/// Output format for CLI results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
enum OutputFormat {
    #[default]
    Plain,
    Json,
}

/// Token format for auth tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
enum TokenFormat {
    #[default]
    Base64,
    Hex,
}

impl From<TokenFormat> for Format {
    fn from(value: TokenFormat) -> Self {
        match value {
            TokenFormat::Base64 => Format::Base64Url,
            TokenFormat::Hex => Format::Hex,
        }
    }
}

/// API key type for CLI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
enum CliApiKeyType {
    #[default]
    Api,
    Sk,
    Pk,
}

impl From<CliApiKeyType> for ApiKeyType {
    fn from(value: CliApiKeyType) -> Self {
        match value {
            CliApiKeyType::Api => ApiKeyType::Api,
            CliApiKeyType::Sk => ApiKeyType::Secret,
            CliApiKeyType::Pk => ApiKeyType::Public,
        }
    }
}

/// Environment for API keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
enum CliEnvironment {
    #[default]
    Live,
    Test,
    Staging,
}

impl From<CliEnvironment> for Environment {
    fn from(value: CliEnvironment) -> Self {
        match value {
            CliEnvironment::Live => Environment::Live,
            CliEnvironment::Test => Environment::Test,
            CliEnvironment::Staging => Environment::Staging,
        }
    }
}

/// Auth token generation arguments.
#[derive(Parser)]
struct AuthArgs {
    /// Number of random bytes (default: 32)
    #[arg(short = 'l', long, default_value = "32")]
    length: usize,

    /// Number of tokens to generate (default: 1)
    #[arg(short = 'n', long, default_value = "1")]
    count: usize,

    /// Output format (plain or json)
    #[arg(short = 'o', long, default_value = "plain")]
    output: OutputFormat,

    /// Token format (base64 or hex)
    #[arg(short = 'f', long, default_value = "base64")]
    format: TokenFormat,

    /// Expiry in seconds from now
    #[arg(short = 'x', long)]
    expires_in: Option<u64>,

    /// Check if a token is expired
    #[arg(long, value_name = "TOKEN", allow_hyphen_values = true)]
    check_expiry: Option<String>,

    /// Secret key for signing/verifying expiry-bearing auth tokens
    #[arg(short = 's', long)]
    secret: Option<String>,
}

/// API key generation arguments.
#[derive(Parser)]
struct ApiArgs {
    /// Number of random bytes (default: 32)
    #[arg(short = 'l', long, default_value = "32")]
    length: usize,

    /// Number of tokens to generate (default: 1)
    #[arg(short = 'n', long, default_value = "1")]
    count: usize,

    /// Output format (plain or json)
    #[arg(short = 'o', long, default_value = "plain")]
    output: OutputFormat,

    /// Environment (live, test, staging)
    #[arg(short = 'e', long, default_value = "live")]
    env: CliEnvironment,

    /// Key type prefix (api, sk, pk)
    #[arg(short = 't', long, default_value = "api")]
    key_type: CliApiKeyType,

    /// Hash an existing API key
    #[arg(long, value_name = "KEY")]
    hash: Option<String>,

    /// Verify a key against a hash (KEY and HASH)
    #[arg(long, value_name = "KEY", num_args = 2)]
    verify: Option<Vec<String>>,
}

/// CSRF token generation arguments.
#[derive(Parser)]
struct CsrfArgs {
    /// Number of random bytes (default: 32)
    #[arg(short = 'l', long, default_value = "32")]
    length: usize,

    /// Number of tokens to generate (default: 1)
    #[arg(short = 'n', long, default_value = "1")]
    count: usize,

    /// Output format (plain or json)
    #[arg(short = 'o', long, default_value = "plain")]
    output: OutputFormat,

    /// Development-only inline secret; prefer TOKEN_GEN_SECRET
    #[arg(short = 's', long)]
    secret: Option<String>,

    /// Session ID to bind the token to
    #[arg(
        long,
        value_name = "SESSION_ID",
        value_parser = clap::builder::NonEmptyStringValueParser::new()
    )]
    session_id: String,

    /// Verify a CSRF token
    #[arg(long, value_name = "TOKEN", allow_hyphen_values = true)]
    verify: Option<String>,

    /// Max token age in seconds for verify (default: 3600)
    #[arg(long, default_value = "3600")]
    max_age: u64,
}

// Helper to get CSRF/auth secret from args or env
fn get_secret(secret_arg: Option<&str>) -> Result<SecretKey, String> {
    // Check arg first, then env var
    if let Some(s) = secret_arg {
        return SecretKey::from_string(s).map_err(|e| format!("Invalid secret: {}", e));
    }

    match env::var("TOKEN_GEN_SECRET") {
        Ok(s) => SecretKey::from_string(&s).map_err(|e| format!("Invalid secret: {}", e)),
        Err(_) => {
            Err("Secret required. Use -s/--secret or set TOKEN_GEN_SECRET env var.".to_string())
        }
    }
}

// Output handling
#[derive(Serialize)]
struct AuthTokenResult {
    token: String,
}

#[derive(Serialize)]
struct ApiKeyResult {
    key: String,
    key_hash: String,
}

#[derive(Serialize)]
struct HashResult {
    hash: String,
}

#[derive(Serialize)]
struct VerifyResult {
    valid: bool,
}

#[derive(Serialize)]
struct ExpiredResult {
    expired: bool,
}

#[derive(Serialize)]
struct CsrfTokenResult {
    token: String,
}

fn output_json<T: Serialize>(value: &T) {
    println!("{}", serde_json::to_string(value).unwrap());
}

fn output_plain_dict(items: &[(&str, &str)]) {
    for (key, value) in items {
        println!("{}: {}", key, value);
    }
}

fn run_auth(args: AuthArgs) -> Result<(), String> {
    // Check expiry mode
    if let Some(token_str) = &args.check_expiry {
        let expired = if token_str.contains('.') {
            // Looks like an expiring token
            let token: AuthToken = token_str
                .parse()
                .map_err(|e| format!("Failed to parse token: {}", e))?;
            token.is_expired().map_err(|e| e.to_string())?
        } else {
            // Simple token - never expires
            false
        };

        match args.output {
            OutputFormat::Json => output_json(&ExpiredResult { expired }),
            OutputFormat::Plain => output_plain_dict(&[("expired", &expired.to_string())]),
        }
        return Ok(());
    }

    // Generate tokens
    let format: Format = args.format.into();
    let results: Vec<String> = (0..args.count)
        .map(|_| {
            if let Some(expires_secs) = args.expires_in {
                let secret = get_secret(args.secret.as_deref())?;
                let token = AuthToken::builder()
                    .length(args.length)
                    .format(format)
                    .expires_in(Duration::from_secs(expires_secs))
                    .secret_key(&secret)
                    .generate()
                    .map_err(|e| e.to_string())?;
                Ok(token.to_string())
            } else {
                let token = AuthToken::generate(args.length, format).map_err(|e| e.to_string())?;
                Ok(token.to_string())
            }
        })
        .collect::<Result<Vec<_>, String>>()?;

    match args.output {
        OutputFormat::Json => {
            if args.count == 1 {
                output_json(&AuthTokenResult {
                    token: results[0].clone(),
                });
            } else {
                let tokens: Vec<AuthTokenResult> = results
                    .into_iter()
                    .map(|token| AuthTokenResult { token })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({ "tokens": tokens })).unwrap()
                );
            }
        }
        OutputFormat::Plain => {
            for token in results {
                println!("{}", token);
            }
        }
    }

    Ok(())
}

fn run_api(args: ApiArgs) -> Result<(), String> {
    // Hash mode
    if let Some(key) = &args.hash {
        // Parse the key to get an ApiKey instance
        let api_key = ApiKey::from_str(key).map_err(|e| e.to_string())?;
        let hash = api_key.hash_sha256();

        match args.output {
            OutputFormat::Json => output_json(&HashResult { hash }),
            OutputFormat::Plain => output_plain_dict(&[("hash", &hash)]),
        }
        return Ok(());
    }

    // Verify mode
    if let Some(verify_args) = &args.verify {
        let key = &verify_args[0];
        let stored_hash = &verify_args[1];
        let api_key = ApiKey::from_str(key).map_err(|e| e.to_string())?;
        let valid = api_key.verify(stored_hash);

        match args.output {
            OutputFormat::Json => output_json(&VerifyResult { valid }),
            OutputFormat::Plain => output_plain_dict(&[("valid", &valid.to_string())]),
        }
        return Ok(());
    }

    // Generate mode
    let key_type: ApiKeyType = args.key_type.into();
    let environment: Environment = args.env.into();

    let results: Vec<(String, String)> = (0..args.count)
        .map(|_| {
            let generated = ApiKey::builder()
                .key_type(key_type)
                .environment(environment)
                .length(args.length)
                .generate_with_hash()
                .map_err(|e| e.to_string())?;
            Ok((generated.key.to_string(), generated.key_hash))
        })
        .collect::<Result<Vec<_>, String>>()?;

    match args.output {
        OutputFormat::Json => {
            if args.count == 1 {
                let (key, key_hash) = &results[0];
                output_json(&ApiKeyResult {
                    key: key.clone(),
                    key_hash: key_hash.clone(),
                });
            } else {
                let keys: Vec<ApiKeyResult> = results
                    .into_iter()
                    .map(|(key, key_hash)| ApiKeyResult { key, key_hash })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({ "tokens": keys })).unwrap()
                );
            }
        }
        OutputFormat::Plain => {
            for (key, key_hash) in results {
                output_plain_dict(&[("key", &key), ("key_hash", &key_hash)]);
            }
        }
    }

    Ok(())
}

fn run_csrf(args: CsrfArgs) -> Result<(), String> {
    let secret = get_secret(args.secret.as_deref())?;

    // Verify mode
    if let Some(token_str) = &args.verify {
        let token: CsrfToken = token_str
            .parse()
            .map_err(|e| format!("Failed to parse token: {}", e))?;

        let valid = token
            .verify(&secret, &args.session_id, args.max_age)
            .is_ok();

        match args.output {
            OutputFormat::Json => output_json(&VerifyResult { valid }),
            OutputFormat::Plain => output_plain_dict(&[("valid", &valid.to_string())]),
        }
        return Ok(());
    }

    let results: Vec<String> = (0..args.count)
        .map(|_| {
            let token = CsrfToken::generate(&secret, &args.session_id, args.length)
                .map_err(|e| e.to_string())?;
            Ok(token.to_string())
        })
        .collect::<Result<Vec<_>, String>>()?;

    match args.output {
        OutputFormat::Json => {
            if args.count == 1 {
                output_json(&CsrfTokenResult {
                    token: results[0].clone(),
                });
            } else {
                let tokens: Vec<CsrfTokenResult> = results
                    .into_iter()
                    .map(|token| CsrfTokenResult { token })
                    .collect();
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({ "tokens": tokens })).unwrap()
                );
            }
        }
        OutputFormat::Plain => {
            for token in results {
                println!("{}", token);
            }
        }
    }

    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Auth(args) => run_auth(args),
        Commands::Api(args) => run_api(args),
        Commands::Csrf(args) => run_csrf(args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {}", e);
            ExitCode::FAILURE
        }
    }
}
