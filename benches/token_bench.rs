//! Criterion benchmarks for token-gen.
//!
//! Benchmarks cover:
//! - AuthToken generation and verification
//! - ApiKey generation and hashing
//! - CsrfToken generation and verification

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::time::Duration;
use token_gen::{
    ApiKey, ApiKeyType, AuthToken, CsrfToken, Environment, Format, HashAlgorithm, SecretKey,
};

// =============================================================================
// AuthToken Benchmarks
// =============================================================================

fn bench_auth_token_generate(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_token_generate");

    // Benchmark various lengths
    for length in [16, 32, 64, 128] {
        group.bench_with_input(BenchmarkId::new("base64url", length), &length, |b, &len| {
            b.iter(|| AuthToken::generate(black_box(len), black_box(Format::Base64Url)));
        });

        group.bench_with_input(BenchmarkId::new("hex", length), &length, |b, &len| {
            b.iter(|| AuthToken::generate(black_box(len), black_box(Format::Hex)));
        });
    }

    group.finish();
}

fn bench_auth_token_builder(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_token_builder");

    let secret = SecretKey::from_string("benchmark-secret-key").unwrap();

    // Simple token (no expiration)
    group.bench_function("simple", |b| {
        b.iter(|| {
            AuthToken::builder()
                .length(black_box(32))
                .format(black_box(Format::Base64Url))
                .generate()
        });
    });

    // Expiring token
    group.bench_function("expiring", |b| {
        b.iter(|| {
            AuthToken::builder()
                .length(black_box(32))
                .format(black_box(Format::Base64Url))
                .expires_in(black_box(Duration::from_secs(3600)))
                .secret_key(&secret)
                .generate()
        });
    });

    // Various expiration durations
    for secs in [60, 3600, 86400] {
        group.bench_with_input(
            BenchmarkId::new("expires_in_secs", secs),
            &secs,
            |b, &secs| {
                b.iter(|| {
                    AuthToken::builder()
                        .length(black_box(32))
                        .expires_in(black_box(Duration::from_secs(secs)))
                        .secret_key(&secret)
                        .generate()
                });
            },
        );
    }

    group.finish();
}

fn bench_auth_token_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("auth_token_verify");

    let secret = SecretKey::from_string("benchmark-secret-key").unwrap();

    // Pre-generate token for verification benchmarks
    let token = AuthToken::builder()
        .length(32)
        .expires_in(Duration::from_secs(3600))
        .secret_key(&secret)
        .generate()
        .unwrap();

    group.bench_function("expiring_token", |b| {
        b.iter(|| black_box(&token).verify(&secret));
    });

    group.finish();
}

// =============================================================================
// ApiKey Benchmarks
// =============================================================================

fn bench_api_key_generate(c: &mut Criterion) {
    let mut group = c.benchmark_group("api_key_generate");

    // Benchmark various combinations
    for (key_type, key_name) in [
        (ApiKeyType::Api, "api"),
        (ApiKeyType::Secret, "secret"),
        (ApiKeyType::Public, "public"),
    ] {
        for (env, env_name) in [
            (Environment::Live, "live"),
            (Environment::Test, "test"),
            (Environment::Staging, "staging"),
        ] {
            let name = format!("{}_{}", key_name, env_name);
            group.bench_function(&name, |b| {
                b.iter(|| ApiKey::generate(black_box(key_type), black_box(env), black_box(32)));
            });
        }
    }

    // Benchmark various lengths
    for length in [16, 32, 64] {
        group.bench_with_input(BenchmarkId::new("length", length), &length, |b, len| {
            b.iter(|| {
                ApiKey::generate(
                    black_box(ApiKeyType::Api),
                    black_box(Environment::Live),
                    black_box(*len),
                )
            });
        });
    }

    group.finish();
}

fn bench_api_key_hash_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("api_key_hash_sha256");

    let key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();

    group.bench_function("hash", |b| {
        b.iter(|| black_box(&key).hash_sha256());
    });

    // Benchmark verification
    let hash = key.hash_sha256();
    group.bench_function("verify", |b| {
        b.iter(|| black_box(&key).verify(black_box(&hash)));
    });

    group.finish();
}

fn bench_api_key_hash_scrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("api_key_hash_scrypt");

    // Note: scrypt is intentionally slow, so we use smaller sample sizes
    group.sample_size(20);

    let key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();

    group.bench_function("hash", |b| {
        b.iter(|| black_box(&key).hash_scrypt());
    });

    // Benchmark verification
    let hash = key.hash_scrypt().unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| black_box(&key).verify(black_box(&hash)));
    });

    group.finish();
}

fn bench_api_key_hash_enum(c: &mut Criterion) {
    let mut group = c.benchmark_group("api_key_hash_enum");

    let key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();

    group.bench_function("sha256_via_enum", |b| {
        b.iter(|| black_box(&key).hash(black_box(HashAlgorithm::Sha256)));
    });

    // Scrypt is slow, reduce sample size
    group.sample_size(20);
    group.bench_function("scrypt_via_enum", |b| {
        b.iter(|| black_box(&key).hash(black_box(HashAlgorithm::Scrypt)));
    });

    group.finish();
}

// =============================================================================
// CsrfToken Benchmarks
// =============================================================================

fn bench_csrf_token_generate(c: &mut Criterion) {
    let mut group = c.benchmark_group("csrf_token_generate");

    let secret = SecretKey::from_string("benchmark-csrf-secret").unwrap();
    let session_id = "session-abc123";

    // Benchmark various lengths
    for length in [16, 32, 64] {
        group.bench_with_input(BenchmarkId::new("length", length), &length, |b, len| {
            b.iter(|| {
                CsrfToken::generate(black_box(&secret), black_box(session_id), black_box(*len))
            });
        });
    }

    // Benchmark with various session ID lengths
    for session_len in [8, 32, 64, 128] {
        let sid = "x".repeat(session_len);
        group.throughput(Throughput::Bytes(session_len as u64));
        group.bench_with_input(
            BenchmarkId::new("session_len", session_len),
            &sid,
            |b, sid| {
                b.iter(|| CsrfToken::generate(black_box(&secret), black_box(sid), black_box(32)));
            },
        );
    }

    group.finish();
}

fn bench_csrf_token_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("csrf_token_verify");

    let secret = SecretKey::from_string("benchmark-csrf-secret").unwrap();
    let session_id = "session-abc123";

    // Pre-generate token for verification benchmark
    let token = CsrfToken::generate(&secret, session_id, 32).unwrap();

    group.bench_function("verify", |b| {
        b.iter(|| {
            black_box(&token).verify(black_box(&secret), black_box(session_id), black_box(3600))
        });
    });

    // Benchmark with various max_age values
    for max_age in [60, 3600, 86400] {
        group.bench_with_input(BenchmarkId::new("max_age", max_age), &max_age, |b, &ma| {
            b.iter(|| {
                black_box(&token).verify(black_box(&secret), black_box(session_id), black_box(ma))
            });
        });
    }

    // Benchmark with various session ID lengths
    for session_len in [8, 32, 64, 128] {
        let sid = "x".repeat(session_len);
        let tok = CsrfToken::generate(&secret, &sid, 32).unwrap();
        group.throughput(Throughput::Bytes(session_len as u64));
        group.bench_with_input(
            BenchmarkId::new("session_len", session_len),
            &(tok, sid),
            |b, (tok, sid)| {
                b.iter(|| {
                    black_box(tok).verify(black_box(&secret), black_box(sid), black_box(3600))
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Combined/Real-world Scenarios
// =============================================================================

fn bench_real_world_scenarios(c: &mut Criterion) {
    let mut group = c.benchmark_group("real_world");

    let secret = SecretKey::from_string("production-secret-key").unwrap();
    let session_id = "user-session-12345";

    // Simulate a typical auth flow: generate token -> verify
    group.bench_function("auth_flow", |b| {
        b.iter(|| {
            let token = AuthToken::builder()
                .length(32)
                .expires_in(Duration::from_secs(3600))
                .secret_key(&secret)
                .generate()
                .unwrap();
            black_box(&token).verify(&secret)
        });
    });

    // Simulate CSRF flow: generate token -> verify
    group.bench_function("csrf_flow", |b| {
        b.iter(|| {
            let token = CsrfToken::generate(&secret, session_id, 32).unwrap();
            token.verify(&secret, session_id, 3600)
        });
    });

    // Simulate API key generation with hash
    group.bench_function("api_key_with_sha256", |b| {
        b.iter(|| {
            let key = ApiKey::generate(ApiKeyType::Api, Environment::Live, 32).unwrap();
            key.hash_sha256()
        });
    });

    group.finish();
}

// =============================================================================
// Benchmark Groups
// =============================================================================

criterion_group!(
    auth_token_benches,
    bench_auth_token_generate,
    bench_auth_token_builder,
    bench_auth_token_verify,
);

criterion_group!(
    api_key_benches,
    bench_api_key_generate,
    bench_api_key_hash_sha256,
    bench_api_key_hash_scrypt,
    bench_api_key_hash_enum,
);

criterion_group!(
    csrf_token_benches,
    bench_csrf_token_generate,
    bench_csrf_token_verify,
);

criterion_group!(real_world_benches, bench_real_world_scenarios);

criterion_main!(
    auth_token_benches,
    api_key_benches,
    csrf_token_benches,
    real_world_benches,
);
