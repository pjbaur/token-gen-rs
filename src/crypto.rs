//! Cryptographic primitives for token generation.
//!
//! This module provides a trait-based interface for random number generation,
//! allowing for dependency injection in testing contexts.

use rand::TryRng;
use rand::rngs::SysRng;
use subtle::ConstantTimeEq;

use crate::error::TokenError;

/// Minimum entropy in bytes (128 bits).
pub const MIN_ENTROPY_BYTES: usize = 16;

/// Trait for random number generation.
///
/// Implement this trait to provide custom RNG for testing purposes.
pub trait TokenRng {
    /// Fill the destination buffer with random bytes.
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), TokenError>;
}

/// System random number generator using `SysRng`.
#[derive(Debug, Default)]
pub struct SystemRng {
    inner: SysRng,
}

impl SystemRng {
    /// Create a new system RNG.
    pub fn new() -> Self {
        Self::default()
    }
}

impl TokenRng for SystemRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), TokenError> {
        self.inner
            .try_fill_bytes(dest)
            .map_err(|e| TokenError::CryptoError(e.to_string()))
    }
}

/// Generate random bytes using the system RNG.
///
/// # Errors
///
/// Returns an error if the requested length is less than `MIN_ENTROPY_BYTES`
/// or if the system RNG fails.
pub fn generate_bytes(length: usize) -> Result<Vec<u8>, TokenError> {
    generate_bytes_with_rng(&mut SystemRng::new(), length)
}

/// Generate random bytes using a custom RNG.
///
/// # Errors
///
/// Returns an error if the requested length is less than `MIN_ENTROPY_BYTES`
/// or if the RNG fails.
pub fn generate_bytes_with_rng<R: TokenRng>(
    rng: &mut R,
    length: usize,
) -> Result<Vec<u8>, TokenError> {
    if length < MIN_ENTROPY_BYTES {
        return Err(TokenError::InsufficientEntropy {
            requested: length,
            minimum: MIN_ENTROPY_BYTES,
        });
    }

    let mut bytes = vec![0u8; length];
    rng.fill_bytes(&mut bytes)?;
    Ok(bytes)
}

/// Compare two byte slices in constant time.
///
/// This function is resistant to timing attacks.
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRng {
        counter: u8,
    }

    impl TestRng {
        fn new() -> Self {
            Self { counter: 0 }
        }
    }

    impl TokenRng for TestRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), TokenError> {
            for byte in dest.iter_mut() {
                *byte = self.counter;
                self.counter = self.counter.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[test]
    fn test_rng_generates_deterministic_bytes() {
        let mut rng = TestRng::new();
        let bytes = generate_bytes_with_rng(&mut rng, 16).unwrap();
        assert_eq!(
            bytes,
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
    }

    #[test]
    fn insufficient_entropy_error() {
        let result = generate_bytes(8);
        assert!(matches!(
            result,
            Err(TokenError::InsufficientEntropy { .. })
        ));
    }

    #[test]
    fn constant_time_compare_equal() {
        assert!(constant_time_compare(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_compare_not_equal() {
        assert!(!constant_time_compare(b"hello", b"world"));
    }

    #[test]
    fn system_rng_generates_unique_bytes() {
        let bytes1 = generate_bytes(32).unwrap();
        let bytes2 = generate_bytes(32).unwrap();
        assert_ne!(bytes1, bytes2);
    }
}
