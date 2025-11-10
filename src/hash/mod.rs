//! Hash functions used in Cardano cryptography
//!
//! This module provides hash functions required for Cardano protocols:
//!
//! - [`Blake2b224`] - 28-byte Blake2b hash (used in address derivation)
//! - [`Blake2b256`] - 32-byte Blake2b hash (used in KES verification keys)
//! - [`Blake2b512`] - 64-byte Blake2b hash (general purpose)
//! - Additional cross-chain hashes (SHA-256, SHA-512, etc.) for compatibility

use alloc::vec::Vec;

mod blake2b;
mod sha;

// Re-export hash implementations
pub use blake2b::{Blake2b224, Blake2b256, Blake2b512};
pub use sha::{hash160, keccak256, ripemd160, sha256, sha256d, sha3_256, sha3_512, sha512};

/// Trait for hash algorithms used in KES schemes
///
/// This trait provides a simple interface for hash algorithms used in
/// Key Evolving Signature (KES) constructions, particularly for the
/// binary sum composition where verification keys are hashed.
pub trait HashAlgorithm: Clone + Send + Sync + 'static {
    /// Output size in bytes
    const OUTPUT_SIZE: usize;

    /// Algorithm name for debugging
    const ALGORITHM_NAME: &'static str;

    /// Hash the input data
    fn hash(data: &[u8]) -> Vec<u8>;

    /// Hash two inputs concatenated together
    fn hash_concat(data1: &[u8], data2: &[u8]) -> Vec<u8> {
        let mut combined = Vec::with_capacity(data1.len() + data2.len());
        combined.extend_from_slice(data1);
        combined.extend_from_slice(data2);
        Self::hash(&combined)
    }

    /// Expand a seed into two new seeds using domain separation
    fn expand_seed(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut seed0_input = Vec::with_capacity(seed.len() + 1);
        seed0_input.extend_from_slice(seed);
        seed0_input.push(0);
        let seed0 = Self::hash(&seed0_input);

        let mut seed1_input = Vec::with_capacity(seed.len() + 1);
        seed1_input.extend_from_slice(seed);
        seed1_input.push(1);
        let seed1 = Self::hash(&seed1_input);

        (seed0, seed1)
    }
}

/// Constant-time equality over raw hash byte slices
///
/// Returns `false` if the inputs differ in length. When lengths match, the
/// comparison is performed in constant time to prevent timing attacks.
#[must_use]
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;

    if a.len() != b.len() {
        return false;
    }

    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq(b"hello", b"hello"));
        assert!(!constant_time_eq(b"hello", b"world"));
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn test_all_hash_lengths() {
        let data = b"test data";

        assert_eq!(sha256(data).len(), 32);
        assert_eq!(sha256d(data).len(), 32);
        assert_eq!(sha512(data).len(), 64);
        assert_eq!(sha3_256(data).len(), 32);
        assert_eq!(sha3_512(data).len(), 64);
        assert_eq!(keccak256(data).len(), 32);
        assert_eq!(ripemd160(data).len(), 20);
        assert_eq!(hash160(data).len(), 20);
    }

    #[test]
    fn test_blake2b_output_lengths() {
        let inputs = [b"".as_ref(), b"cardano".as_ref(), b"hash-length".as_ref()];

        for input in inputs {
            assert_eq!(Blake2b224::hash(input).len(), 28);
            assert_eq!(Blake2b256::hash(input).len(), 32);
            assert_eq!(Blake2b512::hash(input).len(), 64);
        }
    }
}
