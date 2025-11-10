//! Hash algorithms for KES schemes
//!
//! This module provides hash algorithm wrappers specifically designed for use in
//! Key Evolving Signature (KES) constructions. These are used for:
//! - Hashing verification keys in Sum/CompactSum compositions
//! - Seed expansion for subtree generation
//!
//! All implementations use Blake2b variants matching Cardano's conventions.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::hash::HashAlgorithm;

/// Trait for hash algorithms used in KES schemes
///
/// This trait provides the interface needed for hash operations in
/// KES binary tree constructions, particularly for Sum and CompactSum variants.
pub trait KesHashAlgorithm: Clone + Send + Sync + 'static {
    /// The size of the hash output in bytes
    const OUTPUT_SIZE: usize;

    /// The name of the hash algorithm (for debugging)
    const ALGORITHM_NAME: &'static str;

    /// Hash arbitrary data and return a fixed-size output
    fn hash(data: &[u8]) -> Vec<u8>;

    /// Hash two pieces of data concatenated together
    ///
    /// Default implementation concatenates then hashes, but can be overridden for efficiency.
    #[must_use]
    fn hash_concat(data1: &[u8], data2: &[u8]) -> Vec<u8> {
        let mut combined = Vec::with_capacity(data1.len() + data2.len());
        combined.extend_from_slice(data1);
        combined.extend_from_slice(data2);
        Self::hash(&combined)
    }

    /// Expand a seed into two seeds using the hash algorithm
    ///
    /// This is used for seed expansion in Sum/CompactSum compositions.
    /// Returns (left_seed, right_seed) for the two subtrees.
    #[must_use]
    fn expand_seed(seed: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // Hash with different prefixes to derive independent seeds
        let mut left_input = Vec::with_capacity(seed.len() + 1);
        left_input.push(0x00);
        left_input.extend_from_slice(seed);
        let left_seed = Self::hash(&left_input);

        let mut right_input = Vec::with_capacity(seed.len() + 1);
        right_input.push(0x01);
        right_input.extend_from_slice(seed);
        let right_seed = Self::hash(&right_input);

        (left_seed, right_seed)
    }
}

/// Blake2b-224 for KES (28-byte output)
#[derive(Clone, Debug)]
pub struct Blake2b224;

impl KesHashAlgorithm for Blake2b224 {
    const OUTPUT_SIZE: usize = 28;
    const ALGORITHM_NAME: &'static str = "Blake2b-224";

    fn hash(data: &[u8]) -> Vec<u8> {
        crate::hash::Blake2b224::hash(data).to_vec()
    }
}

/// Blake2b-256 for KES (32-byte output)
///
/// This is the standard hash used in Cardano KES implementations for Sum and CompactSum.
#[derive(Clone, Debug)]
pub struct Blake2b256;

impl KesHashAlgorithm for Blake2b256 {
    const OUTPUT_SIZE: usize = 32;
    const ALGORITHM_NAME: &'static str = "Blake2b-256";

    fn hash(data: &[u8]) -> Vec<u8> {
        crate::hash::Blake2b256::hash(data).to_vec()
    }
}

/// Blake2b-512 for KES (64-byte output)
#[derive(Clone, Debug)]
pub struct Blake2b512;

impl KesHashAlgorithm for Blake2b512 {
    const OUTPUT_SIZE: usize = 64;
    const ALGORITHM_NAME: &'static str = "Blake2b-512";

    fn hash(data: &[u8]) -> Vec<u8> {
        crate::hash::Blake2b512::hash(data).to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2b224_output_size() {
        let data = b"test data";
        let hash = Blake2b224::hash(data);
        assert_eq!(hash.len(), Blake2b224::OUTPUT_SIZE);
        assert_eq!(hash.len(), 28);
    }

    #[test]
    fn blake2b256_output_size() {
        let data = b"test data";
        let hash = Blake2b256::hash(data);
        assert_eq!(hash.len(), Blake2b256::OUTPUT_SIZE);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn blake2b512_output_size() {
        let data = b"test data";
        let hash = Blake2b512::hash(data);
        assert_eq!(hash.len(), Blake2b512::OUTPUT_SIZE);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn blake2b256_deterministic() {
        let data = b"cardano";
        let hash1 = Blake2b256::hash(data);
        let hash2 = Blake2b256::hash(data);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn blake2b256_different_inputs() {
        let hash1 = Blake2b256::hash(b"input1");
        let hash2 = Blake2b256::hash(b"input2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn blake2b256_hash_concat() {
        let data1 = b"hello";
        let data2 = b"world";

        // Manual concatenation
        let mut combined = Vec::new();
        combined.extend_from_slice(data1);
        combined.extend_from_slice(data2);
        let hash_manual = Blake2b256::hash(&combined);

        // Using hash_concat
        let hash_concat = Blake2b256::hash_concat(data1, data2);

        assert_eq!(hash_manual, hash_concat);
    }

    #[test]
    fn blake2b256_seed_expansion() {
        let seed = b"master-seed-for-kes-tree";
        let (left, right) = Blake2b256::expand_seed(seed);

        // Outputs should be correct size
        assert_eq!(left.len(), 32);
        assert_eq!(right.len(), 32);

        // Outputs should be different (independent seeds)
        assert_ne!(left, right);

        // Should be deterministic
        let (left2, right2) = Blake2b256::expand_seed(seed);
        assert_eq!(left, left2);
        assert_eq!(right, right2);
    }

    #[test]
    fn different_hash_sizes() {
        let data = b"same input data";

        let hash224 = Blake2b224::hash(data);
        let hash256 = Blake2b256::hash(data);
        let hash512 = Blake2b512::hash(data);

        assert_eq!(hash224.len(), 28);
        assert_eq!(hash256.len(), 32);
        assert_eq!(hash512.len(), 64);

        // All should be different (different output sizes)
        assert_ne!(hash224.len(), hash256.len());
        assert_ne!(hash256.len(), hash512.len());
    }
}
