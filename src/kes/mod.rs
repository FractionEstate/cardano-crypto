//! Key Evolving Signatures (KES)
//!
//! This module provides KES implementations following the paper:
//! "Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures"
//! by Malkin, Micciancio, and Miner.
//!
//! Implementations:
//! - SingleKES - Single-period signature (base case)
//! - Sum0Kes through Sum7Kes - Binary tree composition (2^0 to 2^7 periods)
//! - CompactSum variants - Optimized signatures with smaller size

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::common::Result;

pub mod single;
pub mod sum;
pub mod compact_sum;

pub use single::SingleKes;
pub use sum::{Sum0Kes, Sum1Kes, Sum2Kes, Sum3Kes, Sum4Kes, Sum5Kes, Sum6Kes, Sum7Kes};
pub use compact_sum::{
    CompactSum0Kes, CompactSum1Kes, CompactSum2Kes, CompactSum3Kes, CompactSum4Kes,
    CompactSum5Kes, CompactSum6Kes, CompactSum7Kes,
};

/// KES period type (0 to 2^N - 1)
pub type Period = u64;

/// Trait for KES algorithms
pub trait KesAlgorithm {
    /// Verification key type
    type VerificationKey;
    /// Signing key type
    type SigningKey;
    /// Signature type
    type Signature;

    /// Seed size in bytes
    const SEED_SIZE: usize;
    /// Verification key size in bytes
    const VERIFICATION_KEY_SIZE: usize;
    /// Signing key size in bytes
    const SIGNING_KEY_SIZE: usize;
    /// Signature size in bytes
    const SIGNATURE_SIZE: usize;

    /// Total number of periods this KES scheme supports
    fn total_periods() -> Period;

    /// Generate key from seed
    fn gen_key_from_seed(seed: &[u8]) -> Result<Self::SigningKey>;

    /// Derive verification key from signing key
    fn derive_verification_key(signing_key: &Self::SigningKey) -> Result<Self::VerificationKey>;

    /// Sign a message at a specific period
    fn sign(
        signing_key: &Self::SigningKey,
        period: Period,
        message: &[u8],
    ) -> Result<Self::Signature>;

    /// Verify a signature at a specific period
    fn verify(
        verification_key: &Self::VerificationKey,
        period: Period,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<()>;

    /// Update signing key to next period (evolve the key)
    fn update_key(signing_key: Self::SigningKey, new_period: Period) -> Result<Self::SigningKey>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_period_type() {
        let period: Period = 42;
        assert_eq!(period, 42u64);
    }
}
