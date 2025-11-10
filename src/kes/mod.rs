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

use crate::common::error::Result;

pub mod hash;
pub mod single;
pub mod sum;
pub mod test_vectors;

pub use hash::{Blake2b224, Blake2b256, Blake2b512, KesHashAlgorithm};
pub use single::{CompactSingleKes, CompactSingleSig, OptimizedKesSignature, SingleKes};
pub use sum::{
    CompactSum0Kes, CompactSum1Kes, CompactSum2Kes, CompactSum3Kes, CompactSum4Kes, CompactSum5Kes,
    CompactSum6Kes, CompactSum7Kes, CompactSumKes, Sum0Kes, Sum1Kes, Sum2Kes, Sum3Kes, Sum4Kes,
    Sum5Kes, Sum6Kes, Sum7Kes, SumKes,
};

/// KES period type (0 to 2^N - 1)
pub type Period = u64;

/// KES-specific errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KesError {
    /// Period out of valid range
    PeriodOutOfRange {
        /// Current period
        period: Period,
        /// Maximum allowed period
        max_period: Period,
    },
    /// Key has expired
    KeyExpired,
    /// Verification failed
    VerificationFailed,
    /// Invalid seed length
    InvalidSeedLength {
        /// Expected seed length
        expected: usize,
        /// Actual seed length provided
        actual: usize,
    },
    /// Key update failed
    UpdateFailed,
}

impl core::fmt::Display for KesError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::PeriodOutOfRange { period, max_period } => {
                write!(f, "Period {} out of range (max: {})", period, max_period)
            }
            Self::KeyExpired => write!(f, "KES key has expired"),
            Self::VerificationFailed => write!(f, "KES signature verification failed"),
            Self::InvalidSeedLength { expected, actual } => {
                write!(
                    f,
                    "Invalid seed length: expected {} bytes, got {}",
                    expected, actual
                )
            }
            Self::UpdateFailed => write!(f, "KES key update failed"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for KesError {}

/// Trait for KES algorithms
///
/// Follows the design from "Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures"
/// by Tal Malkin, Daniele Micciancio, and Sara Miner (<https://eprint.iacr.org/2001/034>).
pub trait KesAlgorithm {
    /// Verification key type
    type VerificationKey;
    /// Signing key type
    type SigningKey;
    /// Signature type
    type Signature;
    /// Context type (usually () for most implementations)
    type Context;

    /// Algorithm name
    const ALGORITHM_NAME: &'static str;
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

    /// Generate signing key from seed bytes
    fn gen_key_kes_from_seed_bytes(seed: &[u8]) -> Result<Self::SigningKey>;

    /// Derive verification key from signing key
    fn derive_verification_key(signing_key: &Self::SigningKey) -> Result<Self::VerificationKey>;

    /// Sign a message at a specific period
    fn sign_kes(
        context: &Self::Context,
        period: Period,
        message: &[u8],
        signing_key: &Self::SigningKey,
    ) -> Result<Self::Signature>;

    /// Verify a signature at a specific period
    fn verify_kes(
        context: &Self::Context,
        verification_key: &Self::VerificationKey,
        period: Period,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<()>;

    /// Update signing key to next period (returns None if key expired)
    fn update_kes(
        context: &Self::Context,
        signing_key: Self::SigningKey,
        period: Period,
    ) -> Result<Option<Self::SigningKey>>;

    /// Serialize verification key
    #[cfg(feature = "alloc")]
    fn raw_serialize_verification_key_kes(key: &Self::VerificationKey) -> Vec<u8>;

    /// Deserialize verification key
    fn raw_deserialize_verification_key_kes(bytes: &[u8]) -> Option<Self::VerificationKey>;

    /// Serialize signature
    #[cfg(feature = "alloc")]
    fn raw_serialize_signature_kes(signature: &Self::Signature) -> Vec<u8>;

    /// Deserialize signature
    fn raw_deserialize_signature_kes(bytes: &[u8]) -> Option<Self::Signature>;

    /// Securely forget/zeroize signing key
    fn forget_signing_key_kes(signing_key: Self::SigningKey);
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
