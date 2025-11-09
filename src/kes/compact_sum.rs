//! Compact Sum KES implementations
//!
//! CompactSumKES optimizes signature size by omitting redundant verification keys.
//! Provides the same security as SumKES with smaller signatures.

use crate::common::Result;
use crate::kes::{KesAlgorithm, Period};

/// CompactSum0KES (1 period)
///
/// TODO: Extract from cardano-base-rust
pub struct CompactSum0Kes;

/// CompactSum1KES (2 periods)
///
/// TODO: Extract from cardano-base-rust
pub struct CompactSum1Kes;

/// CompactSum2KES (4 periods)
///
/// TODO: Extract from cardano-base-rust
pub struct CompactSum2Kes;

/// CompactSum3KES (8 periods)
///
/// TODO: Extract from cardano-base-rust
pub struct CompactSum3Kes;

/// CompactSum4KES (16 periods)
///
/// TODO: Extract from cardano-base-rust
pub struct CompactSum4Kes;

/// CompactSum5KES (32 periods)
///
/// TODO: Extract from cardano-base-rust
pub struct CompactSum5Kes;

/// CompactSum6KES (64 periods) - Most commonly used in Cardano
///
/// TODO: Extract from cardano-base-rust
pub struct CompactSum6Kes;

/// CompactSum7KES (128 periods)
///
/// TODO: Extract from cardano-base-rust
pub struct CompactSum7Kes;

// Macro to implement stub KesAlgorithm for each CompactSum variant
macro_rules! impl_compact_sum_kes_stub {
    ($name:ident, $periods:expr) => {
        impl KesAlgorithm for $name {
            type VerificationKey = [u8; 32];
            type SigningKey = Vec<u8>;
            type Signature = Vec<u8>;

            const SEED_SIZE: usize = 32;
            const VERIFICATION_KEY_SIZE: usize = 32;
            const SIGNING_KEY_SIZE: usize = 0; // Variable size
            const SIGNATURE_SIZE: usize = 0; // Variable size (smaller than Sum)

            fn total_periods() -> Period {
                $periods
            }

            fn gen_key_from_seed(_seed: &[u8]) -> Result<Self::SigningKey> {
                unimplemented!(concat!(stringify!($name), "::gen_key_from_seed"))
            }

            fn derive_verification_key(_signing_key: &Self::SigningKey) -> Result<Self::VerificationKey> {
                unimplemented!(concat!(stringify!($name), "::derive_verification_key"))
            }

            fn sign(
                _signing_key: &Self::SigningKey,
                _period: Period,
                _message: &[u8],
            ) -> Result<Self::Signature> {
                unimplemented!(concat!(stringify!($name), "::sign"))
            }

            fn verify(
                _verification_key: &Self::VerificationKey,
                _period: Period,
                _message: &[u8],
                _signature: &Self::Signature,
            ) -> Result<()> {
                unimplemented!(concat!(stringify!($name), "::verify"))
            }

            fn update_key(_signing_key: Self::SigningKey, _new_period: Period) -> Result<Self::SigningKey> {
                unimplemented!(concat!(stringify!($name), "::update_key"))
            }
        }
    };
}

impl_compact_sum_kes_stub!(CompactSum0Kes, 1);
impl_compact_sum_kes_stub!(CompactSum1Kes, 2);
impl_compact_sum_kes_stub!(CompactSum2Kes, 4);
impl_compact_sum_kes_stub!(CompactSum3Kes, 8);
impl_compact_sum_kes_stub!(CompactSum4Kes, 16);
impl_compact_sum_kes_stub!(CompactSum5Kes, 32);
impl_compact_sum_kes_stub!(CompactSum6Kes, 64);
impl_compact_sum_kes_stub!(CompactSum7Kes, 128);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_total_periods() {
        assert_eq!(CompactSum0Kes::total_periods(), 1);
        assert_eq!(CompactSum1Kes::total_periods(), 2);
        assert_eq!(CompactSum2Kes::total_periods(), 4);
        assert_eq!(CompactSum3Kes::total_periods(), 8);
        assert_eq!(CompactSum4Kes::total_periods(), 16);
        assert_eq!(CompactSum5Kes::total_periods(), 32);
        assert_eq!(CompactSum6Kes::total_periods(), 64);
        assert_eq!(CompactSum7Kes::total_periods(), 128);
    }
}
