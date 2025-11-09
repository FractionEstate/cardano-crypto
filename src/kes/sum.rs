//! Sum KES implementations
//!
//! SumKES uses binary tree composition to achieve 2^N periods from two N/2 instances.
//! Sum0Kes = SingleKES (1 period)
//! Sum1Kes = 2 periods
//! Sum2Kes = 4 periods
//! ...
//! Sum7Kes = 128 periods

use crate::common::Result;
use crate::kes::{KesAlgorithm, Period};

/// Sum0KES (1 period, equivalent to SingleKES)
///
/// TODO: Extract from cardano-base-rust
pub struct Sum0Kes;

/// Sum1KES (2 periods)
///
/// TODO: Extract from cardano-base-rust
pub struct Sum1Kes;

/// Sum2KES (4 periods)
///
/// TODO: Extract from cardano-base-rust
pub struct Sum2Kes;

/// Sum3KES (8 periods)
///
/// TODO: Extract from cardano-base-rust
pub struct Sum3Kes;

/// Sum4KES (16 periods)
///
/// TODO: Extract from cardano-base-rust
pub struct Sum4Kes;

/// Sum5KES (32 periods)
///
/// TODO: Extract from cardano-base-rust
pub struct Sum5Kes;

/// Sum6KES (64 periods) - Most commonly used in Cardano
///
/// TODO: Extract from cardano-base-rust
pub struct Sum6Kes;

/// Sum7KES (128 periods)
///
/// TODO: Extract from cardano-base-rust
pub struct Sum7Kes;

// Macro to implement stub KesAlgorithm for each Sum variant
macro_rules! impl_sum_kes_stub {
    ($name:ident, $periods:expr) => {
        impl KesAlgorithm for $name {
            type VerificationKey = [u8; 32];
            type SigningKey = Vec<u8>;
            type Signature = Vec<u8>;

            const SEED_SIZE: usize = 32;
            const VERIFICATION_KEY_SIZE: usize = 32;
            const SIGNING_KEY_SIZE: usize = 0; // Variable size
            const SIGNATURE_SIZE: usize = 0; // Variable size

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

impl_sum_kes_stub!(Sum0Kes, 1);
impl_sum_kes_stub!(Sum1Kes, 2);
impl_sum_kes_stub!(Sum2Kes, 4);
impl_sum_kes_stub!(Sum3Kes, 8);
impl_sum_kes_stub!(Sum4Kes, 16);
impl_sum_kes_stub!(Sum5Kes, 32);
impl_sum_kes_stub!(Sum6Kes, 64);
impl_sum_kes_stub!(Sum7Kes, 128);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_total_periods() {
        assert_eq!(Sum0Kes::total_periods(), 1);
        assert_eq!(Sum1Kes::total_periods(), 2);
        assert_eq!(Sum2Kes::total_periods(), 4);
        assert_eq!(Sum3Kes::total_periods(), 8);
        assert_eq!(Sum4Kes::total_periods(), 16);
        assert_eq!(Sum5Kes::total_periods(), 32);
        assert_eq!(Sum6Kes::total_periods(), 64);
        assert_eq!(Sum7Kes::total_periods(), 128);
    }
}
