//! Single-period KES (base case)
//!
//! SingleKES wraps a standard digital signature algorithm (Ed25519) to provide
//! the KES interface for a single period (no forward security).

use crate::common::Result;
use crate::kes::{KesAlgorithm, Period};

/// Single-period KES implementation
///
/// TODO: Extract from cardano-base-rust
pub struct SingleKes;

impl KesAlgorithm for SingleKes {
    type VerificationKey = [u8; 32];
    type SigningKey = [u8; 64];
    type Signature = [u8; 64];

    const SEED_SIZE: usize = 32;
    const VERIFICATION_KEY_SIZE: usize = 32;
    const SIGNING_KEY_SIZE: usize = 64;
    const SIGNATURE_SIZE: usize = 64;

    fn total_periods() -> Period {
        1
    }

    fn gen_key_from_seed(_seed: &[u8]) -> Result<Self::SigningKey> {
        // TODO: Implement from cardano-base-rust
        unimplemented!("SingleKes::gen_key_from_seed")
    }

    fn derive_verification_key(_signing_key: &Self::SigningKey) -> Result<Self::VerificationKey> {
        // TODO: Implement from cardano-base-rust
        unimplemented!("SingleKes::derive_verification_key")
    }

    fn sign(
        _signing_key: &Self::SigningKey,
        _period: Period,
        _message: &[u8],
    ) -> Result<Self::Signature> {
        // TODO: Implement from cardano-base-rust
        unimplemented!("SingleKes::sign")
    }

    fn verify(
        _verification_key: &Self::VerificationKey,
        _period: Period,
        _message: &[u8],
        _signature: &Self::Signature,
    ) -> Result<()> {
        // TODO: Implement from cardano-base-rust
        unimplemented!("SingleKes::verify")
    }

    fn update_key(_signing_key: Self::SigningKey, _new_period: Period) -> Result<Self::SigningKey> {
        // TODO: Implement from cardano-base-rust
        unimplemented!("SingleKes::update_key")
    }
}
