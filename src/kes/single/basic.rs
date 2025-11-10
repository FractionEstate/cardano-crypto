//! Single-period KES (base case)
//!
//! SingleKES wraps a standard digital signature algorithm (Ed25519) to provide
//! the KES interface for a single period (no forward security).

use core::marker::PhantomData;

use crate::common::error::{CryptoError, Result};
use crate::common::traits::DsignAlgorithm;
use crate::kes::{KesAlgorithm, KesError, Period};

/// SingleKES wraps a DSIGN algorithm to provide a 1-period KES.
///
/// This is the base case for KES composition. It simply delegates to the
/// underlying DSIGN algorithm and only supports period 0.
///
/// # Type Parameters
/// * `D` - The underlying digital signature algorithm
pub struct SingleKes<D: DsignAlgorithm>(PhantomData<D>);

impl<D> KesAlgorithm for SingleKes<D>
where
    D: DsignAlgorithm,
{
    type VerificationKey = D::VerificationKey;
    type SigningKey = D::SigningKey;
    type Signature = D::Signature;
    type Context = D::Context;

    const ALGORITHM_NAME: &'static str = D::ALGORITHM_NAME;
    const SEED_SIZE: usize = D::SEED_SIZE;
    const VERIFICATION_KEY_SIZE: usize = D::VERIFICATION_KEY_SIZE;
    const SIGNING_KEY_SIZE: usize = D::SIGNING_KEY_SIZE;
    const SIGNATURE_SIZE: usize = D::SIGNATURE_SIZE;

    fn total_periods() -> Period {
        1
    }

    fn derive_verification_key(
        signing_key: &Self::SigningKey,
    ) -> Result<Self::VerificationKey> {
        D::derive_verification_key(signing_key)
    }

    fn sign_kes(
        _context: &Self::Context,
        period: Period,
        message: &[u8],
        signing_key: &Self::SigningKey,
    ) -> Result<Self::Signature> {
        if period != 0 {
            return Err(CryptoError::KesError(KesError::PeriodOutOfRange {
                period,
                max_period: 0,
            }));
        }
        D::sign(message, signing_key)
    }

    fn verify_kes(
        _context: &Self::Context,
        verification_key: &Self::VerificationKey,
        period: Period,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<()> {
        if period != 0 {
            return Err(CryptoError::KesError(KesError::PeriodOutOfRange {
                period,
                max_period: 0,
            }));
        }
        D::verify(message, signature, verification_key)
    }

    fn update_kes(
        _context: &Self::Context,
        signing_key: Self::SigningKey,
        period: Period,
    ) -> Result<Option<Self::SigningKey>> {
        // Period 0 is the last valid period for SingleKES (total_periods = 1)
        if period >= Self::total_periods() - 1 {
            // Key expired after period 0
            D::forget_signing_key(signing_key);
            Ok(None)
        } else {
            // Still valid (though this branch never executes for SingleKES)
            Ok(Some(signing_key))
        }
    }

    fn gen_key_kes_from_seed_bytes(seed: &[u8]) -> Result<Self::SigningKey> {
        if seed.len() != Self::SEED_SIZE {
            return Err(CryptoError::KesError(KesError::InvalidSeedLength {
                expected: Self::SEED_SIZE,
                actual: seed.len(),
            }));
        }
        D::gen_key_from_seed(seed)
    }

    fn raw_serialize_verification_key_kes(key: &Self::VerificationKey) -> Vec<u8> {
        D::serialize_verification_key(key)
    }

    fn raw_deserialize_verification_key_kes(bytes: &[u8]) -> Option<Self::VerificationKey> {
        D::deserialize_verification_key(bytes).ok()
    }

    fn raw_serialize_signature_kes(signature: &Self::Signature) -> Vec<u8> {
        D::serialize_signature(signature)
    }

    fn raw_deserialize_signature_kes(bytes: &[u8]) -> Option<Self::Signature> {
        D::deserialize_signature(bytes).ok()
    }

    fn forget_signing_key_kes(signing_key: Self::SigningKey) {
        D::forget_signing_key(signing_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsign::ed25519::Ed25519;

    #[test]
    fn single_kes_only_supports_period_zero() {
        let seed = vec![1u8; <SingleKes<Ed25519>>::SEED_SIZE];
        let sk = <SingleKes<Ed25519>>::gen_key_kes_from_seed_bytes(&seed).unwrap();
        let vk = <SingleKes<Ed25519>>::derive_verification_key(&sk).unwrap();
        let msg = b"test-message";

        // Period 0 should work
        let sig = <SingleKes<Ed25519>>::sign_kes(&(), 0, msg, &sk).unwrap();
        <SingleKes<Ed25519>>::verify_kes(&(), &vk, 0, msg, &sig).unwrap();

        // Period 1 should fail
        assert!(<SingleKes<Ed25519>>::sign_kes(&(), 1, msg, &sk).is_err());
        assert!(<SingleKes<Ed25519>>::verify_kes(&(), &vk, 1, msg, &sig).is_err());
    }

    #[test]
    fn single_kes_update_expires_after_period_zero() {
        let seed = vec![2u8; <SingleKes<Ed25519>>::SEED_SIZE];
        let sk = <SingleKes<Ed25519>>::gen_key_kes_from_seed_bytes(&seed).unwrap();

        // After period 0, the key should expire
        let updated = <SingleKes<Ed25519>>::update_kes(&(), sk, 0).unwrap();
        assert!(updated.is_none(), "SingleKES should expire after period 0");
    }

    #[test]
    fn single_kes_serialization_roundtrip() {
        let seed = vec![3u8; <SingleKes<Ed25519>>::SEED_SIZE];
        let sk = <SingleKes<Ed25519>>::gen_key_kes_from_seed(&seed).unwrap();
        let vk = <SingleKes<Ed25519>>::derive_verification_key(&sk).unwrap();
        let msg = b"serialization-test";
        let sig = <SingleKes<Ed25519>>::sign_kes(&(), 0, msg, &sk).unwrap();

        // Serialize and deserialize verification key
        let vk_bytes = <SingleKes<Ed25519>>::raw_serialize_verification_key_kes(&vk);
        let vk_restored = <SingleKes<Ed25519>>::raw_deserialize_verification_key_kes(&vk_bytes)
            .expect("VK deserialization should succeed");

        // Serialize and deserialize signature
        let sig_bytes = <SingleKes<Ed25519>>::raw_serialize_signature_kes(&sig);
        let sig_restored = <SingleKes<Ed25519>>::raw_deserialize_signature_kes(&sig_bytes)
            .expect("Signature deserialization should succeed");

        // Verify with restored data
        <SingleKes<Ed25519>>::verify_kes(&(), &vk_restored, 0, msg, &sig_restored).unwrap();
    }
}
