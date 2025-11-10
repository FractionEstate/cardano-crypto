//! CompactSingleKES - Single-period KES with embedded verification key
//!
//! Unlike SingleKES, CompactSingleKES embeds the verification key directly in the signature.
//! This allows CompactSumKES to reconstruct verification keys from signatures, reducing
//! the number of keys that need to be stored in the binary tree.

use core::marker::PhantomData;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::common::error::{CryptoError, Result};
use crate::common::traits::DsignAlgorithm;
use crate::kes::{KesAlgorithm, KesError, Period};

/// CompactSingleKES wraps a DSIGN algorithm with an embedded verification key
///
/// The signature includes both the DSIGN signature and the verification key,
/// allowing CompactSumKES to reconstruct the Merkle tree without storing all keys.
///
/// # Type Parameters
/// * `D` - The underlying digital signature algorithm
#[derive(Debug)]
pub struct CompactSingleKes<D: DsignAlgorithm>(PhantomData<D>);

/// Signature type that embeds the verification key
#[derive(Clone, PartialEq, Eq)]
pub struct CompactSingleSig<D: DsignAlgorithm> {
    /// The underlying DSIGN signature
    pub(crate) signature: D::Signature,
    /// The verification key embedded in the signature
    pub(crate) verification_key: D::VerificationKey,
}

impl<D: DsignAlgorithm> core::fmt::Debug for CompactSingleSig<D>
where
    D::Signature: core::fmt::Debug,
    D::VerificationKey: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CompactSingleSig")
            .field("signature", &self.signature)
            .field("verification_key", &self.verification_key)
            .finish()
    }
}

/// Helper trait to extract the verification key from a KES signature
///
/// This is used by CompactSumKES to reconstruct verification keys from signatures.
pub trait OptimizedKesSignature {
    /// The verification key type
    type VerificationKey;

    /// Extract the embedded verification key
    fn extract_verification_key(&self) -> &Self::VerificationKey;
}

/// Trait for KES algorithms that support compact composition
///
/// This trait allows CompactSumKES to extract verification keys from signatures.
pub trait CompactKesComponents: KesAlgorithm {
    /// Extract the active verification key from a signature at a given period
    fn active_verification_key_from_signature(
        signature: &Self::Signature,
        period: Period,
    ) -> Self::VerificationKey;
}

impl<D: DsignAlgorithm> OptimizedKesSignature for CompactSingleSig<D> {
    type VerificationKey = D::VerificationKey;

    fn extract_verification_key(&self) -> &Self::VerificationKey {
        &self.verification_key
    }
}

impl<D> KesAlgorithm for CompactSingleKes<D>
where
    D: DsignAlgorithm,
    D::VerificationKey: Clone,
    D::Signature: Clone,
{
    type VerificationKey = D::VerificationKey;
    type SigningKey = D::SigningKey;
    type Signature = CompactSingleSig<D>;
    type Context = D::Context;

    const ALGORITHM_NAME: &'static str = D::ALGORITHM_NAME;
    const SEED_SIZE: usize = D::SEED_SIZE;
    const VERIFICATION_KEY_SIZE: usize = D::VERIFICATION_KEY_SIZE;
    const SIGNING_KEY_SIZE: usize = D::SIGNING_KEY_SIZE;
    // Signature size includes both DSIGN signature and verification key
    const SIGNATURE_SIZE: usize = D::SIGNATURE_SIZE + D::VERIFICATION_KEY_SIZE;

    fn total_periods() -> Period {
        1
    }

    fn derive_verification_key(signing_key: &Self::SigningKey) -> Result<Self::VerificationKey> {
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

        let signature = D::sign(message, signing_key)?;
        let verification_key = D::derive_verification_key(signing_key)?;

        Ok(CompactSingleSig {
            signature,
            verification_key,
        })
    }

    fn verify_kes(
        _context: &Self::Context,
        _verification_key: &Self::VerificationKey,
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

        // Verify using the embedded verification key from the signature
        D::verify(message, &signature.signature, &signature.verification_key)
    }

    fn update_kes(
        _context: &Self::Context,
        signing_key: Self::SigningKey,
        period: Period,
    ) -> Result<Option<Self::SigningKey>> {
        // Period 0 is the last valid period for CompactSingleKES
        if period >= Self::total_periods() - 1 {
            D::forget_signing_key(signing_key);
            Ok(None)
        } else {
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

    #[cfg(feature = "alloc")]
    fn raw_serialize_verification_key_kes(key: &Self::VerificationKey) -> Vec<u8> {
        D::serialize_verification_key(key)
    }

    fn raw_deserialize_verification_key_kes(bytes: &[u8]) -> Option<Self::VerificationKey> {
        D::deserialize_verification_key(bytes).ok()
    }

    #[cfg(feature = "alloc")]
    fn raw_serialize_signature_kes(signature: &Self::Signature) -> Vec<u8> {
        let mut result = D::serialize_signature(&signature.signature);
        result.extend_from_slice(&D::serialize_verification_key(&signature.verification_key));
        result
    }

    fn raw_deserialize_signature_kes(bytes: &[u8]) -> Option<Self::Signature> {
        if bytes.len() != Self::SIGNATURE_SIZE {
            return None;
        }

        let sig_bytes = &bytes[0..D::SIGNATURE_SIZE];
        let vk_bytes = &bytes[D::SIGNATURE_SIZE..];

        let signature = D::deserialize_signature(sig_bytes).ok()?;
        let verification_key = D::deserialize_verification_key(vk_bytes).ok()?;

        Some(CompactSingleSig {
            signature,
            verification_key,
        })
    }

    fn forget_signing_key_kes(signing_key: Self::SigningKey) {
        D::forget_signing_key(signing_key);
    }
}

impl<D> CompactKesComponents for CompactSingleKes<D>
where
    D: DsignAlgorithm,
    D::VerificationKey: Clone,
    D::Signature: Clone,
{
    fn active_verification_key_from_signature(
        signature: &Self::Signature,
        _period: Period,
    ) -> Self::VerificationKey {
        signature.verification_key.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsign::ed25519::Ed25519;

    type CompactSingleEd25519 = CompactSingleKes<Ed25519>;

    #[test]
    fn compact_single_only_supports_period_zero() {
        let seed = vec![1u8; CompactSingleEd25519::SEED_SIZE];
        let sk = CompactSingleEd25519::gen_key_kes_from_seed_bytes(&seed).unwrap();
        let vk = CompactSingleEd25519::derive_verification_key(&sk).unwrap();
        let msg = b"test-message";

        // Period 0 should work
        let sig = CompactSingleEd25519::sign_kes(&(), 0, msg, &sk).unwrap();
        CompactSingleEd25519::verify_kes(&(), &vk, 0, msg, &sig).unwrap();

        // Period 1 should fail
        assert!(CompactSingleEd25519::sign_kes(&(), 1, msg, &sk).is_err());
    }

    #[test]
    fn compact_single_embeds_verification_key() {
        let seed = vec![2u8; CompactSingleEd25519::SEED_SIZE];
        let sk = CompactSingleEd25519::gen_key_kes_from_seed_bytes(&seed).unwrap();
        let vk = CompactSingleEd25519::derive_verification_key(&sk).unwrap();
        let msg = b"embedded-vk-test";

        let sig = CompactSingleEd25519::sign_kes(&(), 0, msg, &sk).unwrap();

        // The embedded VK should match the derived VK
        assert_eq!(&sig.verification_key, &vk);

        // Extraction should work
        let extracted_vk = sig.extract_verification_key();
        assert_eq!(extracted_vk, &vk);
    }

    #[test]
    fn compact_single_signature_size() {
        let seed = vec![3u8; CompactSingleEd25519::SEED_SIZE];
        let sk = CompactSingleEd25519::gen_key_kes_from_seed_bytes(&seed).unwrap();
        let msg = b"size-test";

        let sig = CompactSingleEd25519::sign_kes(&(), 0, msg, &sk).unwrap();
        let sig_bytes = CompactSingleEd25519::raw_serialize_signature_kes(&sig);

        // Should be DSIGN signature + verification key
        let expected_size = Ed25519::SIGNATURE_SIZE + Ed25519::VERIFICATION_KEY_SIZE;
        assert_eq!(sig_bytes.len(), expected_size);
        assert_eq!(sig_bytes.len(), CompactSingleEd25519::SIGNATURE_SIZE);
    }

    #[test]
    fn compact_single_serialization_roundtrip() {
        let seed = vec![4u8; CompactSingleEd25519::SEED_SIZE];
        let sk = CompactSingleEd25519::gen_key_kes_from_seed_bytes(&seed).unwrap();
        let msg = b"roundtrip-test";

        let sig = CompactSingleEd25519::sign_kes(&(), 0, msg, &sk).unwrap();

        // Serialize and deserialize
        let sig_bytes = CompactSingleEd25519::raw_serialize_signature_kes(&sig);
        let sig_restored = CompactSingleEd25519::raw_deserialize_signature_kes(&sig_bytes)
            .expect("Signature deserialization should succeed");

        // Verify with restored signature
        let vk = CompactSingleEd25519::derive_verification_key(&sk).unwrap();
        CompactSingleEd25519::verify_kes(&(), &vk, 0, msg, &sig_restored).unwrap();
    }

    #[test]
    fn compact_single_update_expires_after_period_zero() {
        let seed = vec![5u8; CompactSingleEd25519::SEED_SIZE];
        let sk = CompactSingleEd25519::gen_key_kes_from_seed_bytes(&seed).unwrap();

        // After period 0, key should expire
        let updated = CompactSingleEd25519::update_kes(&(), sk, 0).unwrap();
        assert!(
            updated.is_none(),
            "CompactSingleKES should expire after period 0"
        );
    }

    #[test]
    fn compact_single_verification_uses_embedded_key() {
        let seed = vec![6u8; CompactSingleEd25519::SEED_SIZE];
        let sk = CompactSingleEd25519::gen_key_kes_from_seed_bytes(&seed).unwrap();
        let msg = b"embedded-verification";

        let sig = CompactSingleEd25519::sign_kes(&(), 0, msg, &sk).unwrap();

        // Even if we provide a different verification key, the signature
        // verification should use the embedded one
        let different_seed = vec![99u8; CompactSingleEd25519::SEED_SIZE];
        let different_sk =
            CompactSingleEd25519::gen_key_kes_from_seed_bytes(&different_seed).unwrap();
        let different_vk = CompactSingleEd25519::derive_verification_key(&different_sk).unwrap();

        // Verification with different VK parameter should still work
        // because the embedded VK in the signature is used
        let result = CompactSingleEd25519::verify_kes(&(), &different_vk, 0, msg, &sig);

        // This should succeed because CompactSingleKES ignores the passed VK
        // and uses the embedded one
        assert!(result.is_ok());
    }
}
