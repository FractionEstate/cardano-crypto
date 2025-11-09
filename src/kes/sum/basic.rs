//! SumKES - Binary tree KES composition
//!
//! This module implements the binary sum composition from the MMM paper
//! "Composition and Efficiency Tradeoffs for Forward-Secure Digital Signatures".
//!
//! SumKES composes two KES schemes to create a scheme with double the periods.
//! The signing key contains keys for both subtrees, and the verification key
//! is the hash of both subtree verification keys.

use core::marker::PhantomData;

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::common::error::{CryptoError, Result};
use crate::kes::hash::KesHashAlgorithm;
use crate::kes::{KesAlgorithm, KesError, Period};

/// SumKES composes two KES schemes to create a scheme with double the periods
///
/// # Type Parameters
/// * `D` - The child KES algorithm
/// * `H` - The hash algorithm for combining verification keys
pub struct SumKes<D, H>(PhantomData<(D, H)>)
where
    D: KesAlgorithm,
    H: KesHashAlgorithm;

/// Signing key for SumKES
///
/// Contains:
/// - `sk`: Current signing key (either left or right subtree)
/// - `r1_seed`: Seed for generating the right subtree key (when in left subtree)
/// - `vk0`, `vk1`: Verification keys for both subtrees
pub struct SumSigningKey<D, H>
where
    D: KesAlgorithm,
    H: KesHashAlgorithm,
{
    /// Current signing key
    pub(crate) sk: D::SigningKey,
    /// Seed for right subtree (None after transition)
    pub(crate) r1_seed: Option<Vec<u8>>,
    /// Left subtree verification key
    pub(crate) vk0: D::VerificationKey,
    /// Right subtree verification key
    pub(crate) vk1: D::VerificationKey,
    _phantom: PhantomData<H>,
}

/// Signature for SumKES includes child signature and both verification keys
#[derive(Clone, PartialEq, Eq)]
pub struct SumSignature<D, H>
where
    D: KesAlgorithm,
    H: KesHashAlgorithm,
{
    /// Child signature
    pub(crate) sigma: D::Signature,
    /// Left verification key
    pub(crate) vk0: D::VerificationKey,
    /// Right verification key
    pub(crate) vk1: D::VerificationKey,
    _phantom: PhantomData<H>,
}

impl<D, H> core::fmt::Debug for SumSignature<D, H>
where
    D: KesAlgorithm,
    D::Signature: core::fmt::Debug,
    D::VerificationKey: core::fmt::Debug,
    H: KesHashAlgorithm,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SumSignature")
            .field("sigma", &self.sigma)
            .field("vk0", &"<VK>")
            .field("vk1", &"<VK>")
            .finish()
    }
}

impl<D, H> KesAlgorithm for SumKes<D, H>
where
    D: KesAlgorithm,
    D::VerificationKey: Clone,
    D::Signature: Clone,
    H: KesHashAlgorithm,
{
    type VerificationKey = Vec<u8>; // Hash of (vk0, vk1)
    type SigningKey = SumSigningKey<D, H>;
    type Signature = SumSignature<D, H>;
    type Context = D::Context;

    const ALGORITHM_NAME: &'static str = D::ALGORITHM_NAME;
    const SEED_SIZE: usize = D::SEED_SIZE;
    const VERIFICATION_KEY_SIZE: usize = H::OUTPUT_SIZE;
    const SIGNING_KEY_SIZE: usize =
        D::SIGNING_KEY_SIZE + D::SEED_SIZE + 2 * D::VERIFICATION_KEY_SIZE;
    const SIGNATURE_SIZE: usize = D::SIGNATURE_SIZE + 2 * D::VERIFICATION_KEY_SIZE;

    fn total_periods() -> Period {
        2 * D::total_periods()
    }

    fn derive_verification_key(signing_key: &Self::SigningKey) -> Result<Self::VerificationKey> {
        // vk = H(vk0 || vk1)
        let vk0_bytes = D::raw_serialize_verification_key_kes(&signing_key.vk0);
        let vk1_bytes = D::raw_serialize_verification_key_kes(&signing_key.vk1);
        Ok(H::hash_concat(&vk0_bytes, &vk1_bytes))
    }

    fn sign_kes(
        context: &Self::Context,
        period: Period,
        message: &[u8],
        signing_key: &Self::SigningKey,
    ) -> Result<Self::Signature> {
        let t_half = D::total_periods();

        let sigma = if period < t_half {
            // Use left subtree
            D::sign_kes(context, period, message, &signing_key.sk)?
        } else {
            // Use right subtree
            D::sign_kes(context, period - t_half, message, &signing_key.sk)?
        };

        Ok(SumSignature {
            sigma,
            vk0: signing_key.vk0.clone(),
            vk1: signing_key.vk1.clone(),
            _phantom: PhantomData,
        })
    }

    fn verify_kes(
        context: &Self::Context,
        verification_key: &Self::VerificationKey,
        period: Period,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<()> {
        // Verify that H(vk0 || vk1) matches the provided verification key
        let vk0_bytes = D::raw_serialize_verification_key_kes(&signature.vk0);
        let vk1_bytes = D::raw_serialize_verification_key_kes(&signature.vk1);
        let computed_vk = H::hash_concat(&vk0_bytes, &vk1_bytes);

        if &computed_vk != verification_key {
            return Err(CryptoError::KesError(KesError::VerificationFailed));
        }

        let t_half = D::total_periods();

        if period < t_half {
            // Verify against left subtree
            D::verify_kes(context, &signature.vk0, period, message, &signature.sigma)
        } else {
            // Verify against right subtree
            D::verify_kes(
                context,
                &signature.vk1,
                period - t_half,
                message,
                &signature.sigma,
            )
        }
    }

    fn update_kes(
        context: &Self::Context,
        mut signing_key: Self::SigningKey,
        period: Period,
    ) -> Result<Option<Self::SigningKey>> {
        let t_half = D::total_periods();

        if period + 1 >= 2 * t_half {
            // Key has expired
            D::forget_signing_key_kes(signing_key.sk);
            return Ok(None);
        }

        if period + 1 == t_half {
            // Transition from left to right subtree
            let r1_seed = signing_key
                .r1_seed
                .take()
                .ok_or(CryptoError::KesError(KesError::KeyExpired))?;

            // Generate right subtree key
            let sk1 = D::gen_key_kes_from_seed(&r1_seed)?;

            // Forget left subtree key
            D::forget_signing_key_kes(signing_key.sk);

            Ok(Some(SumSigningKey {
                sk: sk1,
                r1_seed: None, // Seed consumed
                vk0: signing_key.vk0,
                vk1: signing_key.vk1,
                _phantom: PhantomData,
            }))
        } else if period + 1 < t_half {
            // Still in left subtree
            let updated_sk = D::update_kes(context, signing_key.sk, period)?;
            match updated_sk {
                Some(sk) => Ok(Some(SumSigningKey {
                    sk,
                    r1_seed: signing_key.r1_seed,
                    vk0: signing_key.vk0,
                    vk1: signing_key.vk1,
                    _phantom: PhantomData,
                })),
                None => Ok(None),
            }
        } else {
            // In right subtree
            let adjusted_period = period - t_half;
            let updated_sk = D::update_kes(context, signing_key.sk, adjusted_period)?;
            match updated_sk {
                Some(sk) => Ok(Some(SumSigningKey {
                    sk,
                    r1_seed: None,
                    vk0: signing_key.vk0,
                    vk1: signing_key.vk1,
                    _phantom: PhantomData,
                })),
                None => Ok(None),
            }
        }
    }

    fn gen_key_kes_from_seed(seed: &[u8]) -> Result<Self::SigningKey> {
        if seed.len() != Self::SEED_SIZE {
            return Err(CryptoError::KesError(KesError::InvalidSeedLength {
                expected: Self::SEED_SIZE,
                actual: seed.len(),
            }));
        }

        // Expand seed into two seeds
        let (r0_bytes, r1_bytes) = H::expand_seed(seed);

        // Generate keys for both subtrees
        let sk0 = D::gen_key_kes_from_seed(&r0_bytes)?;
        let vk0 = D::derive_verification_key(&sk0)?;

        let sk1 = D::gen_key_kes_from_seed(&r1_bytes)?;
        let vk1 = D::derive_verification_key(&sk1)?;
        D::forget_signing_key_kes(sk1); // Only keep left key initially

        Ok(SumSigningKey {
            sk: sk0,
            r1_seed: Some(r1_bytes),
            vk0,
            vk1,
            _phantom: PhantomData,
        })
    }

    fn raw_serialize_verification_key_kes(key: &Self::VerificationKey) -> Vec<u8> {
        key.clone()
    }

    fn raw_deserialize_verification_key_kes(bytes: &[u8]) -> Option<Self::VerificationKey> {
        if bytes.len() == Self::VERIFICATION_KEY_SIZE {
            Some(bytes.to_vec())
        } else {
            None
        }
    }

    fn raw_serialize_signature_kes(signature: &Self::Signature) -> Vec<u8> {
        let mut result = D::raw_serialize_signature_kes(&signature.sigma);
        result.extend_from_slice(&D::raw_serialize_verification_key_kes(&signature.vk0));
        result.extend_from_slice(&D::raw_serialize_verification_key_kes(&signature.vk1));
        result
    }

    fn raw_deserialize_signature_kes(bytes: &[u8]) -> Option<Self::Signature> {
        if bytes.len() != Self::SIGNATURE_SIZE {
            return None;
        }

        let sig_bytes = &bytes[0..D::SIGNATURE_SIZE];
        let vk0_offset = D::SIGNATURE_SIZE;
        let vk1_offset = vk0_offset + D::VERIFICATION_KEY_SIZE;

        let sigma = D::raw_deserialize_signature_kes(sig_bytes)?;
        let vk0 = D::raw_deserialize_verification_key_kes(&bytes[vk0_offset..vk1_offset])?;
        let vk1 = D::raw_deserialize_verification_key_kes(&bytes[vk1_offset..])?;

        Some(SumSignature {
            sigma,
            vk0,
            vk1,
            _phantom: PhantomData,
        })
    }

    fn forget_signing_key_kes(signing_key: Self::SigningKey) {
        D::forget_signing_key_kes(signing_key.sk);
        // r1_seed will be dropped automatically
    }
}

// Type aliases for standard KES depths using Blake2b256

use crate::dsign::ed25519::Ed25519;
use crate::kes::hash::Blake2b256;
use crate::kes::single::SingleKes;

/// Base case: SingleKES wrapping Ed25519
pub type Sum0Kes = SingleKes<Ed25519>;

/// 2^1 = 2 periods
pub type Sum1Kes = SumKes<Sum0Kes, Blake2b256>;

/// 2^2 = 4 periods
pub type Sum2Kes = SumKes<Sum1Kes, Blake2b256>;

/// 2^3 = 8 periods
pub type Sum3Kes = SumKes<Sum2Kes, Blake2b256>;

/// 2^4 = 16 periods
pub type Sum4Kes = SumKes<Sum3Kes, Blake2b256>;

/// 2^5 = 32 periods
pub type Sum5Kes = SumKes<Sum4Kes, Blake2b256>;

/// 2^6 = 64 periods
pub type Sum6Kes = SumKes<Sum5Kes, Blake2b256>;

/// 2^7 = 128 periods (standard Cardano KES)
pub type Sum7Kes = SumKes<Sum6Kes, Blake2b256>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sum1_total_periods() {
        assert_eq!(Sum1Kes::total_periods(), 2);
    }

    #[test]
    fn sum2_total_periods() {
        assert_eq!(Sum2Kes::total_periods(), 4);
    }

    #[test]
    fn sum3_total_periods() {
        assert_eq!(Sum3Kes::total_periods(), 8);
    }

    #[test]
    fn sum4_total_periods() {
        assert_eq!(Sum4Kes::total_periods(), 16);
    }

    #[test]
    fn sum1_key_generation_and_derivation() {
        let seed = vec![1u8; Sum1Kes::SEED_SIZE];
        let sk = Sum1Kes::gen_key_kes_from_seed(&seed).unwrap();
        let vk = Sum1Kes::derive_verification_key(&sk).unwrap();

        assert_eq!(vk.len(), Sum1Kes::VERIFICATION_KEY_SIZE);
        assert_eq!(vk.len(), 32); // Blake2b256 output
    }

    #[test]
    fn sum1_sign_and_verify_period_0() {
        let seed = vec![2u8; Sum1Kes::SEED_SIZE];
        let sk = Sum1Kes::gen_key_kes_from_seed(&seed).unwrap();
        let vk = Sum1Kes::derive_verification_key(&sk).unwrap();
        let msg = b"period-0-message";

        let sig = Sum1Kes::sign_kes(&(), 0, msg, &sk).unwrap();
        Sum1Kes::verify_kes(&(), &vk, 0, msg, &sig).unwrap();
    }

    #[test]
    fn sum1_sign_and_verify_period_1() {
        let seed = vec![3u8; Sum1Kes::SEED_SIZE];
        let sk = Sum1Kes::gen_key_kes_from_seed(&seed).unwrap();
        let vk = Sum1Kes::derive_verification_key(&sk).unwrap();

        // Update to period 1
        let sk = Sum1Kes::update_kes(&(), sk, 0).unwrap().unwrap();

        let msg = b"period-1-message";
        let sig = Sum1Kes::sign_kes(&(), 1, msg, &sk).unwrap();
        Sum1Kes::verify_kes(&(), &vk, 1, msg, &sig).unwrap();
    }

    #[test]
    fn sum1_key_expires_after_period_1() {
        let seed = vec![4u8; Sum1Kes::SEED_SIZE];
        let sk = Sum1Kes::gen_key_kes_from_seed(&seed).unwrap();

        // Update through period 0
        let sk = Sum1Kes::update_kes(&(), sk, 0).unwrap().unwrap();

        // Update after period 1 should return None (expired)
        let updated = Sum1Kes::update_kes(&(), sk, 1).unwrap();
        assert!(updated.is_none(), "Sum1Kes should expire after period 1");
    }

    #[test]
    fn sum2_full_lifecycle() {
        let seed = vec![5u8; Sum2Kes::SEED_SIZE];
        let mut sk = Sum2Kes::gen_key_kes_from_seed(&seed).unwrap();
        let vk = Sum2Kes::derive_verification_key(&sk).unwrap();

        // Test all 4 periods
        for period in 0..4 {
            let msg = format!("period-{}", period);
            let sig = Sum2Kes::sign_kes(&(), period, msg.as_bytes(), &sk).unwrap();
            Sum2Kes::verify_kes(&(), &vk, period, msg.as_bytes(), &sig).unwrap();

            if period < 3 {
                sk = Sum2Kes::update_kes(&(), sk, period).unwrap().unwrap();
            }
        }

        // Should expire after period 3
        let updated = Sum2Kes::update_kes(&(), sk, 3).unwrap();
        assert!(updated.is_none(), "Sum2Kes should expire after period 3");
    }

    #[test]
    fn sum1_signature_serialization() {
        let seed = vec![6u8; Sum1Kes::SEED_SIZE];
        let sk = Sum1Kes::gen_key_kes_from_seed(&seed).unwrap();
        let vk = Sum1Kes::derive_verification_key(&sk).unwrap();
        let msg = b"serialize-test";

        let sig = Sum1Kes::sign_kes(&(), 0, msg, &sk).unwrap();

        // Serialize and deserialize
        let sig_bytes = Sum1Kes::raw_serialize_signature_kes(&sig);
        let sig_restored = Sum1Kes::raw_deserialize_signature_kes(&sig_bytes).unwrap();

        // Verify with restored signature
        Sum1Kes::verify_kes(&(), &vk, 0, msg, &sig_restored).unwrap();
    }
}
