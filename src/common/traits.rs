//! Common traits for cryptographic operations

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::common::error::Result;

/// Trait for digital signature algorithms
pub trait DsignAlgorithm {
    /// Verification key type
    type VerificationKey;
    /// Signing key type
    type SigningKey;
    /// Signature type
    type Signature;
    /// Context type (usually () for stateless algorithms)
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

    /// Generate key from seed
    fn gen_key_from_seed(seed: &[u8]) -> Result<Self::SigningKey>;

    /// Derive verification key from signing key
    fn derive_verification_key(signing_key: &Self::SigningKey) -> Result<Self::VerificationKey>;

    /// Sign a message
    fn sign(message: &[u8], signing_key: &Self::SigningKey) -> Result<Self::Signature>;

    /// Verify a signature
    fn verify(
        message: &[u8],
        signature: &Self::Signature,
        verification_key: &Self::VerificationKey,
    ) -> Result<()>;

    /// Serialize verification key
    fn serialize_verification_key(key: &Self::VerificationKey) -> Vec<u8>;

    /// Deserialize verification key
    fn deserialize_verification_key(bytes: &[u8]) -> Result<Self::VerificationKey>;

    /// Serialize signature
    fn serialize_signature(signature: &Self::Signature) -> Vec<u8>;

    /// Deserialize signature
    fn deserialize_signature(bytes: &[u8]) -> Result<Self::Signature>;

    /// Securely forget/zeroize signing key
    fn forget_signing_key(signing_key: Self::SigningKey);
}

/// Trait for types that can be signed/proven
pub trait SignableRepresentation {
    /// Get the byte representation of this type for signing
    fn signable_bytes(&self) -> &[u8];
}

impl SignableRepresentation for [u8] {
    fn signable_bytes(&self) -> &[u8] {
        self
    }
}

#[cfg(feature = "alloc")]
impl SignableRepresentation for Vec<u8> {
    fn signable_bytes(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const N: usize> SignableRepresentation for [u8; N] {
    fn signable_bytes(&self) -> &[u8] {
        self
    }
}

/// Constant-time equality comparison
pub trait ConstantTimeEq {
    /// Compare for equality in constant time
    fn ct_eq(&self, other: &Self) -> bool;
}

impl ConstantTimeEq for [u8] {
    fn ct_eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }

        let mut diff = 0u8;
        for (a, b) in self.iter().zip(other.iter()) {
            diff |= a ^ b;
        }
        diff == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constant_time_eq() {
        let a = [1u8, 2, 3, 4];
        let b = [1u8, 2, 3, 4];
        let c = [1u8, 2, 3, 5];

        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
    }
}
