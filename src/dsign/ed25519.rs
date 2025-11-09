//! Ed25519 digital signature implementation
//!
//! Pure Rust Ed25519 signatures compatible with Cardano.
//! Extracted and adapted from cardano-base-rust.

use crate::common::CryptoError;
use super::DsignAlgorithm;

use ed25519_dalek::{
    Signature as DalekSignature, SigningKey as DalekSigningKey, VerifyingKey as DalekVerifyingKey,
};
use ed25519_dalek::{Signer, Verifier};

const SEED_SIZE: usize = 32;
const VERIFICATION_KEY_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;
const SECRET_COMPOUND_SIZE: usize = 64;

/// Ed25519 verification key (32 bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519VerificationKey([u8; VERIFICATION_KEY_SIZE]);

impl core::fmt::Debug for Ed25519VerificationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ed25519VerificationKey({})", hex::encode(&self.0))
    }
}

impl Ed25519VerificationKey {
    /// Create from bytes, validating that they represent a valid Ed25519 point
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != VERIFICATION_KEY_SIZE {
            return None;
        }
        let mut array = [0u8; VERIFICATION_KEY_SIZE];
        array.copy_from_slice(bytes);
        // Validate that this is a valid verification key
        DalekVerifyingKey::from_bytes(&array).ok()?;
        Some(Self(array))
    }

    /// Get the raw bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; VERIFICATION_KEY_SIZE] {
        &self.0
    }
}

/// Ed25519 signing key (64 bytes: 32-byte seed + 32-byte verification key)
///
/// This matches the libsodium/Cardano convention of storing both the seed
/// and the derived verification key together.
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519SigningKey([u8; SECRET_COMPOUND_SIZE]);

impl core::fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ed25519SigningKey([REDACTED])")
    }
}

impl Ed25519SigningKey {
    /// Create signing key from seed bytes
    ///
    /// The signing key stores both the seed (first 32 bytes) and the
    /// derived verification key (last 32 bytes).
    pub fn from_seed_bytes(seed: &[u8]) -> Self {
        let mut seed_array = [0u8; SEED_SIZE];
        seed_array.copy_from_slice(seed);

        let signing_key = DalekSigningKey::from_bytes(&seed_array);
        let verifying_key = signing_key.verifying_key();

        let mut compound = [0u8; SECRET_COMPOUND_SIZE];
        compound[..SEED_SIZE].copy_from_slice(&seed_array);
        compound[SEED_SIZE..].copy_from_slice(&verifying_key.to_bytes());

        Self(compound)
    }

    /// Get the seed bytes (first 32 bytes)
    #[must_use]
    pub fn seed_bytes(&self) -> [u8; SEED_SIZE] {
        let mut seed = [0u8; SEED_SIZE];
        seed.copy_from_slice(&self.0[..SEED_SIZE]);
        seed
    }

    /// Get the verification key bytes (last 32 bytes)
    #[must_use]
    pub fn verifying_bytes(&self) -> [u8; VERIFICATION_KEY_SIZE] {
        let mut vk = [0u8; VERIFICATION_KEY_SIZE];
        vk.copy_from_slice(&self.0[SEED_SIZE..]);
        vk
    }

    /// Get the dalek signing key for actual signing operations
    fn signing_key(&self) -> DalekSigningKey {
        let seed = self.seed_bytes();
        DalekSigningKey::from_bytes(&seed)
    }

    /// Get the compound bytes (all 64 bytes)
    #[must_use]
    pub fn compound_bytes(&self) -> &[u8; SECRET_COMPOUND_SIZE] {
        &self.0
    }
}

/// Ed25519 signature (64 bytes)
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519Signature([u8; SIGNATURE_SIZE]);

impl core::fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ed25519Signature({})", hex::encode(&self.0))
    }
}

impl Ed25519Signature {
    /// Create from dalek signature
    pub fn from_dalek(signature: &DalekSignature) -> Self {
        Self(signature.to_bytes())
    }

    /// Get the raw bytes
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; SIGNATURE_SIZE] {
        &self.0
    }
}

/// Ed25519 digital signature algorithm
///
/// Standard Ed25519 as used in Cardano transactions and stake pool operations.
/// This implementation is byte-for-byte compatible with Cardano's Ed25519 usage.
#[derive(Clone, Debug)]
pub struct Ed25519;

impl DsignAlgorithm for Ed25519 {
    type SigningKey = Ed25519SigningKey;
    type VerificationKey = Ed25519VerificationKey;
    type Signature = Ed25519Signature;

    const ALGORITHM_NAME: &'static str = "Ed25519";
    const SIGNING_KEY_SIZE: usize = SECRET_COMPOUND_SIZE;
    const VERIFICATION_KEY_SIZE: usize = VERIFICATION_KEY_SIZE;
    const SIGNATURE_SIZE: usize = SIGNATURE_SIZE;

    fn derive_verification_key(signing_key: &Self::SigningKey) -> Self::VerificationKey {
        let mut bytes = [0u8; VERIFICATION_KEY_SIZE];
        bytes.copy_from_slice(&signing_key.verifying_bytes());
        Ed25519VerificationKey(bytes)
    }

    fn sign(signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature {
        let signing_key = signing_key.signing_key();
        let signature = signing_key.sign(message);
        Ed25519Signature::from_dalek(&signature)
    }

    fn verify(
        verification_key: &Self::VerificationKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), CryptoError> {
        let verifying_key = DalekVerifyingKey::from_bytes(verification_key.as_bytes())
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        let signature = DalekSignature::try_from(signature.as_bytes().as_ref())
            .map_err(|_| CryptoError::InvalidSignature)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn gen_key(seed: &[u8]) -> Self::SigningKey {
        assert_eq!(seed.len(), SEED_SIZE, "Ed25519 seed must be exactly 32 bytes");
        Ed25519SigningKey::from_seed_bytes(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation_deterministic() {
        let seed = [7u8; 32];
        let signing1 = Ed25519::gen_key(&seed);
        let signing2 = Ed25519::gen_key(&seed);
        assert_eq!(signing1.compound_bytes(), signing2.compound_bytes());
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let seed = [42u8; 32];
        let signing_key = Ed25519::gen_key(&seed);
        let verification_key = Ed25519::derive_verification_key(&signing_key);

        let message = b"cardano";
        let signature = Ed25519::sign(&signing_key, message);

        let result = Ed25519::verify(&verification_key, message, &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_fails_wrong_message() {
        let seed = [9u8; 32];
        let signing_key = Ed25519::gen_key(&seed);
        let verification_key = Ed25519::derive_verification_key(&signing_key);

        let signature = Ed25519::sign(&signing_key, b"hello");
        let result = Ed25519::verify(&verification_key, b"world", &signature);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CryptoError::VerificationFailed);
    }

    #[test]
    fn test_verify_fails_wrong_key() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let signing_key1 = Ed25519::gen_key(&seed1);
        let signing_key2 = Ed25519::gen_key(&seed2);
        let verification_key2 = Ed25519::derive_verification_key(&signing_key2);

        let message = b"test";
        let signature1 = Ed25519::sign(&signing_key1, message);

        let result = Ed25519::verify(&verification_key2, message, &signature1);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_message() {
        let seed = [42u8; 32];
        let signing_key = Ed25519::gen_key(&seed);
        let verification_key = Ed25519::derive_verification_key(&signing_key);

        let signature = Ed25519::sign(&signing_key, b"");
        let result = Ed25519::verify(&verification_key, b"", &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_large_message() {
        let seed = [99u8; 32];
        let signing_key = Ed25519::gen_key(&seed);
        let verification_key = Ed25519::derive_verification_key(&signing_key);

        let large_message = vec![0xAB; 10_000];
        let signature = Ed25519::sign(&signing_key, &large_message);
        let result = Ed25519::verify(&verification_key, &large_message, &signature);
        assert!(result.is_ok());
    }
}

// Helper for hex encoding in tests
#[cfg(test)]
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
