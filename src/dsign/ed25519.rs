//! Ed25519 digital signature implementation
//!
//! Provides a pure Rust implementation of the Ed25519 signature algorithm that is
//! fully compatible with Cardano's signature verification. Ed25519 is the primary
//! signature scheme used in Cardano for:
//!
//! - Transaction signing and verification
//! - Stake pool operator keys
//! - Payment address authentication
//! - Governance actions
//!
//! # Specification
//!
//! - **Algorithm**: Ed25519 (Edwards-curve Digital Signature Algorithm)
//! - **Curve**: Edwards25519 (twisted Edwards form of Curve25519)
//! - **Security Level**: 128 bits (equivalent to 256-bit symmetric encryption)
//! - **Public Key**: 32 bytes
//! - **Signature**: 64 bytes
//! - **Secret Key**: 64 bytes (32-byte seed + 32-byte public key, Cardano format)
//!
//! # Cardano Compatibility
//!
//! This implementation follows the same Ed25519 format used by Cardano nodes,
//! ensuring full interoperability. Signatures generated here can be verified
//! by Cardano and vice versa.
//!
//! # Security Features
//!
//! - Constant-time operations to prevent timing attacks
//! - Protection against side-channel attacks
//! - Deterministic signatures (no random number generation during signing)
//! - Small keys and signatures for efficient storage and transmission
//!
//! # Examples
//!
//! ```
//! use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
//!
//! // Generate keypair from seed
//! let seed = [42u8; 32];
//! let signing_key = Ed25519::gen_key(&seed);
//! let verification_key = Ed25519::derive_verification_key(&signing_key);
//!
//! // Sign a message
//! let message = b"Cardano transaction";
//! let signature = Ed25519::sign(&signing_key, message);
//!
//! // Verify the signature
//! assert!(Ed25519::verify(&verification_key, message, &signature).is_ok());
//! ```

use crate::common::CryptoError;

use ed25519_dalek::{
    Signature as DalekSignature, SigningKey as DalekSigningKey, VerifyingKey as DalekVerifyingKey,
};
use ed25519_dalek::{Signer, Verifier};

const SEED_SIZE: usize = 32;
const VERIFICATION_KEY_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;
const SECRET_COMPOUND_SIZE: usize = 64;

/// Ed25519 verification (public) key
///
/// A 32-byte compressed Edwards curve point representing the public verification key.
/// This key is derived from the signing key and can be safely shared publicly.
///
/// # Format
///
/// The key is stored as a compressed Edwards curve point in canonical Ed25519 format:
/// - 32 bytes representing the Y coordinate and sign bit
/// - Valid points must lie on the Edwards25519 curve
///
/// # Usage
///
/// - Share publicly for signature verification
/// - Use as input to verification operations
/// - Derive Cardano addresses
/// - Identify stake pools and payment credentials
///
/// # Security
///
/// - Cannot be used to forge signatures (one-way derivation from signing key)
/// - Safe to transmit over untrusted networks
/// - Should be validated before use to ensure it's a valid curve point
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519VerificationKey([u8; VERIFICATION_KEY_SIZE]);

impl core::fmt::Debug for Ed25519VerificationKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ed25519VerificationKey(<{} bytes>)", self.0.len())
    }
}

impl Ed25519VerificationKey {
    /// Create a verification key from raw bytes with validation
    ///
    /// Validates that the provided bytes represent a valid Ed25519 public key
    /// (a valid point on the Edwards25519 curve). This is important for security
    /// as invalid keys could lead to verification failures or security issues.
    ///
    /// # Parameters
    ///
    /// * `bytes` - 32-byte slice containing the verification key
    ///
    /// # Returns
    ///
    /// * `Some(Ed25519VerificationKey)` if the bytes represent a valid key
    /// * `None` if the bytes are invalid (wrong length or not a valid curve point)
    ///
    /// # Examples
    ///
    /// ```
    /// use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
    ///
    /// let seed = [1u8; 32];
    /// let signing_key = Ed25519::gen_key(&seed);
    /// let verification_key = Ed25519::derive_verification_key(&signing_key);
    ///
    /// let bytes = verification_key.as_bytes();
    /// let recovered = cardano_crypto::dsign::ed25519::Ed25519VerificationKey::from_bytes(bytes);
    /// assert!(recovered.is_some());
    /// ```
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

    /// Get the raw bytes of the verification key
    ///
    /// Returns a reference to the internal 32-byte representation of the public key.
    /// This is useful for serialization, transmission, or storage.
    ///
    /// # Returns
    ///
    /// Reference to the 32-byte verification key
    ///
    /// # Examples
    ///
    /// ```
    /// use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
    ///
    /// let seed = [2u8; 32];
    /// let signing_key = Ed25519::gen_key(&seed);
    /// let verification_key = Ed25519::derive_verification_key(&signing_key);
    ///
    /// let bytes = verification_key.as_bytes();
    /// assert_eq!(bytes.len(), 32);
    /// ```
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; VERIFICATION_KEY_SIZE] {
        &self.0
    }
}

/// Ed25519 signing (secret) key
///
/// A 64-byte compound key structure following the Cardano/libsodium convention.
/// Contains both the 32-byte seed and the derived 32-byte verification key.
///
/// # Format
///
/// ```text
/// [0..32]  - Seed (secret random bytes)
/// [32..64] - Verification key (derived public key)
/// ```
///
/// This format matches Cardano's key storage and allows efficient access to both
/// the secret material and the derived public key without recomputation.
///
/// # Security
///
/// ⚠️ **CRITICAL**: This key must be kept absolutely secret!
/// - Never transmit over untrusted networks
/// - Store encrypted at rest
/// - Zeroize from memory after use
/// - Anyone with this key can forge signatures
///
/// # Usage
///
/// - Generate from a high-entropy 32-byte seed
/// - Use for signing transactions and messages
/// - Derive the public verification key
/// - Store securely in wallets and key management systems
///
/// # Examples
///
/// ```
/// use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
///
/// let seed = [42u8; 32];
/// let signing_key = Ed25519::gen_key(&seed);
///
/// // The key contains both seed and verification key
/// assert_eq!(signing_key.compound_bytes().len(), 64);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519SigningKey([u8; SECRET_COMPOUND_SIZE]);

impl core::fmt::Debug for Ed25519SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ed25519SigningKey([REDACTED])")
    }
}

impl Ed25519SigningKey {
    /// Create a signing key from a 32-byte seed
    ///
    /// Generates the complete 64-byte signing key structure from a 32-byte seed.
    /// The verification key is automatically derived and stored in the second half.
    ///
    /// # Parameters
    ///
    /// * `seed` - 32-byte seed (must be from a cryptographically secure RNG)
    ///
    /// # Returns
    ///
    /// 64-byte compound signing key containing seed and derived verification key
    ///
    /// # Security
    ///
    /// The seed must come from a high-quality entropy source. Using predictable
    /// or low-entropy seeds compromises security completely.
    ///
    /// # Examples
    ///
    /// ```
    /// use cardano_crypto::dsign::ed25519::Ed25519SigningKey;
    ///
    /// let seed = [42u8; 32];
    /// let signing_key = Ed25519SigningKey::from_seed_bytes(&seed);
    /// ```
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

/// Ed25519 signature
///
/// A 64-byte digital signature produced by the Ed25519 algorithm.
/// Signatures are deterministic (same message + key always produces the same signature).
///
/// # Format
///
/// ```text
/// [0..32]  - R: Curve point (compressed)
/// [32..64] - S: Scalar value
/// ```
///
/// This follows the standard Ed25519 signature format as defined in RFC 8032.
///
/// # Properties
///
/// - **Deterministic**: No randomness needed; same inputs always produce same signature
/// - **Compact**: Only 64 bytes for quantum-resistant security level
/// - **Fast**: Efficient verification (important for blockchain validation)
/// - **Non-malleable**: Prevents signature modification attacks
///
/// # Usage
///
/// - Prove authenticity of transactions
/// - Verify message integrity
/// - Bind messages to specific keys
/// - Transmit proof of authorization
///
/// # Examples
///
/// ```
/// use cardano_crypto::dsign::{Ed25519, DsignAlgorithm};
///
/// let seed = [1u8; 32];
/// let signing_key = Ed25519::gen_key(&seed);
/// let message = b"sign this message";
/// let signature = Ed25519::sign(&signing_key, message);
///
/// assert_eq!(signature.as_bytes().len(), 64);
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Ed25519Signature([u8; SIGNATURE_SIZE]);

impl core::fmt::Debug for Ed25519Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ed25519Signature(<{} bytes>)", self.0.len())
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

impl super::DsignAlgorithm for Ed25519 {
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
    ) -> Result<()> {
        let verifying_key = DalekVerifyingKey::from_bytes(verification_key.as_bytes())
            .map_err(|_| CryptoError::InvalidPublicKey)?;

        let signature = DalekSignature::try_from(signature.as_bytes().as_ref())
            .map_err(|_| CryptoError::InvalidSignature)?;

        verifying_key
            .verify(message, &signature)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    fn gen_key(seed: &[u8]) -> Self::SigningKey {
        assert_eq!(
            seed.len(),
            SEED_SIZE,
            "Ed25519 seed must be exactly 32 bytes"
        );
        Ed25519SigningKey::from_seed_bytes(seed)
    }
}

// New trait implementation for compatibility with KES
use crate::common::error::{CryptoError as CommonCryptoError, Result};
use crate::common::traits::DsignAlgorithm as CommonDsignAlgorithm;

impl CommonDsignAlgorithm for Ed25519 {
    type SigningKey = Ed25519SigningKey;
    type VerificationKey = Ed25519VerificationKey;
    type Signature = Ed25519Signature;
    type Context = ();

    const ALGORITHM_NAME: &'static str = "Ed25519";
    const SEED_SIZE: usize = SEED_SIZE;
    const SIGNING_KEY_SIZE: usize = SECRET_COMPOUND_SIZE;
    const VERIFICATION_KEY_SIZE: usize = VERIFICATION_KEY_SIZE;
    const SIGNATURE_SIZE: usize = SIGNATURE_SIZE;

    fn gen_key_from_seed(seed: &[u8]) -> Result<Self::SigningKey> {
        if seed.len() != SEED_SIZE {
            return Err(CommonCryptoError::InvalidKeyLength);
        }
        Ok(Ed25519SigningKey::from_seed_bytes(seed))
    }

    fn derive_verification_key(signing_key: &Self::SigningKey) -> Result<Self::VerificationKey> {
        let mut bytes = [0u8; VERIFICATION_KEY_SIZE];
        bytes.copy_from_slice(&signing_key.verifying_bytes());
        Ok(Ed25519VerificationKey(bytes))
    }

    fn sign(message: &[u8], signing_key: &Self::SigningKey) -> Result<Self::Signature> {
        let signing_key_dalek = signing_key.signing_key();
        let signature = signing_key_dalek.sign(message);
        Ok(Ed25519Signature::from_dalek(&signature))
    }

    fn verify(
        message: &[u8],
        signature: &Self::Signature,
        verification_key: &Self::VerificationKey,
    ) -> Result<()> {
        let verifying_key = DalekVerifyingKey::from_bytes(verification_key.as_bytes())
            .map_err(|_| CommonCryptoError::InvalidPublicKey)?;

        let sig = DalekSignature::try_from(signature.as_bytes().as_ref())
            .map_err(|_| CommonCryptoError::InvalidSignature)?;

        verifying_key
            .verify(message, &sig)
            .map_err(|_| CommonCryptoError::VerificationFailed)
    }

    fn serialize_verification_key(key: &Self::VerificationKey) -> alloc::vec::Vec<u8> {
        key.as_bytes().to_vec()
    }

    fn deserialize_verification_key(bytes: &[u8]) -> Result<Self::VerificationKey> {
        Ed25519VerificationKey::from_bytes(bytes).ok_or(CommonCryptoError::InvalidPublicKey)
    }

    fn serialize_signature(signature: &Self::Signature) -> alloc::vec::Vec<u8> {
        signature.as_bytes().to_vec()
    }

    fn deserialize_signature(bytes: &[u8]) -> Result<Self::Signature> {
        if bytes.len() != SIGNATURE_SIZE {
            return Err(CommonCryptoError::InvalidSignature);
        }
        let mut array = [0u8; SIGNATURE_SIZE];
        array.copy_from_slice(bytes);
        Ok(Ed25519Signature(array))
    }

    fn forget_signing_key(mut signing_key: Self::SigningKey) {
        // Securely zeroize the signing key to prevent it from remaining in memory
        use zeroize::Zeroize;
        signing_key.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsign::DsignAlgorithm;

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
        let verification_key =
            <Ed25519 as crate::dsign::DsignAlgorithm>::derive_verification_key(&signing_key);

        let message = b"cardano";
        let signature = <Ed25519 as crate::dsign::DsignAlgorithm>::sign(&signing_key, message);

        let result = <Ed25519 as crate::dsign::DsignAlgorithm>::verify(
            &verification_key,
            message,
            &signature,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_fails_wrong_message() {
        let seed = [9u8; 32];
        let signing_key = Ed25519::gen_key(&seed);
        let verification_key =
            <Ed25519 as crate::dsign::DsignAlgorithm>::derive_verification_key(&signing_key);

        let signature = <Ed25519 as crate::dsign::DsignAlgorithm>::sign(&signing_key, b"hello");
        let result = <Ed25519 as crate::dsign::DsignAlgorithm>::verify(
            &verification_key,
            b"world",
            &signature,
        );

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), CryptoError::VerificationFailed);
    }

    #[test]
    fn test_verify_fails_wrong_key() {
        let seed1 = [1u8; 32];
        let seed2 = [2u8; 32];

        let signing_key1 = Ed25519::gen_key(&seed1);
        let signing_key2 = Ed25519::gen_key(&seed2);
        let verification_key2 =
            <Ed25519 as crate::dsign::DsignAlgorithm>::derive_verification_key(&signing_key2);

        let message = b"test";
        let signature1 = <Ed25519 as crate::dsign::DsignAlgorithm>::sign(&signing_key1, message);

        let result = <Ed25519 as crate::dsign::DsignAlgorithm>::verify(
            &verification_key2,
            message,
            &signature1,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_message() {
        let seed = [42u8; 32];
        let signing_key = Ed25519::gen_key(&seed);
        let verification_key =
            <Ed25519 as crate::dsign::DsignAlgorithm>::derive_verification_key(&signing_key);

        let signature = <Ed25519 as crate::dsign::DsignAlgorithm>::sign(&signing_key, b"");
        let result =
            <Ed25519 as crate::dsign::DsignAlgorithm>::verify(&verification_key, b"", &signature);
        assert!(result.is_ok());
    }

    #[test]
    fn test_large_message() {
        let seed = [99u8; 32];
        let signing_key = Ed25519::gen_key(&seed);
        let verification_key =
            <Ed25519 as crate::dsign::DsignAlgorithm>::derive_verification_key(&signing_key);

        let large_message = vec![0xAB; 10_000];
        let signature =
            <Ed25519 as crate::dsign::DsignAlgorithm>::sign(&signing_key, &large_message);
        let result = <Ed25519 as crate::dsign::DsignAlgorithm>::verify(
            &verification_key,
            &large_message,
            &signature,
        );
        assert!(result.is_ok());
    }
}

// Helper for hex encoding in tests
#[cfg(test)]
mod hex {
    #[allow(dead_code)]
    pub(crate) fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
