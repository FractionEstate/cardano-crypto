//! Common traits for cryptographic operations
//!
//! This module defines shared traits used across different cryptographic primitives
//! in the library, providing a consistent interface for:
//!
//! - Digital signature algorithms (DSIGN)
//! - Signable data representation
//! - Constant-time comparisons for security
//!
//! These traits enable generic implementations and ensure API consistency across
//! different cryptographic schemes.

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

use crate::common::error::Result;

/// Trait for digital signature algorithms used in KES and other constructions
///
/// This trait provides a unified interface for digital signature schemes,
/// primarily used as the base layer for Key Evolving Signatures (KES).
/// It defines the complete lifecycle of key generation, signing, verification,
/// and serialization.
///
/// # Type Parameters
///
/// All associated types must be owned (not references) to allow flexible
/// composition and storage in higher-level structures.
///
/// # Security Requirements
///
/// Implementations must:
/// - Use cryptographically secure key generation
/// - Provide deterministic or properly randomized signing
/// - Implement constant-time operations where applicable
/// - Properly zeroize secret key material in `forget_signing_key`
///
/// # Examples
///
/// ```ignore
/// use cardano_crypto::common::traits::DsignAlgorithm;
/// use cardano_crypto::dsign::Ed25519;
///
/// // Generate a key from a seed
/// let seed = [42u8; 32];
/// let signing_key = Ed25519::gen_key_from_seed(&seed)?;
///
/// // Derive public key
/// let verification_key = Ed25519::derive_verification_key(&signing_key)?;
///
/// // Sign and verify
/// let message = b"important message";
/// let signature = Ed25519::sign(message, &signing_key)?;
/// Ed25519::verify(message, &signature, &verification_key)?;
/// ```
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
    /// Seed size in bytes (entropy required for key generation)
    const SEED_SIZE: usize;
    /// Verification (public) key size in bytes
    const VERIFICATION_KEY_SIZE: usize;
    /// Signing (secret) key size in bytes
    const SIGNING_KEY_SIZE: usize;
    /// Signature size in bytes
    const SIGNATURE_SIZE: usize;

    /// Generate a signing key from a cryptographic seed
    ///
    /// The seed must contain sufficient entropy (typically 32 bytes from a CSPRNG).
    /// The same seed will always produce the same signing key (deterministic).
    ///
    /// # Parameters
    ///
    /// * `seed` - High-entropy seed bytes (length must match `SEED_SIZE`)
    ///
    /// # Errors
    ///
    /// Returns error if seed length is incorrect or key generation fails.
    fn gen_key_from_seed(seed: &[u8]) -> Result<Self::SigningKey>;

    /// Derive the public verification key from a signing key
    ///
    /// This operation is one-way: the verification key cannot be used to
    /// recover the signing key.
    ///
    /// # Parameters
    ///
    /// * `signing_key` - The secret signing key
    ///
    /// # Returns
    ///
    /// The corresponding public verification key
    fn derive_verification_key(signing_key: &Self::SigningKey) -> Result<Self::VerificationKey>;

    /// Sign a message with a signing key
    ///
    /// Produces a digital signature that can be verified by anyone with the
    /// corresponding verification key.
    ///
    /// # Parameters
    ///
    /// * `message` - Data to sign (arbitrary length)
    /// * `signing_key` - Secret signing key
    ///
    /// # Returns
    ///
    /// Digital signature binding the message to the signing key
    fn sign(message: &[u8], signing_key: &Self::SigningKey) -> Result<Self::Signature>;

    /// Verify a signature against a message and verification key
    ///
    /// Checks that the signature is cryptographically valid for the given
    /// message and public key.
    ///
    /// # Parameters
    ///
    /// * `message` - The message that was allegedly signed
    /// * `signature` - The signature to verify
    /// * `verification_key` - Public key to verify against
    ///
    /// # Errors
    ///
    /// Returns error if verification fails (invalid signature, wrong key, etc.)
    fn verify(
        message: &[u8],
        signature: &Self::Signature,
        verification_key: &Self::VerificationKey,
    ) -> Result<()>;

    /// Serialize a verification key to bytes
    ///
    /// Produces a canonical byte representation suitable for storage or transmission.
    ///
    /// # Parameters
    ///
    /// * `key` - Verification key to serialize
    ///
    /// # Returns
    ///
    /// Byte vector containing the serialized key
    #[cfg(feature = "alloc")]
    fn serialize_verification_key(key: &Self::VerificationKey) -> Vec<u8>;

    /// Deserialize a verification key from bytes
    ///
    /// Reconstructs a verification key from its serialized form.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Serialized verification key bytes
    ///
    /// # Errors
    ///
    /// Returns error if bytes are invalid or malformed
    fn deserialize_verification_key(bytes: &[u8]) -> Result<Self::VerificationKey>;

    /// Serialize a signature to bytes
    ///
    /// Produces a canonical byte representation suitable for storage or transmission.
    ///
    /// # Parameters
    ///
    /// * `signature` - Signature to serialize
    ///
    /// # Returns
    ///
    /// Byte vector containing the serialized signature
    #[cfg(feature = "alloc")]
    fn serialize_signature(signature: &Self::Signature) -> Vec<u8>;

    /// Deserialize a signature from bytes
    ///
    /// Reconstructs a signature from its serialized form.
    ///
    /// # Parameters
    ///
    /// * `bytes` - Serialized signature bytes
    ///
    /// # Errors
    ///
    /// Returns error if bytes are invalid or malformed
    fn deserialize_signature(bytes: &[u8]) -> Result<Self::Signature>;

    /// Securely erase and forget a signing key
    ///
    /// Zeroizes the secret key material to prevent it from remaining in memory.
    /// This is critical for security when keys are no longer needed.
    ///
    /// # Parameters
    ///
    /// * `signing_key` - Signing key to securely erase
    fn forget_signing_key(signing_key: Self::SigningKey);
}

/// Trait for types that can be signed or proven over
///
/// Provides a consistent interface for obtaining the canonical byte representation
/// of data that needs to be signed, proven, or hashed. This ensures that signatures
/// and proofs are computed over the correct serialized form.
///
/// # Purpose
///
/// Different types may have multiple possible byte representations. This trait
/// ensures that signing operations always use the canonical form, preventing
/// signature malleability issues.
///
/// # Examples
///
/// ```
/// use cardano_crypto::common::traits::SignableRepresentation;
///
/// let data = b"message to sign";
/// let signable = data.signable_bytes();
/// assert_eq!(signable, b"message to sign");
/// ```
pub trait SignableRepresentation {
    /// Get the canonical byte representation for signing/proving
    ///
    /// Returns the bytes that should be used as input to signature or proof
    /// generation functions.
    ///
    /// # Returns
    ///
    /// Byte slice containing the canonical representation
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

/// Constant-time equality comparison for security-critical code
///
/// Provides timing-safe equality comparison to prevent timing side-channel attacks.
/// Regular equality comparisons may short-circuit on the first mismatched byte,
/// leaking information about the data through timing measurements.
///
/// # Security
///
/// This trait should be used when comparing:
/// - Secret keys or key material
/// - Authentication tags or MACs
/// - Password hashes
/// - Any data where timing leaks could compromise security
///
/// The comparison runs in constant time relative to the data length, preventing
/// attackers from learning information through timing analysis.
///
/// # Examples
///
/// ```
/// use cardano_crypto::common::traits::ConstantTimeEq;
///
/// let secret1 = b"secret_key_12345";
/// let secret2 = b"secret_key_12345";
/// let secret3 = b"different_secret";
///
/// assert!(secret1.ct_eq(secret2));
/// assert!(!secret1.ct_eq(secret3));
/// ```
///
/// # Note
///
/// For maximum security, prefer using the `subtle` crate's `ConstantTimeEq`
/// when available, as it may have additional assembly-level protections.
pub trait ConstantTimeEq {
    /// Compare two values for equality in constant time
    ///
    /// Returns `true` if the values are equal, `false` otherwise.
    /// The time taken depends only on the length of the data, not on
    /// the position of any differences.
    ///
    /// # Parameters
    ///
    /// * `other` - Value to compare against
    ///
    /// # Returns
    ///
    /// `true` if values are equal, `false` if different or different lengths
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
