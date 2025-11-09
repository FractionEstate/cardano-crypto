//! Digital signature algorithms (DSIGN)
//!
//! Provides digital signature schemes used in Cardano:
//!
//! - [`Ed25519`] - Standard Ed25519 signatures (used in Cardano transactions)
//! - Additional signature schemes for cross-chain compatibility

mod ed25519;

pub use ed25519::Ed25519;

/// Trait for digital signature algorithms
pub trait DsignAlgorithm: Clone + Send + Sync + 'static {
    /// Signing key type
    type SigningKey;

    /// Verification key type
    type VerificationKey;

    /// Signature type
    type Signature;

    /// Algorithm name
    const ALGORITHM_NAME: &'static str;

    /// Size of the signing key in bytes
    const SIGNING_KEY_SIZE: usize;

    /// Size of the verification key in bytes
    const VERIFICATION_KEY_SIZE: usize;

    /// Size of the signature in bytes
    const SIGNATURE_SIZE: usize;

    /// Derive verification key from signing key
    fn derive_verification_key(signing_key: &Self::SigningKey) -> Self::VerificationKey;

    /// Sign a message
    fn sign(signing_key: &Self::SigningKey, message: &[u8]) -> Self::Signature;

    /// Verify a signature
    fn verify(
        verification_key: &Self::VerificationKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<(), crate::common::CryptoError>;

    /// Generate a key from a seed
    fn gen_key(seed: &[u8]) -> Self::SigningKey;
}
