//! Seed management and derivation utilities
//!
//! Provides secure seed generation and hierarchical key derivation functions
//! for deterministic generation of cryptographic keys. This module is essential
//! for wallet implementations and key management systems.
//!
//! # Security Considerations
//!
//! - Seeds should be generated from high-entropy sources (e.g., hardware RNG)
//! - Seeds must be kept secret - they can regenerate all derived keys
//! - Use `zeroize` to clear seeds from memory after use
//! - Never reuse seeds across different applications or protocols
//!
//! # Examples
//!
//! ```
//! use cardano_crypto::seed::{derive_seed, expand_seed};
//!
//! // Derive a seed from mnemonic or passphrase
//! let mnemonic = b"example mnemonic phrase with high entropy";
//! let master_seed = derive_seed(mnemonic);
//!
//! // Derive child seeds for hierarchical key derivation
//! let child_seed_0 = expand_seed(&master_seed, 0);
//! let child_seed_1 = expand_seed(&master_seed, 1);
//!
//! // Each child seed can be used for different purposes
//! assert_ne!(child_seed_0, child_seed_1);
//! ```

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

/// Seed type for cryptographic key generation
///
/// A 32-byte (256-bit) seed value used as the root secret for deterministic
/// key generation. This provides sufficient entropy for cryptographic security.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::seed::Seed;
///
/// let seed: Seed = [42u8; 32];
/// assert_eq!(seed.len(), 32);
/// ```
pub type Seed = [u8; 32];

/// Generate a deterministic seed from input data using Blake2b-256
///
/// Derives a cryptographically secure 32-byte seed from arbitrary input data.
/// This function uses Blake2b-256 hash to ensure uniform distribution of the
/// output regardless of the input structure.
///
/// # Use Cases
///
/// - Converting mnemonics or passwords to seeds
/// - Deriving seeds from master secrets
/// - Creating deterministic test seeds for reproducible testing
///
/// # Security Warning
///
/// The security of the derived seed depends entirely on the entropy of the input.
/// Do not use predictable or low-entropy inputs (like simple passwords) for
/// production cryptographic keys.
///
/// # Examples
///
/// ```
/// use cardano_crypto::seed::derive_seed;
///
/// let mnemonic = b"example mnemonic phrase with high entropy";
/// let seed = derive_seed(mnemonic);
/// assert_eq!(seed.len(), 32);
/// ```
///
/// # Parameters
///
/// * `data` - Input data to hash (should have sufficient entropy for security)
///
/// # Returns
///
/// A deterministic 32-byte seed derived from the input
pub fn derive_seed(data: &[u8]) -> Seed {
    use crate::hash::{Blake2b256, HashAlgorithm};

    let hash = Blake2b256::hash(data);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);
    seed
}

/// Expand a parent seed into a child seed using hierarchical derivation
///
/// Implements a simple hierarchical deterministic (HD) key derivation scheme.
/// Given a parent seed and an index, this function deterministically generates
/// a child seed using domain separation to ensure independence between children.
///
/// # Derivation Scheme
///
/// The child seed is derived as: `Blake2b256(parent_seed || index)`
/// where `||` denotes concatenation and the index is encoded as big-endian u32.
///
/// # Use Cases
///
/// - Creating multiple independent keys from a single master seed
/// - Implementing BIP32-style HD wallets
/// - Separating keys by purpose (signing, encryption, etc.)
/// - Generating per-period keys in KES schemes
///
/// # Security Properties
///
/// - Different indices produce independent, uncorrelated seeds
/// - Knowledge of a child seed does not reveal the parent seed (one-way function)
/// - Supports up to 2^32 child seeds from a single parent
///
/// # Examples
///
/// ```
/// use cardano_crypto::seed::{derive_seed, expand_seed};
///
/// let master_seed = derive_seed(b"high entropy master secret");
/// let child_0 = expand_seed(&master_seed, 0);
/// let child_1 = expand_seed(&master_seed, 1);
///
/// // Child seeds are independent
/// assert_ne!(child_0, child_1);
/// assert_eq!(child_0.len(), 32);
/// ```
///
/// # Parameters
///
/// * `parent` - Parent seed to derive from (32 bytes)
/// * `index` - Derivation index (0 to 2^32-1)
///
/// # Returns
///
/// A deterministic 32-byte child seed
pub fn expand_seed(parent: &Seed, index: u32) -> Seed {
    use crate::hash::{Blake2b256, HashAlgorithm};

    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(parent);
    data.extend_from_slice(&index.to_be_bytes());

    let hash = Blake2b256::hash(&data);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);
    seed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_seed() {
        let data = b"test data";
        let seed1 = derive_seed(data);
        let seed2 = derive_seed(data);

        // Should be deterministic
        assert_eq!(seed1, seed2);

        // Different input should give different seed
        let seed3 = derive_seed(b"different data");
        assert_ne!(seed1, seed3);
    }

    #[test]
    fn test_expand_seed() {
        let parent = [42u8; 32];

        let child0 = expand_seed(&parent, 0);
        let child1 = expand_seed(&parent, 1);
        let child2 = expand_seed(&parent, 2);

        // Children should be different
        assert_ne!(child0, child1);
        assert_ne!(child1, child2);
        assert_ne!(child0, child2);

        // Should be deterministic
        assert_eq!(child0, expand_seed(&parent, 0));
        assert_eq!(child1, expand_seed(&parent, 1));
    }
}
