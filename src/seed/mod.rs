//! Seed management and derivation utilities
//!
//! Provides secure seed generation and key derivation functions.

/// Seed type for cryptographic key generation
pub type Seed = [u8; 32];

/// Generate a deterministic seed from input data
///
/// This uses Blake2b-256 to derive a 32-byte seed from arbitrary input.
pub fn derive_seed(data: &[u8]) -> Seed {
    use crate::hash::{Blake2b256, HashAlgorithm};

    let hash = Blake2b256::hash(data);
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&hash);
    seed
}

/// Expand a seed into multiple child seeds
///
/// Uses domain separation to generate independent seeds from a parent seed.
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
