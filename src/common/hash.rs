//! Hashing utilities
//!
//! Provides SHA-512 and other hash functions used by cryptographic primitives.

#[cfg(feature = "vrf")]
use sha2::{Digest, Sha512};

#[cfg(feature = "vrf")]
/// Compute SHA-512 hash of input data
///
/// Computes the SHA-512 (Secure Hash Algorithm 512-bit) cryptographic hash
/// of the provided input data. SHA-512 is used extensively in VRF implementations
/// for key derivation, proof generation, and hash-to-curve operations.
///
/// # Algorithm
///
/// SHA-512 produces a 512-bit (64-byte) hash value from arbitrary-length input.
/// It is part of the SHA-2 family and provides strong collision resistance and
/// preimage resistance suitable for cryptographic applications.
///
/// # Examples
///
/// ```
/// use cardano_crypto::common::hash::hash_sha512;
///
/// let data = b"Hello, Cardano!";
/// let hash = hash_sha512(data);
/// assert_eq!(hash.len(), 64);
/// ```
///
/// # Parameters
///
/// * `data` - Input data to hash (any length)
///
/// # Returns
///
/// Fixed-size 64-byte array containing the SHA-512 hash
#[must_use]
pub fn hash_sha512(data: &[u8]) -> [u8; 64] {
    let hash = Sha512::digest(data);
    let mut result = [0u8; 64];
    result.copy_from_slice(&hash);
    result
}

#[cfg(all(test, feature = "vrf"))]
mod tests {
    use super::*;

    #[test]
    fn test_hash_sha512() {
        let data = b"test message";
        let hash = hash_sha512(data);

        // SHA-512 always produces 64 bytes
        assert_eq!(hash.len(), 64);

        // Same input produces same output
        let hash2 = hash_sha512(data);
        assert_eq!(hash, hash2);

        // Different input produces different output
        let hash3 = hash_sha512(b"different message");
        assert_ne!(hash, hash3);
    }
}
