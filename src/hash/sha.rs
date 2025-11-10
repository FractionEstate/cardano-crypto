//! SHA and other hash functions for cross-chain compatibility
//!
//! Provides hash algorithms used in Bitcoin, Ethereum, and other blockchains.

use digest::Digest;
use ripemd::Ripemd160;
use sha2::{Sha256, Sha512};
use sha3::{Keccak256, Sha3_256, Sha3_512};

/// SHA-256 hash (32 bytes output)
///
/// Used extensively in Bitcoin for transaction hashing, block mining,
/// and address generation.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::hash::sha256;
///
/// let data = b"Bitcoin transaction data";
/// let hash = sha256(data);
/// assert_eq!(hash.len(), 32);
/// ```
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Double SHA-256 hash (32 bytes output)
///
/// Common pattern in Bitcoin: `SHA256(SHA256(data))`.
/// Used for transaction IDs and block hashing.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::hash::sha256d;
///
/// let data = b"Bitcoin block header";
/// let hash = sha256d(data);
/// assert_eq!(hash.len(), 32);
/// ```
#[must_use]
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

/// SHA-512 hash (64 bytes output)
///
/// General purpose cryptographic hash with longer output.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::hash::sha512;
///
/// let data = b"Large data needing 512-bit hash";
/// let hash = sha512(data);
/// assert_eq!(hash.len(), 64);
/// ```
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA3-256 hash (32 bytes output)
///
/// Keccak-based standardized hash function.
/// Used in Ethereum 2.0 and various modern protocols.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::hash::sha3_256;
///
/// let data = b"Ethereum 2.0 data";
/// let hash = sha3_256(data);
/// assert_eq!(hash.len(), 32);
/// ```
#[must_use]
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// SHA3-512 hash (64 bytes output)
///
/// Keccak-based standardized hash function with longer output.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::hash::sha3_512;
///
/// let data = b"SHA3-512 data";
/// let hash = sha3_512(data);
/// assert_eq!(hash.len(), 64);
/// ```
#[must_use]
pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Keccak-256 hash (32 bytes output)
///
/// Original Keccak algorithm before NIST standardization.
/// Used in Ethereum 1.0 for transaction hashing and address generation.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::hash::keccak256;
///
/// let data = b"Ethereum transaction";
/// let hash = keccak256(data);
/// assert_eq!(hash.len(), 32);
/// ```
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// RIPEMD-160 hash (20 bytes output)
///
/// Used in Bitcoin address generation: `RIPEMD160(SHA256(pubkey))`.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::hash::ripemd160;
///
/// let data = b"Bitcoin pubkey hash";
/// let hash = ripemd160(data);
/// assert_eq!(hash.len(), 20);
/// ```
#[must_use]
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
    let mut hasher = Ripemd160::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Bitcoin-style address hash: `RIPEMD160(SHA256(data))`
///
/// Used in Bitcoin P2PKH address generation.
///
/// # Example
///
/// ```rust
/// use cardano_crypto::hash::hash160;
///
/// let pubkey = b"Bitcoin public key";
/// let hash = hash160(pubkey);
/// assert_eq!(hash.len(), 20);
/// ```
#[must_use]
pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd160(&sha256(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_empty() {
        let hash = sha256(b"");
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assert_eq!(hex::encode(hash), expected);
    }

    #[test]
    fn test_sha256_hello() {
        let hash = sha256(b"hello");
        let expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        assert_eq!(hex::encode(hash), expected);
    }

    #[test]
    fn test_sha256d() {
        let hash = sha256d(b"hello");
        // Should be different from single SHA-256
        let single = sha256(b"hello");
        assert_ne!(hash, single);
        // Should be deterministic
        assert_eq!(hash, sha256d(b"hello"));
    }

    #[test]
    fn test_sha512_hello() {
        let hash = sha512(b"hello");
        assert_eq!(hash.len(), 64);
        // SHA-512 should be deterministic
        assert_eq!(hash, sha512(b"hello"));
    }

    #[test]
    fn test_deterministic_hashing() {
        let data = b"deterministic test";

        assert_eq!(sha256(data), sha256(data));
        assert_eq!(sha512(data), sha512(data));
        assert_eq!(keccak256(data), keccak256(data));
        assert_eq!(ripemd160(data), ripemd160(data));
    }

    #[test]
    fn test_hash160() {
        let data = b"test";
        let hash = hash160(data);
        assert_eq!(hash.len(), 20);

        // Should equal RIPEMD160(SHA256(data))
        let manual = ripemd160(&sha256(data));
        assert_eq!(hash, manual);
    }
}

// Helper for hex encoding in tests
#[cfg(test)]
mod hex {
    pub(crate) fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}
