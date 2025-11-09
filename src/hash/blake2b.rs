//! Blake2b hash implementations
//!
//! Provides Blake2b variants used in Cardano:
//! - Blake2b-224 (28 bytes) - Address derivation
//! - Blake2b-256 (32 bytes) - KES verification keys (matches Haskell)
//! - Blake2b-512 (64 bytes) - General purpose

use super::HashAlgorithm;
use blake2::digest::consts::{U28, U32, U64};
use blake2::{Blake2b, Digest};

/// Blake2b-224 hash algorithm (28-byte output)
///
/// Used in Cardano for address derivation and verification key hashing.
/// This matches `Cardano.Crypto.Hash.Blake2b_224` from cardano-base.
#[derive(Clone, Debug)]
pub struct Blake2b224;

impl HashAlgorithm for Blake2b224 {
    const OUTPUT_SIZE: usize = 28;
    const ALGORITHM_NAME: &'static str = "blake2b_224";

    fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Blake2b::<U28>::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

/// Blake2b-256 hash algorithm (32-byte output)
///
/// This is the hash algorithm used in Haskell's cardano-base for KES Sum types.
/// Critical for binary compatibility with Cardano node verification keys.
#[derive(Clone, Debug)]
pub struct Blake2b256;

impl HashAlgorithm for Blake2b256 {
    const OUTPUT_SIZE: usize = 32;
    const ALGORITHM_NAME: &'static str = "blake2b_256";

    fn hash(data: &[u8]) -> Vec<u8> {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

/// Blake2b-512 hash algorithm (64-byte output)
///
/// General purpose Blake2b with maximum output size.
/// Used for compatibility with existing code.
#[derive(Clone, Debug)]
pub struct Blake2b512;

impl HashAlgorithm for Blake2b512 {
    const OUTPUT_SIZE: usize = 64;
    const ALGORITHM_NAME: &'static str = "blake2b_512";

    fn hash(data: &[u8]) -> Vec<u8> {
        use blake2::Blake2b512 as Blake2b512Hasher;

        let mut hasher = Blake2b512Hasher::new();
        hasher.update(data);
        hasher.finalize().to_vec()
    }
}

/// Standalone Blake2b-224 hash function (28 bytes output)
///
/// Convenience function matching the trait implementation.
#[must_use]
pub fn blake2b224(data: &[u8]) -> [u8; 28] {
    let mut hasher = Blake2b::<U28>::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Standalone Blake2b-256 hash function (32 bytes output)
///
/// Convenience function matching the trait implementation.
#[must_use]
pub fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Standalone Blake2b-512 hash function (64 bytes output)
///
/// Convenience function matching the trait implementation.
#[must_use]
pub fn blake2b512(data: &[u8]) -> [u8; 64] {
    use blake2::Blake2b512 as Blake2b512Hasher;

    let mut hasher = Blake2b512Hasher::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2b224_empty() {
        let expected = "836cc68931c2e4e3e838602eca1902591d216837bafddfe6f0c8cb07";
        let out = Blake2b224::hash(b"");
        assert_eq!(hex::encode(out), expected);
    }

    #[test]
    fn test_blake2b224_hello_world() {
        let expected = "42d1854b7d69e3b57c64fcc7b4f64171b47dff43fba6ac0499ff437f";
        let out = Blake2b224::hash(b"hello world");
        assert_eq!(hex::encode(out), expected);
    }

    #[test]
    fn test_blake2b256_empty() {
        let expected = "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8";
        let out = Blake2b256::hash(b"");
        assert_eq!(hex::encode(out), expected);
    }

    #[test]
    fn test_blake2b256_hello_world() {
        let expected = "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610";
        let out = Blake2b256::hash(b"hello world");
        assert_eq!(hex::encode(out), expected);
    }

    #[test]
    fn test_blake2b512_empty() {
        let expected = "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce";
        let out = Blake2b512::hash(b"");
        assert_eq!(hex::encode(out), expected);
    }

    #[test]
    fn test_blake2b512_hello_world() {
        let expected = "021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0";
        let out = Blake2b512::hash(b"hello world");
        assert_eq!(hex::encode(out), expected);
    }

    #[test]
    fn test_hash_concat() {
        let data1 = b"hello";
        let data2 = b"world";
        let hash1 = Blake2b256::hash_concat(data1, data2);
        let hash2 = Blake2b256::hash(b"helloworld");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_expand_seed() {
        let seed = b"test seed";
        let (seed0, seed1) = Blake2b256::expand_seed(seed);
        assert_eq!(seed0.len(), 32);
        assert_eq!(seed1.len(), 32);
        assert_ne!(seed0, seed1, "Expanded seeds should be different");
    }

    #[test]
    fn test_blake2b256_not_simple_truncation() {
        let cases = [b"".as_ref(), b"cardano".as_ref(), b"longer-message".as_ref()];

        for input in cases {
            let blake512 = Blake2b512::hash(input);
            let blake256 = Blake2b256::hash(input);
            assert_ne!(&blake512[..32], &blake256[..]);
        }
    }

    #[test]
    fn test_blake2b224_not_truncation() {
        let cases = [b"".as_ref(), b"address-key".as_ref(), b"longer-message".as_ref()];

        for input in cases {
            let blake512 = Blake2b512::hash(input);
            let blake224 = Blake2b224::hash(input);
            assert_ne!(&blake512[..28], blake224.as_ref());

            let blake256 = Blake2b256::hash(input);
            assert_ne!(&blake256[..28], blake224.as_ref());
        }
    }
}

// Helper for hex encoding in tests
#[cfg(test)]
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
}
