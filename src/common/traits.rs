//! Common traits for cryptographic operations

#[cfg(feature = "alloc")]
use alloc::vec::Vec;

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
