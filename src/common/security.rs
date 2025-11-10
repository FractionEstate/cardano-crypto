//! Security utilities for sensitive data handling
//!
//! This module provides cryptographic security utilities, particularly for
//! handling sensitive data like private keys and ensuring they are properly
//! cleared from memory after use.

/// Securely clear sensitive data from memory
///
/// This function overwrites the provided byte slice with zeros using volatile
/// writes to prevent compiler optimizations from eliminating the zeroing operation.
/// This is critical for security when handling sensitive cryptographic material
/// like private keys, seeds, or intermediate values.
///
/// # Security Notes
///
/// - Uses `ptr::write_volatile` to ensure the compiler doesn't optimize away the write
/// - Should be called on all sensitive data before it goes out of scope
/// - For production use, consider using the `zeroize` crate's `Zeroize` trait
///   which provides additional protections
///
/// # Examples
///
/// ```
/// use cardano_crypto::common::security::zeroize;
///
/// let mut secret_key = [0x42u8; 32];
/// // ... use the secret key ...
/// zeroize(&mut secret_key);
/// assert_eq!(secret_key, [0u8; 32]);
/// ```
///
/// # Parameters
///
/// * `data` - Mutable byte slice to be zeroed. All bytes will be overwritten with 0x00.
pub fn zeroize(data: &mut [u8]) {
    for byte in data.iter_mut() {
        // Use volatile write to prevent compiler optimization
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroize() {
        let mut data = [1u8, 2, 3, 4, 5];
        zeroize(&mut data);
        assert_eq!(data, [0u8; 5]);
    }
}
