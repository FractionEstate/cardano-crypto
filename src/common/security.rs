// ! Security utilities for sensitive data handling

/// Utility to clear sensitive data from memory
///
/// Note: When the `zeroize` crate is available, prefer using its
/// `Zeroize` trait for more robust protection.
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
