//! VRF-specific constants and suite identifiers

/// Suite identifier for Draft-03 VRF (ECVRF-ED25519-SHA512-ELL2)
pub const SUITE_DRAFT03: u8 = 0x04;

/// Suite identifier for Draft-13 VRF (ECVRF-ED25519-SHA512-TAI)
pub const SUITE_DRAFT13: u8 = 0x03;

/// Domain separation byte: Used in hash-to-curve operations
pub const ONE: u8 = 0x01;

/// Domain separation byte: Used in challenge generation
pub const TWO: u8 = 0x02;

/// Domain separation byte: Used in VRF output computation
pub const THREE: u8 = 0x03;
