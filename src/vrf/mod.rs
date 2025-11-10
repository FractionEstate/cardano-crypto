//! Verifiable Random Functions (VRF)
//!
//! This module provides VRF implementations following IETF specifications:
//! - **Draft-03** (ECVRF-ED25519-SHA512-Elligator2) - 80-byte proofs, Cardano standard
//! - **Draft-13** (ECVRF-ED25519-SHA512-TAI) - 128-byte proofs, batch-compatible
//!
//! Both variants maintain byte-level compatibility with Cardano's libsodium VRF implementation.
//!
//! # Examples
//!
//! ## VRF Draft-03 (Cardano Standard)
//!
//! ```rust,ignore
//! use cardano_crypto::vrf::VrfDraft03;
//!
//! let seed = [42u8; 32];
//! let (secret_key, public_key) = VrfDraft03::keypair_from_seed(&seed);
//!
//! let message = b"Cardano block slot 12345";
//! let proof = VrfDraft03::prove(&secret_key, message)?;
//! let output = VrfDraft03::verify(&public_key, &proof, message)?;
//! ```

pub mod cardano_compat;
pub mod draft03;
pub mod draft13;
pub mod test_vectors;

// Re-export main types
pub use draft03::{
    VrfDraft03, OUTPUT_SIZE, PROOF_SIZE as DRAFT03_PROOF_SIZE, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE,
    SEED_SIZE,
};

pub use draft13::{VrfDraft13, PROOF_SIZE as DRAFT13_PROOF_SIZE};

// Re-export Cardano compatibility functions for advanced usage
pub use cardano_compat::{
    cardano_clear_cofactor, cardano_hash_to_curve, cardano_vrf_prove, cardano_vrf_verify,
};
