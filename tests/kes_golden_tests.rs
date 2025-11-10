//! Golden test vectors for KES implementations (Cardano-compatible)

use cardano_crypto::common::Result;
use cardano_crypto::kes::{KesAlgorithm, SingleKes, Sum2Kes, Sum6Kes};

#[test]
fn test_single_kes_basic() -> Result<()> {
    type TestKes = SingleKes<cardano_crypto::dsign::Ed25519>;

    let seed = [0x42u8; 32];
    let sk = TestKes::gen_key_kes_from_seed_bytes(&seed)?;
    let vk = TestKes::derive_verification_key(&sk)?;

    let message = b"SingleKES test";
    let sig = TestKes::sign_kes(&(), 0, message, &sk)?;

    assert!(TestKes::verify_kes(&(), &vk, 0, message, &sig).is_ok());
    assert!(TestKes::verify_kes(&(), &vk, 1, message, &sig).is_err());
    assert!(TestKes::update_kes(&(), sk, 0)?.is_none());

    Ok(())
}

#[test]
fn test_sum2_kes() -> Result<()> {
    let seed = [0x44u8; 32];
    let sk = Sum2Kes::gen_key_kes_from_seed_bytes(&seed)?;
    let vk = Sum2Kes::derive_verification_key(&sk)?;

    let sig0 = Sum2Kes::sign_kes(&(), 0, b"Period 0", &sk)?;
    assert!(Sum2Kes::verify_kes(&(), &vk, 0, b"Period 0", &sig0).is_ok());

    let sk = Sum2Kes::update_kes(&(), sk, 0)?.expect("Updated key");
    let sig1 = Sum2Kes::sign_kes(&(), 1, b"Period 1", &sk)?;
    assert!(Sum2Kes::verify_kes(&(), &vk, 1, b"Period 1", &sig1).is_ok());
    assert!(Sum2Kes::verify_kes(&(), &vk, 0, b"Period 0", &sig0).is_ok());

    Ok(())
}

#[test]
fn test_sum6_kes_evolution() -> Result<()> {
    let seed = [0x45u8; 32];
    for &period in &[0, 1, 2, 4, 8, 16, 32, 63] {
        let mut sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
        let vk = Sum6Kes::derive_verification_key(&sk)?;
        for p in 0..period {
            sk = Sum6Kes::update_kes(&(), sk, p)?.expect("Updated key");
        }
        let msg = format!("Period {}", period);
        let sig = Sum6Kes::sign_kes(&(), period, msg.as_bytes(), &sk)?;
        assert!(Sum6Kes::verify_kes(&(), &vk, period, msg.as_bytes(), &sig).is_ok());
    }
    Ok(())
}

#[test]
fn test_sum6_kes_total_periods() {
    assert_eq!(Sum6Kes::total_periods(), 64);
}

#[test]
fn test_sum6_kes_cardano_standard() -> Result<()> {
    let seed = [0x4Cu8; 32];
    for (period, message) in [
        (0, b"Genesis" as &[u8]),
        (10, b"Early"),
        (31, b"Mid"),
        (63, b"Final"),
    ] {
        let mut sk = Sum6Kes::gen_key_kes_from_seed_bytes(&seed)?;
        let vk = Sum6Kes::derive_verification_key(&sk)?;
        for t in 0..period {
            sk = Sum6Kes::update_kes(&(), sk, t)?.expect("Updated key");
        }
        let sig = Sum6Kes::sign_kes(&(), period, message, &sk)?;
        assert!(Sum6Kes::verify_kes(&(), &vk, period, message, &sig).is_ok());
        if period > 0 {
            assert!(Sum6Kes::verify_kes(&(), &vk, period - 1, message, &sig).is_err());
        }
    }
    Ok(())
}

#[test]
fn test_kes_serialization() -> Result<()> {
    let sk = Sum6Kes::gen_key_kes_from_seed_bytes(&[0x99u8; 32])?;
    let vk = Sum6Kes::derive_verification_key(&sk)?;
    let vk_bytes = Sum6Kes::raw_serialize_verification_key_kes(&vk);
    let vk_restored = Sum6Kes::raw_deserialize_verification_key_kes(&vk_bytes)
        .expect("Deserialization should succeed");
    assert_eq!(
        vk_bytes,
        Sum6Kes::raw_serialize_verification_key_kes(&vk_restored)
    );
    Ok(())
}

#[test]
fn test_signature_serialization() -> Result<()> {
    let sk = Sum2Kes::gen_key_kes_from_seed_bytes(&[0xAAu8; 32])?;
    let vk = Sum2Kes::derive_verification_key(&sk)?;
    let sig = Sum2Kes::sign_kes(&(), 0, b"test", &sk)?;
    let sig_bytes = Sum2Kes::raw_serialize_signature_kes(&sig);
    let sig_restored =
        Sum2Kes::raw_deserialize_signature_kes(&sig_bytes).expect("Deserialization should succeed");
    assert!(Sum2Kes::verify_kes(&(), &vk, 0, b"test", &sig_restored).is_ok());
    Ok(())
}

#[test]
fn test_cross_period_validation_failure() -> Result<()> {
    let sk = Sum2Kes::gen_key_kes_from_seed_bytes(&[0xBBu8; 32])?;
    let vk = Sum2Kes::derive_verification_key(&sk)?;
    let sig = Sum2Kes::sign_kes(&(), 0, b"test", &sk)?;
    assert!(Sum2Kes::verify_kes(&(), &vk, 0, b"test", &sig).is_ok());
    assert!(Sum2Kes::verify_kes(&(), &vk, 1, b"test", &sig).is_err());
    Ok(())
}

#[test]
fn test_deterministic_key_generation() -> Result<()> {
    let sk1 = Sum6Kes::gen_key_kes_from_seed_bytes(&[0xCCu8; 32])?;
    let sk2 = Sum6Kes::gen_key_kes_from_seed_bytes(&[0xCCu8; 32])?;
    let vk1_bytes =
        Sum6Kes::raw_serialize_verification_key_kes(&Sum6Kes::derive_verification_key(&sk1)?);
    let vk2_bytes =
        Sum6Kes::raw_serialize_verification_key_kes(&Sum6Kes::derive_verification_key(&sk2)?);
    assert_eq!(vk1_bytes, vk2_bytes);

    let sig1_bytes =
        Sum6Kes::raw_serialize_signature_kes(&Sum6Kes::sign_kes(&(), 0, b"test", &sk1)?);
    let sig2_bytes =
        Sum6Kes::raw_serialize_signature_kes(&Sum6Kes::sign_kes(&(), 0, b"test", &sk2)?);
    assert_eq!(sig1_bytes, sig2_bytes);
    Ok(())
}
