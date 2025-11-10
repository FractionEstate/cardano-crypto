//! Common error types for all cryptographic operations

/// Alias for backward compatibility
pub type Result<T> = core::result::Result<T, CryptoError>;

/// Result type for cryptographic operations
pub type CryptoResult<T> = core::result::Result<T, CryptoError>;

/// Common cryptographic error types
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "thiserror", derive(thiserror::Error))]
pub enum CryptoError {
    /// Invalid VRF proof structure or verification failed
    #[cfg_attr(feature = "thiserror", error("Invalid VRF proof"))]
    InvalidProof,

    /// Public key is malformed or not a valid curve point
    #[cfg_attr(feature = "thiserror", error("Invalid public key"))]
    InvalidPublicKey,

    /// Secret key is malformed or invalid
    #[cfg_attr(feature = "thiserror", error("Invalid secret key"))]
    InvalidSecretKey,

    /// Failed to decode bytes as an Edwards curve point
    #[cfg_attr(feature = "thiserror", error("Invalid point encoding"))]
    InvalidPoint,

    /// Failed to decode bytes as a valid scalar
    #[cfg_attr(feature = "thiserror", error("Invalid scalar"))]
    InvalidScalar,

    /// VRF proof verification failed
    #[cfg_attr(feature = "thiserror", error("VRF verification failed"))]
    VerificationFailed,

    /// Invalid input data (wrong length, etc.)
    #[cfg_attr(feature = "thiserror", error("Invalid input"))]
    InvalidInput,

    /// Key generation failed
    #[cfg_attr(feature = "thiserror", error("Key generation failed"))]
    KeyGenerationFailed,

    /// KES evolution error
    #[cfg_attr(feature = "thiserror", error("KES evolution error"))]
    KesEvolutionError,

    /// KES period out of range
    #[cfg_attr(feature = "thiserror", error("KES period out of range"))]
    KesPeriodError,

    /// Invalid key length
    #[cfg_attr(feature = "thiserror", error("Invalid key length"))]
    InvalidKeyLength,

    /// Invalid signature
    #[cfg_attr(feature = "thiserror", error("Invalid signature"))]
    InvalidSignature,

    /// Key expired (for KES)
    #[cfg_attr(feature = "thiserror", error("Key has expired"))]
    KeyExpired,

    /// Invalid period (for KES)
    #[cfg_attr(feature = "thiserror", error("Invalid period"))]
    InvalidPeriod,

    /// Serialization error
    #[cfg_attr(feature = "thiserror", error("Serialization error"))]
    SerializationError,

    /// Deserialization error
    #[cfg_attr(feature = "thiserror", error("Deserialization error"))]
    DeserializationError,

    /// Generic cryptographic error
    #[cfg_attr(feature = "thiserror", error("Cryptographic operation failed"))]
    CryptoFailure,

    /// KES-specific error
    #[cfg_attr(feature = "thiserror", error("KES error: {0}"))]
    KesError(crate::kes::KesError),

    /// Other error with description
    #[cfg_attr(feature = "thiserror", error("{0}"))]
    Other(&'static str),
}

#[cfg(not(feature = "thiserror"))]
impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::InvalidProof => write!(f, "Invalid VRF proof"),
            CryptoError::InvalidPublicKey => write!(f, "Invalid public key"),
            CryptoError::InvalidSecretKey => write!(f, "Invalid secret key"),
            CryptoError::InvalidPoint => write!(f, "Invalid point encoding"),
            CryptoError::InvalidScalar => write!(f, "Invalid scalar"),
            CryptoError::VerificationFailed => write!(f, "VRF verification failed"),
            CryptoError::InvalidInput => write!(f, "Invalid input"),
            CryptoError::KeyGenerationFailed => write!(f, "Key generation failed"),
            CryptoError::KesEvolutionError => write!(f, "KES evolution error"),
            CryptoError::KesPeriodError => write!(f, "KES period out of range"),
            CryptoError::InvalidKeyLength => write!(f, "Invalid key length"),
            CryptoError::InvalidSignature => write!(f, "Invalid signature"),
            CryptoError::KeyExpired => write!(f, "Key has expired"),
            CryptoError::InvalidPeriod => write!(f, "Invalid period"),
            CryptoError::SerializationError => write!(f, "Serialization error"),
            CryptoError::DeserializationError => write!(f, "Deserialization error"),
            CryptoError::CryptoFailure => write!(f, "Cryptographic operation failed"),
            CryptoError::KesError(e) => write!(f, "KES error: {}", e),
            CryptoError::Other(msg) => write!(f, "{}", msg),
        }
    }
}

#[cfg(all(not(feature = "thiserror"), feature = "std"))]
impl std::error::Error for CryptoError {}

#[cfg(all(not(feature = "thiserror"), not(feature = "std")))]
impl core::error::Error for CryptoError {}
