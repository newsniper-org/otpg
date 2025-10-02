// src/error.rs

use thiserror::Error;

#[derive(Error, Debug)]
pub enum OtpgError {
    #[error("Failed to generate random bytes: {0}")]
    RandomnessError(#[from] getrandom::Error),

    #[error("Serialization failed: {0}")]
    SerializationError(#[from] Box<bincode::error::EncodeError>),
    
    #[error("Deserialization failed: {0}")]
    DeserializationError(#[from] bincode::error::DecodeError), // 복호화를 위해 추가

    #[error("AEAD encryption/decryption failed")]
    AeadError,

    #[error("Authentication failed")]
    AuthenticationError,

    #[error("Ed448 signature error: {0}")]
    SignatureError(#[from] ed448::signature::Error),

    #[error("OpenSSL error: {0}")]
    OpenSSLError(#[from] openssl::error::ErrorStack),

    #[error("No available one-time pre-key found")]
    NoPreKeyAvailable,
    
    #[error("Key conversion error: invalid length")]
    KeyConversionError,
}

pub type Result<T> = std::result::Result<T, OtpgError>;