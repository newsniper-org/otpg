// src/error.rs

use thiserror::Error;

use creusot_contracts::{trusted};

#[trusted]
#[derive(Error, Debug)]
pub enum OtpgError {
    #[error("Failed to generate random bytes: {0}")]
    RandomnessError(#[from] getrandom::Error),

    #[error("Serialization failed: {0}")]
    SerializationError(#[from] bincode::error::EncodeError),
    
    #[error("Deserialization failed: {0}")]
    DeserializationError(#[from] bincode::error::DecodeError),

    #[error("AEAD failed: {0}")]
    AeadError(String),

    #[error("Authentication failed")]
    AuthenticationError,

    #[error("Ed448 signature error: {0}")]
    SignatureError(#[from] signature::Error),

    #[error("No available one-time pre-key found")]
    NoPreKeyAvailable,
    
    #[error("Key conversion error: invalid length")]
    KeyConversionError,
}

pub type Result<T> = std::result::Result<T, OtpgError>;