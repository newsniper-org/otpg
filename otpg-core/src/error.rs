// src/error.rs

use thiserror::Error;

#[derive(Error, Debug)]
pub enum OtpgAEADError {
    #[error("AEAD encryption failed")]
    EncrptionFailed,

    #[error("AEAD decryption failed")]
    DecrptionFailed,

    #[error("Too short for nonce")]
    TooShortForNonce
}

#[derive(Error, Debug)]
pub enum OtpgError {
    /*
    #[error("Failed to generate random bytes: {0}")]
    RandomnessError(#[from] getrandom::Error),
    */
    #[error("AEAD failed: {0}!")]
    AeadError(OtpgAEADError),

    #[error("Authentication failed")]
    AuthenticationError,
    /*
    #[error("Ed448 signature error: {0}")]
    SignatureError(#[from] signature::Error),
    */

    #[error("No available one-time pre-key found")]
    NoPreKeyAvailable,
    
    #[error("Key conversion error: invalid length")]
    KeyConversionError,
}

pub type Result<T> = std::result::Result<T, OtpgError>;