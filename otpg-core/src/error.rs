// src/error.rs

use thiserror::Error;

#[derive(Debug, Clone, Copy)]
pub enum OtpgAEADError {
    EncrptionFailed,
    DecrptionFailed,
    TooShortForNonce
}
impl OtpgAEADError {
    pub const fn to_str(self) -> &'static str {
        match self {
            Self::EncrptionFailed => "AEAD encryption failed",
            Self::DecrptionFailed => "AEAD decryption failed",
            Self::TooShortForNonce => "Too short for nonce"
        }
    }
}

impl std::fmt::Display for OtpgAEADError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
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