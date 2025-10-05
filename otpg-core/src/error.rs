// src/error.rs

#[cfg(not(hax))]
mod real {
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum OtpgError {
        #[error("Failed to generate random bytes: {0}")]
        RandomnessError(#[from] getrandom::Error),

        #[error("Serialization failed: {0}")]
        SerializationError(#[from] Box<bincode::error::EncodeError>),
        
        #[error("Deserialization failed: {0}")]
        DeserializationError(#[from] bincode::error::DecodeError),

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
}

// --- 정형 검증(hax) 환경 ---
// hax 플래그가 있을 때는, 외부 의존성이 전혀 없는 단순한 열거형을 사용합니다.
#[cfg(hax)]
mod fake {
    #[derive(Debug)]
    pub enum OtpgError {
        RandomnessError,
        SerializationError,
        DeserializationError,
        AeadError,
        AuthenticationError,
        SignatureError,
        OpenSSLError,
        NoPreKeyAvailable,
        KeyConversionError,
    }
}

// 조건부 컴파일을 통해 두 모듈 중 하나에서 OtpgError를 가져와 공개합니다.
#[cfg(not(hax))]
pub use real::OtpgError;
#[cfg(hax)]
pub use fake::OtpgError;

pub type Result<T> = std::result::Result<T, OtpgError>;