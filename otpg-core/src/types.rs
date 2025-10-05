use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::constants::KYBER1024_SECRET_KEY_LEN;

// --- 공개키 관련 상수 ---
// X448 공개키는 56바이트, Ed448 서명은 114바이트입니다.
pub(crate) const X448_PUBLIC_KEY_LEN: usize = 56;
pub(crate) const ED448_SIGNATURE_LEN: usize = 114;
// Kyber1024 공개키는 1568바이트입니다.
pub(crate) const KYBER1024_PUBLIC_KEY_LEN: usize = 1568;

// --- 개인키 저장소 관련 상수 ---
pub(crate) const S_OTP_LEN: usize = 20; // 160 bits
pub(crate) const XCHACHA20_NONCE_LEN: usize = 24; // 192 bits

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bytes<const LEN: usize>(pub(crate) [u8; LEN]);

impl<const LEN: usize> Bytes<LEN> {
    pub fn inner_ref(&self) -> &[u8; LEN] {
        &self.0
    }
    
    pub fn inner_ref_as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const LEN: usize> Serialize for Bytes<LEN> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        self.0.serialize::<S>(serializer)
    }
}

impl<'de, const LEN: usize> Deserialize<'de> for Bytes<LEN> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> {
        let tmp0 = Vec::<u8>::deserialize::<D>(deserializer);
        let result = match tmp0 {
            Ok(parsed) => {
                if parsed.len() == LEN {
                    let mut inner_result = [0u8;LEN];
                    inner_result.clone_from_slice(&parsed);
                    Ok(Self(inner_result))
                } else {
                    Err(serde::de::Error::custom("wrong signed prekey length"))
                }
            },
            Err(e) => Err(e)
        };
        result
    }
}


#[derive(Serialize, Deserialize, Clone)]
pub struct SignedPreKey {
    pub key: Bytes<X448_PUBLIC_KEY_LEN>,
    pub signature: Bytes<ED448_SIGNATURE_LEN>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PublicKeyBundle {
    pub version: (u32, u32),
    pub identity_key: Bytes<X448_PUBLIC_KEY_LEN>,
    pub identity_key_pq: Bytes<KYBER1024_PUBLIC_KEY_LEN>,
    pub signed_prekey: SignedPreKey,
    pub one_time_prekeys: HashMap<u32, Bytes<X448_PUBLIC_KEY_LEN>>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct AuthenticationVault {
    pub method: String,
    pub s_otp: Bytes<S_OTP_LEN>,
    pub kdf_context: String
}

#[derive(Serialize, Deserialize, Clone)]
pub struct EncryptedData {
    pub nonce: Bytes<XCHACHA20_NONCE_LEN>,
    pub ciphertext: Vec<u8>
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PrivateKeyVault {
    pub version: (u32, u32),
    pub authentication: AuthenticationVault,
    pub encrypted_data: EncryptedData
}

// keygen 내부에서만 사용될 임시 구조체
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PrivateKeyBundle {
    pub(crate) identity_key_sig: ed448_goldilocks::SigningKey,
    pub(crate) identity_key_kx: Bytes<X448_PUBLIC_KEY_LEN>,
    pub(crate) identity_key_pq: Bytes<KYBER1024_SECRET_KEY_LEN>,
    pub(crate) signed_prekey: Bytes<X448_PUBLIC_KEY_LEN>,
    pub(crate) one_time_prekeys: HashMap<u32, Bytes<X448_PUBLIC_KEY_LEN>>,
}



/// 암호화된 메시지와 수신자가 복호화에 필요한 모든 정보를 담는 구조체
#[derive(Serialize, Deserialize)]
pub struct CiphertextBundle {
    /// 발신자의 장기 X448 공개키 (IK_B)
    pub sender_identity_key: Bytes<X448_PUBLIC_KEY_LEN>,
    /// 발신자의 임시 X448 공개키 (EK_B)
    pub sender_ephemeral_key: Bytes<X448_PUBLIC_KEY_LEN>,
    /// 수신자의 어떤 일회성 사전 키를 사용했는지 가리키는 ID
    pub opk_id: u32,
    /// Kyber KEM 암호문
    pub pq_ciphertext: Bytes<KYBER1024_CIPHERTEXT_LEN>, // 상수 추가 필요
    /// XChaCha20-Poly1305로 암호화된 최종 암호문
    pub aead_ciphertext: Vec<u8>,
}

// src/constants.rs 에 Kyber 암호문 길이 상수 추가
pub const KYBER1024_CIPHERTEXT_LEN: usize = 1568;