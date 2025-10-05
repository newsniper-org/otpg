use std::collections::HashMap;

#[cfg(all(not(hax), feature = "serde"))]
use serde::{Deserialize, Serialize};

use crate::{define_with_serde, optional_serde_derive};

pub trait GetContextStr {
    fn get_context_str() -> &'static str;
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Bytes<const LEN: usize>(pub [u8; LEN]);

impl<const LEN: usize> Bytes<LEN> {
    pub fn inner_ref(&self) -> &[u8; LEN] {
        &self.0
    }
    
    pub fn inner_ref_as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}


define_with_serde! {
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
}


optional_serde_derive! {
    #[derive(Clone)]
    pub struct SignedPreKey {
        pub key: Vec<u8>,
        pub signature: Vec<u8>
    }

    #[derive(Clone)]
    pub struct PublicKeyBundle {
        pub version: (u32, u32),
        pub identity_key: Vec<u8>,
        pub identity_key_pq: Vec<u8>,
        pub signed_prekey: SignedPreKey,
        pub one_time_prekeys: HashMap<u32, Vec<u8>>
    }

    #[derive(Clone)]
    pub struct AuthenticationVault {
        pub method: String,
        pub s_otp: Vec<u8>,
        pub kdf_context: String
    }

    #[derive(Clone)]
    pub struct EncryptedData {
        pub nonce: Vec<u8>,
        pub ciphertext: Vec<u8>
    }

    #[derive(Clone)]
    pub struct PrivateKeyVault {
        pub version: (u32, u32),
        pub authentication: AuthenticationVault,
        pub encrypted_data: EncryptedData
    }

    // keygen 내부에서만 사용될 임시 구조체
    pub struct PrivateKeyBundle {
        pub identity_key_sig: Vec<u8>,
        pub identity_key_kx: Vec<u8>,
        pub identity_key_pq: Vec<u8>,
        pub signed_prekey: Vec<u8>,
        pub one_time_prekeys: HashMap<u32, Vec<u8>>,
    }



    /// 암호화된 메시지와 수신자가 복호화에 필요한 모든 정보를 담는 구조체
    pub struct CiphertextBundle {
        /// 발신자의 장기 X448 공개키 (IK_B)
        pub sender_identity_key: Vec<u8>,
        /// 발신자의 임시 X448 공개키 (EK_B)
        pub sender_ephemeral_key: Vec<u8>,
        /// 수신자의 어떤 일회성 사전 키를 사용했는지 가리키는 ID
        pub opk_id: u32,
        /// Kyber KEM 암호문
        pub pq_ciphertext: Vec<u8>,
        /// XChaCha20-Poly1305로 암호화된 최종 암호문
        pub aead_ciphertext: Vec<u8>,
    }

}

// src/constants.rs 에 Kyber 암호문 길이 상수 추가
pub const KYBER1024_CIPHERTEXT_LEN: usize = 1568;