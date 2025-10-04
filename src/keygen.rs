// src/keygen.rs

use crate::constants::*;
use crate::error::{OtpgError, Result};
use crate::types::{
    AuthenticationVault, Bytes as BytesWrapper, EncryptedData, PrivateKeyBundle, PrivateKeyVault, PublicKeyBundle, SignedPreKey
};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305,
};
use crypt_guard::{kyber};
use ed448::signature::Signer;
use std::collections::HashMap;
use openssl::pkey::{PKey, Private}; // OpenSSL PKey 사용

/// OTPG를 위한 새로운 키 쌍과 개인키 저장소를 생성합니다.
pub fn generate_keys(num_opks: u32) -> Result<(PublicKeyBundle, PrivateKeyVault)> {
    let mut rng = rand::rng();
    // --- 1. 모든 키 쌍 생성 ---
    let ik_sig = ed448_goldilocks::SigningKey::generate(&mut rng);
    // 장기 신원 키 (IK_KX)
    let ik_kx = PKey::generate_x448().unwrap();
    let ik_kx_pk_bytes = ik_kx.raw_public_key().unwrap();
    let ik_kx_sk_bytes = ik_kx.raw_private_key().unwrap();
    let (ik_pq_pk, ik_pq_sk) = kyber::key_controler::KeyControKyber1024::keypair().unwrap();
    // 서명된 사전 키 (SPK)
    let spk: PKey<Private> = PKey::generate_x448().unwrap();
    let spk_pk_bytes: Vec<u8> = spk.raw_public_key().unwrap();
    let spk_sk_bytes: Vec<u8> = spk.raw_private_key().unwrap();

    let opks: HashMap<u32, PKey<Private>> = (0..num_opks)
        .map(|id| (id, PKey::generate_x448().unwrap()))
        .collect();

    // --- 2. 사전 키 서명 ---
    let signature = ik_sig.sign(&spk_pk_bytes);

    let mut ik_pq_pk_bytes: [u8; KYBER1024_PUBLIC_KEY_LEN] = [0u8; KYBER1024_PUBLIC_KEY_LEN];
    ik_pq_pk_bytes.clone_from_slice(&ik_pq_pk[..KYBER1024_PUBLIC_KEY_LEN]);

    // --- 3. PublicKeyBundle 조립 ---
    let public_bundle = PublicKeyBundle {
        version: (1, 0),
        identity_key: BytesWrapper(ik_kx_pk_bytes.try_into().unwrap()),
        identity_key_pq: BytesWrapper(ik_pq_pk_bytes),
        signed_prekey: SignedPreKey {
            key: BytesWrapper(spk_pk_bytes.try_into().unwrap()),
            signature: BytesWrapper(signature.to_bytes()),
        },
        one_time_prekeys: opks
            .iter()
            .map(|(id, sk)| {
                (*id, BytesWrapper(sk.raw_public_key().unwrap().try_into().unwrap()))
            })
            .collect(),
    };
    let mut tmp: [u8; KYBER1024_SECRET_KEY_LEN] = [0u8; KYBER1024_SECRET_KEY_LEN];
    tmp.clone_from_slice(&ik_pq_sk[..KYBER1024_SECRET_KEY_LEN]);

    // --- 4. S_OTP 생성 및 개인키 암호화 ---
    let private_bundle = PrivateKeyBundle {
        identity_key_sig: ik_sig,
        identity_key_kx: BytesWrapper(ik_kx_sk_bytes.try_into().unwrap()),
        identity_key_pq: BytesWrapper(tmp),
        signed_prekey: BytesWrapper(spk_sk_bytes.try_into().unwrap()),
        one_time_prekeys: opks
            .iter()
            .map(|(id, sk)| {
                (*id, BytesWrapper(sk.raw_private_key().unwrap().try_into().unwrap()))
            })
            .collect(),
    };
    let serialized_private_keys = bincode::serde::encode_to_vec(private_bundle, bincode::config::standard().with_fixed_int_encoding()).unwrap();

    let mut s_otp = [0u8; S_OTP_LEN];
    rand::fill(&mut s_otp);
    let kek = blake3::derive_key("otpg-key-wrapping-v1", &s_otp);

    let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
    rand::fill(&mut nonce);
    let cipher = XChaCha20Poly1305::new(&kek.into());
    let ciphertext = cipher
        .encrypt(&nonce.into(), serialized_private_keys.as_slice())
        .map_err(|_| OtpgError::AeadError)?;

    // --- 5. PrivateKeyVault 조립 ---
    let private_vault = PrivateKeyVault {
        version: (1, 0),
        authentication: AuthenticationVault {
            method: "TOTP-BLAKE3-XCHACHA20POLY1305".to_string(),
            s_otp: BytesWrapper(s_otp),
            kdf_context: "otpg-key-wrapping-v1".to_string(),
        },
        encrypted_data: EncryptedData {
            nonce: BytesWrapper(nonce),
            ciphertext,
        },
    };

    // --- 6. 결과 반환 ---
    Ok((public_bundle, private_vault))
}