// src/encrypt.rs

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use crypt_guard::{kyber};
use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey};
use rand::seq::IteratorRandom;

use crate::error::{OtpgError, Result};
use crate::types::{Bytes, CiphertextBundle, PrivateKeyBundle, PublicKeyBundle};
use crate::constants::*;
// ... 필요한 다른 use 구문들 ...

/// 발신자의 개인키와 수신자의 공개키 묶음을 사용하여 메시지를 암호화합니다.
pub fn encrypt(
    sender_keys: &PrivateKeyBundle,
    recipient_bundle: &PublicKeyBundle,
    plaintext: &[u8],
) -> Result<CiphertextBundle> {
    // --- 1. 사용할 수신자의 일회성 사전 키(OPK) 랜덤 선택 ---
    let mut rng = rand::rng();
    let chosen = recipient_bundle.one_time_prekeys.keys().choose(&mut rng).ok_or(OtpgError::NoPreKeyAvailable)?;
    let (&opk_id, &recipient_opk_pub) = recipient_bundle.one_time_prekeys.get_key_value(chosen).unwrap().clone();

    // --- 2. 발신자의 임시 키(Ephemeral Key) 생성 ---
    let sender_ephemeral_key = PKey::generate_x448()?;

    // --- 3. 필요한 모든 키들을 라이브러리 타입으로 변환 ---
    // 발신자 키
    let sender_ik_pkey = PKey::private_key_from_raw_bytes(&sender_keys.identity_key_kx.0, Id::X448)?;

    // 수신자 키
    let recipient_ik_pkey = PKey::public_key_from_raw_bytes(&recipient_bundle.identity_key.0, Id::X448)?;
    let recipient_spk_pkey = PKey::public_key_from_raw_bytes(&recipient_bundle.signed_prekey.key.0, Id::X448)?;
    let recipient_opk_pkey = PKey::public_key_from_raw_bytes(&recipient_opk_pub.0, Id::X448)?;
    let recipient_pq_pk = recipient_bundle.identity_key_pq.0;

    // --- 4. PQXDH 키 교환 수행 ---
    let mut dh1_deriver = Deriver::new(&sender_ephemeral_key)?;
    dh1_deriver.set_peer(&recipient_spk_pkey)?;
    let dh1 = dh1_deriver.derive_to_vec()?;

    let mut dh2_deriver = Deriver::new(&sender_ik_pkey)?;
    dh2_deriver.set_peer(&recipient_ik_pkey)?;
    let dh2 = dh2_deriver.derive_to_vec()?;
    
    let mut dh3_deriver = Deriver::new(&sender_ephemeral_key)?;
    dh3_deriver.set_peer(&recipient_ik_pkey)?;
    let dh3 = dh3_deriver.derive_to_vec()?;

    let mut dh4_deriver = Deriver::new(&sender_ephemeral_key)?;
    dh4_deriver.set_peer(&recipient_opk_pkey)?;
    let dh4 = dh4_deriver.derive_to_vec()?;
    
    let (pq_ciphertext, shared_secret_pq) = kyber::key_controler::KeyControKyber1024::encap(&recipient_pq_pk).unwrap();

    // --- 5. 최종 세션 키 유도 ---
    let master_secret = [dh1.as_slice(), dh2.as_slice(), dh3.as_slice(), dh4.as_slice(), shared_secret_pq.as_slice()].concat();
    let session_key = blake3::derive_key("otpg-encryption-v1", &master_secret);
    
    // --- 6. AEAD 대칭키 암호화 ---
    let cipher = XChaCha20Poly1305::new(session_key.as_slice().into());
    let mut nonce = [0u8; XCHACHA20_NONCE_LEN];
    rand::fill(&mut nonce);

    // 부가 인증 데이터(AD): 발신자와 수신자의 장기 공개키를 묶어, 이 암호문이 누구와 누구 사이의 대화인지 증명
    let associated_data = [
        sender_ik_pkey.raw_public_key()?.as_slice(), 
        recipient_bundle.identity_key.0.as_slice()
    ].concat();
    let payload = chacha20poly1305::aead::Payload {
        msg: plaintext,
        aad: &associated_data,
    };

    let aead_ciphertext = cipher.encrypt(&nonce.into(), payload)
        .map_err(|_| OtpgError::AeadError)?;

    // --- 7. CiphertextBundle 조립 및 반환 ---
    Ok(CiphertextBundle {
        sender_identity_key: Bytes(sender_ik_pkey.raw_public_key()?.try_into().map_err(|_| OtpgError::KeyConversionError)?),
        sender_ephemeral_key: Bytes(sender_ephemeral_key.raw_public_key()?.try_into().map_err(|_| OtpgError::KeyConversionError)?),
        opk_id: opk_id,
        pq_ciphertext: Bytes(pq_ciphertext.try_into().unwrap()),
        aead_ciphertext: [nonce.as_slice(), aead_ciphertext.as_slice()].concat(),
    })
}