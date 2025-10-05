// src/encrypt.rs

use crate::error::{OtpgError, Result};
use crate::types::{Bytes, CiphertextBundle, PrivateKeyBundle, PublicKeyBundle};
use crate::cipher::{AeadCipher, KeyAgreement, PostQuantumKEM, KDF};
// ... 필요한 다른 use 구문들 ...

/// 발신자의 개인키와 수신자의 공개키 묶음을 사용하여 메시지를 암호화합니다.
pub fn encrypt<C: AeadCipher, PQ: PostQuantumKEM, KA: KeyAgreement, const DERIVED_KEY_LEN: usize, KD: KDF<DERIVED_KEY_LEN>>(
    sender_keys: &PrivateKeyBundle,
    recipient_bundle: &PublicKeyBundle,
    plaintext: &[u8],
) -> Result<CiphertextBundle> {
    let (opk_id, master_secret, pq_ciphertext, sender_identity_key, sender_ephemeral_key) = KA::derive_when_encrypt(sender_keys, recipient_bundle, |b| PQ::encap(b).unwrap());

    let session_key = KD::derive_key("otpg-encryption-v1", &master_secret);
    
    // --- 6. AEAD 대칭키 암호화 ---
    

    // 부가 인증 데이터(AD): 발신자와 수신자의 장기 공개키를 묶어, 이 암호문이 누구와 누구 사이의 대화인지 증명
    let associated_data = [
        &sender_identity_key, 
        recipient_bundle.identity_key.0.as_slice()
    ].concat();
    

    // --- 6. AEAD 대칭키 암호화 ---
    let (nonce, aead_ciphertext) = C::encrypt(session_key.as_slice(), plaintext, &associated_data)?;

    // --- 7. CiphertextBundle 조립 및 반환 ---
    Ok(CiphertextBundle {
        sender_identity_key: Bytes(sender_identity_key.try_into().map_err(|_| OtpgError::KeyConversionError)?),
        sender_ephemeral_key: Bytes(sender_ephemeral_key.try_into().map_err(|_| OtpgError::KeyConversionError)?),
        opk_id: opk_id,
        pq_ciphertext: Bytes(pq_ciphertext.try_into().map_err(|_| OtpgError::KeyConversionError)?),
        aead_ciphertext: [nonce.0.as_slice(), aead_ciphertext.as_slice()].concat(),
    })
}