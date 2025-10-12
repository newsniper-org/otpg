// src/encrypt.rs

// ... 필요한 다른 use 구문들 ...

#[cfg(creusot)]
mod for_creusot {
    use creusot_contracts::*;

    use crate::bytes_concat;
    use crate::error::{Result};
    use crate::types::{CiphertextBundle, PrivateKeyBundle, PublicKeyBundle};
    use crate::cipher::{AeadCipher, KeyAgreement, PostQuantumKEM, KDF};
    use crate::creusot_utils::{is_ok};
    
    #[requires(plaintext@.len() > 0)] // 전제 조건: 평문은 비어있지 않아야 한다.
    #[requires(recipient_bundle.one_time_prekeys@.len() > 0)] // 전제 조건: 수신자의 일회용 키는 최소 1개 이상 존재해야 한다.
    #[ensures(is_ok(result))]
    /// 발신자의 개인키와 수신자의 공개키 묶음을 사용하여 메시지를 암호화합니다.
    pub fn encrypt<const NONCE_BYTES: usize, C: AeadCipher<DERIVED_KEY_BYTES, NONCE_BYTES>, const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const PQ_SEC_BYTES: usize, const PQ_CT_BYTES: usize, PQ: PostQuantumKEM<PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES>, const KA_PUBKEY_BYTES: usize, const KA_PRVKEY_BYTES: usize, const KA_CT_BYTES: usize, KA: KeyAgreement<KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_CT_BYTES>, const DERIVED_KEY_BYTES: usize, KD: KDF<DERIVED_KEY_BYTES>, const SIGKEY_BYTES: usize, const SIGN_BYTES: usize>(
        sender_keys: &PrivateKeyBundle<KA_PRVKEY_BYTES,PQ_PRVKEY_BYTES,SIGKEY_BYTES>,
        recipient_bundle: &PublicKeyBundle<KA_PUBKEY_BYTES, PQ_PUBKEY_BYTES, SIGN_BYTES>,
        plaintext: &[u8],
    ) -> Result<CiphertextBundle<KA_PUBKEY_BYTES,PQ_CT_BYTES,NONCE_BYTES>> {
        match encrypt_to_verify::<NONCE_BYTES, C, PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES, PQ, KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_CT_BYTES, KA, DERIVED_KEY_BYTES, KD, SIGKEY_BYTES, SIGN_BYTES>(sender_keys, recipient_bundle, plaintext) {
            Ok((cb, _)) => Ok(cb),
            Err(e) => Err(e)
        }
    }

    pub(crate) fn encrypt_to_verify<const NONCE_BYTES: usize, C: AeadCipher<DERIVED_KEY_BYTES, NONCE_BYTES>, const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const PQ_SEC_BYTES: usize, const PQ_CT_BYTES: usize, PQ: PostQuantumKEM<PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES>, const KA_PUBKEY_BYTES: usize, const KA_PRVKEY_BYTES: usize, const KA_CT_BYTES: usize, KA: KeyAgreement<KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_CT_BYTES>, const DERIVED_KEY_BYTES: usize, KD: KDF<DERIVED_KEY_BYTES>, const SIGKEY_BYTES: usize, const SIGN_BYTES: usize>(
        sender_keys: &PrivateKeyBundle<KA_PRVKEY_BYTES,PQ_PRVKEY_BYTES,SIGKEY_BYTES>,
        recipient_bundle: &PublicKeyBundle<KA_PUBKEY_BYTES, PQ_PUBKEY_BYTES, SIGN_BYTES>,
        plaintext: &[u8],
    ) -> Result<(CiphertextBundle<KA_PUBKEY_BYTES,PQ_CT_BYTES,NONCE_BYTES>, Vec<u8>)> {
        let (opk_id, classic_dh_secrets, sender_identity_key, sender_ephemeral_key) = 
            KA::derive_when_encrypt(sender_keys, recipient_bundle)?;
        let (shared_secret_pq, pq_ciphertext) = PQ::encap(&recipient_bundle.identity_key_pq.0)?;

        let master_secret = bytes_concat![classic_dh_secrets.0, shared_secret_pq.0];

        let session_key = KD::derive_key("otpg-encryption-v1", &master_secret);

        // 부가 인증 데이터(AD): 발신자와 수신자의 장기 공개키를 묶어, 이 암호문이 누구와 누구 사이의 대화인지 증명
        let associated_data = bytes_concat![
            sender_identity_key.0,
            recipient_bundle.identity_key.0
        ];
        

        // --- 6. AEAD 대칭키 암호화 ---
        let (nonce, aead_ciphertext) = C::encrypt_aead(&session_key, plaintext, &associated_data)?;

        // --- 7. CiphertextBundle 조립 및 반환 ---
        Ok((CiphertextBundle {
            sender_identity_key,
            sender_ephemeral_key,
            opk_id: opk_id,
            pq_ciphertext,
            aead_ciphertext: bytes_concat![nonce.0, aead_ciphertext]
        }, master_secret))
    }
}

#[cfg(not(creusot))]
mod not_for_creusot {

    use crate::bytes_concat;
    use crate::error::{Result};
    use crate::types::{CiphertextBundle, PrivateKeyBundle, PublicKeyBundle};
    use crate::cipher::{AeadCipher, KeyAgreement, PostQuantumKEM, KDF};

    /// 발신자의 개인키와 수신자의 공개키 묶음을 사용하여 메시지를 암호화합니다.
    pub fn encrypt<const NONCE_BYTES: usize, C: AeadCipher<DERIVED_KEY_BYTES, NONCE_BYTES>, const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const PQ_SEC_BYTES: usize, const PQ_CT_BYTES: usize, PQ: PostQuantumKEM<PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES>, const KA_PUBKEY_BYTES: usize, const KA_PRVKEY_BYTES: usize, const KA_CT_BYTES: usize, KA: KeyAgreement<KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_CT_BYTES>, const DERIVED_KEY_BYTES: usize, KD: KDF<DERIVED_KEY_BYTES>, const SIGKEY_BYTES: usize, const SIGN_BYTES: usize>(
        sender_keys: &PrivateKeyBundle<KA_PRVKEY_BYTES,PQ_PRVKEY_BYTES,SIGKEY_BYTES>,
        recipient_bundle: &PublicKeyBundle<KA_PUBKEY_BYTES, PQ_PUBKEY_BYTES, SIGN_BYTES>,
        plaintext: &[u8],
    ) -> Result<CiphertextBundle<KA_PUBKEY_BYTES,PQ_CT_BYTES,NONCE_BYTES>> {
        let (opk_id, classic_dh_secrets, sender_identity_key, sender_ephemeral_key) = 
            KA::derive_when_encrypt(sender_keys, recipient_bundle)?;
        let (shared_secret_pq, pq_ciphertext) = PQ::encap(&recipient_bundle.identity_key_pq.0)?;

        let master_secret = bytes_concat![classic_dh_secrets.0, shared_secret_pq.0];

        let session_key = KD::derive_key("otpg-encryption-v1", &master_secret);

        // 부가 인증 데이터(AD): 발신자와 수신자의 장기 공개키를 묶어, 이 암호문이 누구와 누구 사이의 대화인지 증명
        let associated_data = bytes_concat![
            sender_identity_key.0,
            recipient_bundle.identity_key.0
        ];
        

        // --- 6. AEAD 대칭키 암호화 ---
        let (nonce, aead_ciphertext) = C::encrypt_aead(&session_key, plaintext, &associated_data)?;

        // --- 7. CiphertextBundle 조립 및 반환 ---
        Ok(CiphertextBundle {
            sender_identity_key,
            sender_ephemeral_key,
            opk_id: opk_id,
            pq_ciphertext,
            aead_ciphertext: bytes_concat![nonce.0, aead_ciphertext]
        })
    }
}

#[cfg(creusot)]
pub use for_creusot::encrypt;
#[cfg(creusot)]
pub(crate) use for_creusot::encrypt_to_verify;
#[cfg(not(creusot))]
pub use not_for_creusot::encrypt;