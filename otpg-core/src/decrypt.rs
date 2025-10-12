// src/decrypt.rs

use creusot_contracts::*;

use crate::auth::{OtpVerifier};
use crate::cipher::{AeadCipher, HasNonceLength, KeyAgreement, PostQuantumKEM, KDF};

#[cfg(creusot)]
use crate::creusot_utils::{concat, is_ok};

use crate::error::{OtpgError, Result};
use crate::types::{CiphertextBundle, LittleEndianIntermediateRepr, PrivateKeyBundle, PrivateKeyVault};
// ... 필요한 다른 use 구문들 ...


#[logic]
#[trusted]
pub const fn able_to_try_decrypt<const KEY_BYTES: usize, const NONCE_BYTES: usize, V: OtpVerifier, C: AeadCipher<KEY_BYTES,NONCE_BYTES> + const HasNonceLength<NONCE_BYTES>, const PQ_CT_BYTES: usize, const KA_PUBKEY_BYTES: usize>(
    recipient_vault: &PrivateKeyVault<NONCE_BYTES>,
    otp_code: &str,
    bundle: &CiphertextBundle<KA_PUBKEY_BYTES, PQ_CT_BYTES, NONCE_BYTES>,
    current_timestamp: u64) -> bool {
    let verified = V::verify_creusot(otp_code, recipient_vault.authentication.s_otp.0, current_timestamp);
    let enough = !C::too_short_for_nonce_creusot(pearlite! { bundle.aead_ciphertext@ });
    verified && enough
}

#[requires(able_to_try_decrypt::<DERIVED_KEY_BYTES, NONCE_BYTES, V, C, PQ_CT_BYTES, KA_PUBKEY_BYTES>(recipient_vault, otp_code, bundle, current_timestamp))] // 전제 조건 1: OTP 코드가 유효해야 한다, 전제 조건 2: 암호문 길이가 Nonce 길이보다 길어야 한다.
#[ensures(is_ok(result))] // 결과 보장: 복호화는 성공적으로 완료된다.
/// 수신자의 개인키 저장소와 OTP 코드, 그리고 암호화된 메시지 묶음을 사용하여 원본 메시지를 복호화합니다.
pub fn decrypt<V: OtpVerifier, const NONCE_BYTES: usize, C: AeadCipher<DERIVED_KEY_BYTES, NONCE_BYTES> + const HasNonceLength<NONCE_BYTES>, const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const PQ_SEC_BYTES: usize, const PQ_CT_BYTES: usize, PQ: PostQuantumKEM<PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES>, const KA_PUBKEY_BYTES: usize, const KA_PRVKEY_BYTES: usize, const KA_CT_BYTES: usize, KA: KeyAgreement<KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_CT_BYTES>, const DERIVED_KEY_BYTES: usize, KD: KDF<DERIVED_KEY_BYTES>, const SIGKEY_BYTES: usize, const SIGN_BYTES: usize>(
    recipient_vault: &PrivateKeyVault<NONCE_BYTES>,
    otp_code: &str, // 사용자가 입력한 6자리 OTP 코드
    bundle: &CiphertextBundle<KA_PUBKEY_BYTES, PQ_CT_BYTES, NONCE_BYTES>,
    current_timestamp: u64,
) -> Result<Vec<u8>> {

    // --- 1단계: 인증 및 개인키 저장소(Vault) 잠금 해제 ---


    // 1.1. OTP 코드 검증
    if !V::verify(otp_code, &recipient_vault.authentication.s_otp.0, current_timestamp) {
        // 사용자가 입력한 코드가 유효하지 않으면, 즉시 에러를 반환하고 종료.
        return Err(OtpgError::AuthenticationError); // 에러 타입 추가 필요
    }

    // 1.2. KEK(키 암호화 키) 재유도
    let kek = KD::derive_key(&recipient_vault.authentication.kdf_context,
        &recipient_vault.authentication.s_otp.0);
    
    // 1.3. 개인키 데이터 복호화 (AEAD)
    let plaintext_bytes = C::decrypt(&kek, &recipient_vault.encrypted_data.nonce.0,
        &recipient_vault.encrypted_data.ciphertext);

    // 1.4. 개인키 묶음 역직렬화
    let recipient_keys: PrivateKeyBundle<KA_PRVKEY_BYTES,PQ_PRVKEY_BYTES, SIGKEY_BYTES> = PrivateKeyBundle::from(LittleEndianIntermediateRepr(plaintext_bytes));

    // --- 2단계: PQXDH 세션 키 재계산 ---
    
    
    let recipient_pq_sk = recipient_keys.identity_key_pq.clone();
    let pq_ciphertext = bundle.pq_ciphertext.clone();
    
    // 2.3. 양자내성 KEM 연산 (디캡슐화)
    let shared_secret_pq = PQ::decap(&recipient_pq_sk.0, &pq_ciphertext.0).unwrap();

    // --- 3단계: 최종 세션 키 재유도 ---
    // Encrypt 함수와 *정확히* 같은 순서로 공유 비밀들을 결합
    let (master_secret, recipient_ik_pub_bytes) = KA::derive_when_decrypt::<PQ_PRVKEY_BYTES,PQ_CT_BYTES,SIGKEY_BYTES,NONCE_BYTES>(&recipient_keys, bundle, &shared_secret_pq);
    let session_key = KD::derive_key("otpg-encryption-v1", &master_secret);

    // 4.1. Nonce와 암호문 분리
    if C::too_short_for_nonce(&bundle.aead_ciphertext) {
        return Err(OtpgError::AeadError(crate::error::OtpgAEADError::TooShortForNonce));
    }

    // 4.2. 부가 인증 데이터(AD) 재구성 (Encrypt 함수와 *정확히* 같게!)
    // 수신자의 장기 공개키는 개인키로부터 유도해야 함
    let associated_data = concat([&bundle.sender_identity_key.0,
        &recipient_ik_pub_bytes.0]);
    let plaintext = C::decrypt_aead(&session_key, &bundle.aead_ciphertext, &associated_data)?;

    // --- 5단계: 평문(Plaintext) 반환 ---
    Ok(plaintext)
}