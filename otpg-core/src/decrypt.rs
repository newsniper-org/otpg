// src/decrypt.rs

use crate::auth::{OtpVerifier};
use crate::cipher::{AeadCipher, KeyAgreement, PostQuantumKEM, KDF};
use crate::error::{OtpgError, Result};
use crate::types::{PrivateKeyVault, CiphertextBundle, PrivateKeyBundle};
// ... 필요한 다른 use 구문들 ...
use crate::serialization::BundleDeserializer;


/// 수신자의 개인키 저장소와 OTP 코드, 그리고 암호화된 메시지 묶음을 사용하여 원본 메시지를 복호화합니다.
pub fn decrypt<V: OtpVerifier, D: BundleDeserializer, const NONCE_LEN: usize, C: AeadCipher<NONCE_LEN>, PQ: PostQuantumKEM, KA: KeyAgreement, const DERIVED_KEY_LEN: usize, KD: KDF<DERIVED_KEY_LEN>>(
    verifier: &V, // "OtpVerifier 역할을 할 수 있는 무언가"를 인자로 받음
    recipient_vault: &PrivateKeyVault,
    otp_code: &str, // 사용자가 입력한 6자리 OTP 코드
    bundle: &CiphertextBundle,
    current_timestamp: u64,
) -> Result<Vec<u8>> {

    // --- 1단계: 인증 및 개인키 저장소(Vault) 잠금 해제 ---

    // 1.1. OTP 코드 검증
    if !verifier.verify(otp_code, &recipient_vault.authentication.s_otp, current_timestamp) {
        // 사용자가 입력한 코드가 유효하지 않으면, 즉시 에러를 반환하고 종료.
        return Err(OtpgError::AuthenticationError); // 에러 타입 추가 필요
    }

    // 1.2. KEK(키 암호화 키) 재유도
    let kek = KD::derive_key(&recipient_vault.authentication.kdf_context,
        &recipient_vault.authentication.s_otp);
    
    // 1.3. 개인키 데이터 복호화 (AEAD)
    let plaintext_bytes = C::decrypt(kek.as_slice(), &recipient_vault.encrypted_data.nonce,
        recipient_vault.encrypted_data.ciphertext.as_slice())?;

    // 1.4. 개인키 묶음 역직렬화
    let recipient_keys: PrivateKeyBundle = D::deserialize(&plaintext_bytes).unwrap();

    // --- 2단계: PQXDH 세션 키 재계산 ---
    
    
    let recipient_pq_sk = recipient_keys.identity_key_pq.clone();
    let pq_ciphertext = bundle.pq_ciphertext.clone();
    
    // 2.3. 양자내성 KEM 연산 (디캡슐화)
    let shared_secret_pq = PQ::decap(&recipient_pq_sk, &pq_ciphertext).unwrap();

    // --- 3단계: 최종 세션 키 재유도 ---
    // Encrypt 함수와 *정확히* 같은 순서로 공유 비밀들을 결합
    let (master_secret, recipient_ik_pub_bytes) = KA::derive_when_decrypt(&recipient_keys, bundle, &shared_secret_pq);
    let session_key = KD::derive_key("otpg-encryption-v1", &master_secret);

    // 4.1. Nonce와 암호문 분리
    if C::too_short_for_nonce(bundle.aead_ciphertext.len()) {
        return Err(OtpgError::AeadError); // 암호문이 너무 짧으면 에러
    }

    // 4.2. 부가 인증 데이터(AD) 재구성 (Encrypt 함수와 *정확히* 같게!)
    // 수신자의 장기 공개키는 개인키로부터 유도해야 함
    let associated_data = [
        bundle.sender_identity_key.as_slice(),
        recipient_ik_pub_bytes.as_slice(),
    ].concat();
    let plaintext = C::decrypt_aead(session_key.as_slice(), &bundle.aead_ciphertext, &associated_data)?;

    // --- 5단계: 평문(Plaintext) 반환 ---
    Ok(plaintext)
}

#[cfg(hax)]
pub fn decrypt_to_verify<V : OtpVerifier>(
    verifier: V, // "OtpVerifier 역할을 할 수 있는 무언가"를 인자로 받음
    recipient_vault: &PrivateKeyVault,
    otp_code: &str, // 사용자가 입력한 6자리 OTP 코드
    bundle: &CiphertextBundle,
    current_timestamp: u64,
) -> Result<Vec<u8>> {
    todo!()
}