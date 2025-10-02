// src/decrypt.rs

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use crypt_guard::kyber;
use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey};

use crate::auth::verify_totp;
use crate::constants::XCHACHA20_NONCE_LEN;
use crate::error::{OtpgError, Result};
use crate::types::{PrivateKeyVault, CiphertextBundle, PrivateKeyBundle};
// ... 필요한 다른 use 구문들 ...

/// 수신자의 개인키 저장소와 OTP 코드, 그리고 암호화된 메시지 묶음을 사용하여 원본 메시지를 복호화합니다.
pub fn decrypt(
    recipient_vault: &PrivateKeyVault,
    otp_code: &str, // 사용자가 입력한 6자리 OTP 코드
    bundle: &CiphertextBundle,
) -> Result<Vec<u8>> {

    // --- 1단계: 인증 및 개인키 저장소(Vault) 잠금 해제 ---

    // 1.1. OTP 코드 검증
    if !verify_totp(otp_code, &recipient_vault.authentication.s_otp.0) {
        // 사용자가 입력한 코드가 유효하지 않으면, 즉시 에러를 반환하고 종료.
        return Err(OtpgError::AuthenticationError); // 에러 타입 추가 필요
    }

    // 1.2. KEK(키 암호화 키) 재유도
    let kek = blake3::derive_key(
        &recipient_vault.authentication.kdf_context,
        &recipient_vault.authentication.s_otp.0,
    );
    
    // 1.3. 개인키 데이터 복호화 (AEAD)
    let cipher = XChaCha20Poly1305::new(kek.as_slice().into());
    let plaintext_bytes = cipher.decrypt(
        &recipient_vault.encrypted_data.nonce.0.into(),
        recipient_vault.encrypted_data.ciphertext.as_slice()
    ).map_err(|_| OtpgError::AeadError)?;

    // 1.4. 개인키 묶음 역직렬화
    let (recipient_keys, _) = bincode::serde::decode_from_slice::<PrivateKeyBundle, _>(&plaintext_bytes, bincode::config::standard().with_fixed_int_encoding()).unwrap();

    // --- 2단계: PQXDH 세션 키 재계산 ---
    
    // 2.1. 필요한 모든 키들을 라이브러리 타입으로 변환
    // recipient_keys와 bundle에서 키 바이트들을 PKey 객체 등으로 변환합니다.
    let sender_ik_pkey = PKey::public_key_from_raw_bytes(&bundle.sender_identity_key.0, Id::X448)?;
    let sender_ek_pkey = PKey::public_key_from_raw_bytes(&bundle.sender_ephemeral_key.0, Id::X448)?;
    
    let recipient_ik_pkey = PKey::private_key_from_raw_bytes(&recipient_keys.identity_key_kx.0, Id::X448)?;
    let recipient_spk_pkey = PKey::private_key_from_raw_bytes(&recipient_keys.signed_prekey.0, Id::X448)?;
    
    // opk_id를 사용하여 정확한 일회성 사전 개인키를 찾음
    let recipient_opk_bytes = recipient_keys.one_time_prekeys.get(&bundle.opk_id)
        .ok_or(OtpgError::NoPreKeyAvailable)?; // 해당 ID의 키가 없으면 에러
    let recipient_opk_pkey = PKey::private_key_from_raw_bytes(&recipient_opk_bytes.0, Id::X448)?;

    let recipient_pq_sk = recipient_keys.identity_key_pq.clone();
    let pq_ciphertext = bundle.pq_ciphertext.clone();
    
    // 2.2. 클래식 DH 연산 (발신자와 정확히 동일한 쌍으로 수행)
    let mut dh1_deriver = Deriver::new(&recipient_spk_pkey)?;
    dh1_deriver.set_peer(&sender_ek_pkey)?;
    let dh1 = dh1_deriver.derive_to_vec()?;

    let mut dh2_deriver = Deriver::new(&recipient_ik_pkey)?;
    dh2_deriver.set_peer(&sender_ik_pkey)?;
    let dh2 = dh2_deriver.derive_to_vec()?;

    let mut dh3_deriver = Deriver::new(&recipient_ik_pkey)?;
    dh3_deriver.set_peer(&sender_ek_pkey)?;
    let dh3 = dh3_deriver.derive_to_vec()?;

    let mut dh4_deriver = Deriver::new(&recipient_opk_pkey)?;
    dh4_deriver.set_peer(&sender_ek_pkey)?;
    let dh4 = dh4_deriver.derive_to_vec()?;

    // 2.3. 양자내성 KEM 연산 (디캡슐화)
    let shared_secret_pq = kyber::key_controler::KeyControKyber1024::decap(&recipient_pq_sk.0, &pq_ciphertext.0).unwrap();

    // --- 3단계: 최종 세션 키 재유도 ---
    // Encrypt 함수와 *정확히* 같은 순서로 공유 비밀들을 결합
    let master_secret = [
        dh1.as_slice(),
        dh2.as_slice(),
        dh3.as_slice(),
        dh4.as_slice(),
        shared_secret_pq.as_slice(),
    ].concat();
    let session_key = blake3::derive_key("otpg-encryption-v1", &master_secret);
    
    // --- 4단계: AEAD 대칭키 복호화 ---
    let aead_cipher = XChaCha20Poly1305::new(session_key.as_slice().into());

    // 4.1. Nonce와 암호문 분리
    if bundle.aead_ciphertext.len() < XCHACHA20_NONCE_LEN {
        return Err(OtpgError::AeadError); // 암호문이 너무 짧으면 에러
    }
    let (nonce, ciphertext) = bundle.aead_ciphertext.split_at(XCHACHA20_NONCE_LEN);

    // 4.2. 부가 인증 데이터(AD) 재구성 (Encrypt 함수와 *정확히* 같게!)
    // 수신자의 장기 공개키는 개인키로부터 유도해야 함
    let recipient_ik_pub_bytes = recipient_ik_pkey.raw_public_key()?;
    let associated_data = [
        bundle.sender_identity_key.0.as_slice(),
        recipient_ik_pub_bytes.as_slice(),
    ].concat();

    // 4.3. 최종 복호화
    let payload = chacha20poly1305::aead::Payload {
        msg: ciphertext,
        aad: &associated_data,
    };
    let plaintext = aead_cipher.decrypt(nonce.into(), payload)
        .map_err(|_| OtpgError::AeadError)?; // 태그가 일치하지 않으면 여기서 에러 발생

    // --- 5단계: 평문(Plaintext) 반환 ---
    Ok(plaintext)
}