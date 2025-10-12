use crate::{encrypt::*, decrypt::*};
use crate::types::*;
use creusot_contracts::*;
use crate::cipher::*;
use crate::auth::*;
use crate::error::*;

use totp_rs::*;

#[trusted]
fn generate_valid_otp(s_otp: &[u8; 20]) -> String {
    let secret = Rfc6238::new(6, s_otp.to_vec()).unwrap();

    // 2. 빌더(builder) 패턴을 사용하여 TOTP 객체 생성
    let totp = TOTP::from_rfc6238(secret).unwrap();
    totp.generate_current().unwrap()
}

#[trusted]
fn get_current_timestamp() -> u64 {
    chrono::Utc::now().timestamp() as u64
}

// 이 함수는 실행되지 않으며, 오직 Creusot에 의해 논리적으로만 분석됩니다.
#[requires(plaintext@.len() > 0)]
#[ensures(match result {
    Ok((decrypted, enc_ms, dec_ms)) => (decrypted@ == plaintext@) && (enc_ms@ == dec_ms@), // 결과 보장: 복호화 성공 시, 결과는 원본 평문과 같다.
    Err(_) => false, // 이 증명에서는 실패하는 경우를 고려하지 않는다.
})]
pub fn encrypt_decrypt_roundtrip<V: OtpVerifier, const NONCE_BYTES: usize, C: AeadCipher<DERIVED_KEY_BYTES, NONCE_BYTES>, const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const PQ_SEC_BYTES: usize, const PQ_CT_BYTES: usize, PQ: PostQuantumKEM<PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES>, const KA_PUBKEY_BYTES: usize, const KA_PRVKEY_BYTES: usize, const KA_CT_BYTES: usize, KA: KeyAgreement<KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_CT_BYTES>, const DERIVED_KEY_BYTES: usize, KD: KDF<DERIVED_KEY_BYTES>, const SIGKEY_BYTES: usize, const SIGN_BYTES: usize>(
    alice_pub: PublicKeyBundle<KA_PUBKEY_BYTES, PQ_PUBKEY_BYTES, SIGN_BYTES>,
    alice_vault: PrivateKeyVault<NONCE_BYTES>,
    bob_prv_bundle: PrivateKeyBundle<KA_PRVKEY_BYTES,PQ_PRVKEY_BYTES,SIGKEY_BYTES>,
    plaintext: Vec<u8>
) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {

    // 1. `encrypt`를 호출합니다.
    let (ciphertext_bundle, enc_ms) = encrypt_to_verify::<NONCE_BYTES, C, PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES, PQ, KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_CT_BYTES, KA, DERIVED_KEY_BYTES, KD, SIGKEY_BYTES, SIGN_BYTES>(&bob_prv_bundle, &alice_pub, &plaintext)?;

    let current_timestamp = get_current_timestamp();
    let valid_otp = generate_valid_otp(&alice_vault.authentication.s_otp.0);

    // 2. `decrypt`를 호출합니다.
    let (decrypted, dec_ms) = decrypt_to_verify::<V, NONCE_BYTES, C, PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES, PQ, KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_CT_BYTES, KA, DERIVED_KEY_BYTES, KD, SIGKEY_BYTES, SIGN_BYTES>(&alice_vault, &valid_otp, &ciphertext_bundle, current_timestamp)?;

    Ok((decrypted, enc_ms, dec_ms))
}