// src/keygen.rs

use rand::{CryptoRng};

use crate::auth::OtpVerifier;
use crate::cipher::{AeadCipher, KeyAgreement, OneTimePrekeysPairGen, PostQuantumKEM, KDF};
use crate::error::{Result};
use crate::types::{
    AuthenticationVault, EncryptedData, GetContextStr, PrivateKeyBundle, PrivateKeyVault, PublicKeyBundle, SignedPreKey
};

use crate::conditional_serde;

/// OTPG를 위한 새로운 키 쌍과 개인키 저장소를 생성합니다.
pub fn generate_keys<V: OtpVerifier + GetContextStr, const NONCE_LEN: usize, C: AeadCipher<NONCE_LEN> + GetContextStr, PQ: PostQuantumKEM, KA: KeyAgreement + OneTimePrekeysPairGen, const DERIVED_KEY_LEN: usize, KD: KDF<DERIVED_KEY_LEN> + GetContextStr, S: crate::cipher::Signer, R: CryptoRng + ?Sized>(num_opks: u32, rng: &mut R) -> Result<(PublicKeyBundle, PrivateKeyVault)> {
    // 장기 신원 키 (IK_KX)
    let (ik_kx_pk_bytes, ik_kx_sk_bytes) = KA::generate_keypair();
    let (ik_pq_pk, ik_pq_sk) = PQ::generate_keypair();
    // 서명된 사전 키 (SPK)
    let (spk_pk_bytes, spk_sk_bytes) = KA::generate_keypair();

    let (opks_pub, opks_prv) = KA::gen_opkspair(num_opks);

    // --- 2. 사전 키 서명 ---
    let (ik_sig, signature) = S::sign(&spk_pk_bytes, rng);

    // --- 3. PublicKeyBundle 조립 ---
    let public_bundle = PublicKeyBundle {
        version: (1, 0),
        identity_key: ik_kx_pk_bytes,
        identity_key_pq: ik_pq_pk,
        signed_prekey: SignedPreKey {
            key: spk_pk_bytes,
            signature: signature,
        },
        one_time_prekeys: opks_pub
    };

    // --- 4. S_OTP 생성 및 개인키 암호화 ---
    let private_bundle = PrivateKeyBundle {
        identity_key_sig: ik_sig,
        identity_key_kx: ik_kx_sk_bytes,
        identity_key_pq: ik_pq_sk,
        signed_prekey: spk_sk_bytes,
        one_time_prekeys: opks_prv
    };

    conditional_serde!(
        let serialized_private_keys = bincode::serde::encode_to_vec(
            &private_bundle,
            bincode::config::standard().with_fixed_int_encoding(),
        ),
        or_else_hax Result::<Vec<u8>>::Ok(Vec::<u8>::new()) // hax 환경에서는 빈 벡터를 사용합니다.
    );

    let s_otp = V::gen_s_otp(rng);
    let kek = KD::derive_key("otpg-key-wrapping-v1", &s_otp);

    let nonce = C::gen_nonce(rng);
    conditional_serde!(
        let ciphertext = C::encrypt(
            &kek,
            &nonce,
            serialized_private_keys.unwrap().as_slice()
        )?,
        or_else_hax Vec::<u8>::new() // hax 환경에서는 빈 벡터를 사용합니다.
    );

    // --- 5. PrivateKeyVault 조립 ---
    let private_vault = PrivateKeyVault {
        version: (1, 0),
        authentication: AuthenticationVault {
            method: format!("{0}-{1}-{2}", V::get_context_str(), KD::get_context_str(), C::get_context_str()),
            s_otp: s_otp.to_vec(),
            kdf_context: "otpg-key-wrapping-v1".to_string(),
        },
        encrypted_data: EncryptedData {
            nonce: nonce.to_vec(),
            ciphertext: ciphertext,
        },
    };

    // --- 6. 결과 반환 ---
    Ok((public_bundle, private_vault))
}