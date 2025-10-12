// src/keygen.rs

use rand::{CryptoRng};

use crate::auth::OtpVerifier;
use crate::cipher::{AeadCipher, KeyAgreement, OneTimePrekeysPairGen, PostQuantumKEM, KDF};
use crate::error::{Result};
use crate::types::{
    GetContextStr, LittleEndianIntermediateRepr, PrivateKeyBundle, PrivateKeyVault, PublicKeyBundle, SignedPreKey, Version
};

use crate::types::make_private_vault;

/// OTPG를 위한 새로운 키 쌍과 개인키 저장소를 생성합니다.

pub fn generate_keys<V: OtpVerifier + GetContextStr, const NONCE_BYTES: usize, C: AeadCipher<DERIVED_KEY_BYTES, NONCE_BYTES> + GetContextStr, const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const PQ_SEC_BYTES: usize, const PQ_CT_BYTES: usize, PQ: PostQuantumKEM<PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES>, const KA_PUBKEY_BYTES: usize, const KA_PRVKEY_BYTES: usize, const KA_CT_BYTES: usize, KA: KeyAgreement<KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_CT_BYTES> + OneTimePrekeysPairGen<KA_PUBKEY_BYTES, KA_PRVKEY_BYTES>, const DERIVED_KEY_BYTES: usize, KD: KDF<DERIVED_KEY_BYTES> + GetContextStr, const SIGKEY_BYTES: usize, const SIGN_BYTES: usize, S: crate::cipher::Signer<SIGKEY_BYTES, SIGN_BYTES>, R: CryptoRng + ?Sized>(num_opks: u32, rng: &mut R) -> Result<(PublicKeyBundle<KA_PUBKEY_BYTES, PQ_PUBKEY_BYTES, SIGN_BYTES>, PrivateKeyVault<NONCE_BYTES>)> {
    // 장기 신원 키 (IK_KX)
    let (ik_kx_pk_bytes, ik_kx_sk_bytes) = KA::generate_keypair();
    let (ik_pq_pk, ik_pq_sk) = PQ::generate_keypair();
    // 서명된 사전 키 (SPK)
    let (spk_pk_bytes, spk_sk_bytes) = KA::generate_keypair();

    let (opks_pub, opks_prv) = KA::gen_opkspair(num_opks);

    // --- 2. 사전 키 서명 ---
    let (ik_sig, signature) = S::sign(&spk_pk_bytes.0, rng);

    // --- 3. PublicKeyBundle 조립 ---
    let public_bundle = PublicKeyBundle {
        version: Version(1, 0),
        identity_key: ik_kx_pk_bytes,
        identity_key_pq: ik_pq_pk,
        signed_prekey: SignedPreKey(spk_pk_bytes, signature),
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

    let serialized_private_keys = {
        let tmp: LittleEndianIntermediateRepr = private_bundle.into();
        tmp.0
    };

    let s_otp = V::gen_s_otp(rng);
    let kek = KD::derive_key("otpg-key-wrapping-v1", &s_otp);

    let nonce = C::gen_nonce(rng);
    let ciphertext = C::encrypt(
        &kek,
        &nonce,
        &serialized_private_keys
    );

    // --- 5. PrivateKeyVault 조립 ---
    let private_vault = make_private_vault::<NONCE_BYTES,V,DERIVED_KEY_BYTES,KD,C>(1, 0, s_otp, nonce, ciphertext);

    // --- 6. 결과 반환 ---
    Ok((public_bundle, private_vault))
}