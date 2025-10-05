use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey};
use otpg_core::cipher::{AeadCipher, KeyAgreement, KeyPairGen, PostQuantumKEM, KDF};
use otpg_core::constants::XCHACHA20_NONCE_LEN;
use otpg_core::error::{OtpgError, Result};
use otpg_core::types::Bytes;

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};

use crypt_guard::kyber;
use rand::seq::IteratorRandom;

// `chacha20poly1305`를 사용한 실제 구현체를 만듭니다.
pub struct XChaCha20Poly1305Cipher;

impl AeadCipher for XChaCha20Poly1305Cipher {
    fn encrypt(key: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<(Bytes<XCHACHA20_NONCE_LEN>, Vec<u8>)> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let mut nonce_bytes = [0u8; XCHACHA20_NONCE_LEN];
        rand::fill(&mut nonce_bytes);

        let payload = Payload { msg: plaintext, aad: associated_data };
        let ciphertext = cipher.encrypt(&nonce_bytes.into(), payload)
            .map_err(|_| OtpgError::AeadError)?;
        
        Ok((Bytes(nonce_bytes), ciphertext))
    }

    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let plaintext = cipher.decrypt(nonce.into(), ciphertext)
            .map_err(|_| OtpgError::AeadError)?;

        Ok(plaintext)
    }

    fn decrypt_aead(key: &[u8], nonce_and_ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let (nonce, ciphertext) = nonce_and_ciphertext.split_at(XCHACHA20_NONCE_LEN);

        let payload = Payload { msg: ciphertext, aad: associated_data };
        let plaintext = cipher.decrypt(nonce.into(), payload)
            .map_err(|_| OtpgError::AeadError)?;

        Ok(plaintext)
    }
    
    fn too_short_for_nonce(input_size: usize) -> bool {
        input_size < XCHACHA20_NONCE_LEN
    }
}



pub struct Kyber1024KEM;

impl PostQuantumKEM for Kyber1024KEM {
    fn encap(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let result = kyber::key_controler::KeyControKyber1024::encap(public_key).unwrap();
        Ok(result)
    }

    fn decap(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let result = kyber::key_controler::KeyControKyber1024::decap(secret_key, ciphertext).unwrap();
        Ok(result)
    }
}

impl KeyPairGen for Kyber1024KEM {
    fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        kyber::key_controler::KeyControKyber1024::keypair().unwrap()
    }
}



pub struct X448KeyAgreement;

impl KeyAgreement for X448KeyAgreement {
    fn derive_when_encrypt<F: FnOnce(&[u8]) -> (Vec<u8>, Vec<u8>)>(sender_keys: &otpg_core::types::PrivateKeyBundle, recipient_bundle: &otpg_core::types::PublicKeyBundle, kem: F) -> (u32, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
        // --- 1. 사용할 수신자의 일회성 사전 키(OPK) 랜덤 선택 ---
        let mut rng = rand::rng();
        let chosen = recipient_bundle.one_time_prekeys.keys().choose(&mut rng).ok_or(OtpgError::NoPreKeyAvailable).unwrap();
        let (&opk_id, &recipient_opk_pub) = recipient_bundle.one_time_prekeys.get_key_value(chosen).unwrap().clone();

        // --- 2. 발신자의 임시 키(Ephemeral Key) 생성 ---
        let sender_ephemeral_key = PKey::generate_x448().unwrap();

        // --- 3. 필요한 모든 키들을 라이브러리 타입으로 변환 ---
        // 발신자 키
        let sender_ik_pkey = PKey::private_key_from_raw_bytes(&sender_keys.identity_key_kx.0, Id::X448).unwrap();

        // 수신자 키
        let recipient_ik_pkey = PKey::public_key_from_raw_bytes(&recipient_bundle.identity_key.0, Id::X448).unwrap();
        let recipient_spk_pkey = PKey::public_key_from_raw_bytes(&recipient_bundle.signed_prekey.key.0, Id::X448).unwrap();
        let recipient_opk_pkey = PKey::public_key_from_raw_bytes(&recipient_opk_pub.0, Id::X448).unwrap();

        // --- 4. PQXDH 키 교환 수행 ---
        let mut dh1_deriver = Deriver::new(&sender_ephemeral_key).unwrap();
        dh1_deriver.set_peer(&recipient_spk_pkey).unwrap();
        let dh1 = dh1_deriver.derive_to_vec().unwrap();

        let mut dh2_deriver = Deriver::new(&sender_ik_pkey).unwrap();
        dh2_deriver.set_peer(&recipient_ik_pkey).unwrap();
        let dh2 = dh2_deriver.derive_to_vec().unwrap();
        
        let mut dh3_deriver = Deriver::new(&sender_ephemeral_key).unwrap();
        dh3_deriver.set_peer(&recipient_ik_pkey).unwrap();
        let dh3 = dh3_deriver.derive_to_vec().unwrap();

        let mut dh4_deriver = Deriver::new(&sender_ephemeral_key).unwrap();
        dh4_deriver.set_peer(&recipient_opk_pkey).unwrap();
        let dh4 = dh4_deriver.derive_to_vec().unwrap();

        let (shared_secret_pq, pq_ciphertext) = kem(&recipient_bundle.identity_key_pq.0);

        let master_secret = [dh1.as_slice(), dh2.as_slice(), dh3.as_slice(), dh4.as_slice(), shared_secret_pq.as_slice()].concat();
        (opk_id, master_secret, pq_ciphertext, sender_ik_pkey.raw_public_key().unwrap(), sender_ephemeral_key.raw_public_key().unwrap())
    }

    fn derive_when_decrypt(recipient_keys: &otpg_core::types::PrivateKeyBundle, bundle: &otpg_core::types::CiphertextBundle, shared_secret_pq: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // 1. 필요한 모든 키들을 라이브러리 타입으로 변환
        // recipient_keys와 bundle에서 키 바이트들을 PKey 객체 등으로 변환합니다.
        let sender_ik_pkey = PKey::public_key_from_raw_bytes(&bundle.sender_identity_key.0, Id::X448).unwrap();
        let sender_ek_pkey = PKey::public_key_from_raw_bytes(&bundle.sender_ephemeral_key.0, Id::X448).unwrap();
        
        let recipient_ik_pkey = PKey::private_key_from_raw_bytes(&recipient_keys.identity_key_kx.0, Id::X448).unwrap();
        let recipient_spk_pkey = PKey::private_key_from_raw_bytes(&recipient_keys.signed_prekey.0, Id::X448).unwrap();
        
        // opk_id를 사용하여 정확한 일회성 사전 개인키를 찾음
        let recipient_opk_bytes = recipient_keys.one_time_prekeys.get(&bundle.opk_id)
            .ok_or(OtpgError::NoPreKeyAvailable).unwrap(); // 해당 ID의 키가 없으면 에러
        let recipient_opk_pkey = PKey::private_key_from_raw_bytes(&recipient_opk_bytes.0, Id::X448).unwrap();


        // 2. 클래식 DH 연산 (발신자와 정확히 동일한 쌍으로 수행)
        let mut dh1_deriver = Deriver::new(&recipient_spk_pkey).unwrap();
        dh1_deriver.set_peer(&sender_ek_pkey).unwrap();
        let dh1 = dh1_deriver.derive_to_vec().unwrap();

        let mut dh2_deriver = Deriver::new(&recipient_ik_pkey).unwrap();
        dh2_deriver.set_peer(&sender_ik_pkey).unwrap();
        let dh2 = dh2_deriver.derive_to_vec().unwrap();

        let mut dh3_deriver = Deriver::new(&recipient_ik_pkey).unwrap();
        dh3_deriver.set_peer(&sender_ek_pkey).unwrap();
        let dh3 = dh3_deriver.derive_to_vec().unwrap();

        let mut dh4_deriver = Deriver::new(&recipient_opk_pkey).unwrap();
        dh4_deriver.set_peer(&sender_ek_pkey).unwrap();
        let dh4 = dh4_deriver.derive_to_vec().unwrap();

        // --- 3단계: 최종 세션 키 재유도 ---
        // Encrypt 함수와 *정확히* 같은 순서로 공유 비밀들을 결합
        let master_secret = [
            dh1.as_slice(),
            dh2.as_slice(),
            dh3.as_slice(),
            dh4.as_slice(),
            shared_secret_pq,
        ].concat();
        (master_secret, recipient_ik_pkey.raw_public_key().unwrap())
    }
}

impl KeyPairGen for X448KeyAgreement {
    fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
        let kx = PKey::generate_x448().unwrap();
        let kx_pk_bytes = kx.raw_public_key().unwrap();
        let kx_sk_bytes = kx.raw_private_key().unwrap();
        (kx_pk_bytes, kx_sk_bytes)
    }
}

pub struct BLAKE3KDF;

impl KDF<32> for BLAKE3KDF {
    fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32] {
        blake3::derive_key(context, key_material)
    }
}