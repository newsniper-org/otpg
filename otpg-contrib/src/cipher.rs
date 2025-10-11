use chacha20::cipher::{Array, StreamCipher};
use chacha20poly1305::consts::U24;
use creusot_contracts::trusted;
use ed448::Signature;
use ed448_goldilocks::SigningKey;
use openssl::derive::Deriver;
use openssl::pkey::{Id, PKey};
use otpg_core::cipher::{AeadCipher, KeyAgreement, KeyPairGen, OneTimePrekeysPairGen, PostQuantumKEM, Signer, KDF};
use otpg_core::constants::{XCHACHA20_NONCE_LEN, XCHACHA20_KEY_LEN};
use otpg_core::error::{OtpgError, Result};
use otpg_core::types::{Bytes, GetContextStr, CiphertextBundle, PrivateKeyBundle, PublicKeyBundle};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305,
};

use crypt_guard::kyber;
use rand::seq::IteratorRandom;

use chacha20::{
    KeyIvInit, XChaCha20
};

// `chacha20poly1305`를 사용한 실제 구현체를 만듭니다.
pub struct XChaCha20Poly1305Cipher;


impl AeadCipher<XCHACHA20_KEY_LEN, XCHACHA20_NONCE_LEN> for XChaCha20Poly1305Cipher {
    
    fn encrypt_aead(key: &[u8; 32], plaintext: &[u8], associated_data: &[u8]) -> Result<(otpg_core::types::Bytes<XCHACHA20_NONCE_LEN>, Vec<u8>)> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let mut nonce_bytes = [0u8; XCHACHA20_NONCE_LEN];
        rand::fill(&mut nonce_bytes);

        let payload = Payload { msg: plaintext, aad: associated_data };
        let ciphertext = cipher.encrypt(&nonce_bytes.into(), payload)
            .map_err(|_| OtpgError::AeadError("AEAD Encryption failed!".to_string()))?;
        
        let nonce = otpg_core::types::Bytes(nonce_bytes);
        Ok((nonce, ciphertext))
    }

    
    fn decrypt(key: &[u8; 32], nonce: &[u8; XCHACHA20_NONCE_LEN], ciphertext: &[u8]) -> Vec<u8> {
        let mut cipher = <XChaCha20 as KeyIvInit>::new(&(*key).into(), &(*nonce).into());

        let plaintext = {
            let mut result = ciphertext.to_vec();
            <XChaCha20 as chacha20::cipher::StreamCipher>::apply_keystream(&mut cipher,&mut result);
            result
        };

        plaintext
    }

    
    fn decrypt_aead(key: &[u8; 32], nonce_and_ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>> {
        let cipher = XChaCha20Poly1305::new(key.into());
        let (tmp_nonce, ciphertext) = nonce_and_ciphertext.split_at(XCHACHA20_NONCE_LEN);
        let mut nonce: Array::<u8, U24> = Array::default();
        nonce.clone_from_slice(tmp_nonce);

        let payload = Payload { msg: ciphertext, aad: associated_data };
        let plaintext = cipher.decrypt(&nonce, payload)
            .map_err(|err| OtpgError::AeadError(format!("AEAD Decryption failed: {0}", err)))?;

        Ok(plaintext)
    }
    
    fn too_short_for_nonce(input_size: usize) -> bool {
        input_size < XCHACHA20_NONCE_LEN
    }
    
    
    fn encrypt(key: &[u8; 32], nonce: &[u8; XCHACHA20_NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
        let mut cipher = <XChaCha20 as KeyIvInit>::new(key.into(), nonce.into());

        let ciphertext = {
            let mut result = plaintext.to_vec();
            <XChaCha20 as StreamCipher>::apply_keystream(&mut cipher, &mut result);
            result
        };

        ciphertext
    }
    
    fn gen_nonce<R: rand::CryptoRng + ?Sized>(rng: &mut R) -> [u8; XCHACHA20_NONCE_LEN] {
        crate::gen_bytearr(rng)
    }
}

impl GetContextStr for XChaCha20Poly1305Cipher {
    fn get_context_str() -> &'static str {
        "XCHACHA20POLY1305"
    }
}


pub struct Kyber1024KEM;

impl PostQuantumKEM<1568,3168,32, 1568> for Kyber1024KEM {
    
    fn encap(public_key: &[u8; 1568]) -> Result<(Bytes<32>, Bytes<1568>)> {
        let (sec, ct) = kyber::key_controler::KeyControKyber1024::encap(public_key).unwrap();
        Ok((Bytes::copy_from(&sec), Bytes::copy_from(&ct)))
    }

    
    fn decap(secret_key: &[u8; 3168], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let result = kyber::key_controler::KeyControKyber1024::decap(secret_key, ciphertext).unwrap();
        Ok(result)
    }
}

impl KeyPairGen<1568, 3168> for Kyber1024KEM {

    
    fn generate_keypair() -> (Bytes<1568>, Bytes<3168>) {
        let (pubkey, prvkey) = kyber::key_controler::KeyControKyber1024::keypair().unwrap();
        (Bytes::copy_from(&pubkey), Bytes::copy_from(&prvkey))
    }
}



pub struct X448KeyAgreement;

impl KeyAgreement<56,56,224> for X448KeyAgreement {
    
    fn derive_when_encrypt<const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const SIGKEY_BYTES: usize, const SIGN_BYTES: usize>(sender_keys: &PrivateKeyBundle<56, PQ_PRVKEY_BYTES, SIGKEY_BYTES>, recipient_bundle: &PublicKeyBundle<56,PQ_PUBKEY_BYTES,SIGN_BYTES>) -> Result<(u32, Bytes<224>, Bytes<56>, Bytes<56>)> {
        // --- 1. 사용할 수신자의 일회성 사전 키(OPK) 랜덤 선택 ---
        let mut rng = rand::rng();
        let opks = recipient_bundle.one_time_prekeys.clone();
        let (opk_id, recipient_opk_pub) = opks.iter().enumerate().choose(&mut rng).ok_or(OtpgError::NoPreKeyAvailable).unwrap();

        // --- 2. 발신자의 임시 키(Ephemeral Key) 생성 ---
        let sender_ephemeral_key = PKey::generate_x448().unwrap();

        // --- 3. 필요한 모든 키들을 라이브러리 타입으로 변환 ---
        // 발신자 키
        let sender_ik_pkey = PKey::private_key_from_raw_bytes(sender_keys.identity_key_kx.0.as_slice(), Id::X448).unwrap();

        // 수신자 키
        let recipient_ik_pkey = PKey::public_key_from_raw_bytes(recipient_bundle.identity_key.0.as_slice(), Id::X448).unwrap();
        let recipient_spk_pkey = PKey::public_key_from_raw_bytes(recipient_bundle.signed_prekey.0.0.as_slice(), Id::X448).unwrap();
        let recipient_opk_pkey = PKey::public_key_from_raw_bytes(recipient_opk_pub.0.as_slice(), Id::X448).unwrap();

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

        let classic_dh_secrets = [dh1.as_slice(), dh2.as_slice(), dh3.as_slice(), dh4.as_slice()].concat();
        Ok((
            opk_id as u32, 
            Bytes::copy_from(&classic_dh_secrets), 
            Bytes::copy_from(&sender_ik_pkey.raw_public_key().unwrap()), 
            Bytes::copy_from(&sender_ephemeral_key.raw_public_key().unwrap())
        ))
    }

    
    fn derive_when_decrypt<const PQ_PRVKEY_BYTES: usize, const PQ_CT_BYTES: usize, const SIGKEY_BYTES: usize, const NONCE_BYTES: usize>(recipient_keys: &PrivateKeyBundle<56, PQ_PRVKEY_BYTES, SIGKEY_BYTES>, bundle: &CiphertextBundle<56, PQ_CT_BYTES, NONCE_BYTES>, shared_secret_pq: &[u8]) -> (Vec<u8>, Bytes<56>) {
        // 1. 필요한 모든 키들을 라이브러리 타입으로 변환
        // recipient_keys와 bundle에서 키 바이트들을 PKey 객체 등으로 변환합니다.
        let sender_ik_pkey = PKey::public_key_from_raw_bytes(bundle.sender_identity_key.0.as_slice(), Id::X448).unwrap();
        let sender_ek_pkey = PKey::public_key_from_raw_bytes(bundle.sender_ephemeral_key.0.as_slice(), Id::X448).unwrap();
        
        let recipient_ik_pkey = PKey::private_key_from_raw_bytes(recipient_keys.identity_key_kx.0.as_slice(), Id::X448).unwrap();
        let recipient_spk_pkey = PKey::private_key_from_raw_bytes(recipient_keys.signed_prekey.0.as_slice(), Id::X448).unwrap();
        
        // opk_id를 사용하여 정확한 일회성 사전 개인키를 찾음
        let recipient_opk_bytes = recipient_keys.one_time_prekeys[bundle.opk_id as usize];
        let recipient_opk_pkey = PKey::private_key_from_raw_bytes(recipient_opk_bytes.0.as_slice(), Id::X448).unwrap();


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
        (master_secret, Bytes::copy_from(&recipient_ik_pkey.raw_public_key().unwrap()))
    }
}

impl KeyPairGen<56, 56> for X448KeyAgreement {
    
    fn generate_keypair() -> (Bytes<56>, Bytes<56>) {
        let kx = PKey::generate_x448().unwrap();
        let kx_pk_bytes = Bytes::copy_from(&kx.raw_public_key().unwrap());
        let kx_sk_bytes = Bytes::copy_from(&kx.raw_private_key().unwrap());
        (kx_pk_bytes, kx_sk_bytes)
    }
}


impl OneTimePrekeysPairGen<56, 56> for X448KeyAgreement {
}


pub struct BLAKE3KDF;

impl KDF<32> for BLAKE3KDF {
    
    fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32] {
        blake3::derive_key(context, key_material)
    }
}

impl GetContextStr for BLAKE3KDF {
    fn get_context_str() -> &'static str {
        "BLAKE3"
    }
}



pub struct ED448Signer;

impl Signer<57,114> for ED448Signer {
    
    fn sign<R: rand::CryptoRng + ?Sized>(msg: &[u8], rng: &mut R) -> (Bytes<57>, Bytes<114>) {
        let ik_sig = SigningKey::generate(rng);

        let signature = <SigningKey as ed448_goldilocks::signature::Signer<Signature>>::sign(&ik_sig, msg);
        
        (Bytes::<57>::copy_from(ik_sig.to_bytes().as_slice()), Bytes::<114>::copy_from(signature.to_bytes().as_slice()))
    }
}