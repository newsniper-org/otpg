use crate::error::Result;
use crate::types::{Bytes, CiphertextBundle, PrivateKeyBundle, PublicKeyBundle};
use crate::constants::XCHACHA20_NONCE_LEN;

// "대칭키 암호화/복호화"라는 역할을 정의합니다.
pub trait AeadCipher {
    fn encrypt(key: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<(Bytes<XCHACHA20_NONCE_LEN>, Vec<u8>)>;
    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_aead(key: &[u8], nonce_and_ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>>;
    fn too_short_for_nonce(input_size: usize) -> bool;
}

pub trait PostQuantumKEM : KeyPairGen {
    fn encap(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
    fn decap(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

pub trait KeyAgreement : KeyPairGen {
    fn derive_when_encrypt<F: FnOnce(&[u8]) -> (Vec<u8>, Vec<u8>)>(sender_keys: &PrivateKeyBundle, recipient_bundle: &PublicKeyBundle, kem: F) -> (u32, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>); // (opk_id, master_secret, pq_ciphertext, sender_identity_key, sender_ephemeral_key)
    fn derive_when_decrypt(recipient_keys: &PrivateKeyBundle, bundle: &CiphertextBundle, shared_secret_pq: &[u8]) -> (Vec<u8>, Vec<u8>); // (master_secret, recipient_ik_pub_bytes)
}

pub trait KeyPairGen {
    fn generate_keypair() -> (Vec<u8>, Vec<u8>); // (public_key, private_key)
}


pub trait KDF<const DERIVED_KEY_LEN: usize> {
    fn derive_key(context: &str, key_material: &[u8]) -> [u8; DERIVED_KEY_LEN];
}