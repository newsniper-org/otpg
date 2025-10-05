use std::collections::HashMap;

use rand::CryptoRng;

use crate::error::Result;
use crate::types::{Bytes, CiphertextBundle, GetContextStr, PrivateKeyBundle, PublicKeyBundle};

// "대칭키 암호화/복호화"라는 역할을 정의합니다.
pub trait AeadCipher<const NONCE_LEN: usize> : GetContextStr {
    fn encrypt(key: &[u8], nonce: &[u8], plaintext: &[u8]) -> Result<Vec<u8>>;
    fn encrypt_aead(key: &[u8], plaintext: &[u8], associated_data: &[u8]) -> Result<(Bytes<NONCE_LEN>, Vec<u8>)>;
    fn decrypt(key: &[u8], nonce: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
    fn decrypt_aead(key: &[u8], nonce_and_ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>>;
    fn too_short_for_nonce(input_size: usize) -> bool;
    fn gen_nonce<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; NONCE_LEN];
}

pub trait PostQuantumKEM : KeyPairGen {
    fn encap(public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;
    fn decap(secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

pub trait KeyAgreement : KeyPairGen {
    fn derive_when_encrypt(sender_keys: &PrivateKeyBundle, recipient_bundle: &PublicKeyBundle) -> Result<(u32, Vec<u8>, Vec<u8>, Vec<u8>)>; // (opk_id, classic_dh_secrets, sender_identity_key, sender_ephemeral_key)
    fn derive_when_decrypt(recipient_keys: &PrivateKeyBundle, bundle: &CiphertextBundle, shared_secret_pq: &[u8]) -> (Vec<u8>, Vec<u8>); // (master_secret, recipient_ik_pub_bytes)
}

pub trait KeyPairGen {
    fn generate_keypair() -> (Vec<u8>, Vec<u8>); // (public_key, private_key)
}

pub trait OneTimePrekeysPairGen {
    fn gen_opkspair(num_opks: u32) -> (HashMap<u32, Vec<u8>>, HashMap<u32, Vec<u8>>);
}


pub trait KDF<const DERIVED_KEY_LEN: usize> : GetContextStr {
    fn derive_key(context: &str, key_material: &[u8]) -> [u8; DERIVED_KEY_LEN];
}


pub trait Signer {
    fn sign<R: CryptoRng + ?Sized>(msg: &[u8], rng: &mut R) -> (Vec<u8>, Vec<u8>); // (identity_key_sig, signature)
}