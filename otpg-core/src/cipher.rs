use rand::CryptoRng;

use crate::error::Result;
use crate::types::{Bytes, CiphertextBundle, GetContextStr, PrivateKeyBundle, PublicKeyBundle};

use creusot_contracts::prelude::ensures;

// "대칭키 암호화/복호화"라는 역할을 정의합니다.
pub trait AeadCipher<const KEY_BYTES: usize, const NONCE_BYTES: usize> : GetContextStr {
    fn encrypt(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], plaintext: &[u8]) -> Vec<u8>;
    fn encrypt_aead(key: &[u8; KEY_BYTES], plaintext: &[u8], associated_data: &[u8]) -> Result<(Bytes<NONCE_BYTES>, Vec<u8>)>;
    fn decrypt(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], ciphertext: &[u8]) -> Vec<u8>;
    fn decrypt_aead(key: &[u8; KEY_BYTES], nonce_and_ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>>;
    fn too_short_for_nonce(input_size: usize) -> bool;
    fn gen_nonce<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; NONCE_BYTES];

    #[ensures(
        result
    )]
    fn is_valid_cipher(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], plaintext: &[u8]) -> bool {
        let ciphertext = Self::encrypt(key, nonce, plaintext);
        let decrypted = Self::decrypt(key, nonce, ciphertext.as_slice());
        decrypted == plaintext
    }

    #[ensures(
        result
    )]
    fn is_valid_aead_cipher(key: &[u8; KEY_BYTES], plaintext: &[u8; NONCE_BYTES], associated_data: &[u8]) -> bool {
        let encrypted = Self::encrypt_aead(key, plaintext, associated_data);
        let decrypted = match encrypted {
            Ok((nonce, ciphertext)) => {
                let concated = [nonce.0.as_slice(), &ciphertext].concat();
                Self::decrypt_aead(key, &concated, associated_data)
            },
            Err(e) => Err(e)
        };
        match decrypted {
            Ok(succ_dec) => succ_dec == plaintext,
            Err(_) => false
        }
    }

}

pub trait PostQuantumKEM<const PUBKEY_BYTES: usize, const PRVKEY_BYTES: usize, const SEC_BYTES: usize, const CT_BYTES: usize> : KeyPairGen<PUBKEY_BYTES, PRVKEY_BYTES> {
    fn encap(public_key: &[u8; PUBKEY_BYTES]) -> Result<(Bytes<SEC_BYTES>, Bytes<CT_BYTES>)>;
    fn decap(secret_key: &[u8; PRVKEY_BYTES], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

pub trait KeyAgreement<const PUBKEY_BYTES: usize, const PRVKEY_BYTES: usize, const SEC_BYTES: usize> : KeyPairGen<PUBKEY_BYTES, PRVKEY_BYTES> {
    fn derive_when_encrypt<const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const SIGKEY_BYTES: usize, const SIGN_BYTES: usize>(sender_keys: &PrivateKeyBundle<PRVKEY_BYTES, PQ_PRVKEY_BYTES, SIGKEY_BYTES>, recipient_bundle: &PublicKeyBundle<PUBKEY_BYTES,PQ_PUBKEY_BYTES,SIGN_BYTES>) -> Result<(u32, Bytes<SEC_BYTES>, Bytes<PUBKEY_BYTES>, Bytes<PUBKEY_BYTES>)>; // (opk_id, classic_dh_secrets, sender_identity_key, sender_ephemeral_key)
    fn derive_when_decrypt<const PQ_PRVKEY_BYTES: usize, const PQ_CT_BYTES: usize, const SIGKEY_BYTES: usize, const NONCE_BYTES: usize>(recipient_keys: &PrivateKeyBundle<PRVKEY_BYTES, PQ_PRVKEY_BYTES, SIGKEY_BYTES>, bundle: &CiphertextBundle<PUBKEY_BYTES,PQ_CT_BYTES, NONCE_BYTES>, shared_secret_pq: &[u8]) -> (Vec<u8>, Bytes<PUBKEY_BYTES>); // (master_secret, recipient_ik_pub_bytes)
}

pub trait KeyPairGen<const PUBKEY_BYTES: usize, const PRVKEY_BYTES: usize> {
    fn generate_keypair() -> (Bytes<PUBKEY_BYTES>, Bytes<PRVKEY_BYTES>); // (public_key, private_key)
}

pub trait OneTimePrekeysPairGen<const PUBKEY_BYTES: usize, const PRVKEY_BYTES: usize> : KeyPairGen<PUBKEY_BYTES, PRVKEY_BYTES> {
    fn gen_opkspair(num_opks: u32) -> (Vec<Bytes<PUBKEY_BYTES>>, Vec<Bytes<PRVKEY_BYTES>>) {
        let opks= (0..num_opks).map(|_| {
            Self::generate_keypair()
        }).collect::<Vec<(Bytes<PUBKEY_BYTES>, Bytes<PRVKEY_BYTES>)>>();
        let (opk_pub, opk_prv): (Vec<Bytes<PUBKEY_BYTES>>, Vec<Bytes<PRVKEY_BYTES>>)  = opks.into_iter().unzip();
        (opk_pub, opk_prv)
    }
}


pub trait KDF<const DERIVED_KEY_BYTES: usize> : GetContextStr {
    fn derive_key(context: &str, key_material: &[u8]) -> [u8; DERIVED_KEY_BYTES];
}


pub trait Signer<const SIGKEY_BYTES: usize, const SIGN_BYTES: usize> {
    fn sign<R: CryptoRng + ?Sized>(msg: &[u8], rng: &mut R) -> (Bytes<SIGKEY_BYTES>, Bytes<SIGN_BYTES>); // (identity_key_sig, signature)
}