use creusot_contracts::{ensures, logic, requires, trusted, Seq};
use rand::CryptoRng;

use crate::error::Result;
use crate::types::{Bytes, CiphertextBundle, GetContextStr, PrivateKeyBundle, PublicKeyBundle};

#[cfg(creusot)]
use crate::creusot_utils::{cmp_if_ok, fmap_result, has_any_item, is_ok, select_left_if_ok, select_right_if_ok, OptionalOrdering};

use crate::utils::eq_bytes;

pub const trait HasNonceLength<const NONCE_BYTES: usize> {
    #[ensures(input@.len() <= NONCE_BYTES@ ==> result)]
    fn too_short_for_nonce(input: &[u8]) -> bool;

    #[logic]
    #[ensures(input.len() <= NONCE_BYTES@ ==> result)]
    fn too_short_for_nonce_creusot(input: Seq<u8>) -> bool;
}
// "대칭키 암호화/복호화"라는 역할을 정의합니다.
pub trait AeadCipher<const KEY_BYTES: usize, const NONCE_BYTES: usize> : const GetContextStr + const HasNonceLength<NONCE_BYTES> {

    
    #[requires(plaintext@.len() > 0)]
    #[ensures(result@.len() >= plaintext@.len())]
    fn encrypt(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], plaintext: &[u8]) -> Vec<u8>;

    #[requires(plaintext@.len() > 0 && associated_data@.len() > 0)]
    #[ensures(is_ok(result) ==> cmp_if_ok(select_right_if_ok(result, |v: Vec<u8>| v@.len()), 0) == OptionalOrdering::Greater)]
    fn encrypt_aead(key: &[u8; KEY_BYTES], plaintext: &[u8], associated_data: &[u8]) -> Result<(Bytes<NONCE_BYTES>, Vec<u8>)>;

    #[requires(ciphertext@.len() > 0)]
    #[ensures(result@.len() > 0 && result@.len() <= ciphertext@.len())]
    fn decrypt(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], ciphertext: &[u8]) -> Vec<u8>;

    #[requires(nonce_and_ciphertext@.len() > NONCE_BYTES@ && associated_data@.len() > 0)]
    #[ensures(has_any_item(result))]
    fn decrypt_aead(key: &[u8; KEY_BYTES], nonce_and_ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>>;

    #[ensures(plaintext@.len() > 0 ==> result == true)]
    #[trusted]
    fn is_valid_cipher(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], plaintext: &[u8]) -> bool {
        let ciphertext = Self::encrypt(key, nonce, plaintext);
        let decrypted = Self::decrypt(key, nonce, ciphertext.as_slice());
        eq_bytes(plaintext, decrypted.as_slice())
    }

    #[ensures(plaintext@.len() > 0 ==> result == true)]
    #[trusted]
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

    #[ensures(result@.len() == NONCE_BYTES@)]
    fn gen_nonce<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; NONCE_BYTES];

}

pub trait PostQuantumKEM<const PUBKEY_BYTES: usize, const PRVKEY_BYTES: usize, const SEC_BYTES: usize, const CT_BYTES: usize> : KeyPairGen<PUBKEY_BYTES, PRVKEY_BYTES> {
    #[ensures(
        is_ok(result) &&
        cmp_if_ok(select_left_if_ok(result, |v: Bytes<SEC_BYTES>| v.0@.len()), SEC_BYTES@) == OptionalOrdering::Equal &&
        cmp_if_ok(select_right_if_ok(result, |v: Bytes<CT_BYTES>| v.0@.len()), CT_BYTES@) == OptionalOrdering::Equal
    )]
    fn encap(public_key: &[u8; PUBKEY_BYTES]) -> Result<(Bytes<SEC_BYTES>, Bytes<CT_BYTES>)>;

    #[requires(ciphertext@.len() > 0)]
    #[ensures(has_any_item(result))]
    fn decap(secret_key: &[u8; PRVKEY_BYTES], ciphertext: &[u8]) -> Result<Vec<u8>>;
}

pub trait KeyAgreement<const PUBKEY_BYTES: usize, const PRVKEY_BYTES: usize, const SEC_BYTES: usize> : KeyPairGen<PUBKEY_BYTES, PRVKEY_BYTES> {
    #[ensures(
        is_ok(result) &&
        cmp_if_ok(fmap_result(result, |(_,b, _, _): (u32, Bytes<SEC_BYTES>, Bytes<PUBKEY_BYTES>, Bytes<PUBKEY_BYTES>)| b.0@.len()), SEC_BYTES@) == OptionalOrdering::Equal &&
        cmp_if_ok(fmap_result(result, |(_,_, c, _): (u32, Bytes<SEC_BYTES>, Bytes<PUBKEY_BYTES>, Bytes<PUBKEY_BYTES>)| c.0@.len()), PUBKEY_BYTES@) == OptionalOrdering::Equal &&
        cmp_if_ok(fmap_result(result, |(_,_, _, d): (u32, Bytes<SEC_BYTES>, Bytes<PUBKEY_BYTES>, Bytes<PUBKEY_BYTES>)| d.0@.len()), PUBKEY_BYTES@) == OptionalOrdering::Equal
    )]
    fn derive_when_encrypt<const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const SIGKEY_BYTES: usize, const SIGN_BYTES: usize>(sender_keys: &PrivateKeyBundle<PRVKEY_BYTES, PQ_PRVKEY_BYTES, SIGKEY_BYTES>, recipient_bundle: &PublicKeyBundle<PUBKEY_BYTES,PQ_PUBKEY_BYTES,SIGN_BYTES>) -> Result<(u32, Bytes<SEC_BYTES>, Bytes<PUBKEY_BYTES>, Bytes<PUBKEY_BYTES>)>; // (opk_id, classic_dh_secrets, sender_identity_key, sender_ephemeral_key)

    #[ensures(
        result.0@.len() > 0 &&
        result.1.0@.len() == PUBKEY_BYTES@
    )]
    fn derive_when_decrypt<const PQ_PRVKEY_BYTES: usize, const PQ_CT_BYTES: usize, const SIGKEY_BYTES: usize, const NONCE_BYTES: usize>(recipient_keys: &PrivateKeyBundle<PRVKEY_BYTES, PQ_PRVKEY_BYTES, SIGKEY_BYTES>, bundle: &CiphertextBundle<PUBKEY_BYTES,PQ_CT_BYTES, NONCE_BYTES>, shared_secret_pq: &[u8]) -> (Vec<u8>, Bytes<PUBKEY_BYTES>); // (master_secret, recipient_ik_pub_bytes)
}

pub trait KeyPairGen<const PUBKEY_BYTES: usize, const PRVKEY_BYTES: usize> {
    #[ensures(
        result.0.0@.len() == PUBKEY_BYTES@ &&
        result.1.0@.len() == PRVKEY_BYTES@
    )]
    fn generate_keypair() -> (Bytes<PUBKEY_BYTES>, Bytes<PRVKEY_BYTES>); // (public_key, private_key)
}

pub trait OneTimePrekeysPairGen<const PUBKEY_BYTES: usize, const PRVKEY_BYTES: usize> : KeyPairGen<PUBKEY_BYTES, PRVKEY_BYTES> {
    #[trusted]
    #[requires(num_opks@ > 0)]
    #[ensures(
        result.0@.len() == result.1@.len() && result.0@.len() == num_opks@ &&
        (forall<i: usize> i@ < result.0@.len() ==> result.0[i].0@.len() == PUBKEY_BYTES@) &&
        (forall<j: usize> j@ < result.1@.len() ==> result.1[j].0@.len() == PRVKEY_BYTES@)
    )]
    fn gen_opkspair(num_opks: u32) -> (Vec<Bytes<PUBKEY_BYTES>>, Vec<Bytes<PRVKEY_BYTES>>) {
        let opks= (0..num_opks).map(|_| {
            Self::generate_keypair()
        }).collect::<Vec<(Bytes<PUBKEY_BYTES>, Bytes<PRVKEY_BYTES>)>>();
        let (opk_pub, opk_prv): (Vec<Bytes<PUBKEY_BYTES>>, Vec<Bytes<PRVKEY_BYTES>>)  = opks.into_iter().unzip();
        (opk_pub, opk_prv)
    }
}


pub trait KDF<const DERIVED_KEY_BYTES: usize> : const GetContextStr {
    #[requires(key_material@.len() > 0)] // 전제 조건: 키 재료는 비어있으면 안 된다.
    #[ensures(result@.len() == DERIVED_KEY_BYTES@)] // 결과 보장: 결과 키의 길이는 항상 DERIVED_KEY_BYTES와 같다.
    fn derive_key(context: &str, key_material: &[u8]) -> [u8; DERIVED_KEY_BYTES];
}


pub trait Signer<const SIGKEY_BYTES: usize, const SIGN_BYTES: usize> {
    #[ensures(
        result.0.0@.len() == SIGKEY_BYTES@ &&
        result.1.0@.len() == SIGN_BYTES@
    )]
    fn sign<R: CryptoRng + ?Sized>(msg: &[u8], rng: &mut R) -> (Bytes<SIGKEY_BYTES>, Bytes<SIGN_BYTES>); // (identity_key_sig, signature)
}