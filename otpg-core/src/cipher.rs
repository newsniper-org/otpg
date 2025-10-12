use creusot_contracts::{ensures, logic, pearlite, requires, trusted};
#[cfg(creusot)]
use creusot_contracts:: Seq;

use rand::CryptoRng;

use crate::error::Result;
use crate::types::{Bytes, CiphertextBundle, GetContextStr, PrivateKeyBundle, PublicKeyBundle};

#[cfg(creusot)]
use crate::creusot_utils::{cmp_if_ok, has_any_item, is_ok, select_left_if_ok, select_right_if_ok, OptionalOrdering, is_prefix_of};

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

pub trait KeyAgreement<const KA_PUBKEY_BYTES: usize, const KA_PRVKEY_BYTES: usize, const KA_SEC_BYTES: usize> : KeyPairGen<KA_PUBKEY_BYTES, KA_PRVKEY_BYTES> {
    #[ensures(is_ok(result))]
    #[ensures(
        {
            result == Self::derive_when_encrypt_spec::<PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, SIGKEY_BYTES, SIGN_BYTES>(sender_keys, recipient_bundle)
        }
    )]
    fn derive_when_encrypt<const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const SIGKEY_BYTES: usize, const SIGN_BYTES: usize>(sender_keys: &PrivateKeyBundle<KA_PRVKEY_BYTES, PQ_PRVKEY_BYTES, SIGKEY_BYTES>, recipient_bundle: &PublicKeyBundle<KA_PUBKEY_BYTES,PQ_PUBKEY_BYTES,SIGN_BYTES>) -> Result<(u32, Bytes<KA_SEC_BYTES>, Bytes<KA_PUBKEY_BYTES>, Bytes<KA_PUBKEY_BYTES>)>; // (opk_id, classic_dh_secrets, sender_identity_key, sender_ephemeral_key)

    #[ensures(
        result.0@.len() > 0 &&
        result.1.0@.len() == KA_PUBKEY_BYTES@
    )]
    fn derive_when_decrypt<const PQ_PRVKEY_BYTES: usize, const PQ_CT_BYTES: usize, const SIGKEY_BYTES: usize, const NONCE_BYTES: usize>(recipient_keys: &PrivateKeyBundle<KA_PRVKEY_BYTES, PQ_PRVKEY_BYTES, SIGKEY_BYTES>, bundle: &CiphertextBundle<KA_PUBKEY_BYTES,PQ_CT_BYTES, NONCE_BYTES>, shared_secret_pq: &[u8]) -> (Vec<u8>, Bytes<KA_PUBKEY_BYTES>) { // (master_secret, recipient_ik_pub_bytes)
        Self::derive_when_decrypt_inner(recipient_keys, &bundle.sender_identity_key, &bundle.sender_ephemeral_key, bundle.opk_id, shared_secret_pq)
    }

    fn derive_when_decrypt_inner<const PQ_PRVKEY_BYTES: usize, const SIGKEY_BYTES: usize>(recipient_keys: &PrivateKeyBundle<KA_PRVKEY_BYTES, PQ_PRVKEY_BYTES, SIGKEY_BYTES>, sender_identity_key: &Bytes<KA_PUBKEY_BYTES>, sender_ephemeral_key: &Bytes<KA_PUBKEY_BYTES>, opk_id: u32, shared_secret_pq: &[u8]) -> (Vec<u8>, Bytes<KA_PUBKEY_BYTES>);

    // derive_when_encrypt의 논리적 모델
    #[logic(opaque)]
    fn derive_when_encrypt_spec<const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const SIGKEY_BYTES: usize, const SIGN_BYTES: usize>(_sender_keys: &PrivateKeyBundle<KA_PRVKEY_BYTES, PQ_PRVKEY_BYTES, SIGKEY_BYTES>, _recipient_bundle: &PublicKeyBundle<KA_PUBKEY_BYTES,PQ_PUBKEY_BYTES,SIGN_BYTES>) -> Result<(u32, Bytes<KA_SEC_BYTES>, Bytes<KA_PUBKEY_BYTES>, Bytes<KA_PUBKEY_BYTES>)> {
        dead
    }

    // derive_when_decrypt의 논리적 모델
    #[logic(opaque)]
    fn derive_when_decrypt_inner_spec<const PQ_PRVKEY_BYTES: usize, const PQ_CT_BYTES: usize, const SIGKEY_BYTES: usize, const NONCE_BYTES: usize>(_recipient_keys: &PrivateKeyBundle<KA_PRVKEY_BYTES, PQ_PRVKEY_BYTES, SIGKEY_BYTES>, _sender_identity_key: &Bytes<KA_PUBKEY_BYTES>, _sender_ephemeral_key: &Bytes<KA_PUBKEY_BYTES>, _opk_id: u32, _shared_secret_pq: &[u8]) -> (Vec<u8>, Bytes<KA_PUBKEY_BYTES>) {
        dead
    }

    // ⭐ 핵심: Key Agreement의 정확성 공리
    // 암호화 시 생성된 정보(CiphertextBundle)를 이용해 복호화하면,
    // 암호화 시 유도된 classic_dh_secrets와 복호화 시 master_secret의 첫 부분이 일치함을 보장.
    #[logic]
    #[ensures(result)]
    fn key_agreement_law<const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const PQ_SEC_BYTES: usize, const PQ_CT_BYTES: usize, PQ: PostQuantumKEM<PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES>, const DERIVED_KEY_BYTES: usize, KD: KDF<DERIVED_KEY_BYTES>, const SIGKEY_BYTES: usize, const SIGN_BYTES: usize>(
        sender_keys: PrivateKeyBundle<KA_PRVKEY_BYTES,PQ_PRVKEY_BYTES,SIGKEY_BYTES>,
        recipient_keys: PrivateKeyBundle<KA_PRVKEY_BYTES,PQ_PRVKEY_BYTES,SIGKEY_BYTES>,
        recipient_bundle: PublicKeyBundle<KA_PUBKEY_BYTES, PQ_PUBKEY_BYTES, SIGN_BYTES>,
        shared_secret_pq: &[u8]
    ) -> bool {
        
        match Self::derive_when_encrypt_spec::<PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, SIGKEY_BYTES, SIGN_BYTES>(&sender_keys, &recipient_bundle) {
            Ok((opk_id, classic_dh, sender_ik, sender_ek)) => {
                let (master_secret, _) = Self::derive_when_decrypt_inner_spec::<PQ_PRVKEY_BYTES, PQ_CT_BYTES, SIGKEY_BYTES, SIGN_BYTES>(&recipient_keys, &sender_ik, &sender_ek, opk_id, shared_secret_pq);
                pearlite! {
                    is_prefix_of(classic_dh.0@, master_secret@)
                }
            },
            Err(_) => false
        }
        
    }
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