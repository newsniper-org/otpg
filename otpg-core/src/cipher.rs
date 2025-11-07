use creusot_contracts::{macros::{ensures, logic, requires, trusted}};
#[cfg(creusot)]
use creusot_contracts::logic::Seq;

use rand::CryptoRng;

use crate::error::Result;
use crate::types::{Bytes, CiphertextBundle, GetContextStr, PrivateKeyBundle, PublicKeyBundle};

#[cfg(creusot)]
use crate::creusot_utils::{cmp_if_ok, has_any_item, is_ok, select_right_if_ok, OptionalOrdering, is_prefix_of, concat_pearlite};
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
    #[ensures(result@ == Self::encrypt_spec(key@, nonce@, plaintext@))]
    fn encrypt(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], plaintext: &[u8]) -> Vec<u8>;

    #[requires(plaintext@.len() > 0 && associated_data@.len() > 0)]
    #[ensures(is_ok(result) ==> cmp_if_ok(select_right_if_ok(result, |v: Vec<u8>| v@.len()), 0) == OptionalOrdering::Greater)]
    #[ensures(result == Ok(Self::encrypt_aead_spec(key@, plaintext@, associated_data@)))]
    fn encrypt_aead(key: &[u8; KEY_BYTES], plaintext: &[u8], associated_data: &[u8]) -> Result<(Bytes<NONCE_BYTES>, Vec<u8>)>;

    #[requires(ciphertext@.len() > 0)]
    #[ensures(result@.len() > 0 && result@.len() <= ciphertext@.len())]
    #[ensures(result@ == Self::decrypt_spec(key@, nonce@, ciphertext@))]
    fn decrypt(key: &[u8; KEY_BYTES], nonce: &[u8; NONCE_BYTES], ciphertext: &[u8]) -> Vec<u8>;

    #[requires(nonce_and_ciphertext@.len() > NONCE_BYTES@ && associated_data@.len() > 0)]
    #[ensures(has_any_item(result))]
    #[ensures(result == Ok(Self::decrypt_aead_spec(key@, nonce_and_ciphertext@, associated_data@)))]
    fn decrypt_aead(key: &[u8; KEY_BYTES], nonce_and_ciphertext: &[u8], associated_data: &[u8]) -> Result<Vec<u8>>;

    #[logic(opaque)]
    fn encrypt_spec(_key: Seq<u8>, _nonce: Seq<u8>, _plaintext: Seq<u8>) -> Seq<u8> {
        dead
    }

    #[logic(opaque)]
    fn decrypt_spec(_key: Seq<u8>, _nonce: Seq<u8>, _ciphertext: Seq<u8>) -> Seq<u8> {
        dead
    }

    #[logic(law)]
    fn symmetric_key_cipher_law() {
        proof_assert!(
            forall<key: Seq<u8>> forall<nonce: Seq<u8>> forall<plaintext: Seq<u8>>
            key.len() == KEY_BYTES@ && nonce.len() == NONCE_BYTES@ && plaintext.len() > 0 ==> {
                let ciphertext = Self::encrypt_spec(key, nonce, plaintext);
                plaintext == Self::decrypt_spec(key, nonce, ciphertext)
            }
        )
    }

    #[logic(opaque)]
    fn encrypt_aead_spec(_key: Seq<u8>, _plaintext: Seq<u8>, _associated_data: Seq<u8>) -> (Bytes<NONCE_BYTES>, Vec<u8>) {
        dead
    }

    #[logic(opaque)]
    fn decrypt_aead_spec(_key: Seq<u8>, _nonce_and_ciphertext: Seq<u8>, _associated_data: Seq<u8>) -> Vec<u8> {
        dead
    }

    #[logic(law)]
    fn symmetric_key_aead_cipher_law() {
        proof_assert!(
            forall<key: Seq<u8>> forall<associated_data: Seq<u8>> forall<plaintext: Seq<u8>>
            key.len() == KEY_BYTES@ && associated_data.len() > 0 && plaintext.len() > 0 ==> {
                let (nonce, ciphertext) = Self::encrypt_aead_spec(key, plaintext, associated_data);
                let n = nonce.0@;
                let c = ciphertext@;
                let nonce_and_ciphertext = concat_pearlite(seq![n, c]);
                plaintext == Self::decrypt_aead_spec(key, nonce_and_ciphertext, associated_data)@
            }
        )
    }

    #[ensures(result@.len() == NONCE_BYTES@)]
    fn gen_nonce<R: CryptoRng + ?Sized>(rng: &mut R) -> [u8; NONCE_BYTES];

}

pub trait PostQuantumKEM<const PUBKEY_BYTES: usize, const PRVKEY_BYTES: usize, const SEC_BYTES: usize, const CT_BYTES: usize> : KeyPairGen<PUBKEY_BYTES, PRVKEY_BYTES> {
    #[ensures(is_ok(result))]
    #[ensures(
        result == Ok(Self::encap_spec((*public_key)@))
    )]
    fn encap(public_key: &[u8; PUBKEY_BYTES]) -> Result<(Bytes<SEC_BYTES>, Bytes<CT_BYTES>)>;

    #[requires(ciphertext@.len() > 0)]
    #[ensures(has_any_item(result))]
    #[ensures(
        result == Ok(Self::decap_spec((*secret_key)@, ciphertext@))
    )]
    fn decap(secret_key: &[u8; PRVKEY_BYTES], ciphertext: &[u8]) -> Result<Vec<u8>>;

    #[logic(opaque)]
    fn encap_spec(_public_key: Seq<u8>) -> (Bytes<SEC_BYTES>, Bytes<CT_BYTES>) {
        dead
    }

    #[logic(opaque)]
    fn decap_spec(_secret_key: Seq<u8>, _ciphertext: Seq<u8>) -> Vec<u8> {
        dead
    }

    #[logic(opaque)]
    fn logic_pk_from_sk(_sk: Seq<u8>) -> Seq<u8> {
        dead
    }

    #[logic(law)]
    fn encap_decap_law() {
        proof_assert!(
            forall<pk: Seq<u8>> forall<sk: Seq<u8>> Self::logic_pk_from_sk(sk) == pk ==> {
                let (shs, ct) = Self::encap_spec(pk);
                Self::decap_spec(sk, ct.0@)@ == shs.0@
            }
        )
    }
}

pub trait KeyAgreement<const KA_PUBKEY_BYTES: usize, const KA_PRVKEY_BYTES: usize, const KA_SEC_BYTES: usize> : KeyPairGen<KA_PUBKEY_BYTES, KA_PRVKEY_BYTES> {
    #[ensures(is_ok(result))]
    #[ensures(
        {
            result == Ok(Self::derive_when_encrypt_spec(sender_keys.identity_key_kx, recipient_bundle.identity_key, recipient_bundle.signed_prekey.0, recipient_bundle.one_time_prekeys@))
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

    #[ensures(
        result == Self::derive_when_decrypt_inner_spec(recipient_keys.identity_key_kx, recipient_keys.signed_prekey, recipient_keys.one_time_prekeys[opk_id as usize], sender_identity_key, sender_ephemeral_key, shared_secret_pq@)
    )]
    fn derive_when_decrypt_inner<const PQ_PRVKEY_BYTES: usize, const SIGKEY_BYTES: usize>(recipient_keys: &PrivateKeyBundle<KA_PRVKEY_BYTES, PQ_PRVKEY_BYTES, SIGKEY_BYTES>, sender_identity_key: &Bytes<KA_PUBKEY_BYTES>, sender_ephemeral_key: &Bytes<KA_PUBKEY_BYTES>, opk_id: u32, shared_secret_pq: &[u8]) -> (Vec<u8>, Bytes<KA_PUBKEY_BYTES>);

    // derive_when_encrypt의 논리적 모델
    #[logic(opaque)]
    fn derive_when_encrypt_spec(_sender_prvkey: Bytes<KA_PRVKEY_BYTES>, _ik: Bytes<KA_PUBKEY_BYTES>, _spk: Bytes<KA_PUBKEY_BYTES>, _opks: Seq<Bytes<KA_PUBKEY_BYTES>>) -> (u32, Bytes<KA_SEC_BYTES>, Bytes<KA_PUBKEY_BYTES>, Bytes<KA_PUBKEY_BYTES>) {
        dead
    }

    // derive_when_decrypt의 논리적 모델
    #[logic(opaque)]
    fn derive_when_decrypt_inner_spec(_ik_kx: Bytes<KA_PRVKEY_BYTES>, _spk: Bytes<KA_PRVKEY_BYTES>, _opk: Bytes<KA_PRVKEY_BYTES>, _sender_identity_key: &Bytes<KA_PUBKEY_BYTES>, _sender_ephemeral_key: &Bytes<KA_PUBKEY_BYTES>, _shared_secret_pq: Seq<u8>) -> (Vec<u8>, Bytes<KA_PUBKEY_BYTES>) {
        dead
    }

    // ⭐ 핵심: Key Agreement의 정확성 공리
    // 암호화 시 생성된 정보(CiphertextBundle)를 이용해 복호화하면,
    // 암호화 시 유도된 classic_dh_secrets와 복호화 시 master_secret의 첫 부분이 일치함을 보장.
    #[logic(law)]
    fn key_agreement_law() {
        proof_assert!(forall<s_ik_kx: Bytes<KA_PRVKEY_BYTES>> forall<r_ik: Bytes<KA_PUBKEY_BYTES>> forall<r_spk: Bytes<KA_PUBKEY_BYTES>> forall<r_opks: Seq<Bytes<KA_PUBKEY_BYTES>>> forall<rs_ik_kx: Bytes<KA_PRVKEY_BYTES>> forall<rs_spk: Bytes<KA_PRVKEY_BYTES>> forall<rs_opks: Seq<Bytes<KA_PRVKEY_BYTES>>>  forall<shared_secret_pq: Seq<u8>> {
            let (opk_id, classic_dh, sender_ik, sender_ek) = Self::derive_when_encrypt_spec(s_ik_kx, r_ik, r_spk, r_opks);
            let (master_secret, _) = Self::derive_when_decrypt_inner_spec(rs_ik_kx, rs_spk, rs_opks[opk_id@], &sender_ik, &sender_ek, shared_secret_pq);
            is_prefix_of(classic_dh.0@, master_secret@)
        })
    }
}

pub trait KeyPairGen<const PUBKEY_BYTES: usize, const PRVKEY_BYTES: usize> {
    #[ensures(
        result.0.0@.len() == PUBKEY_BYTES@ &&
        result.1.0@.len() == PRVKEY_BYTES@
    )]
    #[ensures({
        let (pubkey, prvkey) = result;
        Self::is_correct_pair(&pubkey, &prvkey)
    })]
    fn generate_keypair() -> (Bytes<PUBKEY_BYTES>, Bytes<PRVKEY_BYTES>); // (public_key, private_key)
    
    #[logic(opaque)]
    fn is_correct_pair(_pubkey: &Bytes<PUBKEY_BYTES>, _prvkey: &Bytes<PRVKEY_BYTES>) -> bool {
        dead
    }
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