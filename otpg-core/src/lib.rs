#![feature(const_slice_make_iter)]
#![feature(const_trait_impl)]

pub mod types;
pub mod error;
pub mod keygen;
pub mod constants;

pub mod encrypt;
pub mod decrypt;
pub mod auth;

pub(crate) mod macros;

pub mod cipher;

pub(crate) mod utils;

pub mod creusot_utils;

#[cfg(creusot)]
use creusot_contracts::logic::Seq;

#[cfg(creusot)]
pub mod proofs;



use creusot_contracts::{macros::logic};
use rand_core::CryptoRng;

use crate::cipher::OneTimePrekeysPairGen;

pub trait Law<
    V: auth::OtpVerifier,
    const NONCE_BYTES: usize, C: cipher::AeadCipher<DERIVED_KEY_BYTES, NONCE_BYTES> + const cipher::HasNonceLength<NONCE_BYTES>,
    const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const PQ_SEC_BYTES: usize, const PQ_CT_BYTES: usize,
    PQ: cipher::PostQuantumKEM<PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES>,
    const KA_PUBKEY_BYTES: usize, const KA_PRVKEY_BYTES: usize, const KA_SEC_BYTES: usize,
    KA: cipher::KeyAgreement<KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_SEC_BYTES>,
    const DERIVED_KEY_BYTES: usize, KD: cipher::KDF<DERIVED_KEY_BYTES>,
    const SIGKEY_BYTES: usize, const SIGN_BYTES: usize, S: cipher::Signer<SIGKEY_BYTES, SIGN_BYTES>
> {
    #[logic]
    fn roundtrip_lemma();
}

pub struct OtpgWrapper<
    V: auth::OtpVerifier,
    const NONCE_BYTES: usize, C: cipher::AeadCipher<DERIVED_KEY_BYTES, NONCE_BYTES> + const cipher::HasNonceLength<NONCE_BYTES>,
    const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const PQ_SEC_BYTES: usize, const PQ_CT_BYTES: usize,
    PQ: cipher::PostQuantumKEM<PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES>,
    const KA_PUBKEY_BYTES: usize, const KA_PRVKEY_BYTES: usize, const KA_SEC_BYTES: usize,
    KA: cipher::KeyAgreement<KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_SEC_BYTES>,
    const DERIVED_KEY_BYTES: usize, KD: cipher::KDF<DERIVED_KEY_BYTES>,
    const SIGKEY_BYTES: usize, const SIGN_BYTES: usize, S: cipher::Signer<SIGKEY_BYTES, SIGN_BYTES>
>(::std::marker::PhantomData<(V, C, PQ, KA, KD, S)>);

impl<
    V: auth::OtpVerifier,
    const NONCE_BYTES: usize, C: cipher::AeadCipher<DERIVED_KEY_BYTES, NONCE_BYTES> + const cipher::HasNonceLength<NONCE_BYTES>,
    const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const PQ_SEC_BYTES: usize, const PQ_CT_BYTES: usize,
    PQ: cipher::PostQuantumKEM<PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES>,
    const KA_PUBKEY_BYTES: usize, const KA_PRVKEY_BYTES: usize, const KA_SEC_BYTES: usize,
    KA: cipher::KeyAgreement<KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_SEC_BYTES>,
    const DERIVED_KEY_BYTES: usize, KD: cipher::KDF<DERIVED_KEY_BYTES>,
    const SIGKEY_BYTES: usize, const SIGN_BYTES: usize, S: cipher::Signer<SIGKEY_BYTES, SIGN_BYTES>
> Law<
    V,NONCE_BYTES,C,PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES,PQ_CT_BYTES,PQ,
    KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_SEC_BYTES, KA,
    DERIVED_KEY_BYTES, KD,SIGKEY_BYTES, SIGN_BYTES, S
> for OtpgWrapper<
    V,NONCE_BYTES,C,PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES,PQ_CT_BYTES,PQ,
    KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_SEC_BYTES, KA,
    DERIVED_KEY_BYTES, KD,SIGKEY_BYTES, SIGN_BYTES, S
> {
    #[logic]
    fn roundtrip_lemma() {
        proof_assert! {
            forall<recv_pub_bundle: types::PublicKeyBundle<KA_PUBKEY_BYTES, PQ_PUBKEY_BYTES, SIGN_BYTES>> forall <recv_prv_vault: types::PrivateKeyVault<NONCE_BYTES>> forall <send_prv_bundle: types::PrivateKeyBundle<KA_PRVKEY_BYTES,PQ_PRVKEY_BYTES,SIGKEY_BYTES>> forall <plaintext: Seq<u8>> forall<current_timestamp: u64> forall<otp_code: &str> {
                let is_cbp = crate::keygen::is_correct_bundle_pair(&recv_pub_bundle, &recv_prv_vault);
                let ciphertext_bundle = encrypt::encrypt_spec::<NONCE_BYTES, C, PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES, PQ, KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_SEC_BYTES, KA, DERIVED_KEY_BYTES, KD, SIGKEY_BYTES, SIGN_BYTES>(&send_prv_bundle, &recv_pub_bundle, plaintext);

                let s_otp = recv_prv_vault.authentication.s_otp;
                let otp_passed = V::verify_spec(otp_code, s_otp@, current_timestamp);
                let long_enough_for_nonce = !C::too_short_for_nonce_creusot(ciphertext_bundle.aead_ciphertext@);
                let decrypted_result = decrypt::decrypt_spec::<V, NONCE_BYTES, C, PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES, PQ, KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_SEC_BYTES, KA, DERIVED_KEY_BYTES, KD, SIGKEY_BYTES, SIGN_BYTES>(&recv_prv_vault, otp_code, &ciphertext_bundle, current_timestamp);
                (!otp_passed ==> decrypted_result == Err(error::OtpgError::AuthenticationError)) &&
                otp_passed ==> 
                    (!long_enough_for_nonce ==> decrypted_result == Err(error::OtpgError::AeadError(error::OtpgAEADError::TooShortForNonce))) &&
                    long_enough_for_nonce ==> 
                        (!is_cbp ==> decrypted_result == Err(error::OtpgError::AeadError(error::OtpgAEADError::DecrptionFailed))) &&
                        (is_cbp ==> match decrypted_result {
                            Ok(decrypted) => decrypted@ == plaintext,
                            Err(_) => false
                        })
                    
                
            }
        }
    }
}

impl<
    V: auth::OtpVerifier + types::GetContextStr,
    const NONCE_BYTES: usize, C: cipher::AeadCipher<DERIVED_KEY_BYTES, NONCE_BYTES> + const cipher::HasNonceLength<NONCE_BYTES> + types::GetContextStr,
    const PQ_PUBKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const PQ_SEC_BYTES: usize, const PQ_CT_BYTES: usize,
    PQ: cipher::PostQuantumKEM<PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES>,
    const KA_PUBKEY_BYTES: usize, const KA_PRVKEY_BYTES: usize, const KA_SEC_BYTES: usize,
    KA: cipher::KeyAgreement<KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_SEC_BYTES> + OneTimePrekeysPairGen<KA_PUBKEY_BYTES, KA_PRVKEY_BYTES>,
    const DERIVED_KEY_BYTES: usize, KD: cipher::KDF<DERIVED_KEY_BYTES> + types::GetContextStr,
    const SIGKEY_BYTES: usize, const SIGN_BYTES: usize, S: cipher::Signer<SIGKEY_BYTES, SIGN_BYTES>
> OtpgWrapper<
    V,NONCE_BYTES,C,PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES,PQ_CT_BYTES,PQ,
    KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_SEC_BYTES, KA,
    DERIVED_KEY_BYTES, KD,SIGKEY_BYTES, SIGN_BYTES, S
> {
    pub fn encrypt(
        sender_keys: &types::PrivateKeyBundle<KA_PRVKEY_BYTES,PQ_PRVKEY_BYTES,SIGKEY_BYTES>,
        recipient_bundle: &types::PublicKeyBundle<KA_PUBKEY_BYTES, PQ_PUBKEY_BYTES, SIGN_BYTES>,
        plaintext: &[u8]
    ) -> error::Result<types::CiphertextBundle<KA_PUBKEY_BYTES,PQ_CT_BYTES,NONCE_BYTES>> {
        encrypt::encrypt::<
            NONCE_BYTES,C,PQ_PUBKEY_BYTES,PQ_PRVKEY_BYTES,PQ_SEC_BYTES,PQ_CT_BYTES,PQ,KA_PUBKEY_BYTES,KA_PRVKEY_BYTES,KA_SEC_BYTES,KA,DERIVED_KEY_BYTES,KD,SIGKEY_BYTES,SIGN_BYTES
        >(sender_keys, recipient_bundle, plaintext)
    }

    pub fn decrypt(
        recipient_vault: &types::PrivateKeyVault<NONCE_BYTES>,
        otp_code: &str, // 사용자가 입력한 6자리 OTP 코드
        bundle: &types::CiphertextBundle<KA_PUBKEY_BYTES, PQ_CT_BYTES, NONCE_BYTES>,
        current_timestamp: u64
    ) -> error::Result<Vec<u8>> {
        decrypt::decrypt::<
            V, NONCE_BYTES, C, PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES, PQ, KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_SEC_BYTES, KA, DERIVED_KEY_BYTES, KD, SIGKEY_BYTES, SIGN_BYTES
        >(recipient_vault, otp_code, bundle, current_timestamp)
    }

    pub fn generate_keys<R: CryptoRng + ?Sized>(num_opks: u32, rng: &mut R) -> error::Result<(types::PublicKeyBundle<KA_PUBKEY_BYTES, PQ_PUBKEY_BYTES, SIGN_BYTES>, types::PrivateKeyVault<NONCE_BYTES>)> {
        keygen::generate_keys::<
            V, NONCE_BYTES, C, PQ_PUBKEY_BYTES, PQ_PRVKEY_BYTES, PQ_SEC_BYTES, PQ_CT_BYTES, PQ, KA_PUBKEY_BYTES, KA_PRVKEY_BYTES, KA_SEC_BYTES, KA, DERIVED_KEY_BYTES, KD, SIGKEY_BYTES, SIGN_BYTES, S, R
        >(num_opks, rng)
    }
}