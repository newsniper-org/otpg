#![feature(const_trait_impl)]

use creusot_contracts::macros::trusted;

use crate::cipher::{Ed448Signer, Kyber1024KEM, X448KeyAgreement, XChaCha20Poly1305Cipher, BLAKE3KDF};

pub mod auth;
pub mod cipher;

#[trusted]
pub(crate) fn gen_bytearr<R : rand_core::CryptoRng + ?Sized, const LEN: usize>(rng: &mut R) -> [u8; LEN] {
    let mut result = [0u8; LEN];
    rng.fill_bytes(&mut result);
    result
}



pub type TotpXChaCha20Poly1305Kyber1024X448BLAKE3Ed448 = otpg_core::OtpgWrapper<
    auth::TotpRsVerifier,
    24usize, XChaCha20Poly1305Cipher,
    1568usize, 3168usize, 32usize, 1568usize, Kyber1024KEM,
    56usize, 56usize, 224usize, X448KeyAgreement,
    32usize, BLAKE3KDF,
    57usize, 114usize, Ed448Signer
>;