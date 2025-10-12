#![feature(const_trait_impl)]

use creusot_contracts::trusted;
use rand::Fill;

pub mod auth;
pub mod cipher;

#[trusted]
fn gen_bytearr<R : rand::CryptoRng + ?Sized, const LEN: usize>(rng: &mut R) -> [u8; LEN] {
    let mut result = [0u8; LEN];
    <[u8; LEN] as Fill>::fill(&mut result, rng);
    result
}