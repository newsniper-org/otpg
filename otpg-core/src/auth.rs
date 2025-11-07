// src/auth.rs (수정본)

use crate::types::GetContextStr;

use creusot_contracts::{logic::Seq, macros::{ensures, logic, requires}};

// 1. "OTP 검증기"라는 역할(Trait)을 정의합니다.
// 이 역할은 코드가 유효한지 검사하는 기능만 가집니다.
pub trait OtpVerifier : const GetContextStr {
    #[requires(s_otp@.len() == 20)]
    #[ensures(result == Self::verify_spec(code, s_otp@, timestamp))]
    fn verify(code: &str, s_otp: &[u8], timestamp: u64) -> bool;

    #[logic(opaque)]
    fn verify_spec(_code: &str, _s_otp: Seq<u8>, _timestamp: u64) -> bool {
        dead
    }

    #[ensures(result@.len() == 20)]
    fn gen_s_otp<R : rand::CryptoRng + ?Sized>(rng: &mut R) -> [u8; 20];
}