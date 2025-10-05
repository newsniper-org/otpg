// src/auth.rs (수정본)

use crate::types::GetContextStr;

// 1. "OTP 검증기"라는 역할(Trait)을 정의합니다.
// 이 역할은 코드가 유효한지 검사하는 기능만 가집니다.
pub trait OtpVerifier : GetContextStr {
    fn verify(&self, code: &str, s_otp: &[u8], timestamp: u64) -> bool;
    fn gen_s_otp<R : rand::CryptoRng + ?Sized>(rng: &mut R) -> [u8; 20];
}