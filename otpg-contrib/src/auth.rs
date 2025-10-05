use otpg_core::{auth::OtpVerifier, types::GetContextStr};

pub struct TotpRsVerifier;



impl OtpVerifier for TotpRsVerifier {
    fn verify(&self, code: &str, s_otp: &[u8], timestamp: u64) -> bool {
        // 기존의 verify_totp 함수 로직을 그대로 가져옵니다.
        let secret = match totp_rs::Rfc6238::new(6, s_otp.to_vec()) {
            Ok(rfc) => rfc,
            Err(_) => return false,
        };
        let totp = match totp_rs::TOTP::from_rfc6238(secret) {
            Ok(t) => t,
            Err(_) => return false,
        };
        totp.check(code, timestamp)
    }
    
    fn gen_s_otp<R : rand::CryptoRng + ?Sized>(rng: &mut R) -> [u8; 20] {
        crate::gen_bytearr(rng)
    }
}

impl GetContextStr for TotpRsVerifier{
    fn get_context_str() -> &'static str {
        "TOTP"
    }
}