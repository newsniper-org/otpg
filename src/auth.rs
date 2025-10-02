// src/auth.rs (v5.7.0 API 적용)

use totp_rs::{Rfc6238, TOTP};

/// 사용자가 입력한 TOTP 코드가 유효한지 검증합니다. (totp-rs v5.7.0)
///
/// # Arguments
/// * `code` - 사용자가 입력한 6자리 OTP 코드.
/// * `s_otp` - 사용자의 개인키 저장소에 저장된 160비트(20바이트) S_OTP.
///
/// # Returns
/// 코드가 유효하면 `true`, 그렇지 않으면 `false`.
pub fn verify_totp(code: &str, s_otp: &[u8]) -> bool {
    // 1. Secret 객체 생성
    // s_otp가 표준 길이(160비트)가 아닐 경우를 대비하여 안전하게 처리합니다.
    let secret = match Rfc6238::new(6, s_otp.to_vec()) {
        Ok(rfc) => rfc,
        Err(_) => return false,
    };

    // 2. 빌더(builder) 패턴을 사용하여 TOTP 객체 생성
    let totp = match TOTP::from_rfc6238(secret) {
        Ok(t) => t,
        Err(_) => return false, // 빌드 실패 시
    };
    
    // 현재 Unix 타임스탬프를 가져옵니다.
    let current_timestamp = chrono::Utc::now().timestamp() as u64;

    // 3. 코드 검증
    totp.check(code, current_timestamp)
}