// src/constants.rs

// --- 공개키 관련 상수 ---
pub const X448_PUBLIC_KEY_LEN: usize = 56;
pub const ED448_SIGNATURE_LEN: usize = 114;
pub const KYBER1024_PUBLIC_KEY_LEN: usize = 1568;
pub const KYBER1024_SECRET_KEY_LEN: usize = 3168;


// --- 개인키 저장소 관련 상수 ---
pub const S_OTP_LEN: usize = 20; // 160 bits
pub const XCHACHA20_NONCE_LEN: usize = 24; // 192 bits