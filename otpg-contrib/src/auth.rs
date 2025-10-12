
use hmac::Mac;
use otpg_core::{auth::OtpVerifier, types::GetContextStr};

use creusot_contracts::{ensures, logic, pearlite, requires, seq, trusted, Seq};

pub struct TotpRsVerifier;



impl OtpVerifier for TotpRsVerifier {
    #[trusted]
    fn verify(code: &str, s_otp: &[u8], timestamp: u64) -> bool {
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

    #[logic]
    #[trusted]
    fn verify_creusot(code: &str, s_otp: [u8; 20], timestamp: u64) -> bool {
        let step_times: Seq<u64> = seq![(timestamp as u64 / 30u64 - 1)*30, (timestamp as u64 / 30u64)*30, (timestamp as u64 / 30u64 + 1)*30];
        let generated_codes: Seq<bool> = step_times.map(|st| cmp_otp(generate_shim(&s_otp, st, 30u64), code));
        generated_codes[0] || generated_codes[1] || generated_codes[2]
    }
        
    
    #[trusted]
    fn gen_s_otp<R : rand::CryptoRng + ?Sized>(rng: &mut R) -> [u8; 20] {
        crate::gen_bytearr(rng)
    }
}

const fn custom_from_be_bytes_u32(byte0: u8, byte1: u8, byte2: u8, byte3: u8) -> u32 {
    0u32 | ((byte0 as u32) << 24) | ((byte1 as u32) << 16) | ((byte2 as u32) << 8) | (byte3 as u32)
}

const fn custom_to_be_bytes_u64(x: u64) -> [u8; 8] {
    [
        (x & 0xFF00000000000000u64 >> 56) as u8,
        (x & 0x00FF000000000000u64 >> 48)as u8,
        (x & 0x0000FF0000000000u64 >> 40)as u8,
        (x & 0x000000FF00000000u64 >> 32)as u8,
        (x & 0x00000000FF000000u64 >> 24)as u8,
        (x & 0x0000000000FF0000u64 >> 16)as u8,
        (x & 0x000000000000FF00u64 >> 8)as u8,
        (x & 0x00000000000000FFu64 >> 0)as u8,
    ]
}

#[logic]
#[requires(m@ > 1)]
#[ensures(result@ < m@)]
const fn modulo_u32(x: u32, m: u32) -> u32 {
    if x < m {
        x
    } else {
        modulo_u32(x - m, m)
    }
}

#[logic]
#[requires(d@ > 0)]
#[ensures((result@ * d@) <= x@)]
const fn div_u64(x: u64, d: u64) -> u64 {
    if x < d {
        0u64
    } else {
        1u64 + div_u64(x-d, d)
    }
}


#[logic]
#[trusted]
#[ensures(result@ < 1000000)]
fn generate_shim(s_otp: &[u8; 20], step_time: u64, step: u64) -> u32 {
    let mut digest = hmac::Hmac::<sha1::Sha1>::new_from_slice(s_otp).unwrap();
    let be: [u8; 8] = custom_to_be_bytes_u64(div_u64(step_time, step));
    digest.update(&be);
    let tmp: Vec<u8> = digest.finalize().into_bytes().to_vec();
    let offset = ((tmp[7usize]) & 15u8) as usize;

    let parsed: u32 = custom_from_be_bytes_u32(tmp[offset], tmp[offset+1usize], tmp[offset+2usize], tmp[offset+3usize]);
    modulo_u32(parsed, 1000000u32)
}

#[logic]
const fn get_last_digit_str(n: u32) -> u8 {
    match n {
        0u32 => b"0"[0],
        1u32 => b"1"[0],
        2u32 => b"2"[0],
        3u32 => b"3"[0],
        4u32 => b"4"[0],
        5u32 => b"5"[0],
        6u32 => b"6"[0],
        7u32 => b"7"[0],
        8u32 => b"8"[0],
        9u32 => b"9"[0],
        _ => get_last_digit_str(modulo_u32(n, 10u32))
    }
}

#[logic]
#[requires(generated@ < 1000000)]
const fn cmp_otp(generated: u32, code: &str) -> bool {
    let for_use = modulo_u32(generated, 1000000u32);
    let digits: Seq<u8> = seq![
        get_last_digit_str((for_use / 100000u32) % 10),
        get_last_digit_str((for_use / 10000u32) % 10),
        get_last_digit_str((for_use / 1000u32) % 10),
        get_last_digit_str((for_use / 100u32) % 10),
        get_last_digit_str((for_use / 10u32) % 10),
        get_last_digit_str(for_use % 10)
    ];
    let bytes = code.as_bytes();
    pearlite! {
        bytes@ == digits
    }
}



impl const GetContextStr for TotpRsVerifier{
    fn get_context_str() -> &'static str {
        "TOTP"
    }
}