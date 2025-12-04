use otpg_contrib::TotpXChaCha20Poly1305Kyber1024X448BLAKE3Ed448 as cipher;
use otpg_core::types::{LittleEndianIntermediateRepr, PrivateKeyBundle, PrivateKeyVault};

use serde::{Serialize, Deserialize};

use std::{env::Args, error, io::{Error, ErrorKind}, path::PathBuf};

use chacha20::{
    KeyIvInit, XChaCha20, cipher::StreamCipher
};

#[cfg(not(creusot))]
fn print_otp_qr(params_raw: Args) -> Option<String> {
    let params = params_raw.collect::<Vec<String>>();
    let name = if params.len() <= 1 {
        Some(String::from("default"))
    } else if params.len() == 2 {
        Some(params[1].clone())
    } else {
        None
    };
    if let Some(keyname) = name {
        use otpg_core::types::PrivateKeyVault;

        let user = std::env::var("USER").unwrap();
        let dir = if user == "root" {
            PathBuf::from("/root")
        } else {
            PathBuf::from("/home").join(user)
        }.join(".otpg");
        let path = dir.join(&keyname);
        if let Ok(sk_json) = std::fs::read_to_string(path) && let Ok(sk) = serde_json::from_str::<PrivateKeyVault<24>>(&sk_json) {
            use qrcode::QrCode;

            let s_otp = sk.authentication.s_otp;
            let s_otp_base32 = data_encoding::BASE32.encode(&s_otp.0);
            let label = format!("{}:{}", "otpg", keyname.clone());
            let uri = format!(
                "otpauth://totp/{}?secret={}&issuer={}&algorithm=SHA1&digits=6&period=30",
                label, s_otp_base32, "otpg"
            );

            if let Ok(qr) = QrCode::new(uri) {
                use qrcode::render::svg;

                let svg = qr.render::<svg::Color>().build();
                let dest = dir.join(format!("qr_{}.svg", keyname));
                std::fs::write(dest.clone(), svg).unwrap();
                return Some(format!("The QR code SVG file is generated at {:?}", dest));                        
            } else {
                return None;
            }
        } else {
            return None;
        }
    } else {
        return None;
    }
}

#[cfg(not(creusot))]
fn main() {
    if let Some(msg) = print_otp_qr(std::env::args()) {
        println!("{}", msg);
    } else {
        println!("otpg_print_otp_qr [key name]");
    }
}

#[cfg(creusot)]
fn main() {}