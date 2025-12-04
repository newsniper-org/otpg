use otpg_contrib::TotpXChaCha20Poly1305Kyber1024X448BLAKE3Ed448 as cipher;
use otpg_core::types::{LittleEndianIntermediateRepr, PrivateKeyBundle, PrivateKeyVault};

use serde::{Serialize, Deserialize};

use std::{env::Args, error, io::{Error, ErrorKind}, path::PathBuf};

use chacha20::{
    KeyIvInit, XChaCha20, cipher::StreamCipher
};

#[cfg(not(creusot))]
fn self_encrypt_random(params_raw: Args) -> Option<String> {
    let params = params_raw.collect::<Vec<String>>();
    let args = match params.len() {
        3 => Some((params[1].clone(), params[2].clone(), "default".to_string(), 32usize)),
        4 => {
            if let Ok(size) = params[3].clone().parse::<usize>() {
                Some((params[1].clone(), params[2].clone(), "default".to_string(), size))
            } else {
                None
            }
        },
        5 => {
            if let Ok(size) = params[4].clone().parse::<usize>() {
                Some((params[1].clone(), params[2].clone(), params[3].clone(), size))
            } else {
                None
            }
        },
        _ => {
            None
        }
    };

    if let Some((otp_code, output_pathstr, keyname, size)) = args {
        use otpg_core::types::{PrivateKeyVault, PublicKeyBundle};

        let user = std::env::var("USER").unwrap();
        let otpg_path = if user == "root" {
            PathBuf::from("/root")
        } else {
            PathBuf::from("/home").join(user)
        }.join(".otpg");
        if let Ok(pk_json) = std::fs::read_to_string(otpg_path.join(keyname.clone() + ".pub")) && let Ok(pk) = serde_json::from_str::<PublicKeyBundle<56, 1568, 114>>(&pk_json)
            && let Ok(sk_json) = std::fs::read_to_string(otpg_path.join(keyname)) && let Ok(sk) = serde_json::from_str::<PrivateKeyVault<24>>(&sk_json) {
            let current_timestamp = chrono::Utc::now().timestamp() as u64;
            if cipher::verify(&otp_code,&sk.authentication.s_otp.0, current_timestamp) {
                let bundle = unlock_vault(&sk);
                let mut plaintext = vec![0u8; size];
                rand::fill(plaintext.as_mut_slice());
                if let Ok(result) = cipher::encrypt(&bundle,&pk, &plaintext) {
                    let result_json = serde_json::to_string(&result).unwrap();
                    std::fs::write(PathBuf::from(output_pathstr.clone()), result_json).unwrap();
                    return Some(format!("random ciphertext from {}-byte data is saved to {}", size, output_pathstr));
                } else {
                    return Some("Something went wrong with encryption :(".to_string());
                }
            } else {
                return Some("WRONG OTP :(".to_string());
            }
        } else {
            return None;
        }
    } else {
        return None;
    }
}

#[allow(unused)]
fn unlock_vault(vault: &PrivateKeyVault<24>) -> PrivateKeyBundle<56,3168, 57> {
    let kek = blake3::derive_key(
        &vault.authentication.kdf_context,
        &vault.authentication.s_otp.0.as_slice()
    );

    let mut cipher = XChaCha20::new(&(kek.into()), &(vault.encrypted_data.nonce.0.into()));
    let plaintext_bytes = {
        let mut buf = vault.encrypted_data.ciphertext.clone();
        cipher.apply_keystream(&mut buf);
        buf
    };
    let private_keys: PrivateKeyBundle<56,3168, 57> = LittleEndianIntermediateRepr(plaintext_bytes).into();
    private_keys
}

#[cfg(not(creusot))]
fn main() {
    if let Some(msg) = self_encrypt_random(std::env::args()) {
        println!("{}", msg);
    } else {
        println!("otpg_self_encrypt_random <otp code> <output path> [key name] [plaintext size]");
    }
}

#[cfg(creusot)]
fn main() {}