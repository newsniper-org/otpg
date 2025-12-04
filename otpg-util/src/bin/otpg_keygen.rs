use otpg_contrib::TotpXChaCha20Poly1305Kyber1024X448BLAKE3Ed448 as cipher;
use otpg_core::types::{LittleEndianIntermediateRepr, PrivateKeyBundle, PrivateKeyVault};

use serde::{Serialize, Deserialize};

use std::{env::Args, error, io::{Error, ErrorKind}, path::PathBuf};

use chacha20::{
    KeyIvInit, XChaCha20, cipher::StreamCipher
};

#[cfg(not(creusot))]
fn keygen(params_raw: Args) -> Option<String> {
    let params = params_raw.collect::<Vec<String>>();
    let keyname = if params.len() <= 1 {
        String::from("default")
    } else {
        params[1].clone()
    };
    let user = std::env::var("USER").unwrap();
    let otpg_path = if user == "root" {
        PathBuf::from("/root")
    } else {
        PathBuf::from("/home").join(user)
    }.join(".otpg");

    let mut rng = rand::rng();
    let sk_path = otpg_path.join(keyname.clone());
    let pk_path = otpg_path.join(keyname.clone() + ".pub");
    let _ = dbg!(sk_path.to_str());
    println!();
    let _ = dbg!(pk_path.to_str());
    if let Ok((pk, sk)) = cipher::generate_keys(10, &mut rng)
        && let (Ok(pk_json), Ok(sk_json)) = (serde_json::to_string(&pk), serde_json::to_string(&sk)) {
            use std::io::Write;

        let mut sk_file = std::fs::File::create(sk_path).unwrap();
        sk_file.write(sk_json.as_bytes()).unwrap();
        let mut pk_file = std::fs::File::create(pk_path).unwrap();
        pk_file.write(pk_json.as_bytes()).unwrap();
        return Some(format!("keypair \"{}\" generated at {:?}", keyname, otpg_path.to_str()));
    } else {
        return None;
    }
}

#[cfg(not(creusot))]
fn main() {
    if let Some(msg) = keygen(std::env::args()) {
        println!("{}", msg);
    } else {
        println!("otpg_keygen [key name]");
    }
}

#[cfg(creusot)]
fn main() {}