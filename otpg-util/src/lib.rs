use otpg_contrib::TotpXChaCha20Poly1305Kyber1024X448BLAKE3Ed448 as cipher;
use otpg_core::types::{LittleEndianIntermediateRepr, PrivateKeyBundle, PrivateKeyVault};

use serde::{Serialize, Deserialize};

use std::{env::Args, error, io::{Error, ErrorKind}, path::PathBuf};

use chacha20::{
    KeyIvInit, XChaCha20, cipher::StreamCipher
};