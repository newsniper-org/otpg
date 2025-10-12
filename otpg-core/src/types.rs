

use creusot_contracts::requires;
#[allow(unused_imports)]
use creusot_contracts::{prelude::DeepModel, Seq, prelude::logic, prelude::trusted, prelude::ensures};


#[cfg(not(creusot))]
use serde::{Deserialize, Serialize};

use crate::auth::OtpVerifier;
use crate::cipher::{AeadCipher, KDF};
use crate::creusot_utils::{concat, concat_mat};


pub const trait GetContextStr {
    fn get_context_str() -> &'static str;
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, DeepModel)]
pub struct Bytes<const LEN: usize>(
    pub [u8; LEN]
);

impl<const LEN: usize> Bytes<LEN> {
    #[trusted]
    pub fn copy_from_inplace(&mut self, source: &[u8]) {
        self.0.iter_mut().zip(source.iter()).for_each(|(this, other)| {
            (*this) = *other;
        });
    }

    pub fn copy_from(source: &[u8]) -> Self {
        let mut result = Self::default();
        result.copy_from_inplace(source);
        result
    }
}

impl<const LEN: usize> Default for Bytes<LEN> {
    fn default() -> Self {
        Self([0u8; LEN])
    }
}


#[derive(Clone)]
pub struct SignedPreKey<const PUBKEY_BYTES: usize, const SIGN_BYTES: usize>(pub Bytes<PUBKEY_BYTES>, pub Bytes<SIGN_BYTES>);

#[derive(Clone, Copy)]
pub struct Version(pub u32, pub u32);

#[derive(Clone)]
pub struct PublicKeyBundle<const KA_PUBKEY_BYTES: usize, const PQ_PUBKEY_BYTES: usize, const SIGN_BYTES: usize> {
    pub version: Version,
    pub identity_key: Bytes<KA_PUBKEY_BYTES>,
    pub identity_key_pq: Bytes<PQ_PUBKEY_BYTES>,
    pub signed_prekey: SignedPreKey<KA_PUBKEY_BYTES, SIGN_BYTES>,
    pub one_time_prekeys: Vec<Bytes<KA_PUBKEY_BYTES>>
}

#[derive(Clone)]
pub struct AuthenticationVault {
    pub method: String,
    pub s_otp: Bytes<20>,
    pub kdf_context: String
}

#[derive(Clone)]
pub struct EncryptedData<const NONCE_BYTES: usize> {
    pub nonce: Bytes<NONCE_BYTES>,
    pub ciphertext: Vec<u8>
}

#[derive(Clone)]
pub struct PrivateKeyVault<const NONCE_BYTES: usize> {
    pub version: Version,
    pub authentication: AuthenticationVault,
    pub encrypted_data: EncryptedData<NONCE_BYTES>
}

// keygen 내부에서만 사용될 임시 구조체
pub struct PrivateKeyBundle<const KA_PRVKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const SIGKEY_BYTES: usize> {
    pub identity_key_sig: Bytes<SIGKEY_BYTES>,
    pub identity_key_kx: Bytes<KA_PRVKEY_BYTES>,
    pub identity_key_pq: Bytes<PQ_PRVKEY_BYTES>,
    pub signed_prekey: Bytes<KA_PRVKEY_BYTES>,
    pub one_time_prekeys: Vec<Bytes<KA_PRVKEY_BYTES>>,
}



/// 암호화된 메시지와 수신자가 복호화에 필요한 모든 정보를 담는 구조체
pub struct CiphertextBundle<const KA_PUBKEY_BYTES: usize, const PQ_CT_BYTES: usize, const NONCE_BYTES: usize> {
    /// 발신자의 장기 공개키 (IK_B)
    pub sender_identity_key: Bytes<KA_PUBKEY_BYTES>,
    /// 발신자의 임시 공개키 (EK_B)
    pub sender_ephemeral_key: Bytes<KA_PUBKEY_BYTES>,
    /// 수신자의 어떤 일회성 사전 키를 사용했는지 가리키는 ID
    pub opk_id: u32,
    /// Post-quantum KEM 암호문
    pub pq_ciphertext: Bytes<PQ_CT_BYTES>,
    /// AEAD cipher(예: XChaCha20-Poly1305)로 암호화된 최종 암호문
    pub aead_ciphertext: Vec<u8>,
}

// src/constants.rs 에 Kyber 암호문 길이 상수 추가
pub const KYBER1024_CIPHERTEXT_LEN: usize = 1568;


#[cfg_attr(not(creusot), derive(Serialize, Deserialize))]
#[derive(Clone)]
pub struct LittleEndianIntermediateRepr(pub Vec<u8>);

impl LittleEndianIntermediateRepr {
    #[trusted]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl<const KA_PUBKEY_BYTES: usize, const PQ_CT_BYTES: usize, const NONCE_BYTES: usize> From<LittleEndianIntermediateRepr> for CiphertextBundle<KA_PUBKEY_BYTES, PQ_CT_BYTES, NONCE_BYTES> {
    #[trusted]
    fn from(value: LittleEndianIntermediateRepr) -> Self {
        let sender_identity_key = Bytes::copy_from(&value.0[0..KA_PUBKEY_BYTES]);
        let sender_ephemeral_key = Bytes::copy_from(&value.0[KA_PUBKEY_BYTES..(KA_PUBKEY_BYTES+KA_PUBKEY_BYTES)]);
        let opk_id_le_bytes = [value.0[KA_PUBKEY_BYTES+KA_PUBKEY_BYTES], value.0[KA_PUBKEY_BYTES+KA_PUBKEY_BYTES+1], value.0[KA_PUBKEY_BYTES+KA_PUBKEY_BYTES+2], value.0[KA_PUBKEY_BYTES+KA_PUBKEY_BYTES+3]];
        let opk_id = u32::from_le_bytes(opk_id_le_bytes);
        let pq_ciphertext = Bytes::copy_from(&value.0[(KA_PUBKEY_BYTES+KA_PUBKEY_BYTES+4)..(KA_PUBKEY_BYTES+KA_PUBKEY_BYTES+4+PQ_CT_BYTES)]);
        let aead_ciphertext = value.0[(KA_PUBKEY_BYTES+KA_PUBKEY_BYTES+4+PQ_CT_BYTES)..].to_vec();
        Self {
            sender_identity_key, sender_ephemeral_key, opk_id, pq_ciphertext, aead_ciphertext
        }
    }
}

impl<const KA_PUBKEY_BYTES: usize, const PQ_CT_BYTES: usize, const NONCE_BYTES: usize> Into<LittleEndianIntermediateRepr>  for CiphertextBundle<KA_PUBKEY_BYTES, PQ_CT_BYTES, NONCE_BYTES> {
    #[trusted]
    fn into(self) -> LittleEndianIntermediateRepr {
        let opk_id_le_bytes: [u8; 4] = self.opk_id.to_le_bytes();
        let slices = [self.sender_identity_key.0.as_slice(), &self.sender_ephemeral_key.0.as_slice(), opk_id_le_bytes.as_slice(), self.pq_ciphertext.0.as_slice(), self.aead_ciphertext.as_slice()];
        LittleEndianIntermediateRepr(crate::utils::flatten(slices))
    }
}

impl<const KA_PRVKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const SIGKEY_BYTES: usize> From<LittleEndianIntermediateRepr> for PrivateKeyBundle<KA_PRVKEY_BYTES, PQ_PRVKEY_BYTES, SIGKEY_BYTES> {

    #[requires(
        value.0@.len() > (SIGKEY_BYTES@ + KA_PRVKEY_BYTES@ + PQ_PRVKEY_BYTES@ + KA_PRVKEY_BYTES@)
        && (value.0@.len() - (SIGKEY_BYTES@ + KA_PRVKEY_BYTES@ + PQ_PRVKEY_BYTES@ + KA_PRVKEY_BYTES@)) % KA_PRVKEY_BYTES@ == 0
    )]
    #[ensures(
        result.identity_key_sig.0@.len() == SIGKEY_BYTES@ &&
        result.identity_key_kx.0@.len() == KA_PRVKEY_BYTES@ &&
        result.identity_key_pq.0@.len() == PQ_PRVKEY_BYTES@ &&
        result.signed_prekey.0@.len() == KA_PRVKEY_BYTES@ &&
        result.one_time_prekeys@.len() == ((value.0@.len() - (SIGKEY_BYTES@ + KA_PRVKEY_BYTES@ + PQ_PRVKEY_BYTES@ + KA_PRVKEY_BYTES@)) / KA_PRVKEY_BYTES@) &&
        (forall<i: usize> i@ < result.one_time_prekeys@.len() ==> result.one_time_prekeys[i].0@.len() == KA_PRVKEY_BYTES@)
    )]
    fn from(value: LittleEndianIntermediateRepr) -> Self {
        let identity_key_sig = Bytes::copy_from(&value.0[0..SIGKEY_BYTES]);
        let identity_key_kx = Bytes::copy_from(&value.0[SIGKEY_BYTES..SIGKEY_BYTES+KA_PRVKEY_BYTES]);
        let identity_key_pq = Bytes::copy_from(&value.0[SIGKEY_BYTES+KA_PRVKEY_BYTES..SIGKEY_BYTES+KA_PRVKEY_BYTES+PQ_PRVKEY_BYTES]);
        let signed_prekey = Bytes::copy_from(&value.0[SIGKEY_BYTES+KA_PRVKEY_BYTES+PQ_PRVKEY_BYTES..SIGKEY_BYTES+KA_PRVKEY_BYTES+PQ_PRVKEY_BYTES+KA_PRVKEY_BYTES]);
        
        let remaining_count = value.0[SIGKEY_BYTES+KA_PRVKEY_BYTES+PQ_PRVKEY_BYTES+KA_PRVKEY_BYTES..].len() / KA_PRVKEY_BYTES;
        let one_time_prekeys = (0..remaining_count).map(|i| {
            let v0 = value.as_slice();
            Bytes::copy_from(&v0[(SIGKEY_BYTES+KA_PRVKEY_BYTES+PQ_PRVKEY_BYTES+KA_PRVKEY_BYTES + i*KA_PRVKEY_BYTES)..(SIGKEY_BYTES+KA_PRVKEY_BYTES+PQ_PRVKEY_BYTES+KA_PRVKEY_BYTES + (i+1)*KA_PRVKEY_BYTES)])
        }).collect();
        // .chunks_exact().map(|chunk: &[u8]|Bytes(*chunk.as_array::<KA_PRVKEY_BYTES>().unwrap())).into_iter().collect::<Vec<Bytes<KA_PRVKEY_BYTES>>>();

        Self {
            identity_key_sig, identity_key_kx, identity_key_pq, signed_prekey, one_time_prekeys
        }
    }
}

impl<const KA_PRVKEY_BYTES: usize, const PQ_PRVKEY_BYTES: usize, const SIGKEY_BYTES: usize> Into<LittleEndianIntermediateRepr> for PrivateKeyBundle<KA_PRVKEY_BYTES, PQ_PRVKEY_BYTES, SIGKEY_BYTES> {
    #[ensures(
        result.0@.len() == (SIGKEY_BYTES@ + KA_PRVKEY_BYTES@ + PQ_PRVKEY_BYTES@ + KA_PRVKEY_BYTES@) + (KA_PRVKEY_BYTES@ * self.one_time_prekeys@.len())
    )]
    fn into(self) -> LittleEndianIntermediateRepr {
        let Self{
            identity_key_sig, identity_key_kx, identity_key_pq, signed_prekey, one_time_prekeys
        } = self;
        let chained1 = concat_mat(one_time_prekeys.iter().map(|b| b.0).collect::<Vec<[u8; KA_PRVKEY_BYTES]>>());
        let chained0 = concat([&identity_key_sig.0, &identity_key_kx.0, &identity_key_pq.0, &signed_prekey.0, &chained1]);
        
        LittleEndianIntermediateRepr(chained0)
    }
}


impl Version {
    #[trusted]
    pub const fn to_le_bytes(self) -> [u8; 8] {
        let major_le: [u8; 4] = self.0.to_le_bytes();
        let minor_le: [u8; 4] = self.1.to_le_bytes();
        [major_le[0], major_le[1], major_le[2], major_le[3], minor_le[0], minor_le[1], minor_le[2], minor_le[3]]
    }

    #[trusted]
    pub const fn from_le_bytes(le_bytes: [u8; 8]) -> Self {
        let major = u32::from_le_bytes([le_bytes[0], le_bytes[1], le_bytes[2], le_bytes[3]]);
        let minor = u32::from_le_bytes([le_bytes[4], le_bytes[5], le_bytes[6], le_bytes[7]]);
        Self(major,minor)
    }
}

#[trusted]
pub(crate) fn make_private_vault<const NONCE_BYTES: usize, V: OtpVerifier + GetContextStr, const DERIVED_KEY_BYTES: usize, KD: KDF<DERIVED_KEY_BYTES> + GetContextStr, C: AeadCipher<DERIVED_KEY_BYTES, NONCE_BYTES> + GetContextStr>(major: u32, minor: u32, s_otp: [u8; 20], nonce: [u8; NONCE_BYTES], ciphertext:Vec<u8>) -> PrivateKeyVault<NONCE_BYTES> {
    PrivateKeyVault {
        version: Version(major, minor),
        authentication: AuthenticationVault {
            method: [V::get_context_str(), KD::get_context_str(), C::get_context_str()].join("-").to_string(),
            s_otp: Bytes(s_otp),
            kdf_context: format!("otpg-key-wrapping-v{}", major),
        },
        encrypted_data: EncryptedData {
            nonce: Bytes(nonce),
            ciphertext: ciphertext,
        },
    }
}