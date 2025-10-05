use crate::error::Result;
use crate::types::PrivateKeyBundle;

#[cfg(any(hax, not(feature = "serde")))]
use crate::keygen::generate_keys;

// "바이트 슬라이스로부터 PrivateKeyBundle을 만들어내는" 역할을 정의합니다.
pub trait BundleDeserializer {
    fn deserialize(bytes: &[u8]) -> Result<PrivateKeyBundle>;
}

// `bincode`를 사용한 실제 구현체를 만듭니다.
pub struct BincodeDeserializer;

impl BundleDeserializer for BincodeDeserializer {

    #[cfg(all(not(hax), feature = "serde"))]
    fn deserialize(bytes: &[u8]) -> Result<PrivateKeyBundle> {
        let (bundle, _) = bincode::serde::decode_from_slice(
            bytes,
            bincode::config::standard().with_fixed_int_encoding(),
        ).unwrap();
        Ok(bundle)
    }

    #[cfg(any(hax, not(feature = "serde")))]
    fn deserialize(_bytes: &[u8]) -> Result<PrivateKeyBundle> {
        Ok(todo!())
    }
}