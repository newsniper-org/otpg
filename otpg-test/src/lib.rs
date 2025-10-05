#[cfg(test)]
mod tests {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::KeyInit;
    use otpg_contrib::auth::TotpRsVerifier;
    use otpg_core::error::OtpgError;
    use otpg_core::keygen;
    use otpg_core::encrypt;
    use otpg_core::decrypt;
    use totp_rs::Rfc6238;
    use totp_rs::TOTP;

    /// 테스트를 위해 S_OTP로부터 유효한 현재 OTP 코드를 생성하는 헬퍼 함수
    fn generate_valid_otp(s_otp: &[u8]) -> String {
        let secret = Rfc6238::new(6, s_otp.to_vec()).unwrap();

        // 2. 빌더(builder) 패턴을 사용하여 TOTP 객체 생성
        let totp = TOTP::from_rfc6238(secret).unwrap();
        totp.generate_current().unwrap()
    }

    #[test]
    fn test_happy_path_roundtrip() {
        // --- 1. 설정: 앨리스와 밥의 키 생성 ---
        let (alice_pub, alice_vault) = keygen::generate_keys(10).unwrap();
        let (_bob_pub, bob_vault) = keygen::generate_keys(10).unwrap();
        
        // 1단계(인증)를 통과했다고 가정하고, 밥의 개인키를 미리 복호화/역직렬화.
        // 실제 앱에서는 이 부분이 OTP 인증 후에 발생. 테스트를 위해 수동으로 수행.
        let bob_keys = unlock_private_keys_for_test(&bob_vault).unwrap();
        
        let original_plaintext = b"The crow flies at midnight.";

        // --- 2. 실행: 밥이 앨리스에게 암호화 ---
        let ciphertext_bundle = encrypt::encrypt(
            &bob_keys,
            &alice_pub,
            original_plaintext,
        ).unwrap();

        // --- 3. 실행: 앨리스가 유효한 OTP로 복호화 ---
        // 현재 Unix 타임스탬프를 가져옵니다.
        let current_timestamp = chrono::Utc::now().timestamp() as u64;
        let valid_otp = generate_valid_otp(alice_vault.authentication.s_otp.inner_ref_as_slice());
        let decryption_result = decrypt::decrypt(
            &TotpRsVerifier,
            &alice_vault,
            &valid_otp,
            &ciphertext_bundle,
            current_timestamp
        );

        // --- 4. 검증 ---
        assert!(decryption_result.is_ok());
        assert_eq!(decryption_result.unwrap(), original_plaintext);
    }

    #[test]
    fn test_decrypt_with_wrong_otp() {
        // --- 1. 설정 ---
        let (alice_pub, alice_vault) = keygen::generate_keys(10).unwrap();
        let (_bob_pub, bob_vault) = keygen::generate_keys(10).unwrap();
        let bob_keys = unlock_private_keys_for_test(&bob_vault).unwrap();
        let ciphertext_bundle = encrypt::encrypt(&bob_keys, &alice_pub, b"test").unwrap();

        // --- 2. 실행: 잘못된 OTP로 복호화 시도 ---
        let wrong_otp = "000000";
        // 현재 Unix 타임스탬프를 가져옵니다.
        let current_timestamp = chrono::Utc::now().timestamp() as u64;
        let decryption_result = decrypt::decrypt(
            &TotpRsVerifier,
            &alice_vault,
            wrong_otp,
            &ciphertext_bundle,
            current_timestamp
        );

        // --- 3. 검증 ---
        assert!(decryption_result.is_err());
        assert!(matches!(decryption_result.unwrap_err(), OtpgError::AuthenticationError));
    }

    #[test]
    fn test_decrypt_with_wrong_keys() {
        // --- 1. 설정: 앨리스, 밥, 찰리 키 생성 ---
        let (alice_pub, _alice_vault) = keygen::generate_keys(10).unwrap();
        let (_bob_pub, bob_vault) = keygen::generate_keys(10).unwrap();
        let bob_keys = unlock_private_keys_for_test(&bob_vault).unwrap();
        let (_charlie_pub, charlie_vault) = keygen::generate_keys(10).unwrap(); // 찰리의 키
        
        // 밥이 앨리스에게 메시지 암호화
        let bundle_for_alice = encrypt::encrypt(&bob_keys, &alice_pub, b"test").unwrap();
        
        // --- 2. 실행: 찰리가 앨리스를 위한 메시지를 자신의 키로 복호화 시도 ---
        let valid_otp_charlie = generate_valid_otp(charlie_vault.authentication.s_otp.inner_ref_as_slice());
        // 현재 Unix 타임스탬프를 가져옵니다.
        let current_timestamp = chrono::Utc::now().timestamp() as u64;
        let decryption_result = decrypt::decrypt(
            &TotpRsVerifier,
            &charlie_vault,
            &valid_otp_charlie,
            &bundle_for_alice,
            current_timestamp
        );

        // --- 3. 검증 ---
        assert!(decryption_result.is_err());
        // 키가 다르므로 AEAD 태그 검증에서 실패해야 함
        assert!(matches!(decryption_result.unwrap_err(), OtpgError::AeadError));
    }

    #[test]
    fn test_decrypt_with_tampered_ciphertext() {
        // --- 1. 설정 ---
        let (alice_pub, alice_vault) = keygen::generate_keys(10).unwrap();
        let (_bob_pub, bob_vault) = keygen::generate_keys(10).unwrap();
        let bob_keys = unlock_private_keys_for_test(&bob_vault).unwrap();
        let mut bundle = encrypt::encrypt(&bob_keys, &alice_pub, b"test").unwrap();

        // --- 2. 실행: 암호문 1바이트 변조 ---
        let last_byte_index = bundle.aead_ciphertext.len() - 1;
        bundle.aead_ciphertext[last_byte_index] ^= 0x01; // 마지막 바이트의 1비트를 뒤집음

        let valid_otp = generate_valid_otp(alice_vault.authentication.s_otp.inner_ref_as_slice());
        // 현재 Unix 타임스탬프를 가져옵니다.
        let current_timestamp = chrono::Utc::now().timestamp() as u64;
        let decryption_result = decrypt::decrypt(
            &TotpRsVerifier,
            &alice_vault,
            &valid_otp,
            &bundle,
            current_timestamp
        );
        
        // --- 3. 검증 ---
        assert!(decryption_result.is_err());
        // 암호문이 변조되었으므로 AEAD 태그 검증에서 실패해야 함
        assert!(matches!(decryption_result.unwrap_err(), OtpgError::AeadError));
    }

    // 참고: 위 테스트를 통과시키려면, decrypt.rs에 테스트 전용으로
    // PrivateKeyVault를 여는 헬퍼 함수가 필요할 수 있습니다.
    // --- 테스트 전용 헬퍼 함수 ---

    /// 오직 테스트 목적으로만 사용됩니다.
    /// OTP 검증 없이 PrivateKeyVault를 복호화하여 PrivateKeyBundle을 반환합니다.
    // 이 함수는 `cargo test` 실행 시에만 컴파일됩니다.
    fn unlock_private_keys_for_test(
        vault: &otpg_core::types::PrivateKeyVault,
    ) -> otpg_core::error::Result<otpg_core::types::PrivateKeyBundle> {
        // 1. KEK(키 암호화 키) 재유도
        // 실제 decrypt 함수 1.2 단계와 동일합니다.
        let kek = blake3::derive_key(
            &vault.authentication.kdf_context,
            vault.authentication.s_otp.inner_ref_as_slice(),
        );

        // 2. 개인키 데이터 복호화 (AEAD)
        // 실제 decrypt 함수 1.3 단계와 동일합니다.
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(kek.as_slice().into());
        let plaintext_bytes = cipher.decrypt(
            vault.encrypted_data.nonce.inner_ref_as_slice().into(),
            vault.encrypted_data.ciphertext.as_slice()
        ).map_err(|_| otpg_core::error::OtpgError::AeadError)?;

        // 3. 개인키 묶음 역직렬화
        // 실제 decrypt 함수 1.4 단계와 동일합니다.
        let (private_keys, _) = bincode::serde::decode_from_slice::<otpg_core::types::PrivateKeyBundle, _>(&plaintext_bytes, bincode::config::standard().with_fixed_int_encoding())?;
        
        Ok(private_keys)
    }
}
