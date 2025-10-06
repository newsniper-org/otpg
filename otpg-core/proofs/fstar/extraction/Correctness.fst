module Correctness

open Core
open FStar.Mul

open Otpg_core.Types
open Otpg_core.Decrypt
open Otpg_core.Encrypt

assume val is_valid_otp: t_PrivateKeyVault -> string -> u64 -> Tot bool


(*

assume val i1: Otpg_core.Serialization.t_BundleDeserializer v_D
assume val i2: Otpg_core.Cipher.t_AeadCipher v_C v_NONCE_LEN
assume val i3: Otpg_core.Cipher.t_PostQuantumKEM v_PQ
assume val i4: Otpg_core.Cipher.t_KeyAgreement v_KA
assume val i5: Otpg_core.Cipher.t_KDF v_KD v_DERIVED_KEY_LEN
*)

val lemma_decrypt_encrypt_roundtrip:
    #v_V: Type0 ->
    #v_D : Type0 ->
    v_NONCE_LEN: usize ->
    #v_C: Type0 ->
    #v_PQ: Type0 ->
    #v_KA: Type0 ->
    v_DERIVED_KEY_LEN: usize ->
    #v_KD: Type0 ->
    verifier: Otpg_core.Auth.t_OtpVerifier v_V ->
    sender_keys: t_PrivateKeyBundle ->
    recipient_pub: t_PublicKeyBundle ->
    recipient_vault: t_PrivateKeyVault ->
    plaintext: t_Slice u8 ->
    otp: string ->
    timestamp: u64 ->
    bundle_deserializer: Otpg_core.Serialization.t_BundleDeserializer v_D ->
    aead_cipher: Otpg_core.Cipher.t_AeadCipher v_C v_NONCE_LEN ->
    pqkem: Otpg_core.Cipher.t_PostQuantumKEM v_PQ ->
    ka: Otpg_core.Cipher.t_KeyAgreement v_KA ->
    kdf: Otpg_core.Cipher.t_KDF v_KD v_DERIVED_KEY_LEN ->
    Lemma (requires (
            is_valid_otp recipient_vault otp timestamp
          ))
          (ensures (
            let Core.Result.Result_Ok cipher_bundle = encrypt v_NONCE_LEN #v_C #v_PQ #v_KA v_DERIVED_KEY_LEN #v_KD sender_keys recipient_pub plaintext in
            let decrypted_result = decrypt #v_V #v_D v_NONCE_LEN #v_C #v_PQ #v_KA v_DERIVED_KEY_LEN #v_KD verifier recipient_vault otp cipher_bundle timestamp in
            decrypted_result == Core.Result.Result_Ok plaintext
          ))

let lemma_decrypt_encrypt_roundtrip #v_V verifier sender_keys recipient_pub recipient_vault plaintext otp timestamp =
  admit()