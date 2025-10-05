module Correctness

open Core
open FStar.Mul

open Otpg_core.Types
open Otpg_core.Decrypt
open Otpg_core.Encrypt

assume val is_valid_otp: t_PrivateKeyVault -> string -> u64 -> Tot bool


val lemma_decrypt_encrypt_roundtrip:
    #v_V: Type0 ->
    verifier: Otpg_core.Auth.t_OtpVerifier v_V ->
    sender_keys: t_PrivateKeyBundle ->
    recipient_pub: t_PublicKeyBundle ->
    recipient_vault: t_PrivateKeyVault ->
    plaintext: t_Slice u8 ->
    otp: string ->
    timestamp: u64 ->
    Lemma (requires (
            is_valid_otp recipient_vault otp timestamp
          ))
          (ensures (
            let Core.Result.Result_Ok cipher_bundle = encrypt_to_verify sender_keys recipient_pub plaintext in
            let decrypted_result = decrypt_to_verify #v_V verifier recipient_vault otp cipher_bundle timestamp in
            decrypted_result == Core.Result.Result_Ok plaintext
          ))

let lemma_decrypt_encrypt_roundtrip #v_V verifier sender_keys recipient_pub recipient_vault plaintext otp timestamp =
  admit()