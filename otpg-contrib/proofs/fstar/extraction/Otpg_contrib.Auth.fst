module Otpg_contrib.Auth
#set-options "--fuel 0 --ifuel 1 --z3rlimit 15"
open Core
open FStar.Mul

type t_TotpRsVerifier = | TotpRsVerifier : t_TotpRsVerifier

[@@ FStar.Tactics.Typeclasses.tcinstance]
let impl: Otpg_core.Auth.t_OtpVerifier t_TotpRsVerifier =
  {
    f_verify_pre
    =
    (fun (self: t_TotpRsVerifier) (code: string) (s_otp: t_Slice u8) (timestamp: u64) -> true);
    f_verify_post
    =
    (fun (self: t_TotpRsVerifier) (code: string) (s_otp: t_Slice u8) (timestamp: u64) (out: bool) ->
        true);
    f_verify
    =
    fun (self: t_TotpRsVerifier) (code: string) (s_otp: t_Slice u8) (timestamp: u64) ->
      match
        Totp_rs.Rfc.impl_Rfc6238__new (mk_usize 6)
          (Alloc.Slice.impl__to_vec #u8 s_otp <: Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)
        <:
        Core.Result.t_Result Totp_rs.Rfc.t_Rfc6238 Totp_rs.Rfc.t_Rfc6238Error
      with
      | Core.Result.Result_Ok rfc ->
        let secret:Totp_rs.Rfc.t_Rfc6238 = rfc in
        (match
            Totp_rs.impl_TOTP__from_rfc6238 secret
            <:
            Core.Result.t_Result Totp_rs.t_TOTP Totp_rs.Url_error.t_TotpUrlError
          with
          | Core.Result.Result_Ok t ->
            let totp:Totp_rs.t_TOTP = t in
            Totp_rs.impl_TOTP__check totp code timestamp
          | Core.Result.Result_Err _ -> false)
      | Core.Result.Result_Err _ -> false
  }
