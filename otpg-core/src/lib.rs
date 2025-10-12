#![feature(const_slice_make_iter)]
#![feature(const_trait_impl)]

pub mod types;
pub mod error;
pub mod keygen;
pub mod constants;

pub mod encrypt;
pub mod decrypt;
pub mod auth;

pub(crate) mod macros;

pub mod cipher;

pub(crate) mod utils;

pub mod creusot_utils;

#[cfg(creusot)]
pub mod proofs;