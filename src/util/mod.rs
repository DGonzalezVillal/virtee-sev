// SPDX-License-Identifier: Apache-2.0

//! Internal utilities shared across the crate.
//!
//! - [`parser_helper`] — [`Read`](std::io::Read) / [`Write`](std::io::Write)
//!   extensions for [`crate::parser`] decode/encode impls
//! - [`hexline`](self::hexline) — hex formatting for debug display
//! - [`cached_chain`](self::cached_chain) — test helper for fetching AMD cert chains
//! - [`openssl_helpers`](self::openssl_helpers) — OpenSSL little-endian conversions (`crypto-openssl`)

// pub mod array;
pub mod cached_chain;
pub(crate) mod hexline;
mod impl_const_id;
#[cfg(feature = "crypto-openssl")]
pub(crate) mod openssl_helpers;
pub mod parser_helper;

use std::{
    io::{Read, Result, Write},
    mem::{size_of, MaybeUninit},
    slice::{from_raw_parts, from_raw_parts_mut},
};

pub trait TypeLoad: Read {
    fn load<T: Sized + Copy>(&mut self) -> Result<T> {
        #[allow(clippy::uninit_assumed_init)]
        let mut t = unsafe { MaybeUninit::uninit().assume_init() };
        let p = &mut t as *mut T as *mut u8;
        let s = unsafe { from_raw_parts_mut(p, size_of::<T>()) };
        self.read_exact(s)?;
        Ok(t)
    }
}

pub trait TypeSave: Write {
    fn save<T: Sized + Copy>(&mut self, value: &T) -> Result<()> {
        let p = value as *const T as *const u8;
        let s = unsafe { from_raw_parts(p, size_of::<T>()) };
        self.write_all(s)
    }
}

impl<T: Read> TypeLoad for T {}
impl<T: Write> TypeSave for T {}
