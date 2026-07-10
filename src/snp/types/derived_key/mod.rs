// SPDX-License-Identifier: Apache-2.0

//! SNP guest derived-key request types (`SNP_GET_DERIVED_KEY` ioctl).

mod field_select;
mod key_request;

pub use field_select::GuestFieldSelect;
pub use key_request::DerivedKey;
