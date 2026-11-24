// SPDX-License-Identifier: Apache-2.0

//! Traits and concepts shared by the SEV-SNP crates.

#![deny(clippy::all)]
#![deny(missing_docs)]
#![allow(clippy::unreadable_literal)]

pub mod authenticate;
pub mod parser;

pub use authenticate::{Authenticate, AuthenticateError};
