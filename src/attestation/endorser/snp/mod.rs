// SPDX-License-Identifier: Apache-2.0

//! SNP endorsement material: certificate chains and built-in roots.

/// Certificate Authority (CA) certificates.
pub mod ca;

/// Built-in certificates for Milan, Genoa, and Turin machines.
pub mod builtin;

#[cfg(feature = "crypto-openssl")]
mod cert;
#[cfg(feature = "crypto-rust")]
mod cert_nossl;

mod chain;

#[cfg(feature = "crypto-openssl")]
pub use cert::Certificate;
#[cfg(feature = "crypto-rust")]
pub use cert_nossl::Certificate;

pub use chain::Chain;

use std::io::{Error, ErrorKind, Result};
