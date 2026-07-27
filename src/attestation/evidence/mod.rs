// SPDX-License-Identifier: Apache-2.0

//! Attestation evidence types.

#[cfg(feature = "snp")]
pub mod snp;

#[cfg(all(feature = "sev", feature = "crypto-openssl"))]
pub mod sev;
