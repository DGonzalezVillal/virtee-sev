// SPDX-License-Identifier: Apache-2.0

//! RATS Verifier role: appraise attestation evidence and endorsements.

mod verifiable;

#[cfg(all(feature = "snp", any(feature = "crypto-openssl", feature = "crypto-rust")))]
pub mod snp;

#[cfg(all(feature = "sev", feature = "crypto-openssl"))]
pub mod sev;

pub use verifiable::Verifiable;
