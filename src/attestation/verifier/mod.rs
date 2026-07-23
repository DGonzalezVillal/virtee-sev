// SPDX-License-Identifier: Apache-2.0

//! RATS Verifier role: appraise attestation evidence and endorsements.

mod verifiable;

#[cfg(all(feature = "snp", any(feature = "openssl", feature = "crypto_nossl")))]
pub mod snp;

#[cfg(all(feature = "sev", feature = "openssl"))]
pub mod sev;

pub use verifiable::Verifiable;
