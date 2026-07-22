// SPDX-License-Identifier: Apache-2.0

//! RATS-oriented attestation types, production, verification, and reference
//! values.

#[cfg(all(target_os = "linux", feature = "snp"))]
pub mod attester;

#[cfg(feature = "snp")]
pub mod evidence;

#[cfg(all(feature = "snp", any(feature = "openssl", feature = "crypto_nossl")))]
pub mod endorser;

pub mod reference;

#[cfg(all(feature = "snp", any(feature = "openssl", feature = "crypto_nossl")))]
pub mod verifier;

#[cfg(all(feature = "snp", any(feature = "openssl", feature = "crypto_nossl")))]
pub use verifier::Verifiable;

#[cfg(feature = "snp")]
pub use evidence::snp::{KeyInfo, PlatformInfo, Report, ReportBody, ReportVariant, Signature, SignatureAlgorithm};

#[cfg(all(target_os = "linux", feature = "snp"))]
pub use attester::Firmware;
