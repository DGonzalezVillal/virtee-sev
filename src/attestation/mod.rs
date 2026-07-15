// SPDX-License-Identifier: Apache-2.0

//! RATS-oriented attestation types and verification.

pub mod evidence;

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
pub mod endorser;

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
pub mod verifier;

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
pub use verifier::Verifiable;

pub use evidence::snp::{KeyInfo, PlatformInfo, Report, ReportBody, ReportVariant, Signature, SignatureAlgorithm};
