// SPDX-License-Identifier: Apache-2.0

//! RATS-oriented attestation types, production, verification, and reference
//! values.

#[cfg(all(target_os = "linux", any(feature = "sev", feature = "snp")))]
pub mod attester;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod evidence;

#[cfg(any(
    all(feature = "snp", any(feature = "openssl", feature = "crypto_nossl")),
    all(feature = "sev", feature = "openssl")
))]
pub mod endorser;

pub mod reference;

#[cfg(any(
    all(feature = "snp", any(feature = "openssl", feature = "crypto_nossl")),
    all(feature = "sev", feature = "openssl")
))]
pub mod verifier;

#[cfg(any(
    all(feature = "snp", any(feature = "openssl", feature = "crypto_nossl")),
    all(feature = "sev", feature = "openssl")
))]
pub use verifier::Verifiable;

#[cfg(feature = "snp")]
pub use evidence::snp::{KeyInfo, PlatformInfo, Report, ReportBody, ReportVariant, Signature, SignatureAlgorithm};

#[cfg(all(feature = "sev", feature = "openssl"))]
pub use evidence::sev::LegacyAttestationReport;

#[cfg(all(target_os = "linux", feature = "snp"))]
pub use attester::Firmware;
