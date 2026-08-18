// SPDX-License-Identifier: Apache-2.0

//! RATS-oriented attestation roles.
//!
//! Enable individual role features (`evidence`, `verifier`, `endorser`,
//! `attester`, `reference`) to compile only the attestation surface you need.
#[cfg(all(
    feature = "attester",
    target_os = "linux",
    any(feature = "sev", feature = "snp")
))]
pub mod attester;

#[cfg(all(feature = "evidence", any(feature = "sev", feature = "snp")))]
pub mod evidence;

#[cfg(all(
    feature = "endorser",
    any(
        all(
            feature = "snp",
            any(feature = "crypto-openssl", feature = "crypto-rust")
        ),
        all(feature = "sev", feature = "crypto-openssl")
    )
))]
pub mod endorser;

#[cfg(all(feature = "reference", any(feature = "sev", feature = "snp")))]
pub mod reference;

#[cfg(all(feature = "evidence", feature = "snp"))]
pub use evidence::snp::{
    KeyInfo, PlatformInfo, Report, ReportBody, ReportVariant, Signature, SignatureAlgorithm,
};

#[cfg(all(feature = "evidence", feature = "sev", feature = "crypto-openssl"))]
pub use evidence::sev::LegacyAttestationReport;
