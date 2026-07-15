// SPDX-License-Identifier: Apache-2.0

//! SEV-SNP attestation report evidence.

mod body;
mod fields;
mod report;
mod signature;
mod variant;

pub use body::ReportBody;
pub use fields::{KeyInfo, PlatformInfo};
pub use report::Report;
pub use signature::{Signature, SignatureAlgorithm};
pub use variant::ReportVariant;
