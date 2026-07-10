// SPDX-License-Identifier: Apache-2.0

//! RATS-oriented attestation types and verification.

pub mod evidence;

pub use evidence::snp::{KeyInfo, PlatformInfo, Report, ReportBody, ReportVariant};
