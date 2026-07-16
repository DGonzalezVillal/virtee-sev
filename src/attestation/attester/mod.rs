// SPDX-License-Identifier: Apache-2.0

//! RATS Attester role: produce SNP attestation evidence from a guest VM.

#[cfg(target_os = "linux")]
pub mod snp;

#[cfg(target_os = "linux")]
pub use snp::Firmware;
