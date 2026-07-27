// SPDX-License-Identifier: Apache-2.0

//! RATS Attester role: produce SNP attestation evidence from a guest VM.

#[cfg(all(target_os = "linux", feature = "snp"))]
pub mod snp;

#[cfg(all(target_os = "linux", feature = "snp"))]
pub use snp::Firmware;
