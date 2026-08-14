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
