// SPDX-License-Identifier: Apache-2.0

//! Linux SNP guest firmware ioctl definitions.
//!
//! Low-level request/response structures and ioctl bindings for the
//! `/dev/sev-guest` device. Guest attestation APIs live in
//! [`crate::attestation::attester`].

#[cfg(target_os = "linux")]
pub(crate) mod cert_table;
#[cfg(target_os = "linux")]
pub(crate) mod ioctl;
#[cfg(target_os = "linux")]
pub(crate) mod types;
