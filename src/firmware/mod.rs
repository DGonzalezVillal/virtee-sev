// SPDX-License-Identifier: Apache-2.0

//! Modules for interfacing with SEV firmware.
//! Rust-friendly API wrappers to communicate with the FFI functions.

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod host;

#[cfg(all(feature = "attester", feature = "snp"))]
pub(crate) mod guest;

#[cfg(any(feature = "sev", feature = "snp"))]
pub(crate) mod linux;
