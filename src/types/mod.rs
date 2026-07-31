// SPDX-License-Identifier: Apache-2.0

//! Shared firmware ABI value types, organized by generation.

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod shared;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod sev;

#[cfg(feature = "snp")]
pub mod snp;
