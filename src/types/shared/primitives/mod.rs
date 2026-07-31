// SPDX-License-Identifier: Apache-2.0

//! Cross-generation ABI primitives shared across SEV and SEV-SNP.

pub mod generation;
pub mod version;

pub use generation::Generation;
pub use version::FirmwareVersion;

#[cfg(feature = "snp")]
pub use generation::{CpuFamily, CpuModel};
