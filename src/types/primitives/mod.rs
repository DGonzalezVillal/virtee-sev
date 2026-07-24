// SPDX-License-Identifier: Apache-2.0

//! Cross-generation ABI primitives shared across SEV and SEV-SNP.

pub mod generation;

#[cfg(any(feature = "sev", feature = "snp"))]
pub use generation::Generation;

#[cfg(feature = "snp")]
pub use generation::{CpuFamily, CpuModel};
