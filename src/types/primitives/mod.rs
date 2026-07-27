// SPDX-License-Identifier: Apache-2.0

//! Cross-generation ABI primitives shared across SEV and SEV-SNP.

pub mod generation;

#[cfg(any(feature = "sev", feature = "snp"))]
pub use generation::Generation;

#[cfg(all(target_os = "linux", target_arch = "x86_64", feature = "snp"))]
pub use generation::identify_host_generation;

#[cfg(feature = "snp")]
pub use generation::{CpuFamily, CpuModel};
