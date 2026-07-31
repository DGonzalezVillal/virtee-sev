// SPDX-License-Identifier: Apache-2.0

//! ABI types shared across first-generation SEV and SEV-SNP.

pub mod launch;
pub mod primitives;

pub use primitives::{FirmwareVersion, Generation};

#[cfg(feature = "snp")]
pub use primitives::{CpuFamily, CpuModel};
