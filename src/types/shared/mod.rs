// SPDX-License-Identifier: Apache-2.0

//! ABI types shared across first-generation SEV and SEV-SNP.
//!
//! Cross-generation concepts that appear in both legacy SEV and SNP code paths.
//!
//! # Modules
//!
//! | Module | Types | Role |
//! |--------|-------|------|
//! | [`generation`](self::generation) | [`Generation`], [`CpuFamily`](Generation), [`CpuModel`](Generation) | EPYC product line; selects TCB layout and built-in cert chains |
//! | [`version`](self::version) | [`FirmwareVersion`] | Major/minor/build triple in reports and platform status |
//! | [`launch`](self::launch) | OVMF, vCPU, VMSA types | Guest launch metadata for reference measurement |
//!
//! # Generation parameter
//!
//! [`Generation`] is passed explicitly to SNP platform and parsing APIs when
//! wire layout depends on CPU generation. It is **not** inferred automatically
//! except via optional helpers such as
//! [`Generation::identify_host_generation`](Generation::identify_host_generation).

pub mod generation;
pub mod launch;
pub mod version;

pub use generation::Generation;
pub use version::FirmwareVersion;

#[cfg(feature = "snp")]
pub use generation::{CpuFamily, CpuModel};
