// SPDX-License-Identifier: Apache-2.0

//! Guest launch types (OVMF metadata, vCPU models, and SEV-ES VMSA pages).

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod ovmf;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod vcpu;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod vmsa;
