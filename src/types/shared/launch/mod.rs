// SPDX-License-Identifier: Apache-2.0

//! Guest launch metadata types for reference measurement.
//!
//! Wire types and parsers for artifacts the hypervisor and firmware consume
//! during guest bring-up. Used primarily by
//! [`crate::attestation::reference`] to compute launch digests offline.
//!
//! # Submodules
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`ovmf`](self::ovmf) | OVMF SEV metadata sections and firmware image parser |
//! | [`vcpu`](self::vcpu) | QEMU vCPU model identifiers |
//! | [`vmsa`](self::vmsa) | SEV-ES / SNP VMSA page layout and builder |

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod ovmf;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod vcpu;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod vmsa;
