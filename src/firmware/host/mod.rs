// SPDX-License-Identifier: Apache-2.0

//! Host FFI Wrappers for C Kernel APIs
#[cfg(all(target_os = "linux", feature = "snp"))]
pub(crate) mod cpuid;

#[cfg(target_os = "linux")]
pub(crate) mod ioctl;
pub(crate) mod types;
