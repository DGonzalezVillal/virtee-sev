// SPDX-License-Identifier: Apache-2.0

//! Host FFI Wrappers for C Kernel APIs

pub(crate) mod types;

#[cfg(all(target_os = "linux", feature = "platform"))]
pub(crate) mod ioctl;

#[cfg(all(target_os = "linux", feature = "snp"))]
pub(crate) mod cpuid;
