// SPDX-License-Identifier: Apache-2.0

//! Host `/dev/sev` ioctl argument layouts.

#[cfg(feature = "platform")]
pub(crate) mod types;

#[cfg(all(target_os = "linux", feature = "platform"))]
pub(crate) mod ioctl;
