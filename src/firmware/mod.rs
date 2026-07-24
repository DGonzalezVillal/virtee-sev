// SPDX-License-Identifier: Apache-2.0

//! Linux ioctl definitions for SEV host and guest firmware devices.
//!
//! Public host platform APIs live in [`crate::platform`]. Guest attestation
//! APIs live in [`crate::attestation::attester`].

#[cfg(any(feature = "sev", feature = "snp"))]
pub(crate) mod host;

#[cfg(feature = "snp")]
pub(crate) mod guest;

pub(crate) const _4K_PAGE: usize = 4096;
