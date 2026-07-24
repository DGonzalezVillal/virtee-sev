// SPDX-License-Identifier: Apache-2.0

//! Host-side CPUID helpers for identifying the local EPYC generation.

use crate::types::primitives::generation::Generation;

use std::convert::TryInto;

/// Identify the EPYC processor generation based on the CPUID instruction.
#[cfg(feature = "snp")]
pub fn identify_host_generation() -> Result<Generation, std::io::Error> {
    #[cfg(target_arch = "x86_64")]
    return unsafe { std::arch::x86_64::__cpuid(0x8000_0001) }
        .eax
        .to_le_bytes()
        .as_slice()
        .try_into();

    #[cfg(not(target_arch = "x86_64"))]
    Err(std::io::Error::other(
        "Cannot get EPYC generation on non-x86 platform",
    ))
}
