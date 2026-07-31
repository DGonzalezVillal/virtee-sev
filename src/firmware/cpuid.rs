// SPDX-License-Identifier: Apache-2.0

//! Host-side CPUID helpers for identifying the local EPYC generation.

use crate::types::shared::primitives::Generation;

use std::convert::TryInto;

/// Identify the EPYC processor generation based on the CPUID instruction.
///
/// This helper is only compiled for Linux x86_64 targets. Platform APIs that
/// need a [`Generation`] take it as an explicit parameter instead of calling
/// this automatically.
pub(crate) fn identify_host_generation() -> Result<Generation, std::io::Error> {
    unsafe { std::arch::x86_64::__cpuid(0x8000_0001) }
        .eax
        .to_le_bytes()
        .as_slice()
        .try_into()
}
