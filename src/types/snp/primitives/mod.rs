// SPDX-License-Identifier: Apache-2.0

//! Shared SNP ABI value types used across multiple contexts (report, launch,
//! id-block, and similar).

mod policy;
mod version;

pub use policy::GuestPolicy;
pub use version::Version;
