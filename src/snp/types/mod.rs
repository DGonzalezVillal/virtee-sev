// SPDX-License-Identifier: Apache-2.0

//! SNP ABI value types shared across attestation and platform code.

mod cert;
mod derived_key;
mod platform_config;
mod primitives;
mod tcb;

pub use cert::CertType;
pub use derived_key::{DerivedKey, GuestFieldSelect};
pub use platform_config::MaskId;
pub use primitives::{GuestPolicy, Version};
pub use tcb::TcbVersion;
