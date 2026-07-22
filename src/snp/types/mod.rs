// SPDX-License-Identifier: Apache-2.0

//! Shared SNP UAPI value types used across attestation, launch, and platform code.

mod cert;
mod derived_key;
mod id_block;
pub mod launch;
mod launch_digest;
mod platform_config;
mod primitives;
mod tcb;

pub use cert::CertType;
pub use derived_key::{DerivedKey, GuestFieldSelect};
pub use id_block::{
    FamilyId, IdAuth, IdBlock, ImageId, SevEcdsaKeyData, SevEcdsaPubKey, SevEcdsaSig,
    CURVE_P384, ECDSA_POINT_SIZE_BYTES,
};
pub use launch_digest::{SnpLaunchDigest, LD_BITS, LD_BYTES};
pub use platform_config::MaskId;
pub use primitives::{GuestPolicy, Version};
pub use tcb::TcbVersion;
