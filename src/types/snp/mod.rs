// SPDX-License-Identifier: Apache-2.0

//! SEV-SNP UAPI value types.

mod cert;
mod cert_table;
mod derived_key;
mod id_block;
mod launch_digest;
mod page_type;
mod platform_config;
mod primitives;
mod tcb;

pub use cert::CertType;
pub use cert_table::{CertTableEntry, RawData};
pub use derived_key::{DerivedKey, GuestFieldSelect};
pub use id_block::{
    FamilyId, IdAuth, IdBlock, ImageId, SevEcdsaKeyData, SevEcdsaPubKey, SevEcdsaSig,
    CURVE_P384, ECDSA_POINT_SIZE_BYTES,
};
pub use launch_digest::{SnpLaunchDigest, LD_BITS, LD_BYTES};
pub use page_type::PageType;
pub use platform_config::MaskId;
pub use primitives::GuestPolicy;
pub use tcb::TcbVersion;

pub mod platform;
