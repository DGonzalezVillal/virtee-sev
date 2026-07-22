// SPDX-License-Identifier: Apache-2.0

//! SNP ID block and authentication block wire types.

mod auth;
mod block;
mod ecdsa;
mod ids;

pub use auth::IdAuth;
pub use block::IdBlock;
pub use ecdsa::{
    SevEcdsaKeyData, SevEcdsaPubKey, SevEcdsaSig, ECDSA_POINT_SIZE_BYTES,
};
pub use ids::{FamilyId, ImageId};

/// Default ID block format version.
pub const DEFAULT_ID_VERSION: u32 = 1;

/// Default guest policy for ID blocks (`0x30000`).
pub const DEFAULT_ID_POLICY: u64 = 0x30000;

/// Default signing key algorithm identifier (ECDSA P-384).
pub const DEFAULT_KEY_ALGO: u32 = 1;

/// Curve identifier for P-384 keys in ID authentication blocks.
pub const CURVE_P384: u32 = 2;
