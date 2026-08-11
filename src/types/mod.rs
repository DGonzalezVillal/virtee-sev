// SPDX-License-Identifier: Apache-2.0

//! Firmware ABI value types for AMD SEV and SEV-SNP.
//!
//! Rust representations of wire layouts defined by AMD firmware specifications
//! and the Linux kernel UAPI. Types here are **values** — parsing, validation,
//! and display — not ioctl transport (see [`crate::firmware`]) or high-level
//! role APIs (see [`crate::platform`], [`crate::attestation`]).
//!
//! # Module tree
//!
//! ```text
//! types/
//!   shared/     Generation, FirmwareVersion, launch metadata (SEV + SNP)
//!   snp/        SNP attestation, launch, platform, derived-key types
//!   sev/        Legacy SEV platform status (sev feature)
//! ```
//!
//! | Module | Feature | Used by |
//! |--------|---------|---------|
//! | [`shared`](self::shared) | `sev` or `snp` | Platform, attestation, reference measurement |
//! | [`snp`](self::snp) | `snp` | SNP launch, attestation, platform, reference |
//! | [`sev`](self::sev) | `sev` | Legacy SEV platform and launch |
//!
//! # Parsing
//!
//! Most fixed-layout types implement [`ByteParser`](crate::parser::ByteParser),
//! [`Encoder`](crate::parser::Encoder), and/or [`Decoder`](crate::parser::Decoder).
//! Use [`ByteParser::from_bytes`] for context-free layouts and
//! [`ByteParser::from_bytes_with`] when a parameter is required.
//!
//! SNP TCB and platform status decoding often needs an explicit
//! [`Generation`](crate::types::shared::Generation) because field layout changed
//! starting with Turin. Guest policy reserved-bit checks may require
//! [`FirmwareVersion`](crate::types::shared::FirmwareVersion).
//!
//! # Relationship to other modules
//!
//! | Concern | Module |
//! |---------|--------|
//! | C ioctl payloads | [`crate::firmware`] |
//! | Host `/dev/sev` API | [`crate::platform`] |
//! | Guest `/dev/sev-guest` API | [`crate::attestation::attester::snp`] |
//! | Attestation evidence | [`crate::attestation::evidence::snp`] |
//! | Launch digest calculation | [`crate::attestation::reference::snp`] |

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod shared;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod sev;

#[cfg(feature = "snp")]
pub mod snp;
