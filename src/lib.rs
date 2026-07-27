// SPDX-License-Identifier: Apache-2.0

//! The `sev` crate provides an implementation of the [AMD Secure Encrypted
//! Virtualization (SEV)][SEV] APIs and the [SEV Secure Nested Paging
//! Firmware (SNP)][SNP] ABIs.
//!
//! [SEV]: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/programmer-references/55766_SEV-KM_API_Specification.pdf
//! [SNP]: https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf
//!
//! ## SEV APIs
//!
//! The linux kernel exposes two technically distinct AMD SEV APIs:
//!
//! 1. An API for managing the SEV platform itself
//! 2. An API for managing SEV-enabled KVM virtual machines
//!
//! This crate implements both of those APIs and offers them to client.
//! code through a flexible and type-safe high-level interface.
//!
//! ## SNP ABIs
//!
//! Like SEV, the linux kernel exposes another two different AMD SEV-SNP ABIs:
//!
//! 1. An ABI for managing the SEV-SNP platform itself
//! 2. An ABI for managing SEV-SNP enabled KVM virtual machines
//!
//! These new ABIs work only for **SEV-SNP** enabled hosts and guests.
//!
//! This crate implements APIs for both SEV and SEV-SNP management.
//!
//! ## SEV and SEV-SNP enablement
//!
//! By default, only the SEV-SNP library is compiled. First-generation SEV
//! (pre-SNP) support — including platform APIs, certificate and attestation
//! report verification, launch, and session — is available via the `sev`
//! feature flag. Host platform management (`/dev/sev`) requires the `platform`
//! feature; KVM guest launch requires `launch` (which enables `platform`).
//! That legacy stack is separate from SEV-SNP and is not needed for SNP-only
//! consumers such as remote attestation verifiers.
//! Because many modules provide support to both legacy SEV and SEV-SNP, they
//! have been split into individual sub-modules `sev.rs` and `snp.rs`, isolating
//! generation specific behavior.
//!
//! For example, to include first-generation SEV support:  
//! `sev = { version = "1.2.1", default-features = false, features = ["sev"] }`  
//!
//! To use SEV-SNP with the defaults (or explicitly):  
//! `sev = { version = "1.2.1", features = ["snp"] }`  
//!
//! ## Legacy SEV attestation
//!
//! For first-generation SEV remote attestation (`feature = "sev"`), use the same
//! [`attestation`] module roles with legacy SEV types:
//!
//! | Module | Role |
//! |---|---|
//! | [`attestation::evidence::sev`] | `LegacyAttestationReport` |
//! | [`attestation::verifier::sev`] | Certificate chain and report verification |
//! | [`attestation::endorser::sev`] | PEK/PDH/CEK chains and built-in ARK/ASK |
//! | [`attestation::reference::sev`] | Launch digest reference calculation |
//!
//! [`attestation::evidence::sev`]: crate::attestation::evidence::sev
//! [`attestation::reference::sev`]: crate::attestation::reference::sev
//!
//! ## SNP attestation
//!
//! For SEV-SNP remote attestation, use the [`attestation`] module. It is
//! organized around [IETF RATS](https://datatracker.ietf.org/doc/rfc9334/) roles:
//!
//! | Module | Role |
//! |---|---|
//! | [`attestation::evidence::snp`] | Evidence framing and parsing (`Report`, `ReportBody`, …) |
//! | [`attestation::verifier`] | Signature and chain verification |
//! | [`attestation::endorser`] | Endorsement material (VCEK/VLEK chains) |
//! | [`attestation::attester`] | Guest evidence collection (`/dev/sev-guest`) |
//! | [`attestation::reference`] | Reference values (launch digest, ID block) |
//!
//! Shared firmware ABI wire types live in [`types`], organized by generation:
//! [`types::snp`] for SEV-SNP, [`types::sev`] for first-generation SEV, and
//! [`types::shared`] for layouts used by both (for example OVMF and VMSA).
//!
//! [`attestation`]: crate::attestation
//! [`attestation::evidence::snp`]: crate::attestation::evidence::snp
//! [`attestation::verifier`]: crate::attestation::verifier
//! [`attestation::endorser`]: crate::attestation::endorser
//! [`attestation::attester`]: crate::attestation::attester
//! [`attestation::reference`]: crate::attestation::reference
//! [`types`]: crate::types
//! [`types::snp`]: crate::types::snp
//! [`types::sev`]: crate::types::sev
//! [`types::shared`]: crate::types::shared
//!
//! ## Platform Management
//!
//! Refer to the [`platform`] module for host platform APIs (`/dev/sev`).
//! Enable the `platform` Cargo feature to compile it. [`launch`] depends on
//! `platform` and adds KVM guest bring-up ioctls.
//!
//! [`platform`]: crate::platform
//! [`platform::Firmware`]: crate::platform::Firmware
//! [`platform::sev`]: crate::platform::sev
//! [`platform::snp`]: crate::platform::snp
//! [`firmware`]: crate::firmware
//!
//! ## Guest Management
//!
//! Refer to the [`launch`] module for KVM guest bring-up. Enable the `launch`
//! Cargo feature to compile it (`launch` implies `platform`).
//!
//! [`launch`]: crate::launch
//!
//! ## Cryptographic Verification
//!
//! Neither `openssl` nor `crypto_nossl` is enabled by default. Enable one of
//! them explicitly for certificate chain and attestation report verification;
//! [`attestation::verifier`] and [`attestation::endorser`] are gated on either
//! feature.
//!
//! With `openssl`, verification uses OpenSSL. The crate defaults include
//! `openssl?/vendored`, so when the `openssl` feature is enabled, the vendored
//! OpenSSL build is used automatically.
//!
//! With `crypto_nossl`, pure-Rust crates (`p384`, `rsa`, etc.) handle
//! verification instead. `openssl` and `crypto_nossl` are mutually exclusive.
//!
//! Examples:
//!
//! `sev = { version = "1.2.1", features = ["snp", "openssl"] }`  
//! `sev = { version = "1.2.1", features = ["snp", "crypto_nossl"] }`
//!
//! ## Remarks
//!
//! Note that the linux kernel provides access to these APIs through a set
//! of `ioctl`s that are meant to be called on device nodes (`/dev/kvm` and
//! `/dev/sev`, to be specific). As a result, these `ioctl`s form the substrate
//! of the `sev` crate. Binaries that result from consumers of this crate are
//! expected to run as a process with the necessary privileges to interact
//! with the device nodes.
//!
//! ## Using the C API
//!
//! Projects in C can take advantage of the C API for the SEV [`launch`] ioctls.
//! Enable the `launch` feature and use `cargo-c` with the features you would
//! like to produce and install a `pkg-config` file, a static library, a dynamic
//! library, and a C header:
//!
//! `cargo cinstall --prefix=/usr --libdir=/usr/lib64 --features launch`

#![deny(clippy::all)]
#![deny(missing_docs)]
#![allow(unknown_lints)]
#![allow(clippy::identity_op)]
#![allow(clippy::unreadable_literal)]

#[cfg(all(feature = "openssl", feature = "crypto_nossl"))]
compile_error!(
    "feature \"openssl\" and feature \"crypto_nossl\" cannot be enabled at the same time"
);

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod types;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod attestation;

#[cfg(feature = "platform")]
pub mod platform;
#[cfg(any(feature = "sev", feature = "snp"))]
pub(crate) mod firmware;

#[cfg(feature = "launch")]
pub mod launch;
mod util;

/// Error module.
pub mod error;

/// Module for Encoding and Decoding types.
pub mod parser;

#[cfg(all(feature = "sev", feature = "dangerous_hw_tests", feature = "platform"))]
pub use util::cached_chain;

#[cfg(feature = "launch")]
use std::io::{Read, Write};
