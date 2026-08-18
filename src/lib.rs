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
//! By default, both the SEV and SEV-SNP libraries are compiled.
//! Because many modules provide support to both legacy SEV and SEV-SNP, they have been split into individual sub-modules `sev.rs` and `snp.rs`, isolating generation specific behavior.
//! If desired, you may opt to exclude either of the sub-modules by disabling its feature in your project's `Cargo.toml`  
//!
//! For example, to include the SEV APIs only:  
//! `sev = { version = "1.2.1", default-features = false, features = ["sev"] }`  
//!  
//! To include the SEV-SNP APIs only:  
//! `sev = { version = "1.2.1", default-features = false, features = ["snp"] }`  
//!
//! ## Platform Management
//!
//! Refer to the [firmware](crate::firmware) module for more information.
//!
//! ## Guest Management
//!
//! Refer to the [launch](crate::launch) module for more information.
//!
//! ## Cryptographic Verification
//!
//! To enable the cryptographic verification of certificate chains and
//! attestation reports, either the `crypto-openssl` or `crypto-rust` feature
//! has to be enabled manually. With `crypto-openssl`, OpenSSL is used for the
//! verification. With `crypto-rust`, OpenSSL is _not_ used for the
//! verification and instead pure-Rust libraries (e.g., `p384`, `rsa`,
//! etc.) are used. `crypto-openssl` and `crypto-rust` are mutually exclusive,
//! and enabling both at the same time leads to a compiler error.
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
//! Projects in C can take advantage of the C API for the SEV [launch] ioctls.
//! To install the C API, users can use `cargo-c` with the features they would
//! like to produce and install a `pkg-config` file, a static library, a dynamic
//! library, and a C header:
//!
//! `cargo cinstall --prefix=/usr --libdir=/usr/lib64`
//!
//! [firmware]: ./src/firmware/
//! [launch]: ./src/launch/

#![deny(clippy::all)]
#![deny(missing_docs)]
#![allow(unknown_lints)]
#![allow(clippy::identity_op)]
#![allow(clippy::unreadable_literal)]

#[cfg(all(feature = "crypto-openssl", feature = "crypto-rust"))]
compile_error!(
    "features \"crypto-openssl\" and \"crypto-rust\" cannot be enabled at the same time"
);

#[cfg(all(
    any(feature = "verifier", feature = "endorser", feature = "reference"),
    not(any(feature = "crypto-openssl", feature = "crypto-rust"))
))]
compile_error!(
    "features \"verifier\", \"endorser\", and \"reference\" require \"crypto-openssl\" or \"crypto-rust\""
);

#[cfg(all(
    feature = "sev",
    feature = "platform",
    not(all(feature = "endorser", feature = "verifier"))
))]
compile_error!(
    "feature \"platform\" requires \"endorser\" and \"verifier\" when \"sev\" is enabled (legacy SEV host APIs use attestation::endorser::sev certificate types)"
);

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod types;

#[cfg(any(feature = "sev", feature = "snp"))]
pub use types::shared::Generation;

#[cfg(all(
    any(feature = "sev", feature = "snp"),
    any(
        feature = "evidence",
        feature = "reference",
        feature = "verifier",
        feature = "endorser",
        feature = "attester"
    )
))]
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


#[cfg(all(feature = "sev", feature = "dangerous_hw_tests"))]
pub use util::cached_chain;
