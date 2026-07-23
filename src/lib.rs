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
//! feature flag. That stack is separate from SEV-SNP and is not needed for
//! SNP-only consumers such as remote attestation verifiers.
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
//! Shared SNP firmware ABI wire types live in [`snp::types`], including guest
//! launch layouts under [`snp::types::launch`].
//!
//! [`attestation`]: crate::attestation
//! [`attestation::evidence::snp`]: crate::attestation::evidence::snp
//! [`attestation::verifier`]: crate::attestation::verifier
//! [`attestation::endorser`]: crate::attestation::endorser
//! [`attestation::attester`]: crate::attestation::attester
//! [`attestation::reference`]: crate::attestation::reference
//! [`snp::types`]: crate::snp::types
//! [`snp::types::launch`]: crate::snp::types::launch
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

#[cfg(all(feature = "openssl", feature = "crypto_nossl"))]
compile_error!(
    "feature \"openssl\" and feature \"crypto_nossl\" cannot be enabled at the same time"
);

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod attestation;

#[cfg(any(feature = "sev", feature = "snp"))]
pub mod snp;

pub mod firmware;
pub mod launch;
mod util;

/// Error module.
pub mod error;

/// Module for Encoding and Decoding types.
pub mod parser;

use crate::parser::Decoder;

#[cfg(all(feature = "sev", feature = "dangerous_hw_tests"))]
pub use util::cached_chain;

#[cfg(all(feature = "openssl", feature = "sev"))]
use attestation::endorser::sev::sev;

#[cfg(feature = "sev")]
use attestation::endorser::sev::ca::{Certificate, Chain as CertSevCaChain};

#[cfg(all(
    not(feature = "sev"),
    feature = "snp",
    any(feature = "openssl", feature = "crypto_nossl")
))]
use attestation::endorser::snp::ca::Chain as CertSnpCaChain;

#[cfg(feature = "sev")]
use attestation::endorser::sev::builtin as SevBuiltin;

#[cfg(all(
    not(feature = "sev"),
    feature = "snp",
    any(feature = "openssl", feature = "crypto_nossl")
))]
use attestation::endorser::snp::builtin as SnpBuiltin;

#[cfg(any(feature = "sev", feature = "snp"))]
use std::convert::TryFrom;

use std::io::{Read, Write};

/// A representation for EPYC generational product lines.
///
/// Implements type conversion traits to determine which generation
/// a given SEV certificate chain corresponds to. This is helpful for
/// automatically detecting what platform code is running on, as one
/// can simply export the SEV certificate chain and attempt to produce
/// a `Generation` from it with the [TryFrom](
/// https://doc.rust-lang.org/std/convert/trait.TryFrom.html) trait.
///
/// ## Example
///
/// ```no_run
/// # #[cfg(features = "openssl")]
/// # {
///
/// // NOTE: The conversion traits require the `sev` crate to have the
/// // `openssl` feature enabled.
///
/// use std::convert::TryFrom;
/// use sev::attestation::endorser::sev::Usage;
/// use sev::firmware::host::types::Firmware;
/// use sev::Generation;
///
/// let mut firmware = Firmware::open().expect("failed to open /dev/sev");
///
/// let chain = firmware.pdh_cert_export()
///     .expect("unable to export SEV certificates");
///
/// let id = firmware.get_identifier().expect("error fetching identifier");
///
/// // NOTE: Requesting a signed CEK from AMD's KDS has been omitted for
/// // brevity.
///
/// let generation = Generation::try_from(&chain).expect("not a SEV/ES chain");
/// match generation {
///     Generation::Naples => println!("Naples"),
///     Generation::Rome => println!("Rome"),
/// }
/// # }
/// ```
#[derive(Copy, Clone)]
pub enum Generation {
    /// First generation EPYC (SEV).
    #[cfg(feature = "sev")]
    Naples,

    /// Second generation EPYC (SEV, SEV-ES).
    #[cfg(feature = "sev")]
    Rome,

    /// Third generation EPYC (SEV, SEV-ES, SEV-SNP).
    #[cfg(any(feature = "sev", feature = "snp"))]
    Milan,

    /// Fourth generation EPYC (SEV, SEV-ES, SEV-SNP).
    #[cfg(any(feature = "sev", feature = "snp"))]
    Genoa,

    /// Fifth generation EPYC (SEV, SEV-ES, SEV-SNP).
    #[cfg(any(feature = "sev", feature = "snp"))]
    Turin,

    /// Sixth generation EPYC (SEV, SEV-ES, SEV-SNP).
    #[cfg(any(feature = "sev", feature = "snp"))]
    Venice,
}

#[cfg(feature = "snp")]
impl TryFrom<&[u8]> for Generation {
    type Error = std::io::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        if bytes.len() != 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid length of bytes representing cpuid",
            ));
        }

        let base_model = (bytes[0] & 0xF0) >> 4;
        let base_family = bytes[1] & 0x0F;

        let ext_model = bytes[2] & 0x0F;

        let ext_family = {
            let low = (bytes[2] & 0xF0) >> 4;
            let high = (bytes[3] & 0x0F) << 4;

            low | high
        };

        let family = base_family + ext_family;
        let model = (ext_model << 4) | base_model;

        Self::identify_cpu(family, model)
    }
}

/// Type alias for the CPU family
#[cfg(feature = "snp")]
pub type CpuFamily = u8;

/// Type alias for the CPU model
#[cfg(feature = "snp")]
pub type CpuModel = u8;

#[cfg(feature = "snp")]
impl TryFrom<(CpuFamily, CpuModel)> for Generation {
    type Error = std::io::Error;

    fn try_from(val: (CpuFamily, CpuModel)) -> Result<Self, Self::Error> {
        Self::identify_cpu(val.0, val.1)
    }
}

#[cfg(feature = "snp")]
impl Generation {
    /// Identify the SEV generation based on the CPU family and model.
    pub fn identify_cpu(family: u8, model: u8) -> Result<Self, std::io::Error> {
        match family {
            0x19 => match model {
                0x0..=0xF => Ok(Self::Milan),
                0x10..=0x1F | 0xA0..=0xAF => Ok(Self::Genoa),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "processor is not of know SEV-SNP model.",
                )),
            },
            0x1A => match model {
                0x0..=0x11 => Ok(Self::Turin),
                0x50..=0x57 | 0x90..=0x9F | 0xA0..=0xAF | 0xC0..=0xC7 => Ok(Self::Venice),
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "processor is not of know SEV-SNP model.",
                )),
            },
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "processor is not of know SEV-SNP generation.",
            )),
        }
    }

    /// Identify the EPYC processor generation based on the CPUID instruction.
    #[cfg(feature = "snp")]
    pub fn identify_host_generation() -> Result<Self, std::io::Error> {
        use std::convert::TryInto;

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
}

#[cfg(feature = "sev")]
impl From<Generation> for CertSevCaChain {
    fn from(generation: Generation) -> CertSevCaChain {
        let (ark, ask) = match generation {
            #[cfg(feature = "sev")]
            Generation::Naples => (SevBuiltin::naples::ARK, SevBuiltin::naples::ASK),
            #[cfg(feature = "sev")]
            Generation::Rome => (SevBuiltin::rome::ARK, SevBuiltin::rome::ASK),
            #[cfg(any(feature = "sev", feature = "snp"))]
            Generation::Milan => (SevBuiltin::milan::ARK, SevBuiltin::milan::ASK),
            #[cfg(any(feature = "sev", feature = "snp"))]
            Generation::Genoa => (SevBuiltin::genoa::ARK, SevBuiltin::genoa::ASK),
            #[cfg(any(feature = "sev", feature = "snp"))]
            Generation::Turin => (SevBuiltin::turin::ARK, SevBuiltin::turin::ASK),
            #[cfg(any(feature = "sev", feature = "snp"))]
            Generation::Venice => panic!("Venice SEV CA chain is not yet implemented"),
        };

        CertSevCaChain {
            ask: Certificate::decode(&mut &*ask, ()).unwrap(),
            ark: Certificate::decode(&mut &*ark, ()).unwrap(),
        }
    }
}

#[cfg(all(
    not(feature = "sev"),
    feature = "snp",
    any(feature = "openssl", feature = "crypto_nossl")
))]
impl From<Generation> for CertSnpCaChain {
    fn from(gen: Generation) -> CertSnpCaChain {
        let (ark, ask) = match gen {
            Generation::Milan => (
                SnpBuiltin::milan::ark().unwrap(),
                SnpBuiltin::milan::ask().unwrap(),
            ),
            Generation::Genoa => (
                SnpBuiltin::genoa::ark().unwrap(),
                SnpBuiltin::genoa::ask().unwrap(),
            ),
            Generation::Turin => (
                SnpBuiltin::turin::ark().unwrap(),
                SnpBuiltin::turin::ask().unwrap(),
            ),

            Generation::Venice => panic!("Venice SNP CA chain is not yet implemented"),
        };

        CertSnpCaChain { ark, ask }
    }
}

#[cfg(all(feature = "sev", feature = "openssl"))]
impl TryFrom<&sev::Chain> for Generation {
    type Error = ();

    fn try_from(schain: &sev::Chain) -> Result<Self, Self::Error> {
        use crate::attestation::verifier::Verifiable;

        let naples: CertSevCaChain = Generation::Naples.into();
        let rome: CertSevCaChain = Generation::Rome.into();
        let milan: CertSevCaChain = Generation::Milan.into();
        let genoa: CertSevCaChain = Generation::Genoa.into();
        let turin: CertSevCaChain = Generation::Turin.into();

        Ok(if (&naples.ask, &schain.cek).verify().is_ok() {
            Generation::Naples
        } else if (&rome.ask, &schain.cek).verify().is_ok() {
            Generation::Rome
        } else if (&milan.ask, &schain.cek).verify().is_ok() {
            Generation::Milan
        } else if (&genoa.ask, &schain.cek).verify().is_ok() {
            Generation::Genoa
        } else if (&turin.ask, &schain.cek).verify().is_ok() {
            Generation::Turin
        } else {
            return Err(());
        })
    }
}

#[cfg(any(feature = "sev", feature = "snp"))]
impl TryFrom<String> for Generation {
    type Error = ();

    fn try_from(val: String) -> Result<Self, Self::Error> {
        match &val.to_lowercase()[..] {
            #[cfg(feature = "sev")]
            "naples" => Ok(Self::Naples),

            #[cfg(feature = "sev")]
            "rome" => Ok(Self::Rome),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "milan" => Ok(Self::Milan),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "genoa" => Ok(Self::Genoa),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "bergamo" => Ok(Self::Genoa),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "siena" => Ok(Self::Genoa),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "turin" => Ok(Self::Turin),

            #[cfg(any(feature = "sev", feature = "snp"))]
            "venice" => Ok(Self::Venice),

            _ => Err(()),
        }
    }
}

#[cfg(any(feature = "sev", feature = "snp"))]
impl Generation {
    /// Create a title-cased string identifying the SEV generation.
    pub fn titlecase(&self) -> String {
        match self {
            #[cfg(feature = "sev")]
            Self::Naples => "Naples".to_string(),

            #[cfg(feature = "sev")]
            Self::Rome => "Rome".to_string(),

            #[cfg(any(feature = "sev", feature = "snp"))]
            Self::Milan => "Milan".to_string(),

            #[cfg(any(feature = "sev", feature = "snp"))]
            Self::Genoa => "Genoa".to_string(),

            #[cfg(any(feature = "sev", feature = "snp"))]
            Self::Turin => "Turin".to_string(),

            #[cfg(any(feature = "sev", feature = "snp"))]
            Self::Venice => "Venice".to_string(),
        }
    }
}
