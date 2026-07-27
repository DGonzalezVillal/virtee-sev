// SPDX-License-Identifier: Apache-2.0

//! RATS Endorser role: endorsement material for attestation.

#[cfg(all(feature = "snp", any(feature = "crypto-openssl", feature = "crypto-rust")))]
pub mod snp;

#[cfg(all(feature = "sev", feature = "crypto-openssl"))]
pub mod sev;

#[cfg(all(feature = "snp", any(feature = "crypto-openssl", feature = "crypto-rust")))]
pub use snp::{Certificate, Chain};

#[cfg(all(feature = "sev", feature = "crypto-openssl"))]
pub use sev::{Chain as SevChain, PrivateKey, Signer, Usage};
