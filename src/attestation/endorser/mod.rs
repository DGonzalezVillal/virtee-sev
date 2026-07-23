// SPDX-License-Identifier: Apache-2.0

//! RATS Endorser role: endorsement material for attestation.

#[cfg(all(feature = "snp", any(feature = "openssl", feature = "crypto_nossl")))]
pub mod snp;

#[cfg(all(feature = "sev", feature = "openssl"))]
pub mod sev;

#[cfg(all(feature = "snp", any(feature = "openssl", feature = "crypto_nossl")))]
pub use snp::{Certificate, Chain};

#[cfg(all(feature = "sev", feature = "openssl"))]
pub use sev::{Chain as SevChain, PrivateKey, Signer, Usage};
