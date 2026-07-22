// SPDX-License-Identifier: Apache-2.0

//! RATS Reference Value Provider role: expected launch measurements and related
//! reference material.

#[cfg(all(
    any(feature = "sev", feature = "snp"),
    any(feature = "openssl", feature = "crypto_nossl")
))]
pub mod digest;

#[cfg(all(
    any(feature = "sev", feature = "snp"),
    any(feature = "openssl", feature = "crypto_nossl")
))]
pub mod sev_hashes;

#[cfg(all(feature = "snp", any(feature = "openssl", feature = "crypto_nossl")))]
pub mod snp;

#[cfg(all(feature = "sev", feature = "openssl"))]
pub mod sev;
