// SPDX-License-Identifier: Apache-2.0

//! SNP attestation verification.

mod chain;
mod ecdsa;
mod report;
mod signature;

#[cfg(feature = "openssl")]
mod cert;
#[cfg(feature = "openssl")]
mod openssl;

#[cfg(feature = "crypto_nossl")]
mod cert_nossl;
