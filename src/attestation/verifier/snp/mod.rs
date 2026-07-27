// SPDX-License-Identifier: Apache-2.0

//! SNP attestation verification.

mod chain;
mod ecdsa;
mod report;
mod signature;

#[cfg(feature = "crypto-openssl")]
mod cert;
#[cfg(feature = "crypto-openssl")]
mod openssl;

#[cfg(feature = "crypto-rust")]
mod cert_nossl;
