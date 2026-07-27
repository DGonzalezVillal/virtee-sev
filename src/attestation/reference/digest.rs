// SPDX-License-Identifier: Apache-2.0

//! SHA-256 and SHA-384 helpers for reference value calculation.

#[cfg(feature = "crypto-openssl")]
use openssl::sha::{sha256 as openssl_sha256, sha384 as openssl_sha384};

/// Compute a SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    #[cfg(feature = "crypto-openssl")]
    {
        openssl_sha256(data)
    }

    #[cfg(feature = "crypto-rust")]
    {
        use sha2::Digest;
        let hash = sha2::Sha256::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&hash);
        out
    }

    #[cfg(not(any(feature = "crypto-openssl", feature = "crypto-rust")))]
    compile_error!("either \"crypto-openssl\" or \"crypto-rust\" must be enabled");
}

/// Compute a SHA-384 digest.
pub fn sha384(data: &[u8]) -> [u8; 48] {
    #[cfg(feature = "crypto-openssl")]
    {
        openssl_sha384(data)
    }

    #[cfg(feature = "crypto-rust")]
    {
        use sha2::Digest;
        let hash = sha2::Sha384::digest(data);
        let mut out = [0u8; 48];
        out.copy_from_slice(&hash);
        out
    }

    #[cfg(not(any(feature = "crypto-openssl", feature = "crypto-rust")))]
    compile_error!("either \"crypto-openssl\" or \"crypto-rust\" must be enabled");
}
