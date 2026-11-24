// SPDX-License-Identifier: Apache-2.0

//! Signature checks.
//!
//! A type that implements [`Authenticate`] can decide whether a signature
//! belongs to its key. Certificates and other signing keys implement this.
//! The check does not turn the signed artifact into a trusted value. That is
//! [`Verifiable`](crate::Verifiable).

/// Why a signature was not accepted.
///
/// Every [`Authenticate`] implementation reports this type, so callers can
/// name it without knowing which key checked the signature.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthenticateError {
    /// The signature does not belong to this key.
    #[error("signature does not belong to this key")]
    BadSignature,

    /// The signature bytes cannot be parsed for this key's algorithm.
    #[error("signature is malformed: {0}")]
    Malformed(&'static str),
}

/// A key that can check a signature over a byte string.
///
/// # Examples
///
/// ```
/// use sev_core::authenticate::AuthenticateError;
/// use sev_core::Authenticate;
///
/// struct Key(u8);
///
/// impl Authenticate for Key {
///     fn authenticate(&self, signature: &[u8]) -> Result<(), AuthenticateError> {
///         if signature == [self.0] {
///             Ok(())
///         } else {
///             Err(AuthenticateError::BadSignature)
///         }
///     }
/// }
///
/// Key(7).authenticate(&[7]).unwrap();
/// assert_eq!(
///     Key(7).authenticate(&[9]),
///     Err(AuthenticateError::BadSignature),
/// );
/// ```
pub trait Authenticate {
    /// Check that `signature` belongs to this key.
    fn authenticate(&self, signature: &[u8]) -> Result<(), AuthenticateError>;
}
