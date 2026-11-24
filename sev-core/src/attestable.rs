// SPDX-License-Identifier: Apache-2.0

//! Tokens produced from verified artifacts.
//!
//! Implement [`Attestable`] for the artifact your crate owns.
//! [`Verifiable`](crate::Verifiable) chooses what a successful `verify` returns.
//! A certificate can stay a root for a later `verify` and skip this trait.

/// Why an attestation token could not be produced.
///
/// Every [`Attestable`] implementation reports this type, so callers can name
/// it without knowing which artifact produced the token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AttestableError {
    /// The artifact has not passed verification, so it cannot attest.
    #[error("artifact has not been verified")]
    NotVerified,

    /// The artifact was verified but a token cannot be built from it.
    #[error("token unavailable: {0}")]
    Unavailable(&'static str),
}

/// A verified artifact that can produce an attestation token.
///
/// The token type stays in the crate that implements the trait.
///
/// # Examples
///
/// ```
/// use sev_core::{Attestable, Authenticate, AuthenticateError, Verifiable, VerifyError};
///
/// struct Key(u8);
/// struct Report { measurement: u8, signature: [u8; 1] }
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
/// impl Verifiable<Key> for Report {
///     type Output = Self;
///
///     fn verify(self, root: &Key) -> Result<Self::Output, VerifyError> {
///         root.authenticate(&self.signature)?;
///         Ok(self)
///     }
/// }
///
/// impl Attestable for Report {
///     type Token = u8;
///
///     fn to_attestation_result(&self) -> Result<Self::Token, sev_core::AttestableError> {
///         Ok(self.measurement)
///     }
/// }
///
/// let report = Report { measurement: 7, signature: [7] }
///     .verify(&Key(7))
///     .unwrap();
/// assert_eq!(report.to_attestation_result().unwrap(), 7);
/// ```
pub trait Attestable {
    /// Token produced from this verified artifact.
    type Token;

    /// Build the attestation token for this verified artifact.
    fn to_attestation_result(&self) -> Result<Self::Token, AttestableError>;
}
