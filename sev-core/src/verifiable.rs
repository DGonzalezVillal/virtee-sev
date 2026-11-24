// SPDX-License-Identifier: Apache-2.0

//! Checking an artifact against a root.
//!
//! The artifact implements [`Verifiable`]. [`Verifiable::verify`] calls the
//! root's [`Authenticate::authenticate`](crate::Authenticate::authenticate)
//! and returns the [`Output`](Verifiable::Output) chosen by that implementation.
//! A rejected signature is reported as [`VerifyError`].
//!
//! The crate that owns the artifact implements this trait. Artifacts that
//! implement [`Verifiable`] stay out of `sev-types`, because another crate
//! cannot implement a `sev-core` trait for a `sev-types` struct.
//!
//! Implement [`Verifiable`] once, generically over the root, rather than once
//! per root:
//!
//! ```text
//! impl<R: Authenticate> Verifiable<R> for Report { ... }
//! ```
//!
//! That single impl covers every root, including a VEK. A second impl for a
//! specific root in another crate is rejected by the orphan rule, and one in
//! the same crate conflicts with the blanket. Callers pick the root when they
//! call `verify`.

use crate::{Authenticate, AuthenticateError};

/// Why [`Verifiable::verify`] rejected an artifact.
///
/// Every [`Verifiable`] implementation reports this type, so callers can match
/// on it without knowing which artifact or root was involved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    /// The root did not accept the artifact's signature.
    #[error(transparent)]
    Signature(#[from] AuthenticateError),
}

/// An artifact whose signature a root can authenticate.
///
/// `Root` implements [`Authenticate`](crate::Authenticate). The implementation
/// calls `root.authenticate` and chooses [`Output`](Verifiable::Output).
///
/// # Examples
///
/// ```
/// use sev_core::{Authenticate, AuthenticateError, Verifiable, VerifyError};
///
/// struct Key(u8);
///
/// #[derive(Debug)]
/// struct Ask {
///     signature: [u8; 1],
/// }
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
/// impl Verifiable<Key> for Ask {
///     type Output = Self;
///
///     fn verify(self, root: &Key) -> Result<Self::Output, VerifyError> {
///         root.authenticate(&self.signature)?;
///         Ok(self)
///     }
/// }
///
/// let ask = Ask { signature: [7] }.verify(&Key(7)).unwrap();
/// assert_eq!(ask.signature, [7]);
/// assert_eq!(
///     Ask { signature: [1] }.verify(&Key(7)).unwrap_err(),
///     VerifyError::Signature(AuthenticateError::BadSignature),
/// );
/// ```
pub trait Verifiable<Root: Authenticate>: Sized {
    /// Value produced when the root accepts this artifact.
    type Output;

    /// Authenticate `self` with `root` and return [`Output`](Verifiable::Output).
    ///
    /// A rejected signature returns [`VerifyError::Signature`].
    fn verify(self, root: &Root) -> Result<Self::Output, VerifyError>;
}
