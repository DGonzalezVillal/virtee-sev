// SPDX-License-Identifier: Apache-2.0

use std::io::Result;

/// An interface for types that may contain entities such as
/// signatures that must be verified.
pub trait Verifiable {
    /// An output type for successful verification.
    type Output;

    /// Self-verifies signatures.
    fn verify(self) -> Result<Self::Output>;
}
