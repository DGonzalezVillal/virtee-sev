// SPDX-License-Identifier: Apache-2.0

use crate::attestation::endorser::snp::{ca, Certificate, Chain};
use crate::attestation::verifier::Verifiable;

use std::io::Result;

impl<'a> Verifiable for &'a ca::Chain {
    type Output = &'a Certificate;

    fn verify(self) -> Result<Self::Output> {
        // Verify that ARK is self-signed.
        (&self.ark, &self.ark).verify()?;

        // Verify that ARK signs ASK.
        (&self.ark, &self.ask).verify()?;

        Ok(&self.ask)
    }
}

impl<'a> Verifiable for &'a Chain {
    type Output = &'a Certificate;

    fn verify(self) -> Result<Self::Output> {
        // Verify that ARK is self-signed and ARK signs ASK.
        let ask = self.ca.verify()?;

        // Verify that ASK signs VCEK.
        (ask, &self.vek).verify()?;

        Ok(&self.vek)
    }
}
