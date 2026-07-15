// SPDX-License-Identifier: Apache-2.0

use crate::attestation::endorser::snp::{Certificate, Chain};
use crate::attestation::evidence::snp::{Report, ReportBody};
use crate::attestation::verifier::Verifiable;

impl Verifiable for (&Certificate, &Report<'_>) {
    type Output = ();

    fn verify(self) -> Result<Self::Output, std::io::Error> {
        let (vek, report) = self;

        let algo = report.algorithm;

        (algo, report.body, report.signature, vek).verify()
    }
}

impl Verifiable for (&Chain, &Report<'_>) {
    type Output = ();

    fn verify(self) -> Result<(), std::io::Error> {
        let (chain, report) = self;
        let vek = chain.verify()?;
        (vek, report).verify()
    }
}

impl<'a> std::convert::TryFrom<(&Report<'a>, &Certificate)> for ReportBody<'a> {
    type Error = std::io::Error;

    /// Verifies `report` with `vek` and returns a parsed [`ReportBody`].
    fn try_from((report, vek): (&Report<'a>, &Certificate)) -> Result<Self, Self::Error> {
        (vek, report).verify()?;
        ReportBody::from_bytes(report.body)
    }
}

impl<'a> std::convert::TryFrom<(&Report<'a>, &Chain)> for ReportBody<'a> {
    type Error = std::io::Error;

    /// Verifies `report` with `chain` and returns a parsed [`ReportBody`].
    ///
    /// This is the **recommended** way to obtain a `ReportBody`, because it
    /// enforces signature verification before parsing typed fields.
    fn try_from((report, chain): (&Report<'a>, &Chain)) -> Result<Self, Self::Error> {
        (chain, report).verify()?;
        ReportBody::from_bytes(report.body)
    }
}
