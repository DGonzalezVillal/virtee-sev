// SPDX-License-Identifier: Apache-2.0

use crate::attestation::endorser::snp::Certificate;
use crate::attestation::verifier::Verifiable;

use openssl::pkey::{PKey, Public};
use openssl::x509::X509;

use std::io::{Error, ErrorKind, Result};

/// Verify if the public key of one Certificate signs another Certificate.
impl Verifiable for (&Certificate, &Certificate) {
    type Output = ();

    fn verify(self) -> Result<Self::Output> {
        let signer: X509 = self.0.into();
        let signee: X509 = self.1.into();

        let key: PKey<Public> = signer.public_key()?;
        let signed = signee.verify(&key)?;

        match signed {
            true => Ok(()),
            false => Err(Error::new(
                ErrorKind::Other,
                "Signer certificate does not sign signee certificate",
            )),
        }
    }
}
