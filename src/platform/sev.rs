// SPDX-License-Identifier: Apache-2.0

//! First-generation SEV platform management.

pub use crate::types::sev::{Build, PlatformStatusFlags, State, Status, Version};

#[cfg(target_os = "linux")]
use super::Firmware;

#[cfg(target_os = "linux")]
use crate::attestation::endorser::sev::sev::{Certificate, Chain};

#[cfg(target_os = "linux")]
use crate::error::*;

#[cfg(target_os = "linux")]
use crate::firmware::host::{
    ioctl::*,
    types::{PdhCertExport, PdhGen, PekCertImport, PekCsr, PekGen, PlatformReset},
};

#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;

#[cfg(target_os = "linux")]
impl Firmware {
    /// Reset the platform persistent state.
    pub fn platform_reset(&mut self) -> Result<(), UserApiError> {
        let mut cmd_buf = Command::from(&PlatformReset);
        PLATFORM_RESET
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;
        Ok(())
    }

    /// Generate a new Platform Encryption Key (PEK).
    pub fn pek_generate(&mut self) -> Result<(), UserApiError> {
        let mut cmd_buf = Command::from(&PekGen);
        PEK_GEN
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;
        Ok(())
    }

    /// Request a signature for the PEK.
    pub fn pek_csr(&mut self) -> Result<Certificate, UserApiError> {
        #[allow(clippy::uninit_assumed_init)]
        let mut pek: Certificate = unsafe { MaybeUninit::uninit().assume_init() };
        let mut csr = PekCsr::new(&mut pek);
        let mut cmd_buf = Command::from_mut(&mut csr);
        PEK_CSR
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(pek)
    }

    /// Generate a new Platform Diffie-Hellman (PDH) key pair.
    pub fn pdh_generate(&mut self) -> Result<(), UserApiError> {
        let mut cmd_buf = Command::from(&PdhGen);
        PDH_GEN
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;
        Ok(())
    }

    /// Export the SEV certificate chain.
    pub fn pdh_cert_export(&mut self) -> Result<Chain, UserApiError> {
        #[allow(clippy::uninit_assumed_init)]
        let mut chain: [Certificate; 3] = unsafe { MaybeUninit::uninit().assume_init() };
        #[allow(clippy::uninit_assumed_init)]
        let mut pdh: Certificate = unsafe { MaybeUninit::uninit().assume_init() };
        let mut pdh_cert_export = PdhCertExport::new(&mut pdh, &mut chain);
        let mut cmd_buf = Command::from_mut(&mut pdh_cert_export);

        PDH_CERT_EXPORT
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(Chain {
            pdh,
            pek: chain[0],
            oca: chain[1],
            cek: chain[2],
        })
    }

    /// Take ownership of the SEV platform.
    pub fn pek_cert_import(
        &mut self,
        pek: &Certificate,
        oca: &Certificate,
    ) -> Result<(), UserApiError> {
        let pek_cert_import = PekCertImport::new(pek, oca);
        let mut cmd_buf = Command::from(&pek_cert_import);

        PEK_CERT_IMPORT
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;
        Ok(())
    }
}
