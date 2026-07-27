// SPDX-License-Identifier: Apache-2.0

//! SEV-SNP platform management.

pub use crate::types::snp::platform::*;

#[cfg(target_os = "linux")]
use super::Firmware;

#[cfg(target_os = "linux")]
use crate::error::*;

#[cfg(target_os = "linux")]
use crate::firmware::host::{
    ioctl::*,
    types::{SnpCommit, SnpPlatformStatus as FFISnpPlatformStatus, SnpSetConfig},
};

#[cfg(target_os = "linux")]
use crate::parser::ByteParser;

#[cfg(target_os = "linux")]
use crate::types::primitives::Generation;

#[cfg(target_os = "linux")]
use std::convert::TryInto;

#[cfg(target_os = "linux")]
impl Firmware {
    /// Query the SNP platform status.
    ///
    /// `generation` selects the TCB layout used to decode platform and reported
    /// TCB versions in the response.
    pub fn snp_platform_status(
        &mut self,
        generation: Generation,
    ) -> Result<SnpPlatformStatus, UserApiError> {
        let mut platform_status: FFISnpPlatformStatus = FFISnpPlatformStatus::default();

        let mut cmd_buf = Command::from_mut(&mut platform_status);

        SNP_PLATFORM_STATUS
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(SnpPlatformStatus::from_bytes_with(
            &platform_status.buffer,
            generation,
        )?)
    }

    /// The firmware will perform the following actions:
    /// - Set the CommittedTCB to the CurrentTCB of the current firmware.
    /// - Set the CommittedVersion to the FirmwareVersion of the current firmware.
    /// - Sets the ReportedTCB to the CurrentTCB.
    /// - Deletes the VLEK hashstick if the ReportedTCB changed.
    pub fn snp_commit(&mut self) -> Result<(), UserApiError> {
        let mut buf: SnpCommit = Default::default();
        let mut cmd_buf = Command::from_mut(&mut buf);

        SNP_COMMIT
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(())
    }

    /// Set the SNP Configuration.
    pub fn snp_set_config(
        &mut self,
        new_config: Config,
        generation: Generation,
    ) -> Result<(), UserApiError> {
        let mut binding: SnpSetConfig = (new_config, generation).try_into()?;

        let mut cmd_buf = Command::from_mut(&mut binding);

        SNP_SET_CONFIG
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(())
    }

    /// Insert a Version Loaded Endorsement Key Hashstick into the AMD Secure Processor.
    pub fn snp_vlek_load(
        &mut self,
        hashstick: WrappedVlekHashstick,
        generation: Generation,
    ) -> Result<(), UserApiError> {
        use std::convert::TryFrom;

        use crate::firmware::host as FFI;
        use FFI::types::{SnpVlekLoad, WrappedVlekHashstick as FFIWrappedVlekHashstick};

        let buffer = hashstick.to_bytes_with(generation)?;

        let parsed_bytes: FFIWrappedVlekHashstick =
            FFIWrappedVlekHashstick::try_from(buffer.as_slice())?;

        let mut vlek_load: SnpVlekLoad = SnpVlekLoad::new(&parsed_bytes);
        let mut cmd_buf = Command::from_mut(&mut vlek_load);

        SNP_VLEK_LOAD
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(())
    }
}
