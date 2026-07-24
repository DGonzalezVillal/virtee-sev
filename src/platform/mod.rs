// SPDX-License-Identifier: Apache-2.0

//! Host platform management for AMD SEV and SEV-SNP.
//!
//! Opens `/dev/sev` and exposes platform status, configuration, and certificate
//! provisioning. Low-level ioctl layouts live in [`crate::firmware`].
//!
//! Generation-specific APIs live in [`sev`](self::sev) and [`snp`](self::snp).
//! ABI wire types live under [`crate::types`].

#[cfg(feature = "sev")]
pub mod sev;

#[cfg(feature = "snp")]
pub mod snp;

#[cfg(target_os = "linux")]
use crate::firmware::host::{ioctl::*, types::GetId};

#[cfg(all(target_os = "linux", any(feature = "sev", feature = "snp")))]
use crate::firmware::host::types::PlatformStatus;

#[cfg(any(feature = "sev", feature = "snp"))]
pub use crate::types::sev::{Build, State, Status, Version};

#[cfg(target_os = "linux")]
use crate::error::*;

#[cfg(target_os = "linux")]
use std::{
    fs::{File, OpenOptions},
    os::unix::io::{AsRawFd, RawFd},
};

/// The CPU-unique identifier for the platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identifier(pub Vec<u8>);

impl From<Identifier> for Vec<u8> {
    fn from(id: Identifier) -> Vec<u8> {
        id.0
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for b in self.0.iter() {
            write!(f, "{b:02X}")?;
        }

        Ok(())
    }
}

/// A handle to the SEV platform device (`/dev/sev`).
#[cfg(target_os = "linux")]
pub struct Firmware(pub(crate) File);

#[cfg(target_os = "linux")]
impl Firmware {
    /// Create a handle to the SEV platform.
    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new().read(true).write(true).open("/dev/sev")?,
        ))
    }

    /// Get the unique CPU identifier.
    ///
    /// This is especially helpful for sending AMD an HTTP request to fetch
    /// the signed CEK certificate.
    #[cfg(any(feature = "sev", feature = "snp"))]
    pub fn get_identifier(&mut self) -> Result<Identifier, UserApiError> {
        let mut bytes = [0u8; 64];
        let mut id = GetId::new(&mut bytes);
        let mut cmd_buf = Command::from_mut(&mut id);

        GET_ID
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;
        Ok(Identifier(id.as_slice().to_vec()))
    }

    /// Query the legacy SEV platform status.
    #[cfg(any(feature = "sev", feature = "snp"))]
    pub fn platform_status(&mut self) -> Result<Status, UserApiError> {
        let mut info: PlatformStatus = Default::default();
        let mut cmd_buf = Command::from_mut(&mut info);
        PLATFORM_STATUS
            .ioctl(&mut self.0, &mut cmd_buf)
            .map_err(|_| cmd_buf.encapsulate())?;

        Ok(Status {
            build: Build {
                version: Version {
                    major: info.version.major,
                    minor: info.version.minor,
                },
                build: info.build,
            },
            guests: info.guest_count,
            flags: info.flags,
            state: match info.state {
                0 => State::Uninitialized,
                1 => State::Initialized,
                2 => State::Working,
                _ => return Err(SevError::InvalidPlatformState)?,
            },
        })
    }
}

#[cfg(target_os = "linux")]
impl AsRawFd for Firmware {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
