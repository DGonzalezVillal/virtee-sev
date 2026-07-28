// SPDX-License-Identifier: Apache-2.0

//! SNP host ioctl argument layouts.

use std::{
    convert::TryFrom,
    ops::{Deref, DerefMut},
};

use crate::{error::HashstickError, types::snp::MaskId};

/// Expected length for the VLEK hashstick ioctl buffer.
pub const HASHSTICK_BUFFER_LEN: usize = 432;

/// SNP_COMMIT structure
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[repr(C, packed)]
pub struct SnpCommit {
    pub buffer: u32,
}

/// Sets the system wide configuration values for SNP.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C, packed)]
pub struct SnpSetConfig {
    pub reported_tcb: [u8; 8],
    pub mask_id: MaskId,
    reserved: [u8; 52],
}

impl Default for SnpSetConfig {
    fn default() -> Self {
        Self {
            reported_tcb: Default::default(),
            mask_id: Default::default(),
            reserved: [0; 52],
        }
    }
}

impl SnpSetConfig {
    /// Creates an ioctl payload from reported TCB bytes and a mask ID.
    pub fn new(reported_tcb: [u8; 8], mask_id: MaskId) -> Self {
        Self {
            reported_tcb,
            mask_id,
            reserved: [0; 52],
        }
    }
}

/// Wrapped VLEK hashstick bytes passed to SNP_VLEK_LOAD.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C, packed)]
pub struct WrappedVlekHashstick {
    pub data: [u8; HASHSTICK_BUFFER_LEN],
}

impl TryFrom<&[u8]> for WrappedVlekHashstick {
    type Error = HashstickError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() != HASHSTICK_BUFFER_LEN {
            return Err(HashstickError::InvalidLength);
        }

        if value == [0u8; HASHSTICK_BUFFER_LEN] {
            return Err(HashstickError::EmptyHashstickBuffer);
        }

        if value[0x0C..0x10] != [0u8; 4] {
            return Err(HashstickError::InvalidReservedField);
        }

        if value[0x198..0x1A0] != [0u8; 8] {
            return Err(HashstickError::InvalidReservedField);
        }

        let mut data = [0u8; HASHSTICK_BUFFER_LEN];
        data.copy_from_slice(value);

        Ok(Self { data })
    }
}

/// Structure used to load a VLEK hashstick into the AMD Secure Processor.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C, packed)]
pub struct SnpVlekLoad {
    pub len: u32,
    pub vlek_wrapped_version: u8,
    _reserved: [u8; 3],
    pub vlek_wrapped_address: u64,
}

impl SnpVlekLoad {
    pub fn new(hashstick: &WrappedVlekHashstick) -> Self {
        hashstick.into()
    }
}

impl From<&WrappedVlekHashstick> for SnpVlekLoad {
    fn from(value: &WrappedVlekHashstick) -> Self {
        Self {
            len: std::mem::size_of::<SnpVlekLoad>() as u32,
            vlek_wrapped_version: 0u8,
            _reserved: Default::default(),
            vlek_wrapped_address: value as *const WrappedVlekHashstick as u64,
        }
    }
}

/// Kernel SNP platform status ioctl buffer.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
#[repr(C, packed)]
pub struct SnpPlatformStatus {
    pub buffer: [u8; 32],
}

impl Deref for SnpPlatformStatus {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl DerefMut for SnpPlatformStatus {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buffer
    }
}

impl AsRef<[u8]> for SnpPlatformStatus {
    fn as_ref(&self) -> &[u8] {
        &self.buffer
    }
}

impl AsMut<[u8]> for SnpPlatformStatus {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snp_set_config_default() {
        let expected = SnpSetConfig {
            reported_tcb: Default::default(),
            mask_id: Default::default(),
            reserved: [0; 52],
        };
        assert_eq!(expected, SnpSetConfig::default());
    }

    #[cfg(target_os = "linux")]
    mod hashstick {
        use super::*;

        fn valid_hashstick_bytes() -> [u8; HASHSTICK_BUFFER_LEN] {
            let mut bytes = [1u8; HASHSTICK_BUFFER_LEN];
            bytes[0x0C..0x10].copy_from_slice(&[0u8; 4]);
            bytes[0x198..0x1A0].copy_from_slice(&[0u8; 8]);
            bytes
        }

        #[test]
        fn bytes_to_wrapped_hashstick() {
            let bytes = valid_hashstick_bytes();
            let expected = WrappedVlekHashstick { data: bytes };
            let actual = WrappedVlekHashstick::try_from(bytes.as_slice()).unwrap();
            assert_eq!(actual, expected);
        }

        #[test]
        fn wrapped_hashstick_into_snp_vlek_load() {
            let test_hashstick =
                WrappedVlekHashstick::try_from(valid_hashstick_bytes().as_slice()).unwrap();
            let actual: SnpVlekLoad = (&test_hashstick).into();
            assert_eq!(actual.vlek_wrapped_version, 0);
        }
    }
}
