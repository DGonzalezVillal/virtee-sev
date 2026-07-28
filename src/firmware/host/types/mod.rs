// SPDX-License-Identifier: Apache-2.0

//! Host `/dev/sev` ioctl argument layouts.

#[cfg(all(feature = "sev", feature = "platform"))]
mod sev;

#[cfg(all(feature = "snp", feature = "platform"))]
mod snp;

#[cfg(all(feature = "sev", feature = "platform"))]
pub use self::sev::*;

#[cfg(all(feature = "snp", feature = "platform"))]
pub use self::snp::*;

#[cfg(feature = "platform")]
#[cfg(target_os = "linux")]
use std::marker::PhantomData;

use crate::types::sev::{PlatformStatusFlags, Version};

/// Query SEV platform status.
///
/// (Chapter 5.6; Table 17)
#[cfg(feature = "platform")]
#[derive(Default)]
#[repr(C, packed)]
pub struct PlatformStatus {
    /// The firmware version (major.minor)
    pub version: Version,

    /// The Platform State.
    pub state: u8,

    /// Whether the platform is self-owned and encrypted-state support flags.
    pub flags: PlatformStatusFlags,

    /// The firmware build ID for this API version.
    pub build: u8,

    /// The number of valid guests maintained by the SEV firmware.
    pub guest_count: u32,
}

/// Get the CPU's unique ID that can be used for getting
/// a certificate for the CEK public key.
#[cfg(all(feature = "platform", target_os = "linux"))]
#[repr(C, packed)]
pub struct GetId<'a> {
    id_addr: u64,
    id_len: u32,
    _phantom: PhantomData<&'a ()>,
}

#[cfg(all(feature = "platform", target_os = "linux"))]
impl<'a> GetId<'a> {
    pub fn new(id: &'a mut [u8; 64]) -> Self {
        Self {
            id_addr: id.as_mut_ptr() as _,
            id_len: id.len() as _,
            _phantom: PhantomData,
        }
    }

    /// Meaningful only after the GET_ID2 ioctl; the kernel writes the ID length to `id_len`.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.id_addr as *const u8, self.id_len as _) }
    }
}

/// Reset the platform's persistent state.
///
/// (Chapter 5.5)
#[cfg(all(feature = "sev", feature = "platform", target_os = "linux"))]
pub struct PlatformReset;

#[cfg(all(feature = "platform", target_os = "linux"))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_id_new() {
        let mut id = [0u8; 64];
        let get_id = GetId::new(&mut id);

        assert_eq!(
            unsafe { std::ptr::addr_of!(get_id.id_len).read_unaligned() },
            64
        );
        assert_eq!(get_id.id_addr as *const u8, id.as_ptr());
    }

    #[test]
    fn test_get_id_slice() {
        let mut id = [42u8; 64];
        let get_id = GetId::new(&mut id);
        assert_eq!(get_id.as_slice(), &[42u8; 64]);
    }
}
