// SPDX-License-Identifier: Apache-2.0

#[cfg(feature = "sev")]
mod sev;

#[cfg(feature = "snp")]
mod snp;

#[cfg(feature = "sev")]
pub use self::sev::*;

#[cfg(feature = "snp")]
pub use self::snp::*;

#[cfg(any(feature = "sev", feature = "snp"))]
#[cfg(target_os = "linux")]
use std::marker::PhantomData;

#[cfg(any(feature = "sev", feature = "snp"))]
bitflags::bitflags! {
    /// The platform's status flags.
    #[derive(Debug, Default, Clone, PartialEq, Eq, PartialOrd, Ord)]
    pub struct PlatformStatusFlags: u32 {
        /// If set, this platform is owned. Otherwise, it is self-owned.
        const OWNED           = 1 << 0;

        /// If set, encrypted state functionality is present.
        const ENCRYPTED_STATE = 1 << 8;
    }
}

/// Query SEV platform status.
///
/// (Chapter 5.6; Table 17)
#[cfg(any(feature = "sev", feature = "snp"))]
#[derive(Default)]
#[repr(C, packed)]
pub struct PlatformStatus {
    /// The firmware version (major.minor)
    pub version: crate::types::sev::Version,

    /// The Platform State.
    pub state: u8,

    /// Right now the only flag that is communicated in
    /// this single byte is whether the platform is self-
    /// owned or not. If the first bit is set then the
    /// platform is externally owned. If it is cleared, then
    /// the platform is self-owned. Self-owned is the default
    /// state.
    pub flags: PlatformStatusFlags,

    /// The firmware build ID for this API version.
    pub build: u8,

    /// The number of valid guests maintained by the SEV firmware.
    pub guest_count: u32,
}

/// Get the CPU's unique ID that can be used for getting
/// a certificate for the CEK public key.
#[cfg(target_os = "linux")]
#[cfg(any(feature = "sev", feature = "snp"))]
#[repr(C, packed)]
pub struct GetId<'a> {
    id_addr: u64,
    id_len: u32,
    _phantom: PhantomData<&'a ()>,
}

#[cfg(any(feature = "sev", feature = "snp"))]
#[cfg(target_os = "linux")]
impl<'a> GetId<'a> {
    pub fn new(id: &'a mut [u8; 64]) -> Self {
        Self {
            id_addr: id.as_mut_ptr() as _,
            id_len: id.len() as _,
            _phantom: PhantomData,
        }
    }

    /// This method is only meaningful if called *after* the GET_ID2 ioctl is called because the
    /// kernel will write the length of the unique CPU ID to `GetId.id_len`.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.id_addr as *const u8, self.id_len as _) }
    }
}

/// Reset the platform's persistent state.
///
/// (Chapter 5.5)
#[cfg(feature = "sev")]
#[cfg(target_os = "linux")]
pub struct PlatformReset;

#[cfg(target_os = "linux")]
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

    #[test]
    fn test_get_id_phantom() {
        let mut id = [0u8; 64];
        let get_id = GetId::new(&mut id);

        // Verify PhantomData is working as expected
        assert_eq!(std::mem::size_of_val(&get_id._phantom), 0);
    }
}
