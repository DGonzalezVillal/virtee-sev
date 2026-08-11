// SPDX-License-Identifier: Apache-2.0

//! Linux `sev-guest` certificate-table wire format.
//!
//! When a guest requests an extended attestation report, the hypervisor may
//! populate a buffer with a GUID-indexed certificate table (ARK, ASK, VCEK/VLEK).
//! This module serializes and parses that kernel UAPI layout.
//!
//! Higher-level certificate entries are represented by
//! [`CertTableEntry`](crate::types::snp::CertTableEntry). Endorsement chain
//! construction from parsed entries lives in
//! [`crate::attestation::endorser::snp`].

use crate::error::CertError;
use crate::types::snp::CertTableEntry;
use uuid::Uuid;

/// One entry in the Linux kernel `cert_table_entry` chain.
///
/// Each entry is a 16-byte GUID, a byte offset from the table start, and a
/// length. A zero GUID terminates the chain.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(C)]
pub struct KernelCertTableEntry {
    guid: [u8; 16],
    offset: u32,
    length: u32,
}

impl KernelCertTableEntry {
    /// Serialize [`CertTableEntry`] values into the kernel certificate-table layout.
    ///
    /// Writes the header chain (including a zero-GUID terminator) followed by
    /// concatenated certificate DER bytes. Offsets are in native endianness to
    /// match the kernel UAPI.
    pub fn cert_table_to_vec_bytes(table: &[CertTableEntry]) -> Result<Vec<u8>, CertError> {
        let mut bytes: Vec<u8> = vec![];
        let mut offset: u32 =
            (std::mem::size_of::<KernelCertTableEntry>() * (table.len() + 1)) as u32;
        let mut raw_certificates: Vec<u8> = vec![];

        for entry in table.iter() {
            let guid: Uuid = match Uuid::parse_str(&entry.guid_string()) {
                Ok(uuid) => uuid,
                Err(_) => return Err(CertError::InvalidGUID),
            };

            bytes.extend_from_slice(guid.as_bytes());
            bytes.extend_from_slice(&offset.to_ne_bytes());
            bytes.extend_from_slice(&(entry.data().len() as u32).to_ne_bytes());
            raw_certificates.extend_from_slice(entry.data());
            offset += entry.data().len() as u32;
        }

        bytes.append(&mut vec![0u8; 24]);
        bytes.append(&mut raw_certificates);

        Ok(bytes)
    }

    /// Parse a kernel certificate-table buffer into [`CertTableEntry`] values.
    pub fn vec_bytes_to_cert_table(bytes: &mut [u8]) -> Result<Vec<CertTableEntry>, CertError> {
        let cert_bytes_ptr: *mut KernelCertTableEntry =
            bytes.as_mut_ptr() as *mut KernelCertTableEntry;

        unsafe { Self::parse_table(cert_bytes_ptr) }.map_err(|_| CertError::InvalidGUID)
    }

    /// Walk a null-terminated kernel certificate-table pointer chain.
    ///
    /// # Safety
    ///
    /// `data` must point to a valid, null-terminated kernel cert table in guest
    /// memory with correctly sized entries and certificate payloads.
    pub unsafe fn parse_table(
        mut data: *mut KernelCertTableEntry,
    ) -> Result<Vec<CertTableEntry>, uuid::Error> {
        const ZERO_GUID: Uuid = Uuid::from_bytes([0x0; 16]);

        let table_ptr: *mut u8 = data as *mut u8;
        let mut retval: Vec<CertTableEntry> = vec![];

        loop {
            let entry = *data;
            let guid: Uuid = Uuid::from_slice(entry.guid.as_slice())?;

            if guid == ZERO_GUID {
                break;
            }

            let mut cert_bytes: Vec<u8> = vec![];
            let mut cert_addr: *mut u8 = table_ptr.wrapping_add(entry.offset as usize);
            let cert_end: *mut u8 = cert_addr.wrapping_add(entry.length as usize);

            while cert_addr != cert_end {
                cert_bytes.push(*cert_addr);
                cert_addr = cert_addr.wrapping_add(1);
            }

            retval.push(CertTableEntry::from_guid(&guid, cert_bytes)?);
            data = data.offset(1);
        }

        Ok(retval)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::snp::CertType;

    fn build_vec_uapi_cert_table() -> Vec<CertTableEntry> {
        vec![
            CertTableEntry::new(CertType::ARK, vec![1; 25]),
            CertTableEntry::new(CertType::ASK, vec![2; 25]),
            CertTableEntry::new(CertType::VCEK, vec![5; 15]),
            CertTableEntry::new(
                CertType::OTHER(Uuid::parse_str("fbb6ed74-e73e-44ab-8893-4252792d737a").unwrap()),
                vec![7; 6],
            ),
        ]
    }

    #[test]
    fn cert_table_to_vec_bytes() {
        let data = build_vec_uapi_cert_table();
        let actual = KernelCertTableEntry::cert_table_to_vec_bytes(&data).unwrap();
        assert!(!actual.is_empty());
    }

    #[test]
    fn roundtrip() {
        let entries = vec![
            CertTableEntry::new(CertType::ARK, vec![1, 2, 3]),
            CertTableEntry::new(CertType::ASK, vec![4, 5, 6]),
        ];

        let mut bytes = KernelCertTableEntry::cert_table_to_vec_bytes(&entries).unwrap();
        let converted = KernelCertTableEntry::vec_bytes_to_cert_table(&mut bytes).unwrap();

        assert_eq!(entries.len(), converted.len());
        assert_eq!(entries[0].cert_type, converted[0].cert_type);
        assert_eq!(entries[1].cert_type, converted[1].cert_type);
    }
}
