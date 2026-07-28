// SPDX-License-Identifier: Apache-2.0

//! SNP certificate table types and kernel wire conversion.

#[cfg(target_os = "linux")]
use crate::error::CertError;
use crate::{
    parser::{ByteParser, Decoder, Encoder},
    types::snp::CertType,
    util::parser_helper::{ReadExt, WriteExt},
};
use std::{
    convert::TryInto,
    io::{Read, Write},
};

#[cfg(target_os = "linux")]
use uuid::Uuid;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Raw certificate bytes (by pointer or Vec<u8>).
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RawData {
    /// A mutable pointer to an unsigned byte.
    Pointer(*mut u8),
    /// A vector of bytes.
    Vector(Vec<u8>),
}

impl From<*mut u8> for RawData {
    fn from(value: *mut u8) -> Self {
        Self::Pointer(value)
    }
}

impl<const SIZE: usize> From<[u8; SIZE]> for RawData {
    fn from(value: [u8; SIZE]) -> Self {
        Self::Vector(value.into())
    }
}

impl From<&mut [u8]> for RawData {
    fn from(value: &mut [u8]) -> Self {
        Self::Vector(value.into())
    }
}

impl From<Vec<u8>> for RawData {
    fn from(value: Vec<u8>) -> Self {
        Self::Vector(value)
    }
}

impl From<&Vec<u8>> for RawData {
    fn from(value: &Vec<u8>) -> Self {
        Self::Vector(value.to_vec())
    }
}

impl From<&mut Vec<u8>> for RawData {
    fn from(value: &mut Vec<u8>) -> Self {
        Self::Vector(value.to_vec())
    }
}

/// Linux kernel `cert_table_entry` layout from `sev-guest` UAPI headers.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(C)]
pub struct KernelCertTableEntry {
    guid: [u8; 16],
    offset: u32,
    length: u32,
}

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
/// An entry with information regarding a specific certificate.
pub struct CertTableEntry {
    /// Certificate type GUID.
    pub cert_type: CertType,
    /// The raw data of the certificate.
    pub data: Vec<u8>,
}

impl Encoder<()> for CertTableEntry {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.cert_type.clone(), ())?;
        writer.write_bytes(self.data.clone(), ())?;
        Ok(())
    }
}

impl Decoder<()> for CertTableEntry {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let cert_type = reader.read_bytes()?;
        let data = reader.read_bytes()?;
        Ok(Self { cert_type, data })
    }
}

impl ByteParser<()> for CertTableEntry {
    type Bytes = Vec<u8>;

    fn from_bytes(bytes: &[u8]) -> std::io::Result<Self> {
        let mut rdr: &[u8] = bytes;
        Self::decode(&mut rdr, ())
    }

    fn to_bytes(&self) -> std::io::Result<Self::Bytes> {
        let mut out = Vec::new();
        self.encode(&mut out, ())?;
        Ok(out)
    }
}

impl CertTableEntry {
    /// Returns the certificate type GUID as a string.
    pub fn guid_string(&self) -> String {
        self.cert_type.to_string()
    }

    /// Returns the raw certificate bytes.
    pub fn data(&self) -> &[u8] {
        self.data.as_slice()
    }

    /// Creates an entry from a UUID and certificate bytes.
    pub fn from_guid(guid: &uuid::Uuid, data: Vec<u8>) -> Result<Self, uuid::Error> {
        Ok(Self {
            cert_type: guid.try_into()?,
            data,
        })
    }

    /// Creates an entry from a certificate type and raw bytes.
    pub fn new(cert_type: CertType, data: Vec<u8>) -> Self {
        Self { cert_type, data }
    }

    /// Serializes a certificate table to the kernel wire format.
    #[cfg(target_os = "linux")]
    pub fn cert_table_to_vec_bytes(table: &[Self]) -> Result<Vec<u8>, CertError> {
        KernelCertTableEntry::uapi_to_vec_bytes(table)
    }

    /// Parses a kernel certificate-table buffer into entries.
    #[cfg(target_os = "linux")]
    pub fn vec_bytes_to_cert_table(bytes: &mut [u8]) -> Result<Vec<Self>, CertError> {
        let cert_bytes_ptr: *mut KernelCertTableEntry =
            bytes.as_mut_ptr() as *mut KernelCertTableEntry;

        unsafe { KernelCertTableEntry::parse_table(cert_bytes_ptr) }
            .map_err(|_| CertError::InvalidGUID)
    }
}

impl Ord for CertTableEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.cert_type.cmp(&other.cert_type)
    }
}

impl PartialOrd for CertTableEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl KernelCertTableEntry {
    #[cfg(target_os = "linux")]
    pub fn uapi_to_vec_bytes(table: &[CertTableEntry]) -> Result<Vec<u8>, CertError> {
        let mut bytes: Vec<u8> = vec![];
        let mut offset: u32 = (std::mem::size_of::<KernelCertTableEntry>() * (table.len() + 1)) as u32;
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

    #[cfg(target_os = "linux")]
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
    use uuid::Uuid;

    mod raw_data {
        use super::RawData;

        #[test]
        fn from_array() {
            let expected = RawData::Vector(vec![1; 72]);
            let actual: RawData = [1; 72].into();
            assert_eq!(expected, actual);
        }
    }

    #[cfg(target_os = "linux")]
    mod kernel_cert_table_entry {
        use super::*;

        fn build_vec_uapi_cert_table() -> Vec<CertTableEntry> {
            vec![
                CertTableEntry::new(CertType::ARK, vec![1; 25]),
                CertTableEntry::new(CertType::ASK, vec![2; 25]),
                CertTableEntry::new(CertType::VCEK, vec![5; 15]),
                CertTableEntry::new(
                    CertType::OTHER(
                        Uuid::parse_str("fbb6ed74-e73e-44ab-8893-4252792d737a").unwrap(),
                    ),
                    vec![7; 6],
                ),
            ]
        }

        #[test]
        fn uapi_to_vec_bytes() {
            let data = build_vec_uapi_cert_table();
            let actual = KernelCertTableEntry::uapi_to_vec_bytes(&data).unwrap();
            assert!(!actual.is_empty());
        }

        #[test]
        fn roundtrip() {
            let entries = vec![
                CertTableEntry::new(CertType::ARK, vec![1, 2, 3]),
                CertTableEntry::new(CertType::ASK, vec![4, 5, 6]),
            ];

            let mut bytes = CertTableEntry::cert_table_to_vec_bytes(&entries).unwrap();
            let converted = CertTableEntry::vec_bytes_to_cert_table(&mut bytes).unwrap();

            assert_eq!(entries.len(), converted.len());
            assert_eq!(entries[0].cert_type, converted[0].cert_type);
            assert_eq!(entries[1].cert_type, converted[1].cert_type);
        }
    }
}
