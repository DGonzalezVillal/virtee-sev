// SPDX-License-Identifier: Apache-2.0

//! SNP certificate table entry types.

use crate::{
    parser::{ByteParser, Decoder, Encoder},
    types::snp::CertType,
    util::parser_helper::{ReadExt, WriteExt},
};
use std::{
    convert::TryInto,
    io::{Read, Write},
};

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

#[cfg(test)]
mod tests {
    mod raw_data {
        use super::super::RawData;

        #[test]
        fn from_array() {
            let expected = RawData::Vector(vec![1; 72]);
            let actual: RawData = [1; 72].into();
            assert_eq!(expected, actual);
        }
    }
}
