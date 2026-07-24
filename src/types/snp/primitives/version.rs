// SPDX-License-Identifier: Apache-2.0

use crate::{
    parser::{ByteParser, Decoder, Encoder},
    util::parser_helper::{ReadExt, WriteExt},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
/// A semver formatted version.
pub struct Version {
    /// Major Version
    pub major: u8,
    /// Minor Version
    pub minor: u8,
    /// Build Version
    pub build: u8,
}

impl Version {
    /// Create a new version.
    pub fn new(major: u8, minor: u8, build: u8) -> Self {
        Self {
            major,
            minor,
            build,
        }
    }
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.build)
    }
}

impl Encoder<()> for Version {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        writer.write_bytes(self.build, ())?;
        writer.write_bytes(self.minor, ())?;
        writer.write_bytes(self.major, ())?;
        Ok(())
    }
}

impl Decoder<()> for Version {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let build = reader.read_bytes()?;
        let minor = reader.read_bytes()?;
        let major = reader.read_bytes()?;
        Ok(Self {
            major,
            minor,
            build,
        })
    }
}

impl ByteParser<()> for Version {
    type Bytes = [u8; 3];
    const EXPECTED_LEN: Option<usize> = Some(3);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::ByteParser;

    #[test]
    fn test_version_display() {
        let version = Version::new(3, 2, 1);
        assert_eq!(version.to_string(), "3.2.1");

        let max_version = Version::new(255, 255, 255);
        assert_eq!(max_version.to_string(), "255.255.255");

        let min_version = Version::new(0, 0, 0);
        assert_eq!(min_version.to_string(), "0.0.0");
    }

    #[test]
    fn test_version_byte_parser() {
        // Test from_bytes
        let bytes = [1, 2, 3];
        let version = Version::from_bytes(&bytes).unwrap();
        assert_eq!(version, Version::new(3, 2, 1));

        // Test to_bytes
        let version = Version::new(4, 5, 6);
        let bytes = version.to_bytes().unwrap();
        assert_eq!(bytes, [6, 5, 4]);

        // Test roundtrip
        let original = Version::new(7, 8, 9);
        let bytes = original.to_bytes().unwrap();
        let roundtrip = Version::from_bytes(&bytes).unwrap();
        assert_eq!(original, roundtrip);

        // Test default
        assert_eq!(<Version as Default>::default(), Version::new(0, 0, 0));
    }
    #[test]
    fn test_version_edge_cases() {
        // Test max values
        let version = Version::new(255, 255, 255);
        let bytes = version.to_bytes().unwrap();
        assert_eq!(bytes, [255, 255, 255]);

        // Test mixed values
        let version = Version::new(0, 255, 0);
        let bytes = version.to_bytes().unwrap();
        assert_eq!(bytes, [0, 255, 0]);
    }

    #[test]
    fn test_version_ordering() {
        let v1 = Version::new(1, 0, 0);
        let v2 = Version::new(1, 0, 1);
        let v3 = Version::new(1, 1, 0);

        assert!(v1 < v2);
        assert!(v2 < v3);
        assert!(v1 < v3);

        // Test equality
        assert_eq!(Version::new(1, 2, 3), Version::new(1, 2, 3));
        assert_ne!(Version::new(1, 2, 3), Version::new(1, 2, 4));
    }

    #[test]
    fn test_version_copy() {
        let original = Version::new(1, 2, 3);
        let cloned = original;

        assert_eq!(original, cloned);
        assert_eq!(original.to_bytes().unwrap(), cloned.to_bytes().unwrap());
    }
}
