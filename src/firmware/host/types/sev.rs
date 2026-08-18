// SPDX-License-Identifier: Apache-2.0

//! Operations for managing the SEV platform.

use crate::firmware::host::State;
pub use crate::firmware::linux::host::types::PlatformStatusFlags;
use crate::parser::{Decoder, Encoder};
use crate::util::{TypeLoad, TypeSave};

use std::{
    fmt::Debug,
    io::{Read, Write},
};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Information about the SEV platform version.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct Version {
    /// The major version number.
    pub major: u8,

    /// The minor version number.
    pub minor: u8,
}

impl std::fmt::Display for Version {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl From<u16> for Version {
    fn from(v: u16) -> Self {
        Self {
            major: ((v & 0xF0) >> 4) as u8,
            minor: (v & 0x0F) as u8,
        }
    }
}

/// A description of the SEV platform's build information.
#[repr(C)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd)]
pub struct Build {
    /// The version information.
    pub version: Version,

    /// The build number.
    pub build: u8,
}

impl std::fmt::Display for Build {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}.{}", self.version, self.build)
    }
}

impl Decoder<()> for Build {
    fn decode(reader: &mut impl Read, _: ()) -> std::io::Result<Self> {
        reader.load()
    }
}

impl Encoder<()> for Build {
    fn encode(&self, writer: &mut impl Write, _: ()) -> std::io::Result<()> {
        writer.save(self)
    }
}

/// Information regarding the SEV platform's current status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The build number.
    pub build: Build,

    /// The platform's current state.
    pub state: State,

    /// Additional platform information is encoded into flags.
    ///
    /// These could describe whether encrypted state functionality
    /// is enabled, or whether the platform is self-owned.
    pub flags: PlatformStatusFlags,

    /// The number of valid guests supervised by this platform.
    pub guests: u32,
}

