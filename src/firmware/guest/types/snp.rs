// SPDX-License-Identifier: Apache-2.0

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
use crate::certs::snp::{Certificate, Chain, Verifiable};

use crate::{
    certs::snp::signature::SignatureAlgorithm,
    parser::{ByteParser, Decoder, Encoder},
    util::{
        hexline::HexLine,
        parser_helper::{validate_reserved, ReadExt, WriteExt},
    },
    Generation,
};

pub use crate::snp::types::{GuestPolicy, KeyInfo, PlatformInfo, TcbVersion, Version};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "serde")]
use serde_big_array::BigArray;

use std::{
    convert::TryFrom,
    fmt::Display,
    io::{Read, Write},
};

use bitfield::bitfield;

/// Structure of required data for fetching the derived key.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DerivedKey {
    /// Selects the root key to derive the key from.
    /// 0: Indicates VCEK.
    /// 1: Indicates VMRK.
    root_key_select: u32,

    /// Reserved, must be zero
    _reserved_0: u32,

    /// What data will be mixed into the derived key.
    pub guest_field_select: GuestFieldSelect,

    /// The VMPL to mix into the derived key. Must be greater than or equal
    /// to the current VMPL.
    pub vmpl: u32,

    /// The guest SVN to mix into the key. Must not exceed the guest SVN
    /// provided at launch in the ID block.
    pub guest_svn: u32,

    /// The TCB version to mix into the derived key. Must not
    /// exceed CommittedTcb.
    pub tcb_version: u64,

    /// The mitigation vector value to mix into the derived key.
    /// Specific bit settings corresponding to mitigations required for Guest operation.
    pub launch_mit_vector: Option<u64>,
}

impl DerivedKey {
    /// Create a new instance for requesting an DerivedKey.
    pub fn new(
        root_key_select: bool,
        guest_field_select: GuestFieldSelect,
        vmpl: u32,
        guest_svn: u32,
        tcb_version: u64,
        launch_mit_vector: Option<u64>,
    ) -> Self {
        Self {
            root_key_select: u32::from(root_key_select),
            _reserved_0: Default::default(),
            guest_field_select,
            vmpl,
            guest_svn,
            tcb_version,
            launch_mit_vector,
        }
    }

    /// Obtain a copy of the root key select value (Private Field)
    pub fn get_root_key_select(&self) -> u32 {
        self.root_key_select
    }
}

bitfield! {
    /// Data which will be mixed into the derived key.
    ///
    /// | Bit(s) | Name | Description |
    /// |--------|------|-------------|
    /// |0|GUEST_POLICY|Indicates that the guest policy will be mixed into the key.|
    /// |1|IMAGE_ID|Indicates that the image ID of the guest will be mixed into the key.|
    /// |2|FAMILY_ID|Indicates the family ID of the guest will be mixed into the key.|
    /// |3|MEASUREMENT|Indicates the measurement of the guest during launch will be mixed into the key.|
    /// |4|GUEST_SVN|Indicates that the guest-provided SVN will be mixed into the key.|
    /// |5|TCB_VERSION|Indicates that the guest-provided TCB_VERSION will be mixed into the key.|
    /// |6|LAUNCH_MIT_VECTOR|Indicates that the guest-provided LAUNCH_MIT_VECTOR will be mixed into the key.|
    /// |63:7|\-|Reserved. Must be zero.|
    #[repr(C)]
    #[derive(Default, Copy, Clone,PartialEq, Eq, PartialOrd, Ord)]
    pub struct GuestFieldSelect(u64);
    impl Debug;
    /// Check/Set guest policy inclusion in derived key.
    pub get_guest_policy, set_guest_policy: 0;
    /// Check/Set image id inclusion in derived key.
    pub get_image_id, set_image_id: 1;
    /// Check/Set family id inclusion in derived key.
    pub get_family_id, set_family_id: 2;
    /// Check/Set measurement inclusion in derived key.
    pub get_measurement, set_measurement: 3;
    /// Check/Set svn inclusion in derived key.
    pub get_svn, set_svn: 4;
    /// Check/Set tcb version inclusion in derived key.
    pub get_tcb_version, set_tcb_version: 5;
     /// Indicates that the guest-provied LAUNCH_MIT_VECTOR will be mixed into the key.
    pub get_launch_mit_vector, set_launch_mit_vector: 6;
}

/// Identifies the firmware-defined format version of an SEV-SNP attestation report.
///
/// `ReportVariant` corresponds to the *report layout version* as emitted by
/// platform firmware. The variant determines:
///
/// - Which fields are present in the report body
/// - How certain fields are interpreted (e.g. TCB layout)
/// - How platform generation is inferred
///
/// This enum is intentionally **narrow and explicit**: only variants currently
/// understood by the library are represented. Any unknown or future report
/// versions will be rejected during decoding.
///
/// ---
///
/// # Version Semantics
///
/// | Variant | Firmware Versions | Notes |
/// |--------:|-------------------|-------|
/// | `V2` | 2 | Pre-CPUID reports. Platform generation is inferred from the CHIP_ID field. |
/// | `V3` | 3, 4 | Introduces CPUID fields used for platform identification. |
/// | `V5` | 5 | Adds mitigation vector fields and additional reserved regions. |
///
/// Firmware version values `3` and `4` are treated equivalently and both map to
/// [`ReportVariant::V3`], as they share an identical report layout.
///
/// ---
///
/// # Security Considerations
///
/// `ReportVariant` only describes the *format* of the report. It does **not**
/// imply that the report is authentic or trustworthy.
///
/// A parsed `ReportVariant` must not be used as a trust signal on its own.
/// Authenticity is only established after successful cryptographic verification
/// of the report signature.
///
/// ---
///
/// # Parsing and Validation
///
/// `ReportVariant` is decoded from the first 4 bytes of the report body and
/// validated during parsing. Unsupported or unknown version values will cause
/// parsing to fail with an error.
///
/// This ensures forward compatibility is explicit and prevents accidental
/// acceptance of report formats the library does not understand.
///
/// ---
///
/// # Correct Usage
///
/// `ReportVariant` is primarily consumed internally during report parsing to
/// drive generation inference and conditional field handling.
///
/// Consumers should not attempt to construct `ReportVariant` values manually
/// from untrusted inputs; instead, rely on decoding via [`ReportBody`] or
/// verified [`Report`] processing.
///
/// ---
///
/// # Example
///
/// ```ignore
/// let variant = ReportVariant::decode(&mut reader, ())?;
///
/// match variant {
///     ReportVariant::V2 => { /* CHIP_ID-based inference */ }
///     ReportVariant::V3 => { /* CPUID-based inference */ }
///     ReportVariant::V5 => { /* mitigation vector fields present */ }
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u32)]
pub enum ReportVariant {
    /// Version 2 of the attestation report format.
    ///
    /// This variant predates CPUID-based platform identification. Platform
    /// generation is inferred heuristically from the CHIP_ID field.
    V2 = 2,

    /// Version 3 (and firmware version 4) of the attestation report format.
    ///
    /// Introduces CPUID family, model, and stepping fields, enabling explicit
    /// platform identification. Firmware versions `3` and `4` share the same
    /// report layout and are represented by this variant.
    V3 = 3,

    /// Version 5 of the attestation report format.
    ///
    /// Extends the V3 layout with mitigation vector fields and additional
    /// reserved regions. Used by newer firmware revisions.
    V5 = 5,
}

impl TryFrom<u32> for ReportVariant {
    type Error = std::io::Error;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        match v {
            2 => Ok(ReportVariant::V2),
            3 | 4 => Ok(ReportVariant::V3),
            5 => Ok(ReportVariant::V5),
            unknown_variant => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported report variant: {}", unknown_variant),
            )),
        }
    }
}

impl Encoder<()> for ReportVariant {
    fn encode(&self, writer: &mut impl Write, _: ()) -> Result<(), std::io::Error> {
        match self {
            ReportVariant::V2 => writer.write_bytes(2u32, ())?,
            ReportVariant::V3 => writer.write_bytes(3u32, ())?,
            ReportVariant::V5 => writer.write_bytes(5u32, ())?,
        };
        Ok(())
    }
}

impl Decoder<()> for ReportVariant {
    fn decode(reader: &mut impl Read, _: ()) -> Result<Self, std::io::Error> {
        let version: u32 = reader.read_bytes()?;
        Self::try_from(version)
    }
}

impl ByteParser<()> for ReportVariant {
    type Bytes = [u8; 4];
    const EXPECTED_LEN: Option<usize> = Some(4);
}

impl Display for ReportVariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReportVariant::V2 => write!(f, "V2"),
            ReportVariant::V3 => write!(f, "V3"),
            ReportVariant::V5 => write!(f, "V5"),
        }
    }
}

/// A zero-copy view of a raw SEV-SNP attestation report.
///
/// This type splits the report into two byte slices:
/// - `body`: the bytes covered by the report signature
/// - `signature`: the firmware-provided signature bytes
///
/// `Report` does **not** imply authenticity or integrity. It is just a view over
/// untrusted bytes. Consumers should verify the signature (using [`Verifiable`])
/// before interpreting any fields from the body.
///
/// This design supports a two-phase workflow:
/// 1) Parse the outer framing to locate the signed body and signature.
/// 2) Verify the signature over `body`, then parse the verified body into
///    [`ReportBody`] for typed access.
///
/// # Notes
/// - `Report` borrows from the input buffer (`'a`), so the input bytes must
///   outlive the `Report`.
/// - The offsets used by [`Report::from_bytes`] assume the current fixed
///   firmware report layout and size (1184 bytes).
#[derive(Debug, Clone, Copy)]
pub struct Report<'a> {
    /// The signature algorithm used to sign the attestation report
    pub algorithm: SignatureAlgorithm,
    /// The bytes covered by the report signature (bytes 0x00 to 0x2A0).
    pub body: &'a [u8],
    /// The signature bytes (0x2A0..0x4A0).
    pub signature: &'a [u8],
}

impl<'a> Report<'a> {
    const REPORT_LEN: usize = 0x4A0; // 1184
    const BODY_LEN: usize = 0x2A0; // bytes 0x000..=0x29F
    const SIG_OFF: usize = 0x2A0;
    const SIG_LEN: usize = 0x200; // bytes 0x2A0..=0x49F
    const SIG_ALGO_OFF: usize = 0x34;
    const SIG_ALGO_LEN: usize = 0x4;
    /// Parse a raw attestation report into body and signature slices.
    ///
    /// This function performs **framing only**:
    /// - validates the total report length
    /// - returns borrowed slices for the signed body and signature
    ///
    /// It does **not** verify the signature or validate reserved fields.
    /// Use [`ReportBody::try_from`] (with a certificate or chain) to obtain a
    /// verified [`ReportBody`].
    pub fn from_bytes(report: &'a [u8]) -> std::io::Result<Self> {
        if report.len() != Self::REPORT_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Bad report length",
            ));
        };

        let algorithm = SignatureAlgorithm::decode(
            &mut &report[Self::SIG_ALGO_OFF..Self::SIG_ALGO_OFF + Self::SIG_ALGO_LEN],
            (),
        )?;

        Ok(Self {
            algorithm,
            body: &report[..Self::BODY_LEN],
            signature: &report[Self::SIG_OFF..Self::SIG_OFF + Self::SIG_LEN],
        })
    }
}

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
impl Verifiable for (&Certificate, &Report<'_>) {
    type Output = ();

    fn verify(self) -> Result<Self::Output, std::io::Error> {
        let (vek, report) = self;

        let algo = report.algorithm;

        (algo, report.body, report.signature, vek).verify()
    }
}

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
impl Verifiable for (&Chain, &Report<'_>) {
    type Output = ();

    fn verify(self) -> Result<(), std::io::Error> {
        let (chain, report) = self;
        let vek = chain.verify()?;
        (vek, report).verify()
    }
}

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
/// Verifies `report` with `vek` and returns a parsed [`ReportBody`].
impl<'a> TryFrom<(&Report<'a>, &Certificate)> for ReportBody<'a> {
    type Error = std::io::Error;

    fn try_from((report, vek): (&Report<'a>, &Certificate)) -> Result<Self, Self::Error> {
        (vek, report).verify()?;
        ReportBody::from_bytes(report.body)
    }
}

#[cfg(any(feature = "openssl", feature = "crypto_nossl"))]
/// Verifies `report` with `chain` and returns a parsed [`ReportBody`].
///
/// This is the **recommended** way to obtain a `ReportBody`, because it
/// enforces signature verification before parsing typed fields.
impl<'a> TryFrom<(&Report<'a>, &Chain)> for ReportBody<'a> {
    type Error = std::io::Error;

    fn try_from((report, chain): (&Report<'a>, &Chain)) -> Result<Self, Self::Error> {
        (chain, report).verify()?;
        ReportBody::from_bytes(report.body)
    }
}

/// A zero-copy view of the attestation report body.
/// All byte-arrayfields are borrowed from the original report body slice, so the input bytes must outlive this struct.
///
/// This struct contains fully typed and parsed fields from the attestation report body.
/// All fields are parsed to their final types at [`ReportBody::from_bytes`] time, including
/// TCB version parsing with generation-aware layout selection.
///
/// The correct method to generate [`ReportBody`] is from a [`Report`]:
/// ```ignore
/// let report = Report::from_bytes(&raw_bytes);
/// let body = ReportBody::try_from((&report, &vek))
/// ```
///
/// This will verify the signature and body of the report before parsing it into fully typed fields.
///
/// [`ReportBody::from_bytes`] can be used to parse the body from raw bytes, but this should be done for debugging purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReportBody<'a> {
    /// Version number of this attestation report.
    pub version: ReportVariant,

    /// Guest Security Version Number (SVN).
    pub guest_svn: u32,

    /// Guest policy governing hypervisor restrictions.
    pub policy: GuestPolicy,

    /// Family ID provided at launch (128 bits).
    pub family_id: &'a [u8; 16],

    /// Image ID provided at launch (128 bits).
    pub image_id: &'a [u8; 16],

    /// Virtual Machine Privilege Level (VMPL) of the attestation request.
    pub vmpl: u32,

    /// Signature algorithm used to sign this report.
    pub sig_algo: SignatureAlgorithm,

    /// Current TCB (Trusted Computing Base) version, parsed for the inferred generation.
    pub current_tcb: TcbVersion,

    /// Platform information flags.
    pub plat_info: PlatformInfo,

    /// Key and signing information.
    pub key_info: KeyInfo,

    /// Guest-provided data (512 bits).
    pub report_data: &'a [u8; 64],

    /// Launch measurement (SHA-384).
    pub measurement: &'a [u8; 48],

    /// Host-provided data (256 bits).
    pub host_data: &'a [u8; 32],

    /// SHA-384 digest of the ID public key.
    pub id_key_digest: &'a [u8; 48],

    /// SHA-384 digest of the Author public key.
    pub author_key_digest: &'a [u8; 48],

    /// Report ID of this guest (256 bits).
    pub report_id: &'a [u8; 32],

    /// Report ID of this guest's migration agent (256 bits).
    pub report_id_ma: &'a [u8; 32],

    /// Reported TCB version used to derive the VCEK, parsed for the inferred generation.
    pub reported_tcb: TcbVersion,

    /// CPUID Family ID - present in report version 3+.
    pub cpuid_fam_id: Option<u8>,

    /// CPUID Model ID - present in report version 3+.
    pub cpuid_mod_id: Option<u8>,

    /// CPUID Stepping - present in report version 3+.
    pub cpuid_step: Option<u8>,

    /// Chip identifier (512 bits). Zero if MaskChipId was set during launch.
    pub chip_id: &'a [u8; 64],

    /// Committed TCB version, parsed for the inferred generation.
    pub committed_tcb: TcbVersion,

    /// Current firmware version (major.minor.build).
    pub current: Version,

    /// Committed firmware version (major.minor.build).
    pub committed: Version,

    /// Launch TCB version, parsed for the inferred generation.
    pub launch_tcb: TcbVersion,

    /// Launch mitigation vector - present in report version 5+.
    pub launch_mit_vector: Option<u64>,

    /// Current mitigation vector - present in report version 5+.
    pub current_mit_vector: Option<u64>,
}

impl<'a> ReportBody<'a> {
    /// The expected length of the report body (bytes 0x00 to 0x2A0).
    pub const BODY_LEN: usize = 0x2A0;

    /// Parses a raw attestation report body into a typed [`ReportBody`].
    ///
    /// Security Warning
    ///
    /// This function **does not perform any cryptographic verification**.
    /// It only parses the provided byte slice according to the SEV-SNP
    /// attestation report layout.
    ///
    /// Calling this method directly means the caller is responsible for
    /// ensuring that the input bytes are authentic and have not been
    /// tampered with.
    ///
    /// ---
    ///
    /// # Correct Usage
    ///
    /// The **recommended and correct way** to obtain a [`ReportBody`] is via
    /// the `TryFrom` implementation that verifies the report signature first:
    ///
    /// ```ignore
    /// let report = Report::from_bytes(&raw_bytes)?;
    /// let body = ReportBody::try_from((&report, &certificate))?;
    /// ```
    ///
    /// or
    ///
    /// ```ignore
    /// let report = Report::from_bytes(&raw_bytes)?;
    /// let body = ReportBody::try_from((&report, &chain))?;
    /// ```
    ///
    /// These conversion paths:
    ///
    /// 1. Verify the report signature using the provided VEK or certificate chain.
    /// 2. Only after successful verification, parse the signed body bytes
    ///    into a typed [`ReportBody`].
    ///
    /// This ensures that parsed fields such as TCB versions, policy flags,
    /// measurements, and identifiers are cryptographically authenticated.
    ///
    /// ---
    ///
    /// # Intended Use of `from_bytes`
    ///
    /// This method exists primarily for:
    ///
    /// - Internal parsing after successful verification
    /// - Debugging and inspection of raw report bytes
    /// - Unit tests that validate layout and field decoding logic
    ///
    /// It should **not** be used in security-sensitive paths where the
    /// authenticity of the report matters.
    ///
    /// ---
    ///
    /// # Errors
    ///
    /// Returns an error if:
    ///
    /// - The body length is incorrect
    /// - The report version is unsupported
    /// - Reserved fields are non-zero
    /// - The chip ID is masked (for V2 reports)
    /// - Generation inference fails
    ///
    /// This function validates structural correctness, but **not**
    /// authenticity.
    ///
    pub fn from_bytes(body: &'a [u8]) -> Result<Self, std::io::Error> {
        if body.len() != Self::BODY_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "Report body length incorrect: expected {} bytes, got {}",
                    Self::BODY_LEN,
                    body.len()
                ),
            ));
        }

        // Parse version to determine variant and generation
        let version = ReportVariant::decode(&mut &body[0x00..0x04], ())?;

        // Parse firmware version early (needed for policy validation)
        let current = Version {
            build: body[0x1E8],
            minor: body[0x1E9],
            major: body[0x1EA],
        };

        // Infer generation from chip_id (V2) or CPUID fields (V3+)
        let generation = if version >= ReportVariant::V3 {
            // V3+ uses CPUID fields
            let family = body[0x188];
            let model = body[0x189];
            Generation::identify_cpu(family, model)?
        } else {
            // V2 uses chip_id heuristic
            let chip_id_bytes = &body[0x1A0..0x1E0];
            if chip_id_bytes == &[0u8; 64][..] {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Chip ID is masked",
                ));
            } else if chip_id_bytes[8..] == [0u8; 56] {
                // Turin-like: first 8 bytes non-zero, rest zero
                Generation::Turin
            } else {
                // Genoa-like: full 64 bytes used
                Generation::Genoa
            }
        };

        let guest_svn = u32::decode(&mut &body[0x04..0x08], ())?;

        let policy = GuestPolicy::decode(&mut &body[0x08..0x10], current)?;

        let family_id: &'a [u8; 16] = <&[u8; 16]>::try_from(&body[0x10..0x20])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let image_id: &'a [u8; 16] = <&[u8; 16]>::try_from(&body[0x20..0x30])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let vmpl = u32::decode(&mut &body[0x30..0x34], ())?;

        let sig_algo = SignatureAlgorithm::decode(&mut &body[0x34..0x38], ())?;

        let current_tcb = TcbVersion::decode(&mut &body[0x38..0x40], generation)?;

        let plat_info = PlatformInfo::decode(&mut &body[0x40..0x48], current)?;

        let key_info = KeyInfo::decode(&mut &body[0x48..0x4C], current)?;

        // Reserved 0x4C - 0x50
        validate_reserved(&body[0x4C..0x50], 0x4C)?;

        let report_data: &'a [u8; 64] = <&[u8; 64]>::try_from(&body[0x50..0x90])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let measurement: &'a [u8; 48] = <&[u8; 48]>::try_from(&body[0x90..0xC0])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let host_data: &'a [u8; 32] = <&[u8; 32]>::try_from(&body[0xC0..0xE0])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let id_key_digest: &'a [u8; 48] = <&[u8; 48]>::try_from(&body[0xE0..0x110])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let author_key_digest: &'a [u8; 48] = <&[u8; 48]>::try_from(&body[0x110..0x140])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let report_id: &'a [u8; 32] = <&[u8; 32]>::try_from(&body[0x140..0x160])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let report_id_ma: &'a [u8; 32] = <&[u8; 32]>::try_from(&body[0x160..0x180])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let reported_tcb = TcbVersion::decode(&mut &body[0x180..0x188], generation)?;

        // Parse CPUID fields (V3+) or extract raw values
        let (cpuid_fam_id, cpuid_mod_id, cpuid_step) = if version >= ReportVariant::V3 {
            // Reserved 0x18B - 0x1A0
            validate_reserved(&body[0x18B..0x1A0], 0x18B)?;
            (Some(body[0x188]), Some(body[0x189]), Some(body[0x18A]))
        } else {
            // Reserved 0x188 - 0x1A0
            validate_reserved(&body[0x188..0x1A0], 0x188)?;
            (None, None, None)
        };

        let chip_id: &'a [u8; 64] = <&[u8; 64]>::try_from(&body[0x1A0..0x1E0])
            .map_err(|e| std::io::Error::other(format!("Failed TryFrom Operation: {e}")))?;

        let committed_tcb = TcbVersion::decode(&mut &body[0x1E0..0x1E8], generation)?;

        // current firmware version already parsed earlier for policy validation

        // Reserved 0x1EB
        validate_reserved(&body[0x1EB..0x1EC], 0x1EB)?;

        // Parse committed firmware version
        let committed = Version {
            build: body[0x1EC],
            minor: body[0x1ED],
            major: body[0x1EE],
        };

        // Reserved 0x1EF
        validate_reserved(&body[0x1EF..0x1F0], 0x1EF)?;

        let launch_tcb = TcbVersion::decode(&mut &body[0x1F0..0x1F8], generation)?;

        // Parse mitigation vector fields (V5+)
        let (launch_mit_vector, current_mit_vector) = if version >= ReportVariant::V5 {
            // Reserved 0x208 - 0x2A0
            validate_reserved(&body[0x208..0x2A0], 0x208)?;
            let launch = u64::decode(&mut &body[0x1F8..0x200], ())?;
            let current = u64::decode(&mut &body[0x200..0x208], ())?;
            (Some(launch), Some(current))
        } else {
            // Reserved 0x1F8 - 0x2A0
            validate_reserved(&body[0x1F8..0x2A0], 0x1F8)?;
            (None, None)
        };

        Ok(Self {
            version,
            guest_svn,
            policy,
            family_id,
            image_id,
            vmpl,
            sig_algo,
            current_tcb,
            plat_info,
            key_info,
            report_data,
            measurement,
            host_data,
            id_key_digest,
            author_key_digest,
            report_id,
            report_id_ma,
            reported_tcb,
            cpuid_fam_id,
            cpuid_mod_id,
            cpuid_step,
            chip_id,
            committed_tcb,
            current,
            committed,
            launch_tcb,
            launch_mit_vector,
            current_mit_vector,
        })
    }
}

impl Display for ReportBody<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            r#"Attestation Report:

Version:                      {}

Guest SVN:                    {}

{}

Family ID:{}

Image ID:{}

VMPL:                         {}

Signature Algorithm:          {}

Current TCB:

{}

{}

{}

Report Data:{}

Measurement:{}

Host Data:{}

ID Key Digest:{}

Author Key Digest:{}

Report ID:{}

Report ID Migration Agent:{}

Reported TCB:

{}

CPUID Family ID:              {}

CPUID Model ID:               {}

CPUID Stepping:               {}

Chip ID:{}

Committed TCB:

{}

Current Version:              {}

Committed Version:            {}

Launch TCB:

{}

Launch Mitigation Vector:     {}

Current Mitigation Vector:    {}
"#,
            self.version,
            self.guest_svn,
            self.policy.display_for_version(self.current),
            HexLine(self.family_id),
            HexLine(self.image_id),
            self.vmpl,
            self.sig_algo,
            self.current_tcb,
            self.plat_info.display_for_version(self.current),
            self.key_info.display_for_version(self.current),
            HexLine(self.report_data),
            HexLine(self.measurement),
            HexLine(self.host_data),
            HexLine(self.id_key_digest),
            HexLine(self.author_key_digest),
            HexLine(self.report_id),
            HexLine(self.report_id_ma),
            self.reported_tcb,
            self.cpuid_fam_id
                .map_or("None".to_string(), |fam| fam.to_string()),
            self.cpuid_mod_id
                .map_or("None".to_string(), |model| model.to_string()),
            self.cpuid_step
                .map_or("None".to_string(), |step| step.to_string()),
            HexLine(self.chip_id),
            self.committed_tcb,
            self.current,
            self.committed,
            self.launch_tcb,
            self.launch_mit_vector
                .map_or("None".to_string(), |lmv| lmv.to_string()),
            self.current_mit_vector
                .map_or("None".to_string(), |cmv| cmv.to_string()),
        )
    }
}

#[cfg(test)]
mod tests {

    use std::ops::Range;

    use super::*;
    const CHIP_ID_RANGE: Range<usize> = 0x1A0..0x1E0;

    #[test]
    fn test_derive_key_new() {
        let expected: DerivedKey = DerivedKey {
            root_key_select: 0,
            _reserved_0: 0,
            guest_field_select: GuestFieldSelect(0),
            vmpl: 0,
            guest_svn: 0,
            tcb_version: 0,
            launch_mit_vector: None,
        };

        let guest_field: GuestFieldSelect = GuestFieldSelect(0);

        let actual: DerivedKey = DerivedKey::new(false, guest_field, 0, 0, 0, None);

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_derive_key_get_root_key_select() {
        let dk_struct: DerivedKey = DerivedKey {
            root_key_select: 0,
            _reserved_0: 0,
            guest_field_select: GuestFieldSelect(0),
            vmpl: 0,
            guest_svn: 0,
            tcb_version: 0,
            launch_mit_vector: None,
        };

        let expected: u32 = 0;
        let actual: u32 = dk_struct.get_root_key_select();

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_guest_field_select_all_on() {
        let actual: GuestFieldSelect = GuestFieldSelect(0b111111);

        assert!(actual.get_guest_policy());
        assert!(actual.get_image_id());
        assert!(actual.get_family_id());
        assert!(actual.get_measurement());
        assert!(actual.get_svn());
        assert!(actual.get_tcb_version());
    }

    #[test]
    fn test_guest_field_select_all_off() {
        let actual: GuestFieldSelect = GuestFieldSelect(0);

        assert!(!actual.get_guest_policy());
        assert!(!actual.get_image_id());
        assert!(!actual.get_family_id());
        assert!(!actual.get_measurement());
        assert!(!actual.get_svn());
        assert!(!actual.get_tcb_version());
    }

    #[test]
    fn test_report_body_fmt_v2_zero() {
        // Build a full firmware report (1184) with v2 and a non-masked chip_id.
        let mut bytes = vec![0u8; Report::REPORT_LEN];

        // version: u32 LE at 0x00..0x04
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes());

        // sig algo
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        // policy u64 LE at 0x08..0x10
        let policy_raw = 1u64 << 17; // RMB1 bit
        bytes[0x08..0x10].copy_from_slice(&policy_raw.to_le_bytes());

        // Make chip_id non-zero so v2 parsing doesn't error out
        bytes[CHIP_ID_RANGE.start] = 1;

        let report = Report::from_bytes(&bytes).unwrap();
        let body = ReportBody::from_bytes(report.body).unwrap();

        let expected: &str = r#"Attestation Report:

Version:                      V2

Guest SVN:                    0

Guest Policy (0x20000):
  ABI Major:         0
  ABI Minor:         0
  SMT Allowed:       false
  Migrate MA:        false
  Debug Allowed:     false
  Single Socket:     false
  CXL Allowed:       None
  AES 256 XTS:       None
  RAPL Disabled:     None
  Ciphertext Hiding: None
  Page Swap Disable: None

Family ID:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Image ID:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

VMPL:                         0

Signature Algorithm:          ECDSA with SECP384R1

Current TCB:

TCB Version:
  Microcode:   0
  SNP:         0
  TEE:         0
  Boot Loader: 0
  FMC:         0

Platform Info (0):
  SMT Enabled:               false
  TSME Enabled:              false
  ECC Enabled:               None
  RAPL Disabled:             None
  Ciphertext Hiding Enabled: None
  Alias Check Complete:      None
  SEV-TIO Enabled:           None

Key Information:
    author key enabled: false
    mask chip key:      None
    signing key:        vcek

Report Data:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Measurement:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Host Data:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

ID Key Digest:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Author Key Digest:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Report ID:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Report ID Migration Agent:
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Reported TCB:

TCB Version:
  Microcode:   0
  SNP:         0
  TEE:         0
  Boot Loader: 0
  FMC:         0

CPUID Family ID:              None

CPUID Model ID:               None

CPUID Stepping:               None

Chip ID:
01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00

Committed TCB:

TCB Version:
  Microcode:   0
  SNP:         0
  TEE:         0
  Boot Loader: 0
  FMC:         0

Current Version:              0.0.0

Committed Version:            0.0.0

Launch TCB:

TCB Version:
  Microcode:   0
  SNP:         0
  TEE:         0
  Boot Loader: 0
  FMC:         0

Launch Mitigation Vector:     None

Current Mitigation Vector:    None
"#;

        assert_eq!(expected, body.to_string());
    }

    #[test]
    fn test_report_copy() {
        let mut bytes = vec![0u8; Report::REPORT_LEN];

        // Setting sig algo
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        let report = Report::from_bytes(&bytes).unwrap();
        let copy = report;

        assert_eq!(report.body.as_ptr(), copy.body.as_ptr());
        assert_eq!(report.body.len(), copy.body.len());
        assert_eq!(report.signature.as_ptr(), copy.signature.as_ptr());
        assert_eq!(report.signature.len(), copy.signature.len());
    }

    #[test]
    fn test_version_extraction() {
        let raw_v2 = [2, 0, 0, 0]; // Version 2
        let version = u32::from_le_bytes([raw_v2[0], raw_v2[1], raw_v2[2], raw_v2[3]]);
        assert_eq!(version, 2);

        let raw_v3 = [3, 0, 0, 0]; // Version 3
        let version = u32::from_le_bytes([raw_v3[0], raw_v3[1], raw_v3[2], raw_v3[3]]);
        assert_eq!(version, 3);
    }

    #[test]
    fn test_guest_field_select_operations() {
        let mut field = GuestFieldSelect::default();

        field.set_guest_policy(true);
        assert!(field.get_guest_policy());

        field.set_image_id(true);
        assert!(field.get_image_id());

        field.set_family_id(true);
        assert!(field.get_family_id());

        field.set_measurement(true);
        assert!(field.get_measurement());
    }

    #[test]
    fn test_derived_key_fields() {
        let key = DerivedKey::new(true, GuestFieldSelect(0xFF), 2, 3, 0x1234, None);
        assert_eq!(key.get_root_key_select(), 1);
        assert_eq!(key.vmpl, 2);
        assert_eq!(key.guest_svn, 3);
        assert_eq!(key.tcb_version, 0x1234);
    }

    #[test]
    fn test_report_body_selected_fields() {
        let mut bytes = vec![0u8; Report::REPORT_LEN];

        // v2: version u32 LE at 0x00..0x04
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes());

        // v2 requires chip_id not fully masked (not all zeros)
        bytes[CHIP_ID_RANGE.start] = 1;

        // guest_svn at 0x04..0x08
        bytes[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());

        // vmpl at 0x30..0x34
        bytes[0x30..0x34].copy_from_slice(&3u32.to_le_bytes());

        // signature algorithm
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        // policy u64 LE at 0x08..0x10
        let policy_raw = 1u64 << 17; // RMB1 bit
        bytes[0x08..0x10].copy_from_slice(&policy_raw.to_le_bytes());

        let report = Report::from_bytes(&bytes).unwrap();

        // NOTE: parsing-only test: do NOT use TryFrom/verify path here
        let body = ReportBody::from_bytes(report.body).unwrap();

        assert_eq!(body.version, ReportVariant::V2);
        assert_eq!(body.guest_svn, 1);
        assert_eq!(body.vmpl, 3);
        assert_eq!(body.measurement, &[0u8; 48]);
        assert_eq!(body.sig_algo, SignatureAlgorithm::EcdsaSecp384r1)
    }

    #[test]
    fn test_report_from_bytes_ok() {
        let mut bytes = vec![0u8; Report::REPORT_LEN];
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes()); // v2
        bytes[CHIP_ID_RANGE.start] = 1; // unmask chip id

        // signature algorithm
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        // policy u64 LE at 0x08..0x10
        let policy_raw = 1u64 << 17; // RMB1 bit
        bytes[0x08..0x10].copy_from_slice(&policy_raw.to_le_bytes());

        let report = Report::from_bytes(bytes.as_slice());
        assert!(report.is_ok());

        // Also ensure the body can be parsed
        let report = report.unwrap();
        assert!(ReportBody::from_bytes(report.body).is_ok());
    }

    #[test]
    fn test_report_from_bytes_rejects_bad_len() {
        let bytes = vec![0u8; Report::REPORT_LEN - 1];
        let err = Report::from_bytes(&bytes).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_report_body_parse_roundtrip_like() {
        let mut bytes = vec![0u8; Report::REPORT_LEN];
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes()); // v2
        bytes[CHIP_ID_RANGE.start] = 1; // unmask

        // family_id and image_id
        bytes[0x10..0x20].copy_from_slice(&[0xAA; 16]);
        bytes[0x20..0x30].copy_from_slice(&[0xBB; 16]);

        // guest_svn
        bytes[0x04..0x08].copy_from_slice(&1u32.to_le_bytes());

        // signature algorithm
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        // policy u64 LE at 0x08..0x10
        let policy_raw = 1u64 << 17; // RMB1 bit
        bytes[0x08..0x10].copy_from_slice(&policy_raw.to_le_bytes());

        let report = Report::from_bytes(&bytes).unwrap();
        let body = ReportBody::from_bytes(report.body).unwrap();

        assert_eq!(body.family_id, &[0xAA; 16]);
        assert_eq!(body.image_id, &[0xBB; 16]);
        assert_eq!(body.guest_svn, 1);
    }

    #[test]
    fn test_chip_id_v2_genoa_like_allowed() {
        let mut bytes = vec![0u8; Report::REPORT_LEN];
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes()); // v2

        // Genoa-like: full 64 bytes used (i.e., not "first 8 nonzero then rest zero")
        let vcek_bytes = [
            0xD4, 0x95, 0x54, 0xEC, 0x71, 0x7F, 0x4E, 0x5B, 0x0F, 0xE6, 0xB1, 0x43, 0xBC, 0xF0,
            0x40, 0x5B, 0xD7, 0xAE, 0x30, 0x47, 0x27, 0xED, 0xF4, 0x66, 0x03, 0xF2, 0xA7, 0x6A,
            0xEF, 0x6A, 0x3A, 0xBC, 0x15, 0xD7, 0xAF, 0x38, 0xDB, 0x75, 0x70, 0x39, 0x02, 0x9F,
            0x0E, 0xFA, 0xCF, 0xD0, 0x8E, 0x24, 0x43, 0x24, 0x88, 0x47, 0x38, 0xC7, 0x2B, 0x08,
            0x2E, 0x2F, 0x87, 0xA4, 0x4D, 0x54, 0x1E, 0xB6,
        ];

        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        // policy u64 LE at 0x08..0x10
        let policy_raw = 1u64 << 17; // RMB1 bit
        bytes[0x08..0x10].copy_from_slice(&policy_raw.to_le_bytes());

        bytes[CHIP_ID_RANGE.clone()].copy_from_slice(&vcek_bytes);

        let report = Report::from_bytes(&bytes).unwrap();
        let body = ReportBody::from_bytes(report.body).unwrap();

        // Should have cpuid fields absent in v2
        assert_eq!(body.cpuid_fam_id, None);
        assert_eq!(body.cpuid_mod_id, None);
        assert_eq!(body.cpuid_step, None);

        // Should preserve chip_id bytes
        assert_eq!(body.chip_id, &vcek_bytes);
    }

    #[test]
    fn test_chip_id_v2_turin_like_allowed() {
        let mut bytes = vec![0u8; Report::REPORT_LEN];
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes()); // v2

        let mut chip = [0u8; 64];
        chip[0..8].copy_from_slice(&[0xD4, 0x95, 0x54, 0xEC, 0x71, 0x7F, 0x4E, 0x5B]);
        // rest remains zero
        bytes[CHIP_ID_RANGE.clone()].copy_from_slice(&chip);

        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        // policy u64 LE at 0x08..0x10
        let policy_raw = 1u64 << 17; // RMB1 bit
        bytes[0x08..0x10].copy_from_slice(&policy_raw.to_le_bytes());

        let report = Report::from_bytes(&bytes).unwrap();
        let body = ReportBody::from_bytes(report.body).unwrap();

        assert_eq!(body.chip_id, &chip);
    }

    #[test]
    fn test_chip_id_v2_masked_rejected() {
        let mut bytes = vec![0u8; Report::REPORT_LEN];
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes()); // v2
                                                                // chip_id left as all zeros

        // Setting sig algo
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        let report = Report::from_bytes(&bytes).unwrap();
        let err = ReportBody::from_bytes(report.body).unwrap_err();
        assert!(err.to_string().contains("Chip ID is masked"));
    }

    #[test]
    fn test_report_from_bytes_splits_body_and_signature() {
        let mut bytes = vec![0u8; Report::REPORT_LEN];

        // signature algorithm
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        let r = Report::from_bytes(&bytes).unwrap();

        assert_eq!(r.body.len(), 0x2a0);
        assert_eq!(r.signature.len(), 0x49f + 1 - 0x2a0);
        assert_eq!(r.body.as_ptr(), bytes.as_ptr());
        assert_eq!(
            r.signature.as_ptr() as usize - bytes.as_ptr() as usize,
            0x2a0
        );
    }

    #[test]
    fn test_report_variant_tryfrom() {
        assert_eq!(ReportVariant::try_from(2).unwrap(), ReportVariant::V2);
        assert_eq!(ReportVariant::try_from(3).unwrap(), ReportVariant::V3);
        assert_eq!(ReportVariant::try_from(4).unwrap(), ReportVariant::V3);
        assert_eq!(ReportVariant::try_from(5).unwrap(), ReportVariant::V5);
        assert!(ReportVariant::try_from(99).is_err());
    }

    #[test]
    fn test_report_body_rejects_nonzero_reserved_0x4c() {
        let mut bytes = vec![0u8; Report::REPORT_LEN];
        bytes[0x00..0x04].copy_from_slice(&2u32.to_le_bytes());
        bytes[CHIP_ID_RANGE.start] = 1;

        // Setting sig algo
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());

        bytes[0x4C] = 1; // reserved byte non-zero

        let r = Report::from_bytes(&bytes).unwrap();
        assert!(ReportBody::from_bytes(r.body).is_err());
    }
}
