// SPDX-License-Identifier: Apache-2.0

use crate::{error::*, firmware::guest::*, util::array::Array};

use static_assertions::const_assert;

/// This may end up being 4 when the Shadow Stack is enabled.
/// [APMv2 - Table 15-38 - VMPL Permission Mask Definition](https://www.amd.com/system/files/TechDocs/24593.pdf#page=670&zoom=100,0,400)
const MAX_VMPL: u32 = 3;

#[repr(C)]
#[derive(Debug, Default)]
pub struct DerivedKeyReq {
    /// Selects the root key to derive the key from.
    /// 0: Indicates VCEK.
    /// 1: Indicates VMRK.
    root_key_select: u32,

    /// Reserved, must be zero
    reserved_0: u32,

    /// What data will be mixed into the derived key.
    pub guest_field_select: u64,

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
    /// Introduced in FW 1.58, so if unset, it will default to 0.
    pub launch_mit_vector: u64,
}

impl From<DerivedKey> for DerivedKeyReq {
    fn from(value: DerivedKey) -> Self {
        Self {
            root_key_select: value.get_root_key_select(),
            reserved_0: Default::default(),
            guest_field_select: value.guest_field_select.0,
            vmpl: value.vmpl,
            guest_svn: value.guest_svn,
            tcb_version: value.tcb_version,
            launch_mit_vector: value.launch_mit_vector.unwrap_or(0),
        }
    }
}

impl From<&mut DerivedKey> for DerivedKeyReq {
    fn from(value: &mut DerivedKey) -> Self {
        Self {
            root_key_select: value.get_root_key_select(),
            reserved_0: Default::default(),
            guest_field_select: value.guest_field_select.0,
            vmpl: value.vmpl,
            guest_svn: value.guest_svn,
            tcb_version: value.tcb_version,
            launch_mit_vector: value.launch_mit_vector.unwrap_or(0),
        }
    }
}

#[derive(Default, Debug)]
#[repr(C)]
/// A raw representation of the PSP Report Response after calling SNP_GET_DERIVED_KEY.
pub struct DerivedKeyRsp {
    /// The status of key derivation operation.
    /// 0h: Success.
    /// 16h: Invalid parameters
    pub status: u32,

    reserved_0: [u8; 28],

    /// The requested derived key if [DerivedKeyRsp::status](self::DerivedKeyRsp::status) is 0h.
    pub key: [u8; 32],
}

/// Information provided by the guest owner for requesting an attestation
/// report and associated certificate chain from the AMD Secure Processor.
///
/// The certificate buffer *should* be page aligned for the kernel.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ExtReportReq {
    /// The [ReportReq](self::ReportReq).
    pub data: ReportReq,

    /// Starting address of the certificate data buffer.
    pub certs_address: u64,

    /// The page aligned length of the buffer the hypervisor should store the certificates in.
    pub certs_len: u32,
}

impl ExtReportReq {
    /// Creates a new exteded report with a one, 4K-page
    /// for the certs_address field and the certs_len field.
    pub fn new(data: &ReportReq) -> Self {
        Self {
            data: *data,
            certs_address: u64::MAX,
            certs_len: 0u32,
        }
    }
}

/// Information provided by the guest owner for requesting an attestation
/// report from the AMD Secure Processor.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
#[repr(C)]
pub struct ReportReq {
    /// Guest-provided data to be included int the attestation report
    report_data: [u8; 64],

    /// The VMPL to put into the attestation report. Must be greater than or
    /// equal to the current VMPL and at most three.
    vmpl: u32,

    /// Reserved memory slot, must be zero.
    _reserved: [u8; 28],
}

impl Default for ReportReq {
    fn default() -> Self {
        Self {
            report_data: [0; 64],
            vmpl: 1,
            _reserved: Default::default(),
        }
    }
}

impl ReportReq {
    /// Instantiates a new [ReportReq](self::ReportReq) for fetching an [AttestationReport](crate::firmware::guest::types::snp::AttestationReport) from the PSP.
    ///
    /// # Arguments
    ///
    /// * `report_data` - (Optional) 64 bytes of unique data to be included in the generated report.
    /// * `vmpl` - The VMPL level the guest VM is running on.
    pub fn new(report_data: Option<[u8; 64]>, vmpl: Option<u32>) -> Result<Self, UserApiError> {
        let mut request = Self::default();

        if let Some(report_data) = report_data {
            request.report_data = report_data;
        }

        if let Some(vmpl) = vmpl {
            if vmpl > MAX_VMPL {
                return Err(UserApiError::VmplError);
            } else {
                request.vmpl = vmpl;
            }
        }

        Ok(request)
    }
}

const REPORT_SIZE: usize = 1184usize;

/// The response from the PSP containing the generated attestation report.
///
/// The Report is padded to exactly 4000 Bytes to make sure the page size
/// matches.
///
///
/// ```txt
///     96 Bytes (*Message Header)
/// + 4000 Bytes (*Encrypted Message)
/// ------------
///   4096 Bytes (4K Memory Page Alignment)
/// ```
/// <sup>*[Message Header - 8.26 SNP_GUEST_REQUEST - Table 97](<https://www.amd.com/system/files/TechDocs/56860.pdf#page=113>)</sup>
///
/// <sup>*[Encrypted Message - sev-guest.h](<https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/sev-guest.h>)</sup>
#[derive(Clone, Copy)]
#[repr(C)]
pub struct ReportRsp {
    /// The status of key derivation operation.
    ///     0h: Success.
    ///     16h: Invalid parameters.
    pub status: u32,
    /// Size in bytes of the report.
    pub report_size: u32,
    reserved_0: [u8; 24],
    /// The attestation report generated by the firmware.
    pub report: Array<u8, REPORT_SIZE>,
    /// Padding bits to meet the memory page alignment.
    reserved_1: [u8; 4000
        - (REPORT_SIZE + (std::mem::size_of::<u32>() * 2) + std::mem::size_of::<[u8; 24]>())],
}

// Compile-time check that the size is what is expected.
// Will error out with:
//
//      evaluation of constant value failed attempt to compute
//      `0_usize - 1_usize`, which would overflow
//
const_assert!(std::mem::size_of::<ReportRsp>() == 4000);

impl Default for ReportRsp {
    fn default() -> Self {
        Self {
            status: Default::default(),
            report_size: Default::default(),
            reserved_0: Default::default(),
            report: Default::default(),
            reserved_1: [0u8; 4000
                - (REPORT_SIZE
                    + (std::mem::size_of::<u32>() * 2)
                    + std::mem::size_of::<[u8; 24]>())],
        }
    }
}

#[cfg(test)]
mod test {
    mod snp_report_req {
        use crate::firmware::linux::guest::types::ReportReq;
        #[test]
        pub fn test_new() {
            let report_data: [u8; 64] = [
                65, 77, 68, 32, 105, 115, 32, 101, 120, 116, 114, 101, 109, 101, 108, 121, 32, 97,
                119, 101, 115, 111, 109, 101, 33, 32, 87, 101, 32, 109, 97, 107, 101, 32, 116, 104,
                101, 32, 98, 101, 115, 116, 32, 67, 80, 85, 115, 33, 32, 65, 77, 68, 32, 82, 111,
                99, 107, 115, 33, 33, 33, 33, 33, 33,
            ];
            let expected: ReportReq = ReportReq {
                report_data,
                vmpl: 0,
                _reserved: [0; 28],
            };

            let actual: ReportReq = ReportReq::new(Some(report_data), Some(0)).unwrap();

            assert_eq!(expected, actual);
        }

        #[test]
        #[should_panic]
        pub fn test_new_error() {
            let report_data: [u8; 64] = [
                65, 77, 68, 32, 105, 115, 32, 101, 120, 116, 114, 101, 109, 101, 108, 121, 32, 97,
                119, 101, 115, 111, 109, 101, 33, 32, 87, 101, 32, 109, 97, 107, 101, 32, 116, 104,
                101, 32, 98, 101, 115, 116, 32, 67, 80, 85, 115, 33, 32, 65, 77, 68, 32, 82, 111,
                99, 107, 115, 33, 33, 33, 33, 33, 33,
            ];
            let expected: ReportReq = ReportReq {
                report_data,
                vmpl: 7,
                _reserved: [0; 28],
            };

            let actual: ReportReq = ReportReq::new(Some(report_data), Some(0)).unwrap();

            assert_eq!(expected, actual);
        }
    }

    use super::*;

    #[test]
    fn test_derived_key_req_conversion() {
        // Create a mock DerivedKey
        let derived_key = DerivedKey::new(false, GuestFieldSelect(0x1234), 2, 1, 100, Some(123));

        // Test From<DerivedKey>
        let req: DerivedKeyReq = derived_key.into();
        assert_eq!(req.root_key_select, 0);
        assert_eq!(req.reserved_0, 0);
        assert_eq!(req.guest_field_select, 0x1234);
        assert_eq!(req.vmpl, 2);
        assert_eq!(req.guest_svn, 1);
        assert_eq!(req.tcb_version, 100);
        assert_eq!(req.launch_mit_vector, 123);

        // Test From<&mut DerivedKey>
        let mut derived_key = derived_key;
        let req: DerivedKeyReq = (&mut derived_key).into();
        assert_eq!(req.root_key_select, 0);
        assert_eq!(req.reserved_0, 0);
        assert_eq!(req.guest_field_select, 0x1234);
        assert_eq!(req.vmpl, 2);
        assert_eq!(req.guest_svn, 1);
        assert_eq!(req.tcb_version, 100);
        assert_eq!(req.launch_mit_vector, 123);
    }

    #[test]
    fn test_ext_report_req() {
        let report_req = ReportReq::default();
        let ext_report = ExtReportReq::new(&report_req);

        assert_eq!(ext_report.data, report_req);
        assert_eq!(ext_report.certs_address, u64::MAX);
        assert_eq!(ext_report.certs_len, 0);

        // Test Default
        let default_ext = ExtReportReq::default();
        assert_eq!(default_ext.certs_address, 0);
        assert_eq!(default_ext.certs_len, 0);
    }

    #[test]
    fn test_report_req() {
        // Test default values
        let default_req = ReportReq::default();
        assert_eq!(default_req.report_data, [0; 64]);
        assert_eq!(default_req.vmpl, 1);
        assert_eq!(default_req._reserved, [0; 28]);

        // Test successful creation with Some values
        let report_data = [42u8; 64];
        let req = ReportReq::new(Some(report_data), Some(2)).unwrap();
        assert_eq!(req.report_data, report_data);
        assert_eq!(req.vmpl, 2);

        // Test successful creation with None values
        let req = ReportReq::new(None, None).unwrap();
        assert_eq!(req.report_data, [0; 64]);
        assert_eq!(req.vmpl, 1);

        // Test VMPL validation
        assert!(ReportReq::new(None, Some(4)).is_err());
        assert!(ReportReq::new(None, Some(MAX_VMPL)).is_ok());
    }

    #[test]
    fn test_report_rsp() {
        let rsp = ReportRsp::default();

        assert_eq!(rsp.status, 0);
        assert_eq!(rsp.report_size, 0);
        assert_eq!(rsp.reserved_0, [0; 24]);

        // Verify size is exactly 4000 bytes
        assert_eq!(std::mem::size_of::<ReportRsp>(), 4000);
    }

    #[test]
    fn test_derived_key_rsp() {
        let rsp = DerivedKeyRsp::default();

        assert_eq!(rsp.status, 0);
        assert_eq!(rsp.reserved_0, [0; 28]);
        assert_eq!(rsp.key, [0; 32]);
    }
}
