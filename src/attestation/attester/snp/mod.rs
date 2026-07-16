// SPDX-License-Identifier: Apache-2.0

//! SNP guest attester: request attestation reports from `/dev/sev-guest`.

use crate::error::*;
use crate::snp::types::DerivedKey;

#[cfg(target_os = "linux")]
use crate::firmware::{
    guest::{ioctl::*, types::*},
    host::CertTableEntry,
    linux::host as HostFFI,
};

#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};

/// Checks the `fw_err` field on the
/// [`GuestRequest`](crate::firmware::guest::ioctl::GuestRequest) structure
/// to make sure that no errors were encountered by the VMM or the AMD Secure
/// Processor.
fn map_fw_err(raw_error: RawFwError) -> UserApiError {
    let (upper, lower): (u32, u32) = raw_error.into();

    if upper != 0 {
        return VmmError::from(upper).into();
    }

    if lower != 0 {
        return FirmwareError::from(lower).into();
    }

    FirmwareError::UnknownSevError(lower).into()
}

/// SNP guest firmware handle backed by the `/dev/sev-guest` device node.
///
/// This is the RATS Attester role for SEV-SNP guests: it requests attestation
/// reports and derived keys from the AMD Secure Processor. For verification and
/// appraisal, see [`crate::attestation::verifier`].
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub struct Firmware(File);

#[cfg(target_os = "linux")]
impl Firmware {
    /// Open a handle to the SEV-SNP guest device at `/dev/sev-guest`.
    pub fn open() -> std::io::Result<Self> {
        Ok(Self(
            OpenOptions::new().read(true).open("/dev/sev-guest")?,
        ))
    }

    /// Requests an attestation report from the AMD Secure Processor. The
    /// `message_version` will default to `1` if `None` is specified.
    pub fn get_report(
        &mut self,
        message_version: Option<u32>,
        data: Option<[u8; 64]>,
        vmpl: Option<u32>,
    ) -> Result<Vec<u8>, UserApiError> {
        let mut input = ReportReq::new(data, vmpl)?;
        let mut response = ReportRsp::default();

        let mut request: GuestRequest<ReportReq, ReportRsp> =
            GuestRequest::new(message_version, &mut input, &mut response);

        SNP_GET_REPORT
            .ioctl(&mut self.0, &mut request)
            .map_err(|_| map_fw_err(request.fw_err.into()))?;

        if response.status != 0 {
            Err(FirmwareError::from(response.status))?
        }

        Ok(response.report.to_vec())
    }

    /// Request an extended attestation report from the AMD Secure Processor.
    /// The `message_version` will default to `1` if `None` is specified.
    ///
    /// Behaves the same as [`Self::get_report`], but may also return a parsed
    /// certificate table when the platform provides one.
    pub fn get_ext_report(
        &mut self,
        message_version: Option<u32>,
        data: Option<[u8; 64]>,
        vmpl: Option<u32>,
    ) -> Result<(Vec<u8>, Option<Vec<CertTableEntry>>), UserApiError> {
        let report_request = ReportReq::new(data, vmpl)?;

        let mut report_response = ReportRsp::default();
        let mut certificate_bytes: Vec<u8>;
        let mut ext_report_request = ExtReportReq::new(&report_request);

        let mut guest_request: GuestRequest<ExtReportReq, ReportRsp> = GuestRequest::new(
            message_version,
            &mut ext_report_request,
            &mut report_response,
        );

        // KEEP for Kernels before 47894e0f (5.19), as userspace broke at that hash.
        if SNP_GET_EXT_REPORT
            .ioctl(&mut self.0, &mut guest_request)
            .is_err()
        {
            match guest_request.fw_err.into() {
                VmmError::InvalidCertificatePageLength => {
                    certificate_bytes = vec![0u8; ext_report_request.certs_len as usize];
                    ext_report_request.certs_address = certificate_bytes.as_mut_ptr() as u64;
                    let mut guest_request_retry: GuestRequest<ExtReportReq, ReportRsp> =
                        GuestRequest::new(
                            message_version,
                            &mut ext_report_request,
                            &mut report_response,
                        );
                    SNP_GET_EXT_REPORT
                        .ioctl(&mut self.0, &mut guest_request_retry)
                        .map_err(|_| map_fw_err(guest_request_retry.fw_err.into()))?;
                }
                _ => Err(map_fw_err(guest_request.fw_err.into()))?,
            }
        }

        if report_response.status != 0 {
            Err(FirmwareError::from(report_response.status))?
        }

        if ext_report_request.certs_len == 0 {
            return Ok((report_response.report.to_vec(), None));
        }

        let mut certificates: Vec<CertTableEntry>;

        unsafe {
            let entries = (ext_report_request.certs_address as *mut HostFFI::types::CertTableEntry)
                .as_mut()
                .ok_or(CertError::EmptyCertBuffer)?;
            certificates = HostFFI::types::CertTableEntry::parse_table(entries)?;
            certificates.sort();
        }

        Ok((report_response.report.to_vec(), Some(certificates)))
    }

    /// Fetches a derived key from the AMD Secure Processor. The `message_version`
    /// will default to `2` if `None` is specified.
    pub fn get_derived_key(
        &mut self,
        message_version: Option<u32>,
        mut derived_key_request: DerivedKey,
    ) -> Result<[u8; 32], UserApiError> {
        let message_version = if message_version.is_some() {
            message_version
        } else {
            Some(2)
        };

        if let Some(version) = message_version {
            if version >= 2 {
                if derived_key_request.launch_mit_vector.is_none() {
                    use std::io;

                    return Err(UserApiError::IOError(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Launch Mitigation Vector must be provided for message version >= 2",
                    )));
                }
            } else {
                derived_key_request.launch_mit_vector = None;
            }
        }

        let mut ffi_derived_key_request: DerivedKeyReq = derived_key_request.into();
        let mut ffi_derived_key_response: DerivedKeyRsp = Default::default();

        {
            let mut request: GuestRequest<DerivedKeyReq, DerivedKeyRsp> = GuestRequest::new(
                message_version,
                &mut ffi_derived_key_request,
                &mut ffi_derived_key_response,
            );

            SNP_GET_DERIVED_KEY
                .ioctl(&mut self.0, &mut request)
                .map_err(|_| map_fw_err(request.fw_err.into()))?;
        }

        if ffi_derived_key_response.status != 0 {
            Err(FirmwareError::from(ffi_derived_key_response.status))?
        }

        Ok(ffi_derived_key_response.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firmware_error_mapping() {
        let raw_error = RawFwError(1);
        let error = map_fw_err(raw_error);
        assert!(matches!(error, UserApiError::FirmwareError(_)));

        let raw_error = RawFwError(0x100000000u64);
        let error = map_fw_err(raw_error);
        assert!(matches!(error, UserApiError::VmmError(_)));

        let raw_error = RawFwError(0x0u64);
        let error = map_fw_err(raw_error);
        assert!(matches!(
            error,
            UserApiError::FirmwareError(FirmwareError::UnknownSevError(0))
        ));
    }
}
