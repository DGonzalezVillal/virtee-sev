// SPDX-License-Identifier: Apache-2.0

#[cfg(target_os = "linux")]
use crate::attestation::endorser::sev::sev;

#[cfg(target_os = "linux")]
use std::marker::PhantomData;

/// Generate a new Platform Endorsement Key (PEK).
///
/// (Chapter 5.7)
#[cfg(target_os = "linux")]
pub struct PekGen;

/// Request certificate signing.
///
/// (Chapter 5.8; Table 27)
#[repr(C, packed)]
#[cfg(target_os = "linux")]
pub struct PekCsr<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a ()>,
}

#[cfg(target_os = "linux")]
impl<'a> PekCsr<'a> {
    pub fn new(cert: &'a mut sev::Certificate) -> Self {
        Self {
            addr: cert as *mut _ as _,
            len: std::mem::size_of_val(cert) as _,
            _phantom: PhantomData,
        }
    }
}

/// Join the platform to the domain.
///
/// (Chapter 5.9; Table 29)
#[cfg(target_os = "linux")]
#[repr(C, packed)]
pub struct PekCertImport<'a> {
    pek_addr: u64,
    pek_len: u32,
    oca_addr: u64,
    oca_len: u32,
    _phantom: PhantomData<&'a ()>,
}

#[cfg(target_os = "linux")]
impl<'a> PekCertImport<'a> {
    pub fn new(pek: &'a sev::Certificate, oca: &'a sev::Certificate) -> Self {
        Self {
            pek_addr: pek as *const _ as _,
            pek_len: std::mem::size_of_val(pek) as _,
            oca_addr: oca as *const _ as _,
            oca_len: std::mem::size_of_val(oca) as _,
            _phantom: PhantomData,
        }
    }
}

/// (Re)generate the Platform Diffie-Hellman (PDH).
///
/// (Chapter 5.10)
#[cfg(target_os = "linux")]
pub struct PdhGen;

/// Retrieve the PDH and the platform certificate chain.
///
/// (Chapter 5.11)
#[cfg(target_os = "linux")]
#[repr(C, packed)]
pub struct PdhCertExport<'a> {
    pdh_addr: u64,
    pdh_len: u32,
    certs_addr: u64,
    certs_len: u32,
    _phantom: PhantomData<&'a ()>,
}

#[cfg(target_os = "linux")]
impl<'a> PdhCertExport<'a> {
    pub fn new(pdh: &'a mut sev::Certificate, certs: &'a mut [sev::Certificate; 3]) -> Self {
        Self {
            pdh_addr: pdh as *mut _ as _,
            pdh_len: std::mem::size_of_val(pdh) as _,
            certs_addr: certs.as_mut_ptr() as _,
            certs_len: std::mem::size_of_val(certs) as _,
            _phantom: PhantomData,
        }
    }
}
