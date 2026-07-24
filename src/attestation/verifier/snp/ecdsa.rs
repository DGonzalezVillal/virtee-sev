// SPDX-License-Identifier: Apache-2.0

use crate::attestation::endorser::snp::Certificate;
use crate::attestation::evidence::snp::Signature;
use crate::parser::ByteParser;

use std::convert::TryFrom;
use std::io::{Error, Result};

#[cfg(feature = "openssl")]
use openssl::{bn, ecdsa, ecdsa::EcdsaSig, sha::Sha384};

#[cfg(feature = "openssl")]
use super::openssl::{AsLeBytes, FromLe};

#[cfg(feature = "openssl")]
impl From<ecdsa::EcdsaSig> for Signature {
    #[inline]
    fn from(value: ecdsa::EcdsaSig) -> Self {
        Signature::new(value.r().as_le_bytes(), value.s().as_le_bytes())
    }
}

#[cfg(feature = "openssl")]
impl TryFrom<&Signature> for ecdsa::EcdsaSig {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signature) -> Result<Self> {
        let r = bn::BigNum::from_le(value.r())?;
        let s = bn::BigNum::from_le(value.s())?;
        Ok(ecdsa::EcdsaSig::from_private_components(r, s)?)
    }
}

#[cfg(feature = "crypto_nossl")]
impl TryFrom<&Signature> for p384::ecdsa::Signature {
    type Error = Error;

    #[inline]
    fn try_from(signature: &Signature) -> Result<Self> {
        let r_big_endian: Vec<u8> = signature.r().iter().copied().take(48).rev().collect();
        let s_big_endian: Vec<u8> = signature.s().iter().copied().take(48).rev().collect();

        use p384::elliptic_curve::generic_array::GenericArray;
        p384::ecdsa::Signature::from_scalars(
            GenericArray::clone_from_slice(&r_big_endian),
            GenericArray::clone_from_slice(&s_big_endian),
        )
        .map_err(|e| {
            Error::other(format!(
                "failed to deserialize signature from scalars: {e:?}"
            ))
        })
    }
}

#[cfg(feature = "openssl")]
/// Verify ECDSA signature on attestation report using VEK certificate
pub fn verify_ecdsa_signature(body: &[u8], signature: &[u8], vek: &Certificate) -> Result<()> {
    let sev_sig = Signature::from_bytes(signature)?;

    let sig: EcdsaSig = EcdsaSig::try_from(&sev_sig)?;

    let mut hasher = Sha384::new();
    hasher.update(body);
    let base_digest = hasher.finish();

    let ec = vek.public_key()?.ec_key()?;
    let signed = sig.verify(&base_digest, &ec)?;
    match signed {
        true => Ok(()),
        false => Err(Error::other("VEK does not sign the attestation report")),
    }
}

#[cfg(feature = "crypto_nossl")]
/// Verify ECDSA signature on attestation report using VEK certificate
pub fn verify_ecdsa_signature(body: &[u8], signature: &[u8], vek: &Certificate) -> Result<()> {
    let sev_sig = Signature::from_bytes(signature)?;

    let sig = p384::ecdsa::Signature::try_from(&sev_sig).map_err(|e| {
        Error::other(format!(
            "failed to generate signature from raw bytes: {e:?}"
        ))
    })?;

    use sha2::Digest;
    let base_digest = sha2::Sha384::new_with_prefix(body);
    let verifying_key =
        p384::ecdsa::VerifyingKey::from_sec1_bytes(vek.public_key_sec1()).map_err(|e| {
            Error::other(format!(
                "failed to deserialize public key from sec1 bytes: {e:?}"
            ))
        })?;
    use p384::ecdsa::signature::DigestVerifier;
    verifying_key
        .verify_digest(base_digest, &sig)
        .map_err(|e| Error::other(format!("VEK does not sign the attestation report: {e:?}")))
}

#[cfg(test)]
mod tests {
    use crate::attestation::evidence::snp::Signature;

    #[cfg(feature = "openssl")]
    mod openssl_tests {
        use super::*;
        use openssl::{bn::BigNum, ecdsa};
        use std::convert::TryInto;

        #[test]
        fn test_from_ecdsa_sig() {
            let r = BigNum::from_dec_str("123").unwrap();
            let s = BigNum::from_dec_str("456").unwrap();
            let ecdsa_sig = ecdsa::EcdsaSig::from_private_components(r, s).unwrap();
            let sig: Signature = ecdsa_sig.into();
            assert_ne!(sig.r(), &[0u8; 72]);
            assert_ne!(sig.s(), &[0u8; 72]);
        }

        #[test]
        fn test_try_into_ecdsa_sig() {
            let sig: Signature = Default::default();
            let ecdsa_sig: ecdsa::EcdsaSig = (&sig).try_into().unwrap();
            assert_eq!(ecdsa_sig.r().to_vec(), vec![]);
            assert_eq!(ecdsa_sig.s().to_vec(), vec![]);
        }
    }

    #[cfg(feature = "crypto_nossl")]
    mod crypto_nossl_tests {
        use super::*;
        use std::convert::TryInto;

        #[test]
        #[should_panic]
        fn test_try_into_p384_signature_failure() {
            let signature: Signature = Default::default();

            let _p384_sig: p384::ecdsa::Signature = (&signature).try_into().unwrap();
        }

        #[test]
        fn test_try_into_p384_signature() {
            let sig = Signature::new([1u8; 72], [2u8; 72]);
            let p384_sig: p384::ecdsa::Signature = (&sig).try_into().unwrap();
            assert_eq!(p384_sig.r().to_bytes().as_slice(), &[1u8; 48]);
            assert_eq!(p384_sig.s().to_bytes().as_slice(), &[2u8; 48]);
        }
    }
}
