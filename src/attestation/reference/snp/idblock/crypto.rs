// SPDX-License-Identifier: Apache-2.0

//! OpenSSL conversions for SNP ID block wire types.

use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey},
    ecdsa::EcdsaSig,
    md::Md,
    md_ctx::MdCtx,
    nid::Nid,
    pkey::{PKey, Private},
};

use std::convert::{TryFrom, TryInto};

use crate::{
    error::IdBlockError,
    snp::types::{SevEcdsaKeyData, SevEcdsaPubKey, SevEcdsaSig, CURVE_P384, ECDSA_POINT_SIZE_BYTES},
};

const CURVE_P384_NID: Nid = Nid::SECP384R1;

impl TryFrom<(EcKey<Private>, &[u8])> for SevEcdsaSig {
    type Error = IdBlockError;

    fn try_from((priv_key, data): (EcKey<Private>, &[u8])) -> Result<Self, Self::Error> {
        let mut ctx = MdCtx::new().map_err(IdBlockError::CryptoErrorStack)?;

        let pkey = PKey::try_from(priv_key).map_err(IdBlockError::CryptoErrorStack)?;

        ctx.digest_sign_init::<Private>(Some(Md::sha384()), pkey.as_ref())
            .map_err(IdBlockError::CryptoErrorStack)?;

        let sig_size = ctx
            .digest_sign(data, None)
            .map_err(IdBlockError::CryptoErrorStack)?;

        let mut signature = vec![0_u8; sig_size];

        ctx.digest_sign(data, Some(&mut signature))
            .map_err(IdBlockError::CryptoErrorStack)?;

        if signature.len() != sig_size {
            return Err(IdBlockError::SevEcsdsaSigError(
                "Signature is not of the expected length!".to_string(),
            ));
        }

        let ecdsa_sig =
            EcdsaSig::from_der(signature.as_slice()).map_err(IdBlockError::CryptoErrorStack)?;

        let mut pad_r = ecdsa_sig
            .r()
            .to_vec_padded(ECDSA_POINT_SIZE_BYTES as i32)
            .map_err(IdBlockError::CryptoErrorStack)?;
        pad_r.reverse();

        let mut pad_s = ecdsa_sig
            .s()
            .to_vec_padded(ECDSA_POINT_SIZE_BYTES as i32)
            .map_err(IdBlockError::CryptoErrorStack)?;
        pad_s.reverse();

        let r: [u8; ECDSA_POINT_SIZE_BYTES] = pad_r
            .try_into()
            .map_err(|v: Vec<u8>| IdBlockError::BadVectorError(v.len(), ECDSA_POINT_SIZE_BYTES))?;

        let s: [u8; ECDSA_POINT_SIZE_BYTES] = pad_s
            .try_into()
            .map_err(|v: Vec<u8>| IdBlockError::BadVectorError(v.len(), ECDSA_POINT_SIZE_BYTES))?;

        Ok(SevEcdsaSig::from_raw(r, s))
    }
}

impl TryFrom<&EcKey<Private>> for SevEcdsaPubKey {
    type Error = IdBlockError;

    fn try_from(priv_key: &EcKey<Private>) -> Result<Self, Self::Error> {
        let pub_key = priv_key.public_key();

        let mut big_num_ctx = BigNumContext::new().map_err(IdBlockError::CryptoErrorStack)?;

        let curve_group =
            EcGroup::from_curve_name(CURVE_P384_NID).map_err(IdBlockError::CryptoErrorStack)?;

        let mut x = BigNum::new().map_err(IdBlockError::CryptoErrorStack)?;
        let mut y = BigNum::new().map_err(IdBlockError::CryptoErrorStack)?;

        pub_key
            .affine_coordinates(&curve_group, &mut x, &mut y, &mut big_num_ctx)
            .map_err(IdBlockError::CryptoErrorStack)?;

        let mut pad_x = x
            .to_vec_padded(ECDSA_POINT_SIZE_BYTES as i32)
            .map_err(IdBlockError::CryptoErrorStack)?;
        pad_x.reverse();

        let mut pad_y = y
            .to_vec_padded(ECDSA_POINT_SIZE_BYTES as i32)
            .map_err(IdBlockError::CryptoErrorStack)?;
        pad_y.reverse();

        let qx: [u8; ECDSA_POINT_SIZE_BYTES] = pad_x
            .try_into()
            .map_err(|v: Vec<u8>| IdBlockError::BadVectorError(v.len(), ECDSA_POINT_SIZE_BYTES))?;

        let qy: [u8; ECDSA_POINT_SIZE_BYTES] = pad_y
            .try_into()
            .map_err(|v: Vec<u8>| IdBlockError::BadVectorError(v.len(), ECDSA_POINT_SIZE_BYTES))?;

        Ok(SevEcdsaPubKey::new(
            CURVE_P384,
            SevEcdsaKeyData::from_raw(qx, qy),
        ))
    }
}
