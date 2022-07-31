use base64::URL_SAFE_NO_PAD;
use serde::Serialize;

use crate::{
    sign::{Error, Result},
    PrivateKey, SignedJWT,
};

/// Encode a JWT with the given `header` and `claims`, signed with the given `signing_key`.
/// Only exposed for integration testing.
pub fn encode_jwt<Claims: Serialize, JWTHeader: Serialize, PrivKey: PrivateKey + ?Sized>(
    header: &JWTHeader,
    claims: &Claims,
    signing_key: &PrivKey,
) -> Result<SignedJWT> {
    let header_bytes =
        serde_json::to_vec(&header).map_err(|err| Error::SerializationError(Box::new(err)))?;
    let claims_bytes =
        serde_json::to_vec(&claims).map_err(|err| Error::SerializationError(Box::new(err)))?;
    let header_b64 = base64::encode_config(&header_bytes, URL_SAFE_NO_PAD);
    let claims_b64 = base64::encode_config(&claims_bytes, URL_SAFE_NO_PAD);
    let message: Vec<_> = header_b64
        .as_bytes()
        .iter()
        .chain(".".as_bytes())
        .chain(claims_b64.as_bytes())
        .copied()
        .collect();
    let signature = signing_key.sign(&message)?;
    let signature_b64 = base64::encode_config(&signature, URL_SAFE_NO_PAD);
    let mut jwt = header_b64;
    jwt.push('.');
    jwt.push_str(&claims_b64);
    jwt.push('.');
    jwt.push_str(&signature_b64);
    Ok(SignedJWT(jwt))
}
