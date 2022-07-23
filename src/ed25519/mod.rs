//! Module containing [crate::protocol::PrivateKey] and [crate::protocol::PublicKey] implementations for the
//! ed25519 algorithm.

use base64::URL_SAFE_NO_PAD;
use ring::signature::Ed25519KeyPair;
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::protocol::{KeyUse, PrivateKey, PublicKey};

mod ed25519_sign;

pub use ed25519_sign::EddsaKeyGen;

/// Algorithm identifier for the EdDSA (ED25519) algorithm.
pub const EDDSA_ALGORITHM: &str = "EdDSA";

/// Private key for the ed25519 algorithm.
#[derive(Serialize, Clone, ZeroizeOnDrop)]
#[serde(into = "JWK")]
pub struct Ed25519PrivateKey {
    key_id: String,
    pkcs8_bytes: Vec<u8>,
}

impl Ed25519PrivateKey {
    /// Create an ed25519 private key.
    fn new(key_id: String, pkcs8_bytes: &[u8]) -> Self {
        Self {
            key_id,
            pkcs8_bytes: pkcs8_bytes.to_vec(),
        }
    }
}

impl PrivateKey for Ed25519PrivateKey {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn algorithm(&self) -> &str {
        EDDSA_ALGORITHM
    }

    fn sign(&self, message: &[u8]) -> crate::sign::Result<Vec<u8>> {
        let key_pair = Ed25519KeyPair::from_pkcs8(&self.pkcs8_bytes)
            .map_err(|_| crate::sign::Error::CryptoError)?;
        Ok(key_pair.sign(message).as_ref().iter().map(|u| *u).collect())
    }
}

/// Public key for the ed25519 algorithm.
#[derive(Serialize, Clone)]
#[serde(into = "JWK")]
pub struct Ed25519PublicKey {
    key_id: String,
    x: Vec<u8>,
}

impl PublicKey for Ed25519PublicKey {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn algorithm(&self) -> &str {
        EDDSA_ALGORITHM
    }

    fn key_use(&self) -> KeyUse {
        KeyUse::Signing
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let public_key =
            ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &self.x);
        let res = public_key.verify(message, signature);
        res.is_ok()
    }
}

impl Ed25519PublicKey {
    /// Create a public key for the ed25519 algorithm.
    fn new(x: Vec<u8>) -> Self {
        Self {
            key_id: "aky".to_owned(),
            x,
        }
    }
}

/// JWK for [Ed25519PublicKey]s and [Ed25519PrivateKey]s.
#[derive(Clone, Serialize, Deserialize)]
pub struct JWK {
    /// Key ID.
    pub kid: String,
    /// Key use.
    #[serde(rename = "use")]
    pub key_use: KeyUse,
    /// Key operations.
    pub key_ops: Vec<KeyOp>,
    /// Algorithm.
    pub alg: String,
    /// Key type.
    pub kty: String,
    /// Curve.
    pub crv: String,
    /// Public key component.
    pub x: String,
    /// Private key component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

/// Key operation.
#[derive(Clone, Serialize, Deserialize)]
pub enum KeyOp {
    /// Sign.
    #[serde(rename = "sign")]
    Sign,
    /// Verify.
    #[serde(rename = "verify")]
    Verify,
}

impl From<Ed25519PublicKey> for JWK {
    fn from(k: Ed25519PublicKey) -> Self {
        Self::from(&k)
    }
}

impl From<&Ed25519PublicKey> for JWK {
    fn from(k: &Ed25519PublicKey) -> Self {
        JWK {
            kid: k.key_id.clone(),
            key_use: KeyUse::Signing,
            key_ops: vec![KeyOp::Verify],
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            alg: "EdDSA".to_owned(),
            x: base64::encode_config(&k.x, URL_SAFE_NO_PAD),
            d: None,
        }
    }
}

impl From<Ed25519PrivateKey> for JWK {
    fn from(k: Ed25519PrivateKey) -> Self {
        Self::from(&k)
    }
}

impl From<&Ed25519PrivateKey> for JWK {
    fn from(k: &Ed25519PrivateKey) -> Self {
        JWK {
            kid: k.key_id.to_owned(),
            key_use: KeyUse::Signing,
            key_ops: vec![KeyOp::Sign],
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            alg: "EdDSA".to_owned(),
            x: base64::encode_config(
                &k.pkcs8_bytes.as_slice()[0..ring::signature::ED25519_PUBLIC_KEY_LEN],
                URL_SAFE_NO_PAD,
            ),
            d: Some(base64::encode_config(
                &k.pkcs8_bytes.as_slice()[ring::signature::ED25519_PUBLIC_KEY_LEN..],
                URL_SAFE_NO_PAD,
            )),
        }
    }
}

impl TryFrom<&JWK> for Ed25519PublicKey {
    type Error = crate::verify::Error;

    fn try_from(jwk: &JWK) -> std::result::Result<Self, Self::Error> {
        Ok(Ed25519PublicKey {
            key_id: jwk.kid.clone(),
            x: base64::decode_config(&jwk.x, URL_SAFE_NO_PAD)
                .map_err(|_| crate::verify::Error::MalformedAttenuationKeyJWK)?,
        })
    }
}

impl TryFrom<&JWK> for Ed25519PrivateKey {
    type Error = crate::verify::Error;

    fn try_from(jwk: &JWK) -> std::result::Result<Self, Self::Error> {
        if let Some(d) = &jwk.d {
            let x = base64::decode_config(&jwk.x, URL_SAFE_NO_PAD)
                .map_err(|_| crate::verify::Error::MalformedAttenuationKeyJWK)?;
            let d = base64::decode_config(d, URL_SAFE_NO_PAD)
                .map_err(|_| crate::verify::Error::MalformedAttenuationKeyJWK)?;
            let pkcs8_bytes = x.into_iter().chain(d.into_iter()).collect();
            Ok(Ed25519PrivateKey {
                key_id: jwk.kid.clone(),
                pkcs8_bytes,
            })
        } else {
            Err(crate::verify::Error::InvalidKey)
        }
    }
}

#[cfg(test)]
mod test {
    use crate::{ed25519::Ed25519PrivateKey, protocol::AttenuationKeyGenerator};

    use super::{Ed25519PublicKey, EddsaKeyGen, JWK};

    #[test]
    fn test_private_key_jwk() -> Result<(), Box<dyn std::error::Error>> {
        let (_, priv_key) = EddsaKeyGen.generate_attenuation_key()?;
        let jwk = JWK::from(&priv_key);
        let round_trip = Ed25519PrivateKey::try_from(&jwk)?;
        assert_eq!(&priv_key.pkcs8_bytes, &round_trip.pkcs8_bytes);
        assert_eq!(&priv_key.key_id, &round_trip.key_id);
        Ok(())
    }

    #[test]
    fn test_public_key_jwk() -> Result<(), Box<dyn std::error::Error>> {
        let (pub_key, _) = EddsaKeyGen.generate_attenuation_key()?;
        let jwk = JWK::from(&pub_key);
        let round_trip = Ed25519PublicKey::try_from(&jwk)?;
        assert_eq!(&pub_key.key_id, &round_trip.key_id);
        assert_eq!(&pub_key.x, &round_trip.x);
        Ok(())
    }
}
