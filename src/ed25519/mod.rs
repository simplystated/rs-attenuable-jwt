//! Module containing [crate::protocol::PrivateKey] and [crate::protocol::PublicKey] implementations for the
//! ed25519 algorithm.

use std::convert::TryInto;

use base64::URL_SAFE_NO_PAD;
use ed25519_dalek::{
    Keypair as Ed25519DalekKeyPair, PublicKey as Ed25519DalekPublicKey,
    SecretKey as Ed25519DalekSecretKey, Signer, Verifier,
};
use serde::{Deserialize, Serialize};

use crate::protocol::{KeyUse, PrivateKey, PublicKey};

mod ed25519_sign;

pub use ed25519_sign::EddsaKeyGen;

/// Algorithm identifier for the EdDSA (ED25519) algorithm.
pub const EDDSA_ALGORITHM: &str = "EdDSA";

/// Private key for the ed25519 algorithm.
#[derive(Serialize, Deserialize)]
#[serde(into = "JWK", try_from = "JWK")]
pub struct Ed25519PrivateKey {
    key_id: String,
    private_key: Ed25519DalekKeyPair,
}

impl Clone for Ed25519PrivateKey {
    fn clone(&self) -> Self {
        Self {
            key_id: self.key_id.clone(),
            private_key: Ed25519DalekKeyPair::from_bytes(&self.private_key.to_bytes()).unwrap(),
        }
    }
}

impl std::fmt::Debug for Ed25519PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ed25519PrivateKey")
            .field("key_id", &self.key_id)
            .field("private_key", &"***")
            .finish()
    }
}

impl Ed25519PrivateKey {
    /// Create an ed25519 private key.
    fn new(key_id: String, private_key: Ed25519DalekKeyPair) -> Self {
        Self {
            key_id,
            private_key,
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
        Ok(self
            .private_key
            .try_sign(message)
            .map_err(|_| crate::sign::Error::CryptoError)?
            .to_bytes()
            .to_vec())
    }
}

/// Public key for the ed25519 algorithm.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(into = "JWK", try_from = "JWK")]
pub struct Ed25519PublicKey {
    key_id: String,
    public_key: Ed25519DalekPublicKey,
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
        let res = signature
            .try_into()
            .and_then(|signature| self.public_key.verify(message, &signature));
        res.is_ok()
    }
}

impl Ed25519PublicKey {
    /// Create a public key for the ed25519 algorithm.
    fn new(public_key: Ed25519DalekPublicKey) -> Self {
        Self {
            key_id: "aky".to_owned(),
            public_key,
        }
    }
}

/// JWK for [Ed25519PublicKey]s and [Ed25519PrivateKey]s.
#[derive(Clone, Serialize, Deserialize, PartialEq)]
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

impl std::fmt::Debug for JWK {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JWK")
            .field("kid", &self.kid)
            .field("key_use", &self.key_use)
            .field("key_ops", &self.key_ops)
            .field("alg", &self.alg)
            .field("kty", &self.kty)
            .field("crv", &self.crv)
            .field("x", &self.x)
            .field("d", &self.d.as_ref().map(|_| "***"))
            .finish()
    }
}

/// Key operation.
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
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
            x: base64::encode_config(k.public_key.as_bytes(), URL_SAFE_NO_PAD),
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
            x: base64::encode_config(k.private_key.public.as_bytes(), URL_SAFE_NO_PAD),
            d: Some(base64::encode_config(
                k.private_key.secret.as_bytes(),
                URL_SAFE_NO_PAD,
            )),
        }
    }
}

impl TryFrom<JWK> for Ed25519PublicKey {
    type Error = crate::verify::Error;

    fn try_from(value: JWK) -> Result<Self, Self::Error> {
        Ed25519PublicKey::try_from(&value)
    }
}

impl TryFrom<&JWK> for Ed25519PublicKey {
    type Error = crate::verify::Error;

    fn try_from(jwk: &JWK) -> std::result::Result<Self, Self::Error> {
        let x_bytes = base64::decode_config(&jwk.x, URL_SAFE_NO_PAD)
            .map_err(|_| crate::verify::Error::MalformedAttenuationKeyJWK)?;
        let public_key = Ed25519DalekPublicKey::from_bytes(&x_bytes)
            .map_err(|_| crate::verify::Error::MalformedAttenuationKeyJWK)?;
        Ok(Ed25519PublicKey {
            key_id: jwk.kid.clone(),
            public_key,
        })
    }
}

impl TryFrom<JWK> for Ed25519PrivateKey {
    type Error = crate::verify::Error;

    fn try_from(jwk: JWK) -> std::result::Result<Self, Self::Error> {
        Ed25519PrivateKey::try_from(&jwk)
    }
}

impl TryFrom<&JWK> for Ed25519PrivateKey {
    type Error = crate::verify::Error;

    fn try_from(jwk: &JWK) -> std::result::Result<Self, Self::Error> {
        if let Some(d) = &jwk.d {
            let x_bytes = base64::decode_config(&jwk.x, URL_SAFE_NO_PAD)
                .map_err(|_| crate::verify::Error::MalformedAttenuationKeyJWK)?;
            let public = Ed25519DalekPublicKey::from_bytes(&x_bytes)
                .map_err(|_| crate::verify::Error::MalformedAttenuationKeyJWK)?;
            let d_bytes = base64::decode_config(d, URL_SAFE_NO_PAD)
                .map_err(|_| crate::verify::Error::MalformedAttenuationKeyJWK)?;
            let secret = Ed25519DalekSecretKey::from_bytes(&d_bytes)
                .map_err(|_| crate::verify::Error::MalformedAttenuationKeyJWK)?;
            let keypair = Ed25519DalekKeyPair { public, secret };
            Ok(Ed25519PrivateKey {
                key_id: jwk.kid.clone(),
                private_key: keypair,
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
        let kg = EddsaKeyGen::new_with_std_rng();
        let (_, priv_key) = kg.generate_attenuation_key()?;
        let jwk = JWK::from(&priv_key);
        let round_trip = Ed25519PrivateKey::try_from(&jwk)?;
        assert_eq!(
            priv_key.private_key.to_bytes(),
            round_trip.private_key.to_bytes()
        );
        assert_eq!(&priv_key.key_id, &round_trip.key_id);
        Ok(())
    }

    #[test]
    fn test_public_key_jwk() -> Result<(), Box<dyn std::error::Error>> {
        let kg = EddsaKeyGen::new_with_std_rng();
        let (pub_key, _) = kg.generate_attenuation_key()?;
        let jwk = JWK::from(&pub_key);
        let round_trip = Ed25519PublicKey::try_from(&jwk)?;
        assert_eq!(
            pub_key.public_key.as_bytes(),
            round_trip.public_key.as_bytes()
        );
        assert_eq!(&pub_key.key_id, &round_trip.key_id);
        Ok(())
    }
}
