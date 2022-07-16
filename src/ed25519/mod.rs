use base64::URL_SAFE_NO_PAD;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{Deserialize, Serialize};

use crate::protocol::{KeyUse, PrivateKey, PublicKey};
use crate::sign;

mod ed25519_sign;

pub use ed25519_sign::EddsaKeyGen;

pub const EDDSA_ALGORITHM: &str = "EdDSA";

#[derive(Clone)]
pub struct Ed25519PrivateKey {
    key_id: &'static str,
    pkcs8_bytes: Vec<u8>,
}

impl Ed25519PrivateKey {
    fn new(key_id: &'static str, pkcs8_bytes: &[u8]) -> Self {
        Self {
            key_id,
            pkcs8_bytes: pkcs8_bytes.to_vec(),
        }
    }
}

impl PrivateKey for Ed25519PrivateKey {
    fn key_id(&self) -> &str {
        self.key_id
    }

    fn algorithm(&self) -> &str {
        EDDSA_ALGORITHM
    }

    fn to_encoding_key(&self) -> sign::Result<EncodingKey> {
        Ok(EncodingKey::from_ed_der(&self.pkcs8_bytes))
    }
}

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

    fn to_decoding_key(
        &self,
    ) -> std::result::Result<jsonwebtoken::DecodingKey, crate::verify::Error> {
        Ok(DecodingKey::from_ed_der(&self.x))
    }
}

impl Ed25519PublicKey {
    fn new(x: Vec<u8>) -> Self {
        Self {
            key_id: "aky".to_owned(),
            x,
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct JWK {
    kid: String,
    kty: String,
    crv: String,
    x: String,
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
            kty: "OKP".to_owned(),
            crv: "Ed25519".to_owned(),
            x: base64::encode_config(&k.x, URL_SAFE_NO_PAD),
        }
    }
}

impl TryFrom<&JWK> for Ed25519PublicKey {
    type Error = crate::verify::Error;

    fn try_from(jwk: &JWK) -> std::result::Result<Self, Self::Error> {
        Ok(Ed25519PublicKey {
            key_id: jwk.kid.clone(),
            x: base64::decode_config(&jwk.x, URL_SAFE_NO_PAD)?,
        })
    }
}
