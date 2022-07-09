use base64::URL_SAFE_NO_PAD;
use jsonwebtoken::EncodingKey;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{ser::SerializeMap, Serialize};

use crate::protocol::{AttenuationKeyGenerator, KeyUse, PrivateKey, PublicKey};

use super::Result;

const EDDSA_ALGORITHM: &str = "EdDSA";

#[derive(Clone)]
struct EddsaKeyGen;

impl AttenuationKeyGenerator<Ed25519PublicKey, Ed25519PrivateKey> for EddsaKeyGen {
    fn generate_attenuation_key(&self) -> Result<(Ed25519PublicKey, Ed25519PrivateKey)> {
        use ring::rand::SystemRandom;

        let rng = SystemRandom::new();
        let pkcs8_bytes = Ed25519KeyPair::generate_pkcs8(&rng)?;
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
        let pub_key = Ed25519PublicKey::new(key_pair.public_key().as_ref().to_vec());
        let priv_key = Ed25519PrivateKey::new("aky", pkcs8_bytes.as_ref());
        Ok((pub_key, priv_key))
    }
}

struct Ed25519PrivateKey {
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
        &self.key_id
    }

    fn algorithm(&self) -> &str {
        EDDSA_ALGORITHM
    }

    fn to_encoding_key(&self) -> Result<EncodingKey> {
        Ok(EncodingKey::from_ec_pem(&self.pkcs8_bytes)?)
    }
}

struct Ed25519PublicKey {
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
        todo!()
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

impl Serialize for Ed25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("kty", "OKP")?;
        map.serialize_entry("crv", "Ed25519")?;
        map.serialize_entry("x", &base64::encode_config(&self.x, URL_SAFE_NO_PAD))?;
        map.end()
    }
}
