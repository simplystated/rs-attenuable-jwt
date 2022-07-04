use std::borrow::Cow;

use base64::URL_SAFE_NO_PAD;
use jsonwebtoken::EncodingKey;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::{ser::SerializeMap, Serialize};

use super::{AttenuableJWT, KeyGen, PrivateKey, PublicKey, Result, SignedJWT};

impl<'a> AttenuableJWT<'a, EddsaKeyGen> {
    /// Constructs an AttenuableJWT from a chain of signed JWTs and a private_attenuation_key, using the default [KeyGen].
    /// Invariant: the private_attenuation_key must be the private key corresponding to the public key found in
    /// `jwts.last().unwrap().claim("aky")`.
    pub fn with(
        jwts: Vec<SignedJWT>,
        private_attenuation_key: <EddsaKeyGen as KeyGen>::Priv,
    ) -> Self {
        Self::with_keygen(Cow::Owned(EddsaKeyGen), jwts, private_attenuation_key)
    }

    /// Constructs a new AttenuableJWT with the given root_key and claims, using the default [KeyGen].
    /// The `root_key` will be used to sign this initial JWT.
    /// `claims` will be augmented with an `aky` claim containing the public counterpart to the `private_attenuation_key`
    /// in the returned AttenuableJWT.
    pub fn new<Claims: Serialize>(
        root_key: &<EddsaKeyGen as KeyGen>::Priv,
        claims: Claims,
    ) -> Result<Self> {
        Self::new_with_keygen(Cow::Owned(EddsaKeyGen), root_key, claims)
    }
}

#[derive(Clone)]
struct EddsaKeyGen;

impl KeyGen for EddsaKeyGen {
    type Pub = Ed25519PublicKey;
    type Priv = Ed25519PrivateKey;

    fn generate_key(&self) -> Result<(Ed25519PublicKey, Ed25519PrivateKey)> {
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
        "EdDSA"
    }

    fn to_encoding_key(&self) -> Result<EncodingKey> {
        Ok(EncodingKey::from_ec_pem(&self.pkcs8_bytes)?)
    }
}

struct Ed25519PublicKey {
    x: Vec<u8>,
}

impl PublicKey for Ed25519PublicKey {}

impl Ed25519PublicKey {
    fn new(x: Vec<u8>) -> Self {
        Self { x }
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
