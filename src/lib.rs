use std::{borrow::Cow, str::FromStr};

use base64::URL_SAFE_NO_PAD;
use jsonwebtoken::{Header, Algorithm, EncodingKey};
use ring::signature::{KeyPair, Ed25519KeyPair};
use serde::{Serialize, ser::SerializeMap};
use thiserror::Error;

/// An AttenuableJWT carries a set of immutable claims but allows for the creation of a JWT with an attenuated
/// set of claims.
/// 
/// ```
/// let ajwt = AttenuableJWT::with(jwts, key);
/// let attenuated = ajwt.attenuate(&[("allowed-service", "something")])
/// let sealed = attenuated.seal();
/// ```
pub struct AttenuableJWT<'a, KG: KeyGen> {
    key_gen: Cow<'a, KG>,
    jwts: Vec<SignedJWT>,
    private_attenuation_key: KG::Priv,
}

impl <'a> AttenuableJWT<'a, EddsaKeyGen> {
    /// Constructs an AttenuableJWT from a chain of signed JWTs and a private_attenuation_key, using the default [KeyGen].
    /// Invariant: the private_attenuation_key must be the private key corresponding to the public key found in
    /// `jwts.last().unwrap().claim("aky")`.
    pub fn with(jwts: Vec<SignedJWT>, private_attenuation_key: <EddsaKeyGen as KeyGen>::Priv) -> Self {
        Self::with_keygen(Cow::Owned(EddsaKeyGen), jwts, private_attenuation_key)
    }

    /// Constructs a new AttenuableJWT with the given root_key and claims, using the default [KeyGen].
    /// The `root_key` will be used to sign this initial JWT.
    /// `claims` will be augmented with an `aky` claim containing the public counterpart to the `private_attenuation_key`
    /// in the returned AttenuableJWT.
    pub fn new<Claims: Serialize>(root_key: <EddsaKeyGen as KeyGen>::Priv, claims: Claims) -> Result<Self> {
        Self::new_with_keygen(Cow::Owned(EddsaKeyGen), root_key, claims)
    }
}

impl<'a, KG: KeyGen> AttenuableJWT<'a, KG> {
    /// Constructs an AttenuableJWT from a chain of signed JWTs and a private_attenuation_key, using the provided [KeyGen].
    /// Invariant: the private_attenuation_key must be the private key corresponding to the public key found in
    /// `jwts.last().unwrap().claim("aky")`.
    pub fn with_keygen(key_gen: Cow<'a, KG>, jwts: Vec<SignedJWT>, private_attenuation_key: KG::Priv) -> Self {
        Self {
            key_gen,
            jwts,
            private_attenuation_key,
        }
    }

    /// Constructs a new AttenuableJWT with the given root_key and claims, using the provided [KeyGen].
    /// The `root_key` will be used to sign this initial JWT.
    /// `claims` will be augmented with an `aky` claim containing the public counterpart to the `private_attenuation_key`
    /// in the returned AttenuableJWT.
    pub fn new_with_keygen<Claims: Serialize>(key_gen: Cow<'a, KG>, root_key: KG::Priv, claims: Claims) -> Result<Self> {
        let (pub_key, priv_key) = key_gen.generate_key()?;
        let full_claims = FullClaims {
            user_provided_claims: claims,
            aky: &pub_key,
        };
        let header = {
            let mut header = Header::new(Algorithm::from_str(&root_key.algorithm())?);
            header.kid = Some(root_key.key_id().to_owned());
            header
        };

        let token = jsonwebtoken::encode(&header, &full_claims, &root_key.to_encoding_key()?)?;

        Ok(Self {
            key_gen,
            jwts: vec![SignedJWT(token)],
            private_attenuation_key: priv_key
        })
    }
}

#[derive(Serialize)]
struct FullClaims<JWK: Serialize, Claims: Serialize> {
    #[serde(flatten)]
    pub user_provided_claims: Claims,
    #[serde(flatten)]
    pub aky: JWK,
}

pub struct SignedJWT(pub String);

/// A private key
pub trait PrivateKey {
    fn key_id(&self) -> &str;
    fn algorithm(&self) -> &str;
    fn to_encoding_key(&self) -> Result<EncodingKey>;
}

/// A public key. The [Serialize] implementation must serialize to a JWK.
pub trait PublicKey: Serialize { }

pub trait KeyGen: Clone {
    type Pub: PublicKey;
    type Priv: PrivateKey;

    fn generate_key(&self) -> Result<(Self::Pub, Self::Priv)>;
}

#[derive(Clone)]
struct EddsaKeyGen;

impl KeyGen for EddsaKeyGen {
    type Pub = Ed25519PublicKey;
    type Priv = Ed25519PrivateKey;

    fn generate_key(&self) -> Result<(Ed25519PublicKey, Ed25519PrivateKey)> {
        use ring::{rand::SystemRandom};

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
        Self {
            x,
        }
    }
}

impl Serialize for Ed25519PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("kty", "OKP")?;
        map.serialize_entry("crv", "Ed25519")?;
        map.serialize_entry("x", &base64::encode_config(&self.x, URL_SAFE_NO_PAD))?;
        map.end()
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("jwt error")]
    JWTError(#[from] jsonwebtoken::errors::Error),
    #[error("key error")]
    KeyError(#[from] ring::error::KeyRejected),
    #[error("crypto error")]
    CryptoError(#[from] ring::error::Unspecified),
}

pub type Result<R> = std::result::Result<R, Error>;
