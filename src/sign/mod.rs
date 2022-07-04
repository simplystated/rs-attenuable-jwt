use std::{borrow::Cow, str::FromStr};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;

mod ed25519;
mod error;

use error::Result;

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

impl<'a, KG: KeyGen> AttenuableJWT<'a, KG> {
    /// Constructs an AttenuableJWT from a chain of signed JWTs and a private_attenuation_key, using the provided [KeyGen].
    /// Invariant: the private_attenuation_key must be the private key corresponding to the public key found in
    /// `jwts.last().unwrap().claim("aky")`.
    pub fn with_keygen(
        key_gen: Cow<'a, KG>,
        jwts: Vec<SignedJWT>,
        private_attenuation_key: KG::Priv,
    ) -> Self {
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
    pub fn new_with_keygen<Claims: Serialize>(
        key_gen: Cow<'a, KG>,
        root_key: &KG::Priv,
        claims: Claims,
    ) -> Result<Self> {
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
            private_attenuation_key: priv_key,
        })
    }

    /// Create a new AttenuableJWT that has all of the claims from this AttenuableJWT and also
    /// carries the provided claims. When verifying, clients can ensure that the provided claims only restrict the existing
    /// claims.
    pub fn attenuate<Claims: Serialize>(&self, claims: Claims) -> Result<Self> {
        let mut attenuated =
            Self::new_with_keygen(self.key_gen.clone(), &self.private_attenuation_key, claims)?;
        attenuated.jwts = self
            .jwts
            .iter()
            .cloned()
            .chain(attenuated.jwts.into_iter())
            .collect();
        Ok(attenuated)
    }

    /// Sign the full package of jwts that we have accumulated with the final attenuation key.
    /// This creates a usable, verifiable attenuated JWT.
    /// It contains a single claim, `jwts`, which contains an array of signed JWTs, starting from the root JWT
    /// and ending with the most attenuated JWT.
    /// This JWT should be verified with the key in the `aky` claim of the final JWT in `jwts`.
    pub fn seal(&self) -> Result<SignedJWT> {
        let header = {
            let mut header = Header::new(Algorithm::from_str(
                &self.private_attenuation_key.algorithm(),
            )?);
            header.kid = Some(self.private_attenuation_key.key_id().to_owned());
            header
        };
        let claims = SealedClaims {
            jwts: self.jwts.as_slice(),
        };

        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &self.private_attenuation_key.to_encoding_key()?,
        )?;

        Ok(SignedJWT(token))
    }
}

#[derive(Serialize)]
struct SealedClaims<'a> {
    jwts: &'a [SignedJWT],
}

#[derive(Serialize)]
struct FullClaims<JWK: Serialize, Claims: Serialize> {
    #[serde(flatten)]
    pub user_provided_claims: Claims,
    #[serde(flatten)]
    pub aky: JWK,
}

#[derive(Clone, Serialize)]
#[serde(transparent)]
pub struct SignedJWT(pub String);

/// A private key
pub trait PrivateKey {
    fn key_id(&self) -> &str;
    fn algorithm(&self) -> &str;
    fn to_encoding_key(&self) -> Result<EncodingKey>;
}

/// A public key. The [Serialize] implementation must serialize to a JWK.
pub trait PublicKey: Serialize {}

pub trait KeyGen: Clone {
    type Pub: PublicKey;
    type Priv: PrivateKey;

    fn generate_key(&self) -> Result<(Self::Pub, Self::Priv)>;
}
