use std::{borrow::Cow, str::FromStr};

use jsonwebtoken::{Algorithm, Header};

pub mod ed25519;
mod error;

pub use error::Error;
use error::Result;

use crate::protocol::{
    Audience, Issuer, PrivateKey, SealedClaims, SecondsSinceEpoch, SignedJWT, SigningKeyManager,
};

/// An AttenuableJWT carries a set of immutable claims but allows for the creation of a JWT with an attenuated
/// set of claims.
///
/// ```
/// use std::{borrow::Cow, collections::HashMap};
/// use attenuable_jwt::{protocol::{AttenuationKeyGenerator, SigningKeyManager, SecondsSinceEpoch, Issuer}, sign::{ed25519, Error, AttenuableJWT}};
///
/// #[derive(Clone)]
/// struct KeyManager;
///
/// impl AttenuationKeyGenerator<ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey> for KeyManager {
///     fn generate_attenuation_key(
///         &self,
///     ) -> Result<(ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey), Error> {
///         ed25519::EddsaKeyGen.generate_attenuation_key()
///     }
/// }
///
/// impl SigningKeyManager for KeyManager {
///     type JWK = ed25519::JWK;
///
///     type PublicAttenuationKey = ed25519::Ed25519PublicKey;
///
///     type PrivateAttenuationKey = ed25519::Ed25519PrivateKey;
///
///     type PrivateRootKey = ed25519::Ed25519PrivateKey;
///
///     type Claims = HashMap<String, String>;
///
///     fn jwk_for_public_attenuation_key(
///         public_attenuation_key: &Self::PublicAttenuationKey,
///     ) -> Self::JWK {
///         public_attenuation_key.into()
///     }
/// }
///
/// let claims = {
///     let mut claims = HashMap::new();
///     claims.insert("sub".to_owned(), "itsme".to_owned());
///     claims
/// };
/// let key_manager = KeyManager;
/// let (pub_key, priv_key) = key_manager.generate_attenuation_key().unwrap();
/// let ajwt: AttenuableJWT<'_, KeyManager> = AttenuableJWT::new_with_key_manager(Cow::Owned(key_manager), &priv_key, claims).unwrap();
/// let attenuated_claims = {
///     let mut claims = HashMap::new();
///     claims.insert("aud".to_owned(), "restricted-audience".to_owned());
///     claims
/// };
/// let attenuated = ajwt.attenuate(attenuated_claims).unwrap();
/// let sealed = attenuated.seal(SecondsSinceEpoch(0), SecondsSinceEpoch(0), Some(Issuer("my-issuer".to_owned())), None).unwrap();
/// ```
pub struct AttenuableJWT<'a, SKM: SigningKeyManager> {
    key_manager: Cow<'a, SKM>,
    jwts: Vec<SignedJWT>,
    private_attenuation_key: SKM::PrivateAttenuationKey,
}

impl<'a, SKM: SigningKeyManager> AttenuableJWT<'a, SKM> {
    /// Constructs an AttenuableJWT from a chain of signed JWTs and a private_attenuation_key, using the provided [crate::protocol::SigningKeyManager].
    /// Invariant: the private_attenuation_key must be the private key corresponding to the public key found in
    /// `jwts.last().unwrap().claim("aky")`.
    pub fn with_key_manager(
        key_manager: Cow<'a, SKM>,
        jwts: Vec<SignedJWT>,
        private_attenuation_key: SKM::PrivateAttenuationKey,
    ) -> Self {
        Self {
            key_manager,
            jwts,
            private_attenuation_key,
        }
    }

    /// Constructs a new AttenuableJWT with the given root_key and claims, using the provided [crate::protocol::AttenuationKeyGenerator].
    /// The `root_key` will be used to sign this initial JWT.
    /// `claims` will be augmented with an `aky` claim containing the public counterpart to the `private_attenuation_key`
    /// in the returned AttenuableJWT.
    pub fn new_with_key_manager<RootKey: PrivateKey>(
        key_manager: Cow<'a, SKM>,
        root_key: &RootKey,
        claims: SKM::Claims,
    ) -> Result<Self> {
        let (pub_key, priv_key) = key_manager.generate_attenuation_key()?;
        let full_claims = SKM::claims_with_attenuation_key(claims, &pub_key);
        let header = {
            let mut header = Header::new(Algorithm::from_str(&root_key.algorithm())?);
            header.kid = Some(root_key.key_id().to_owned());
            header
        };

        let token = jsonwebtoken::encode(&header, &full_claims, &root_key.to_encoding_key()?)?;

        Ok(Self {
            key_manager,
            jwts: vec![SignedJWT(token)],
            private_attenuation_key: priv_key,
        })
    }

    /// Create a new AttenuableJWT that has all of the claims from this AttenuableJWT and also
    /// carries the provided claims. When verifying, clients can ensure that the provided claims only restrict the existing
    /// claims.
    pub fn attenuate(&self, claims: SKM::Claims) -> Result<Self> {
        let mut attenuated = Self::new_with_key_manager(
            self.key_manager.clone(),
            &self.private_attenuation_key,
            claims,
        )?;
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
    /// It contains the standard claims if provided and a claim, `jwts`,
    /// which contains an array of signed JWTs, starting from the root JWT
    /// and ending with the most attenuated JWT.
    /// This JWT should be verified with the key in the `aky` claim of the final JWT in `jwts`.
    pub fn seal(
        &self,
        expiration: SecondsSinceEpoch,
        not_before: SecondsSinceEpoch,
        issuer: Option<Issuer>,
        audience: Option<Audience>,
    ) -> Result<SignedJWT> {
        let header = {
            let mut header = Header::new(Algorithm::from_str(
                &self.private_attenuation_key.algorithm(),
            )?);
            header.kid = Some(self.private_attenuation_key.key_id().to_owned());
            header
        };
        let claims = SealedClaims {
            jwts: self.jwts.clone(),
            exp: Some(expiration),
            nbf: Some(not_before),
            iss: issuer.map(|iss| iss.to_owned()),
            aud: audience.map(|aud| aud.to_owned()),
        };

        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &self.private_attenuation_key.to_encoding_key()?,
        )?;

        Ok(SignedJWT(token))
    }
}
