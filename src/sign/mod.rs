//! This module provides an [AttenuableJWT] struct as the core type for creating and attenuating JWTs.
//! The JWTs created by calling [AttenuableJWT::seal] may be verified by calling [crate::verify::verify].

use std::borrow::Cow;

mod error;
mod jwt;

pub use error::{Error, Result};

use crate::protocol::{
    Audience, FullClaims, Issuer, JWTHeader, PrivateKey, SealedClaims, SecondsSinceEpoch,
    SignedJWT, SigningKeyManager,
};

#[cfg(not(feature = "integration-test"))]
use jwt::encode_jwt;
#[cfg(feature = "integration-test")]
pub use jwt::encode_jwt;

/// An AttenuableJWT carries a set of immutable claims but allows for the creation of a JWT with an attenuated
/// set of claims.
///
/// ```
/// use std::{borrow::Cow, collections::HashMap, str::FromStr};
/// use attenuable_jwt::{AttenuationKeyGenerator, SigningKeyManager, SecondsSinceEpoch, Issuer, sign::{Result, Error, AttenuableJWT}, ed25519};
///
/// #[derive(Clone)]
/// struct KeyManager {
///     key_gen: ed25519::EddsaKeyGen<rand::rngs::StdRng>,
/// }
///
/// impl KeyManager {
///     pub fn new() -> Self {
///         Self {
///             key_gen: ed25519::EddsaKeyGen::new_with_std_rng(),
///         }
///     }
/// }
///
/// impl AttenuationKeyGenerator<ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey> for KeyManager {
///     fn generate_attenuation_key(
///         &self,
///     ) -> Result<(ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey)> {
///         self.key_gen.generate_attenuation_key()
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
/// # fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
/// let claims = {
///     let mut claims = HashMap::new();
///     claims.insert("sub".to_owned(), "itsme".to_owned());
///     claims
/// };
/// let key_manager = KeyManager::new();
/// let (pub_key, priv_key) = key_manager.generate_attenuation_key()?;
/// let ajwt = AttenuableJWT::with_root_key_and_claims(Cow::Borrowed(&key_manager), &priv_key, claims)?;
/// let attenuated_claims = {
///     let mut claims = HashMap::new();
///     claims.insert("aud".to_owned(), "restricted-audience".to_owned());
///     claims
/// };
/// let attenuated = ajwt.attenuate(attenuated_claims)?;
/// let sealed = attenuated.seal(SecondsSinceEpoch(0), SecondsSinceEpoch(0), Some(Issuer("my-issuer".to_owned())), None)?;
/// # Ok(())
/// # }
/// ```
pub struct AttenuableJWT<'a, SKM: SigningKeyManager> {
    key_manager: Cow<'a, SKM>,
    jwts: Vec<SignedJWT>,
    private_attenuation_key: SKM::PrivateAttenuationKey,
}

#[cfg(feature = "integration-test")]
impl<'a, SKM: SigningKeyManager> AttenuableJWT<'a, SKM> {
    /// Testing-only access to the current set of JWTs
    pub fn jwts(&self) -> &[SignedJWT] {
        &self.jwts
    }

    /// Testing-only access to the current private attenuation key
    pub fn private_attenuation_key(&self) -> &SKM::PrivateAttenuationKey {
        &self.private_attenuation_key
    }
}

impl<'a, SKM: SigningKeyManager> AttenuableJWT<'a, SKM> {
    /// Constructs an AttenuableJWT from a chain of signed JWTs and a private_attenuation_key, using the provided [crate::SigningKeyManager].
    /// Invariant: the private_attenuation_key must be the private key corresponding to the public key found in
    /// `jwts.last().unwrap().claim("aky")`.
    pub fn with_jwts_and_attenuation_key(
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

    /// Constructs a new AttenuableJWT with the given root_key and claims, using the provided [crate::AttenuationKeyGenerator].
    /// The `root_key` will be used to sign this initial JWT.
    /// `claims` will be augmented with an `aky` claim containing the public counterpart to the `private_attenuation_key`
    /// in the returned AttenuableJWT.
    pub fn with_root_key_and_claims<RootKey: PrivateKey>(
        key_manager: Cow<'a, SKM>,
        root_key: &RootKey,
        claims: SKM::Claims,
    ) -> Result<Self> {
        let (pub_key, priv_key) = key_manager.generate_attenuation_key()?;
        let full_claims = FullClaims::new(claims, SKM::jwk_for_public_attenuation_key(&pub_key));
        let header = JWTHeader {
            key_id: Some(root_key.key_id().to_owned()),
            algorithm: root_key.algorithm().to_owned(),
        };

        let token = encode_jwt(&header, &full_claims, root_key)?;

        Ok(Self {
            key_manager,
            jwts: vec![token],
            private_attenuation_key: priv_key,
        })
    }

    /// Create a new AttenuableJWT that has all of the claims from this AttenuableJWT and also
    /// carries the provided claims. When verifying, clients can ensure that the provided claims only restrict the existing
    /// claims.
    pub fn attenuate(&self, claims: SKM::Claims) -> Result<Self> {
        let mut attenuated = Self::with_root_key_and_claims(
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
        let header = JWTHeader {
            key_id: Some(self.private_attenuation_key.key_id().to_owned()),
            algorithm: self.private_attenuation_key.algorithm().to_owned(),
        };
        let claims = SealedClaims {
            jwts: self.jwts.clone(),
            exp: Some(expiration),
            nbf: Some(not_before),
            iss: issuer,
            aud: audience,
        };

        let token = encode_jwt(&header, &claims, &self.private_attenuation_key)?;

        Ok(token)
    }
}
