use std::borrow::Cow;

mod error;

pub use error::{Error, Result};

use crate::protocol::{
    Audience, Issuer, JWTEncoder, JWTHeader, PrivateKey, SealedClaims, SecondsSinceEpoch,
    SignedJWT, SigningKeyManager,
};

/// An AttenuableJWT carries a set of immutable claims but allows for the creation of a JWT with an attenuated
/// set of claims.
///
/// ```
/// use std::{borrow::Cow, collections::HashMap, str::FromStr};
/// use attenuable_jwt::{protocol::{AttenuationKeyGenerator, SigningKeyManager, SecondsSinceEpoch, Issuer, JWTEncoder, PrivateKey, JWTHeader, SignedJWT}, sign::{Result, Error, AttenuableJWT}, ed25519};
/// use jsonwebtoken::{encode, EncodingKey};
///
/// #[derive(Clone)]
/// struct JsonwebtokenEncoder;
///
/// impl JWTEncoder for JsonwebtokenEncoder {
///     fn encode_jwt<Claims: serde::Serialize, PrivKey: PrivateKey + ?Sized>(
///         &self,
///         header: &JWTHeader,
///         claims: &Claims,
///         signing_key: &PrivKey,
///     ) -> Result<SignedJWT> {
///             let mut json: Vec<u8> = Default::default();
///             erased_serde::serialize(
///                 signing_key,
///                 &mut serde_json::Serializer::new(&mut json),
///             )
///             .map_err(|err| Error::KeyError(Some(Box::new(err))))?;
///             let jwk: ed25519::JWK =
///                 serde_json::from_slice(&json).map_err(|err| Error::KeyError(Some(Box::new(err))))?;
///             if let Some(d) = &jwk.d {
///                 let x = base64::decode_config(&jwk.x, base64::URL_SAFE_NO_PAD).map_err(|err| Error::KeyError(Some(Box::new(err))))?;
///                 let d = base64::decode_config(d, base64::URL_SAFE_NO_PAD).map_err(|err| Error::KeyError(Some(Box::new(err))))?;
///                 let der: Vec<_> = x.into_iter().chain(d.into_iter()).collect();
///                 let encoding_key = EncodingKey::from_ed_der(&der);
///                 let header = {
///                     let mut h = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::from_str(
///                         &header.algorithm,
///                     ).map_err(|err| Error::KeyError(Some(Box::new(err))))?);
///                     h.kid = header.key_id.clone();
///                     h
///                 };
///                 let token = encode(
///                     &header,
///                     claims,
///                     &encoding_key,
///                 ).map_err(|err| Error::CryptoError(Some(Box::new(err))))?;
///                 Ok(SignedJWT(token))
///             } else {
///                 Err(Error::KeyError(None))
///             }
///     }
/// }
///
/// #[derive(Clone)]
/// struct KeyManager;
///
/// impl AttenuationKeyGenerator<ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey> for KeyManager {
///     fn generate_attenuation_key(
///         &self,
///     ) -> Result<(ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey)> {
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
/// # fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
/// let claims = {
///     let mut claims = HashMap::new();
///     claims.insert("sub".to_owned(), "itsme".to_owned());
///     claims
/// };
/// let key_manager = KeyManager;
/// let (pub_key, priv_key) = key_manager.generate_attenuation_key()?;
/// let ajwt = AttenuableJWT::new_with_key_manager(Cow::Borrowed(&key_manager), Cow::Borrowed(&JsonwebtokenEncoder), &priv_key, claims)?;
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
pub struct AttenuableJWT<'a, SKM: SigningKeyManager, JWTE: JWTEncoder + Clone> {
    key_manager: Cow<'a, SKM>,
    jwt_encoder: Cow<'a, JWTE>,
    jwts: Vec<SignedJWT>,
    private_attenuation_key: SKM::PrivateAttenuationKey,
}

#[cfg(feature = "integration-test")]
impl<'a, SKM: SigningKeyManager, JWTE: JWTEncoder + Clone> AttenuableJWT<'a, SKM, JWTE> {
    /// Testing-only access to the current set of JWTs
    pub fn jwts(&self) -> &[SignedJWT] {
        &self.jwts
    }

    /// Testing-only access to the current private attenuation key
    pub fn private_attenuation_key(&self) -> &SKM::PrivateAttenuationKey {
        &self.private_attenuation_key
    }
}

impl<'a, SKM: SigningKeyManager, JWTE: JWTEncoder + Clone> AttenuableJWT<'a, SKM, JWTE> {
    /// Constructs an AttenuableJWT from a chain of signed JWTs and a private_attenuation_key, using the provided [crate::protocol::SigningKeyManager].
    /// Invariant: the private_attenuation_key must be the private key corresponding to the public key found in
    /// `jwts.last().unwrap().claim("aky")`.
    pub fn with_key_manager(
        key_manager: Cow<'a, SKM>,
        jwt_encoder: Cow<'a, JWTE>,
        jwts: Vec<SignedJWT>,
        private_attenuation_key: SKM::PrivateAttenuationKey,
    ) -> Self {
        Self {
            key_manager,
            jwt_encoder,
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
        jwt_encoder: Cow<'a, JWTE>,
        root_key: &RootKey,
        claims: SKM::Claims,
    ) -> Result<Self> {
        let (pub_key, priv_key) = key_manager.generate_attenuation_key()?;
        let full_claims = SKM::claims_with_attenuation_key(claims, &pub_key);
        let header = JWTHeader {
            key_id: Some(root_key.key_id().to_owned()),
            algorithm: root_key.algorithm().to_owned(),
        };

        let token = jwt_encoder.encode_jwt(&header, &full_claims, root_key)?;

        Ok(Self {
            key_manager,
            jwt_encoder,
            jwts: vec![token],
            private_attenuation_key: priv_key,
        })
    }

    /// Create a new AttenuableJWT that has all of the claims from this AttenuableJWT and also
    /// carries the provided claims. When verifying, clients can ensure that the provided claims only restrict the existing
    /// claims.
    pub fn attenuate(&self, claims: SKM::Claims) -> Result<Self> {
        let mut attenuated = Self::new_with_key_manager(
            self.key_manager.clone(),
            self.jwt_encoder.clone(),
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

        let token = self
            .jwt_encoder
            .encode_jwt(&header, &claims, &self.private_attenuation_key)?;

        Ok(token)
    }
}
