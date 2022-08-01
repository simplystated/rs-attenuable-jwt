//! This module provides an [AttenuableJWT] struct as the core type for creating and attenuating JWTs.
//! The JWTs created by calling [AttenuableJWT::seal] may be verified by calling [crate::verify::verify].

use std::borrow::Cow;

mod error;
mod jwt;

pub use error::{Error, Result};
use serde::{Deserialize, Serialize};

use crate::protocol::{
    Audience, FullClaims, Issuer, JWTHeader, PrivateKey, SealedClaims, SecondsSinceEpoch,
    SignedJWT, SigningKeyManager,
};

#[cfg(not(any(feature = "integration-test", test)))]
use jwt::encode_jwt;
#[cfg(any(feature = "integration-test", test))]
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
#[derive(Serialize, Clone, PartialEq)]
pub struct AttenuableJWT<'a, SKM: SigningKeyManager> {
    #[serde(skip)]
    key_manager: Cow<'a, SKM>,
    jwts: Vec<SignedJWT>,
    private_attenuation_key: SKM::PrivateAttenuationKey,
}

impl<'a, SKM: SigningKeyManager> std::fmt::Debug for AttenuableJWT<'a, SKM> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttenuableJWT")
            .field("key_manager", &"<key manager>")
            .field("jwts", &self.jwts)
            .field("private_attenuation_key", &"***")
            .finish()
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

    /// The chain of inner JWTs contained in this AttenuableJWT, from least to most attenuated.
    ///
    /// WARNING: the only safe thing to do with this in production is to serialize it with the
    /// associated [Self::private_attenuation_key] to create a new AttenuableJWT via
    /// [AttenuableJWT::with_jwts_and_attenuation_key].
    pub fn jwts(&self) -> &[SignedJWT] {
        &self.jwts
    }

    /// The *PRIVATE* attenuation key associated with the last JWT in the [Self::jwts] chain.
    /// Anyone with this private key can seal the jwt chain as it currently stands, regardless
    /// of any future attenuation.
    ///
    /// WARNING: the only safe thing to do with this in production is to serialize it with the
    /// associated [Self::jwts] to create a new AttenuableJWT via
    /// [AttenuableJWT::with_jwts_and_attenuation_key].
    pub fn private_attenuation_key(&self) -> &SKM::PrivateAttenuationKey {
        &self.private_attenuation_key
    }
}

/// Plain data attributes of an [AttenuableJWT].
/// Useful as a deserialization target, which can then be converted into an AttenuableJWT via
/// [AttenuableJWTData::into_attenuable_jwt].
///
/// Example:
/// ```
/// use std::collections::HashMap;
/// use std::borrow::Cow;
/// use attenuable_jwt::{sign::{AttenuableJWT, AttenuableJWTData, Error}, SigningKeyManager, AttenuationKeyGenerator, ed25519};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let json = r#"{
///     "jwts":["eyJraWQiOiJha3kiLCJhbGciOiJFZERTQSJ9.eyJzdWIiOiJhZGFtIiwiYWt5Ijp7ImtpZCI6ImFreSIsInVzZSI6InNpZyIsImtleV9vcHMiOlsidmVyaWZ5Il0sImFsZyI6IkVkRFNBIiwia3R5IjoiT0tQIiwiY3J2IjoiRWQyNTUxOSIsIngiOiJZNmtyMldHY1lwRXpCem9tUWxaOEFudEhjd2RRcnh2dHNwb0RPNWlON2UwIn19.8TsOXCSYqoZzRU0x5C1CfWbQjr7Sbkx4-WUGtKNgm6r5rKpoV95rvM3pIC9jbdQJsW7NV8mZ61UumAF-WjbDBw"],
///     "private_attenuation_key":{
///         "kid":"aky",
///         "use":"sig",
///         "key_ops":["sign"],
///         "alg":"EdDSA",
///         "kty":"OKP",
///         "crv":"Ed25519",
///         "x":"Y6kr2WGcYpEzBzomQlZ8AntHcwdQrxvtspoDO5iN7e0",
///         "d":"jVq9IGeekRwls8wtdCLCpz_zwqhmLDzbFObUU7zCMBM"
///     }
/// }"#;
///
/// let key_manager = KeyManager::new();
/// let data : AttenuableJWTData<_> = serde_json::from_str(json)?;
/// let deserialized_ajwt = data.into_attenuable_jwt(Cow::Borrowed(&key_manager));
/// assert_eq!(deserialized_ajwt.jwts().len(), 1);
///
/// # Ok(())
/// # }
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
///     ) -> Result<(ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey), Error> {
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
/// ```
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct AttenuableJWTData<PrivateAttenuationKey: PrivateKey> {
    jwts: Vec<SignedJWT>,
    private_attenuation_key: PrivateAttenuationKey,
}

impl<PrivateAttenuationKey: PrivateKey> AttenuableJWTData<PrivateAttenuationKey> {
    /// Consume this AttenuableJWTData and convert it into an [AttenuableJWT].
    pub fn into_attenuable_jwt<
        SKM: SigningKeyManager<PrivateAttenuationKey = PrivateAttenuationKey>,
    >(
        self,
        key_manager: Cow<'_, SKM>,
    ) -> AttenuableJWT<'_, SKM> {
        AttenuableJWT::with_jwts_and_attenuation_key(
            key_manager,
            self.jwts,
            self.private_attenuation_key,
        )
    }
}

#[cfg(all(test, feature = "ed25519"))]
mod test {
    use std::{borrow::Cow, collections::HashMap};

    use super::{AttenuableJWT, Error};
    use crate::{
        ed25519,
        sign::{AttenuableJWTData, Result},
        AttenuationKeyGenerator, SigningKeyManager,
    };

    #[test]
    fn test_serde() -> Result<()> {
        let key_manager = KeyManager::new();
        let (_, priv_root_key) = key_manager.generate_attenuation_key()?;
        let claims = {
            let mut claims = HashMap::new();
            claims.insert("sub".to_owned(), "adam".to_owned());
            claims
        };
        let ajwt = AttenuableJWT::with_root_key_and_claims(
            Cow::Borrowed(&key_manager),
            &priv_root_key,
            claims,
        )?;
        let ajwt_str =
            serde_json::to_string(&ajwt).map_err(|err| Error::SerializationError(Box::new(err)))?;
        let deserialized_ajwt: AttenuableJWTData<_> = serde_json::from_str(&ajwt_str)
            .map_err(|err| Error::SerializationError(Box::new(err)))?;
        let deserialized_ajwt = deserialized_ajwt.into_attenuable_jwt(Cow::Borrowed(&key_manager));
        assert_eq!(&ajwt.jwts, &deserialized_ajwt.jwts);
        assert_eq!(
            ed25519::JWK::from(ajwt.private_attenuation_key()),
            ed25519::JWK::from(deserialized_ajwt.private_attenuation_key())
        );
        Ok(())
    }

    #[derive(Clone)]
    struct KeyManager {
        key_gen: ed25519::EddsaKeyGen<rand::rngs::StdRng>,
    }

    impl KeyManager {
        pub fn new() -> Self {
            Self {
                key_gen: ed25519::EddsaKeyGen::new_with_std_rng(),
            }
        }
    }

    impl AttenuationKeyGenerator<ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey> for KeyManager {
        fn generate_attenuation_key(
            &self,
        ) -> Result<(ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey)> {
            self.key_gen.generate_attenuation_key()
        }
    }

    impl SigningKeyManager for KeyManager {
        type JWK = ed25519::JWK;

        type PublicAttenuationKey = ed25519::Ed25519PublicKey;

        type PrivateAttenuationKey = ed25519::Ed25519PrivateKey;

        type PrivateRootKey = ed25519::Ed25519PrivateKey;

        type Claims = HashMap<String, String>;

        fn jwk_for_public_attenuation_key(
            public_attenuation_key: &Self::PublicAttenuationKey,
        ) -> Self::JWK {
            public_attenuation_key.into()
        }
    }
}
