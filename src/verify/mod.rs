use std::collections::HashMap;

use jsonwebtoken::{decode, decode_header, DecodingKey, Validation};
use serde::de::DeserializeOwned;

mod error;

pub use error::Error;
use error::Result;

use crate::protocol::{
    FullClaims, PublicKey, SealedClaims, VerificationKeyManager, VerificationRequirements,
};

type GetKeyFn<'a> = Box<dyn FnOnce(Option<String>) -> Option<Box<dyn PublicKey + 'static>>>;

/// Verify the provided `jwt`, where `jwt` is expected to be in the format generated by [crate::sign::AttenuableJWT::seal]
///
/// ```
/// use attenuable_jwt::{protocol::{SignedJWT, PublicKey, VerificationRequirements, VerificationKeyManager, SecondsSinceEpoch, Issuer}, sign::ed25519, verify::verify};
/// use std::collections::HashMap;
///
/// # fn generate_attenuated_jwt() -> (ed25519::Ed25519PublicKey, SignedJWT) {
/// #   use std::{borrow::Cow, collections::HashMap, time::{SystemTime, UNIX_EPOCH}};
/// #   use attenuable_jwt::{protocol::{AttenuationKeyGenerator, SigningKeyManager}, sign::{ed25519, Error, AttenuableJWT}};
/// #
/// #   #[derive(Clone)]
/// #   struct KeyManager;
/// #
/// #   impl AttenuationKeyGenerator<ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey> for KeyManager {
/// #       fn generate_attenuation_key(
/// #           &self,
/// #       ) -> Result<(ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey), Error> {
/// #           ed25519::EddsaKeyGen.generate_attenuation_key()
/// #       }
/// #   }
/// #
/// #   impl SigningKeyManager for KeyManager {
/// #       type JWK = ed25519::JWK;
/// #
/// #       type PublicAttenuationKey = ed25519::Ed25519PublicKey;
/// #
/// #       type PrivateAttenuationKey = ed25519::Ed25519PrivateKey;
/// #
/// #       type PrivateRootKey = ed25519::Ed25519PrivateKey;
/// #
/// #       type Claims = HashMap<String, String>;
/// #
/// #       fn jwk_for_public_attenuation_key(
/// #           public_attenuation_key: &Self::PublicAttenuationKey,
/// #       ) -> Self::JWK {
/// #           public_attenuation_key.into()
/// #       }
/// #   }
/// #
/// #   let claims = {
/// #       let mut claims = HashMap::new();
/// #       claims.insert("sub".to_owned(), "itsme".to_owned());
/// #       claims
/// #   };
/// #   let key_manager = KeyManager;
/// #   let (pub_key, priv_key) = key_manager.generate_attenuation_key().unwrap();
/// #   let ajwt: AttenuableJWT<'_, KeyManager> = AttenuableJWT::new_with_key_manager(Cow::Owned(key_manager), &priv_key, claims).unwrap();
/// #   let attenuated_claims = {
/// #       let mut claims = HashMap::new();
/// #       claims.insert("aud".to_owned(), "restricted-audience".to_owned());
/// #       claims
/// #   };
/// #   let attenuated = ajwt.attenuate(attenuated_claims).unwrap();
/// #   let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
/// #   let jwt = attenuated.seal(SecondsSinceEpoch(current_time + 60), SecondsSinceEpoch(current_time), Some(Issuer("my-issuer".to_owned())), None).unwrap();
/// #   (pub_key, jwt)
/// # }
///
/// #[derive(Clone)]
/// struct KeyManager {
///     pub_root_key: ed25519::Ed25519PublicKey,
/// }
///
/// impl VerificationKeyManager for KeyManager {
///     type PublicRootKey = ed25519::Ed25519PublicKey;
///
///     type PublicAttenuationKey = ed25519::Ed25519PublicKey;
///
///     type PrivateAttenuationKey = ed25519::Ed25519PrivateKey;
///
///     type Claims = std::collections::HashMap<String, String>;
///
///     type JWK = ed25519::JWK;
///
///     fn get_root_key(&self, key_id: &Option<String>) -> Option<Self::PublicRootKey> {
///         if key_id.as_ref().map(|kid| kid == self.pub_root_key.key_id()).unwrap_or(true) {
///             Some(self.pub_root_key.clone())
///         } else {
///             None
///         }
///     }
///
///     fn get_root_verification_requirements(&self) -> VerificationRequirements {
///         VerificationRequirements {
///             acceptable_algorithms: vec![ed25519::EDDSA_ALGORITHM.to_owned()],
///             acceptable_issuers: Some(vec![Issuer("my-issuer".to_owned())]),
///             acceptable_audiences: None,
///             acceptable_subjects: None,
///         }
///     }
///
///     fn default_claims(&self) -> Self::Claims {
///         HashMap::new()
///     }
///
///     fn jwk_to_public_attenuation_key(&self, jwk: &Self::JWK) -> Option<Self::PublicAttenuationKey> {
///         jwk.try_into().ok()
///     }
/// }
///
/// let (pub_root_key, attenuated_jwt) = generate_attenuated_jwt();
/// let key_manager = KeyManager {
///     pub_root_key,
/// };
/// let claims = verify(
///     key_manager,
///     attenuated_jwt.as_ref(),
///     |c1, c2| {
///         c2
///             .into_iter()
///             .map(|(k, v)| (k.clone(), v.clone()))
///             .chain(c1.into_iter())
///             .collect()
///     }
/// ).unwrap();
/// let sub = claims.get("sub").unwrap();
/// assert_eq!(sub, "itsme");
/// let aud = claims.get("aud").unwrap();
/// assert_eq!(aud, "restricted-audience");
///
/// ```
pub fn verify<VKM: VerificationKeyManager + 'static, ClaimResolver>(
    verification_key_manager: VKM,
    jwt: &str,
    resolve_claims: ClaimResolver,
) -> Result<VKM::Claims>
where
    ClaimResolver: Fn(VKM::Claims, VKM::Claims) -> VKM::Claims,
{
    let envelope_key: VKM::PublicAttenuationKey =
        final_attenuation_key(&verification_key_manager, jwt)?;
    let header = decode_header(jwt)?;
    let kid_matches = header
        .kid
        .as_ref()
        .map(|kid| kid == envelope_key.key_id())
        .unwrap_or(false);
    if !kid_matches {
        return Err(Error::InvalidEnvelopeKey);
    }
    if Some(header.alg) != envelope_key.algorithm().parse().ok() {
        return Err(Error::InvalidEnvelopeKey);
    }
    let decoding_key = envelope_key
        .to_decoding_key()
        .map_err(|err| Error::InvalidAttenuationKey(Box::new(err)))?;
    let validation_cfg =
        validation_config(verification_key_manager.get_root_verification_requirements())?;
    let token = decode::<SealedClaims>(jwt, &decoding_key, &validation_cfg)?;
    let jwts = token.claims.jwts;

    let default_claims = verification_key_manager.default_claims();
    let vkm = verification_key_manager.clone(); // TODO: this is silly
    let get_root_key = Box::new(move |kid| match vkm.get_root_key(&kid) {
        None => None,
        Some(rk) => Some(Box::new(rk) as Box<dyn PublicKey>),
    }) as GetKeyFn;
    let (_, claims) = jwts.into_iter().fold(
        Ok((get_root_key, default_claims)),
        |accumulated, jwt| -> Result<(_, VKM::Claims)> {
            let (get_key, acc) = accumulated?;
            let full_claims = decode_inner_jwt::<VKM>(jwt.as_ref(), get_key)?;
            let next_pub_key =
                verification_key_manager.jwk_to_public_attenuation_key(&full_claims.aky);
            let get_key = Box::new(move |kid: Option<String>| {
                next_pub_key.and_then(|p| {
                    let kids_match = kid.as_ref().map(|kid| kid == p.key_id()).unwrap_or(true);
                    if kids_match {
                        Some(Box::new(p) as Box<dyn PublicKey>)
                    } else {
                        None
                    }
                })
            }) as GetKeyFn;
            let accumulated = resolve_claims(acc, full_claims.user_provided_claims);
            Ok((get_key, accumulated))
        },
    )?;
    Ok(claims)
}

fn final_attenuation_key<VKM: VerificationKeyManager>(
    verification_key_manager: &VKM,
    jwt: &str,
) -> Result<VKM::PublicAttenuationKey> {
    let claims: SealedClaims = insecurely_extract_claims(jwt)?;

    Ok(claims
        .jwts
        .last()
        .ok_or_else(|| Error::MissingFinalAttenuationKey)
        .and_then(|jwt| extract_aky(verification_key_manager, jwt.as_ref()))?)
}

fn extract_aky<VKM: VerificationKeyManager>(
    verification_key_manager: &VKM,
    jwt: &str,
) -> Result<VKM::PublicAttenuationKey> {
    let claims: FullClaims<VKM::JWK, VKM::PublicAttenuationKey, HashMap<String, String>> =
        insecurely_extract_claims(jwt)?;
    Ok(verification_key_manager
        .jwk_to_public_attenuation_key(&claims.aky)
        .ok_or_else(|| Error::MalformedAttenuationKeyJWK)?)
}

fn insecurely_extract_claims<Claims: DeserializeOwned>(jwt: &str) -> Result<Claims> {
    let token = {
        let no_validation = {
            let mut v = Validation::default();
            v.required_spec_claims.clear();
            v.insecure_disable_signature_validation();
            v
        };
        decode::<Claims>(
            jwt,
            &DecodingKey::from_secret("fake".as_ref()),
            &no_validation,
        )?
    };

    Ok(token.claims)
}

fn decode_inner_jwt<VKM: VerificationKeyManager>(
    jwt: &str,
    get_key: GetKeyFn,
) -> Result<FullClaims<VKM::JWK, VKM::PublicAttenuationKey, VKM::Claims>> {
    let header = decode_header(jwt)?;
    let kid = header.kid.clone();
    let public_key = get_key(kid).ok_or_else(|| Error::MissingKey(header.kid.clone()))?;
    let decoding_key = public_key.to_decoding_key()?;
    let validation_cfg = {
        let mut validation_config = Validation::new(public_key.algorithm().parse()?); // TODO: validate final claims
        validation_config.required_spec_claims.clear();
        validation_config
    };
    let token = decode(jwt, &decoding_key, &validation_cfg)?;
    Ok(token.claims)
}

fn validation_config(reqs: VerificationRequirements) -> Result<Validation> {
    let required_spec_claims = {
        let mut required_spec_claims = Vec::new();
        required_spec_claims.push("exp".to_owned());

        if reqs.acceptable_audiences.is_some() {
            required_spec_claims.push("aud".to_owned());
        }

        if reqs.acceptable_issuers.is_some() {
            required_spec_claims.push("iss".to_owned());
        }

        if reqs.acceptable_subjects.is_some() {
            required_spec_claims.push("sub".to_owned());
        }

        required_spec_claims
    };

    let mut v = Validation::default();
    v.set_required_spec_claims(required_spec_claims.as_slice());
    reqs.acceptable_issuers.as_ref().map(|iss| {
        v.set_issuer(
            iss.into_iter()
                .map(|i| i.as_ref())
                .collect::<Vec<_>>()
                .as_slice(),
        )
    });
    reqs.acceptable_audiences.as_ref().map(|iss| {
        v.set_audience(
            iss.into_iter()
                .map(|a| a.as_ref())
                .collect::<Vec<_>>()
                .as_slice(),
        )
    });
    reqs.acceptable_subjects.map(|sub| v.sub = Some(sub));
    v.algorithms = reqs
        .acceptable_algorithms
        .iter()
        .map(|alg| alg.to_string().parse())
        .collect::<std::result::Result<_, _>>()?;

    Ok(v)
}

#[cfg(test)]
mod test {
    use crate::{
        protocol::{
            AttenuationKeyGenerator, Issuer, PrivateKey, SealedClaims,
            SecondsSinceEpoch, SignedJWT, SigningKeyManager, VerificationKeyManager,
            VerificationRequirements,
        },
        sign::{ed25519, AttenuableJWT, Error as SignError},
        verify::Error,
    };
    use mockall::mock;
    use std::{
        borrow::Cow,
        collections::HashMap,
        str::FromStr,
        time::{SystemTime, UNIX_EPOCH},
    };

    use super::verify;

    mock! {
        KeyManager {}

        impl VerificationKeyManager for KeyManager {
            type PublicRootKey = ed25519::Ed25519PublicKey;

            type PublicAttenuationKey = ed25519::Ed25519PublicKey;

            type PrivateAttenuationKey = ed25519::Ed25519PrivateKey;

            type Claims = std::collections::HashMap<String, String>;

            type JWK = ed25519::JWK;

            fn get_root_key(&self, key_id: &Option<String>) -> Option<<MockKeyManager as VerificationKeyManager>::PublicRootKey>;
            fn get_root_verification_requirements(&self) -> VerificationRequirements;
            fn default_claims(&self) -> <MockKeyManager as VerificationKeyManager>::Claims;
            fn jwk_to_public_attenuation_key(&self, jwk: &<MockKeyManager as VerificationKeyManager>::JWK) -> Option<<MockKeyManager as VerificationKeyManager>::PublicAttenuationKey>;
        }

        impl Clone for KeyManager {
            fn clone(&self) -> Self;
        }
    }

    #[test]
    fn test_bad_envelope_kid() {
        let (_, root_priv_key) = SignKeyManager.generate_attenuation_key().unwrap();
        let header = {
            let mut header = jsonwebtoken::Header::new(
                jsonwebtoken::Algorithm::from_str(&root_priv_key.algorithm()).unwrap(),
            );
            header.kid = Some("wrong".to_owned());
            header
        };
        let full_claims = SealedClaims {
            exp: None,
            nbf: None,
            iss: None,
            aud: None,
            jwts: Default::default(),
        };
        let token = jsonwebtoken::encode(
            &header,
            &full_claims,
            &root_priv_key.to_encoding_key().unwrap(),
        )
        .unwrap();

        let key_manager = MockKeyManager::new();
        let err = verify(key_manager, &token, |mut c1, c2| {
            c1.extend(c2);
            c1
        });

        assert!(matches!(
            err.expect_err("should have failed"),
            Error::MissingFinalAttenuationKey
        ));
    }

    #[test]
    fn test_missing_jwts_claim() {
        let (_, root_priv_key) = SignKeyManager.generate_attenuation_key().unwrap();
        let header = {
            let mut header = jsonwebtoken::Header::new(
                jsonwebtoken::Algorithm::from_str(&root_priv_key.algorithm()).unwrap(),
            );
            header.kid = Some(root_priv_key.key_id().to_owned());
            header
        };
        // no jwts claim
        let full_claims: HashMap<String, String> = Default::default();
        let token = jsonwebtoken::encode(
            &header,
            &full_claims,
            &root_priv_key.to_encoding_key().unwrap(),
        )
        .unwrap();

        let key_manager = MockKeyManager::new();
        let err = verify(key_manager, &token, |mut c1, c2| {
            c1.extend(c2);
            c1
        });

        assert!(matches!(
            err.expect_err("should have failed"),
            Error::JWTError(_)
        ));
    }

    #[test]
    fn test_bad_encoding() {
        let key_manager = MockKeyManager::new();
        let err = verify(key_manager, "*&", |mut c1, c2| {
            c1.extend(c2);
            c1
        });

        assert!(matches!(
            err.expect_err("should have failed"),
            Error::JWTError(_)
        ));
    }

    #[test]
    fn test_missing_root_key() {
        fn make_key_manager() -> MockKeyManager {
            let mut key_manager = MockKeyManager::new();
            key_manager
                .expect_jwk_to_public_attenuation_key()
                .returning(|jwk| jwk.try_into().ok());
            key_manager
                .expect_get_root_verification_requirements()
                .returning(|| VerificationRequirements {
                    acceptable_algorithms: vec![ed25519::EDDSA_ALGORITHM.to_owned()],
                    acceptable_issuers: Some(vec![Issuer("my-issuer".to_owned())]),
                    acceptable_audiences: None,
                    acceptable_subjects: None,
                });
            key_manager
                .expect_default_claims()
                .returning(|| Default::default());
            key_manager.expect_clone().returning(|| make_key_manager());
            key_manager.expect_get_root_key().returning(|_| None);
            key_manager
        }

        let (_, jwt) = generate_attenuated_jwt();
        let key_manager = make_key_manager();
        let err = verify(key_manager, jwt.as_ref(), |mut c1, c2| {
            c1.extend(c2);
            c1
        });

        if let Error::MissingKey(Some(kid)) = err.expect_err("should have failed") {
            assert_eq!(kid, "aky");
        } else {
            assert!(false);
        }
    }

    #[derive(Clone)]
    struct SignKeyManager;

    impl AttenuationKeyGenerator<ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey>
        for SignKeyManager
    {
        fn generate_attenuation_key(
            &self,
        ) -> Result<(ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey), SignError> {
            ed25519::EddsaKeyGen.generate_attenuation_key()
        }
    }

    impl SigningKeyManager for SignKeyManager {
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

    fn generate_attenuated_jwt() -> (ed25519::Ed25519PublicKey, SignedJWT) {
        let claims = {
            let mut claims = HashMap::new();
            claims.insert("sub".to_owned(), "itsme".to_owned());
            claims
        };
        let key_manager = SignKeyManager;
        let (pub_key, priv_key) = key_manager.generate_attenuation_key().unwrap();
        let ajwt: AttenuableJWT<'_, SignKeyManager> =
            AttenuableJWT::new_with_key_manager(Cow::Owned(key_manager), &priv_key, claims)
                .unwrap();
        let attenuated_claims = {
            let mut claims = HashMap::new();
            claims.insert("aud".to_owned(), "restricted-audience".to_owned());
            claims
        };
        let attenuated = ajwt.attenuate(attenuated_claims).unwrap();
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jwt = attenuated
            .seal(
                SecondsSinceEpoch(current_time + 60),
                SecondsSinceEpoch(current_time),
                Some(Issuer("my-issuer".to_owned())),
                None,
            )
            .unwrap();
        (pub_key, jwt)
    }
}
