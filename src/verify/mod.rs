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

pub fn verify<VKM: VerificationKeyManager, ClaimResolver>(
    verification_key_manager: &'static VKM,
    jwt: &str,
    resolve_claims: ClaimResolver,
) -> Result<VKM::Claims>
where
    ClaimResolver: Fn(VKM::Claims, &VKM::Claims) -> VKM::Claims,
{
    let envelope_key: VKM::PublicAttenuationKey = final_attenuation_key::<VKM>(jwt)?;
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

    let get_root_key = Box::new(|kid| match verification_key_manager.get_root_key(&kid) {
        None => None,
        Some(rk) => Some(Box::new(rk) as Box<dyn PublicKey>),
    }) as GetKeyFn;
    let (_, claims) = jwts.into_iter().fold(
        Ok((get_root_key, verification_key_manager.default_claims())),
        |accumulated, jwt| -> Result<(_, VKM::Claims)> {
            let (get_key, acc) = accumulated?;
            let full_claims = decode_inner_jwt::<VKM>(jwt.as_ref(), get_key)?;
            let next_pub_key = VKM::jwk_to_public_attenuation_key(&full_claims.aky);
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
            let accumulated = resolve_claims(acc, &full_claims.user_provided_claims);
            Ok((get_key, accumulated))
        },
    )?;
    Ok(claims)
}

fn final_attenuation_key<VKM: VerificationKeyManager>(
    jwt: &str,
) -> Result<VKM::PublicAttenuationKey> {
    let claims: SealedClaims = insecurely_extract_claims(jwt)?;

    Ok(claims
        .jwts
        .last()
        .ok_or_else(|| Error::MissingFinalAttenuationKey)
        .and_then(|jwt| extract_aky::<VKM>(jwt.as_ref()))?)
}

fn extract_aky<VKM: VerificationKeyManager>(jwt: &str) -> Result<VKM::PublicAttenuationKey> {
    let claims: FullClaims<VKM::JWK, VKM::PublicAttenuationKey, HashMap<String, String>> =
        insecurely_extract_claims(jwt)?;
    Ok(VKM::jwk_to_public_attenuation_key(&claims.aky)
        .ok_or_else(|| Error::MalformedAttenuationKeyJWK)?)
}

fn insecurely_extract_claims<Claims: DeserializeOwned>(jwt: &str) -> Result<Claims> {
    let token = {
        let no_validation = {
            let mut v = Validation::default();
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
    let validation_cfg = Default::default(); // TODO: validate final claims
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
    reqs.acceptable_issuers
        .as_ref()
        .map(|iss| v.set_issuer(iss));
    reqs.acceptable_audiences
        .as_ref()
        .map(|aud| v.set_audience(aud));
    reqs.acceptable_subjects
        .as_ref()
        .map(|sub| v.sub = Some(sub.to_string()));
    v.algorithms = reqs
        .acceptable_algorithms
        .iter()
        .map(|alg| alg.to_string().parse())
        .collect::<std::result::Result<_, _>>()?;

    Ok(v)
}
