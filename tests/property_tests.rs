use attenuable_jwt::{
    ed25519,
    protocol::{
        AttenuationKeyGenerator, Audience, FullClaims, Issuer, JWTDecoder, JWTEncoder, JWTHeader,
        PrivateKey, PublicKey, SealedClaims, SecondsSinceEpoch, SignedJWT, SigningKeyManager,
        VerificationKeyManager, VerificationRequirements,
    },
    sign::{self, AttenuableJWT, Error as SignError},
    verify::{self, verify},
};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Validation,
};
use mockall::mock;
use proptest::{prelude::*, prop_oneof, proptest};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    borrow::Cow,
    collections::HashMap,
    iter,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

const EXPECTED_ISSUER: &str = "expected-issuer";
const EXPECTED_AUDIENCE: &str = "expected-audience";

#[derive(Debug, Clone)]
struct ClaimOperation {
    claim_key: String,
    claim_value: String,
}

#[derive(Debug, Clone)]
enum Operation {
    Attenuate(ClaimOperation),
    IncorrectlyAttenuate(ClaimOperation),
    Seal { issuer: String, audience: String },
    SealBadIssuer,
    SealBadExpiration,
    SealBadNotBefore,
    SealBadAudience,
    SealBadSignature,
}

fn arbitrary_claim_op() -> impl Strategy<Value = ClaimOperation> {
    any::<(String, String)>().prop_map(|(claim_key, claim_value)| ClaimOperation {
        claim_key,
        claim_value,
    })
}

fn arbitrary_operation() -> impl Strategy<Value = Operation> {
    prop_oneof![
        arbitrary_claim_op().prop_map(Operation::Attenuate),
        arbitrary_claim_op().prop_map(Operation::IncorrectlyAttenuate),
        any::<(String, String)>()
            .prop_map(|(issuer, audience)| Operation::Seal { issuer, audience }),
        Just(Operation::SealBadIssuer),
        Just(Operation::SealBadExpiration),
        Just(Operation::SealBadNotBefore),
        Just(Operation::SealBadAudience),
        Just(Operation::SealBadSignature),
    ]
}

fn arbitrary_operations() -> impl Strategy<Value = Vec<Operation>> {
    proptest::collection::vec(arbitrary_operation(), 1..100)
}

mock! {
    VerificationKeyManager {}

    impl VerificationKeyManager for VerificationKeyManager {
        type PublicRootKey = ed25519::Ed25519PublicKey;

        type PublicAttenuationKey = ed25519::Ed25519PublicKey;

        type PrivateAttenuationKey = ed25519::Ed25519PrivateKey;

        type Claims = std::collections::HashMap<String, String>;

        type JWK = ed25519::JWK;

        fn get_root_key(&self, key_id: &Option<String>) -> Option<<MockVerificationKeyManager as VerificationKeyManager>::PublicRootKey>;
        fn get_envelope_verification_requirements(&self) -> VerificationRequirements;
        fn default_claims(&self) -> <MockVerificationKeyManager as VerificationKeyManager>::Claims;
        fn jwk_to_public_attenuation_key(&self, jwk: &<MockVerificationKeyManager as VerificationKeyManager>::JWK) -> Option<<MockVerificationKeyManager as VerificationKeyManager>::PublicAttenuationKey>;
    }

    impl Clone for VerificationKeyManager {
        fn clone(&self) -> Self;
    }
}

#[derive(Clone)]
struct JsonwebtokenEncoder;

impl JWTEncoder for JsonwebtokenEncoder {
    fn encode_jwt<Claims: serde::Serialize, PrivKey: PrivateKey + ?Sized>(
        &self,
        header: &JWTHeader,
        claims: &Claims,
        signing_key: &PrivKey,
    ) -> sign::Result<SignedJWT> {
        let encoding_key = to_encoding_key(signing_key)?;
        let header = {
            let mut h = jsonwebtoken::Header::new(
                jsonwebtoken::Algorithm::from_str(&header.algorithm)
                    .map_err(|err| sign::Error::KeyError(Some(Box::new(err))))?,
            );
            h.kid = header.key_id.clone();
            h
        };
        let token = encode(&header, claims, &encoding_key)
            .map_err(|err| sign::Error::CryptoError(Some(Box::new(err))))?;
        Ok(SignedJWT(token))
    }
}

struct JsonwebtokenDecoder;

impl JWTDecoder for JsonwebtokenDecoder {
    fn decode_jwt<Claims: DeserializeOwned, PubKey: PublicKey + ?Sized>(
        &self,
        jwt: &SignedJWT,
        verification_key: &PubKey,
        verification_reqs: &VerificationRequirements,
    ) -> verify::Result<Claims> {
        let mut json: Vec<u8> = Default::default();
        erased_serde::serialize(
            verification_key,
            &mut serde_json::Serializer::new(&mut json),
        )
        .map_err(|_| verify::Error::InvalidKey)?;
        let jwk: ed25519::JWK =
            serde_json::from_slice(&json).map_err(|_| verify::Error::InvalidKey)?;
        let x = base64::decode_config(&jwk.x, base64::URL_SAFE_NO_PAD)?;
        let decoding_key = DecodingKey::from_ed_der(&x);
        Ok(decode(
            jwt.as_ref(),
            &decoding_key,
            &validation_config(verification_reqs)?,
        )
        .map_err(|err| verify::Error::JWTError(Some(Box::new(err))))?
        .claims)
    }
    fn insecurely_decode_jwt<Claims: DeserializeOwned>(
        &self,
        jwt: &SignedJWT,
    ) -> verify::Result<Claims> {
        let no_validation = {
            let mut v = Validation::default();
            v.required_spec_claims.clear();
            v.insecure_disable_signature_validation();
            v
        };
        Ok(decode(
            jwt.as_ref(),
            &DecodingKey::from_secret("fake".as_ref()),
            &no_validation,
        )
        .map_err(|err| verify::Error::JWTError(Some(Box::new(err))))?
        .claims)
    }
    fn decode_jwt_header(&self, jwt: &SignedJWT) -> verify::Result<JWTHeader> {
        let header = decode_header(jwt.as_ref())
            .map_err(|err| verify::Error::JWTError(Some(Box::new(err))))?;
        Ok(JWTHeader {
            key_id: header.kid,
            algorithm: format!("{:?}", header.alg),
        })
    }
}

fn validation_config(reqs: &VerificationRequirements) -> verify::Result<Validation> {
    match reqs {
        VerificationRequirements::VerifyClaims {
            acceptable_algorithms,
            acceptable_audiences,
            acceptable_issuers,
            acceptable_subject,
        } => {
            let required_spec_claims = {
                let mut required_spec_claims = vec!["exp".to_owned()];
                if acceptable_audiences.is_some() {
                    required_spec_claims.push("aud".to_owned());
                }
                if acceptable_issuers.is_some() {
                    required_spec_claims.push("iss".to_owned());
                }
                if acceptable_subject.is_some() {
                    required_spec_claims.push("sub".to_owned());
                }
                required_spec_claims
            };
            let mut v = Validation::default();
            v.set_required_spec_claims(required_spec_claims.as_slice());
            v.validate_nbf = true;
            if let Some(issuers) = acceptable_issuers.as_ref() {
                v.set_issuer(
                    issuers
                        .iter()
                        .map(|i| i.as_ref())
                        .collect::<Vec<_>>()
                        .as_slice(),
                )
            }
            if let Some(audiences) = acceptable_audiences.as_ref() {
                v.set_audience(
                    audiences
                        .iter()
                        .map(|a| a.as_ref())
                        .collect::<Vec<_>>()
                        .as_slice(),
                )
            }
            v.sub = acceptable_subject.clone();
            v.algorithms = acceptable_algorithms
                .iter()
                .map(|alg| alg.to_string().parse())
                .collect::<std::result::Result<_, _>>()
                .map_err(|err| verify::Error::JWTError(Some(Box::new(err))))?;
            Ok(v)
        }
        VerificationRequirements::VerifySignatureOnly {
            acceptable_algorithms,
        } => {
            let mut v = Validation::default();
            v.set_required_spec_claims(&[] as &[&str]);
            v.algorithms = acceptable_algorithms
                .iter()
                .map(|alg| alg.parse())
                .collect::<std::result::Result<Vec<Algorithm>, jsonwebtoken::errors::Error>>()
                .map_err(|err| verify::Error::JWTError(Some(Box::new(err))))?;
            Ok(v)
        }
    }
}

fn make_verification_key_manager<Expectations>(
    root_key: ed25519::Ed25519PublicKey,
    expectations: Expectations,
) -> MockVerificationKeyManager
where
    Expectations: Fn(MockVerificationKeyManager) -> MockVerificationKeyManager
        + Sync
        + Send
        + Clone
        + 'static,
{
    let mut key_manager = MockVerificationKeyManager::new();
    key_manager
        .expect_jwk_to_public_attenuation_key()
        .returning(|jwk| jwk.try_into().ok());
    key_manager
        .expect_default_claims()
        .returning(|| Default::default());
    let cloned_root_key = root_key.clone();
    let cloned_expectations = expectations.clone();
    key_manager.expect_clone().returning(move || {
        make_verification_key_manager(cloned_root_key.clone(), cloned_expectations.clone())
    });
    key_manager
        .expect_get_root_key()
        .returning(move |_| Some(root_key.clone()));
    expectations(key_manager)
}

fn add_expected_verifications(mut m: MockVerificationKeyManager) -> MockVerificationKeyManager {
    m.expect_get_envelope_verification_requirements()
        .returning(|| VerificationRequirements::VerifyClaims {
            acceptable_algorithms: vec![ed25519::EDDSA_ALGORITHM.to_owned()],
            acceptable_issuers: Some(vec![Issuer(EXPECTED_ISSUER.to_owned())]),
            acceptable_audiences: Some(vec![Audience(EXPECTED_AUDIENCE.to_owned())]),
            acceptable_subject: None,
        });
    m
}

fn run_ops(root_claims: HashMap<String, String>, ops: Vec<Operation>) {
    let current_time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key_manager = SignKeyManager;
    let (pub_root_key, priv_root_key) = key_manager.generate_attenuation_key().unwrap();
    let mut ajwt = AttenuableJWT::new_with_key_manager(
        Cow::Borrowed(&key_manager),
        Cow::Borrowed(&JsonwebtokenEncoder),
        &priv_root_key,
        root_claims.clone(),
    )
    .unwrap();

    let mut expected_claims = root_claims;
    let mut expect_fail = false;

    let resolve_claims = |mut prev_claims: HashMap<String, String>, cur_claims| {
        prev_claims.extend(cur_claims);
        prev_claims
    };

    for op in ops.into_iter() {
        match op {
            Operation::Attenuate(ClaimOperation {
                claim_key,
                claim_value,
            }) => {
                let claims = {
                    let mut claims = HashMap::new();
                    claims.insert(claim_key, claim_value);
                    claims
                };
                ajwt = ajwt.attenuate(claims.clone()).unwrap();
                expected_claims = resolve_claims(expected_claims, claims);
            }
            Operation::IncorrectlyAttenuate(ClaimOperation {
                claim_key,
                claim_value,
            }) => {
                let jwts = ajwt.jwts();
                let claims = {
                    let mut claims = HashMap::new();
                    claims.insert(claim_key, claim_value);
                    claims
                };
                let (_, bad_priv_key) = key_manager.generate_attenuation_key().unwrap();
                let (next_pub_key, next_priv_key) = key_manager.generate_attenuation_key().unwrap();
                let next_pub_key_jwk = ed25519::JWK::from(next_pub_key);
                let jwt = make_inner_jwt(bad_priv_key, claims, next_pub_key_jwk);
                let jwts = jwts.iter().cloned().chain(iter::once(jwt)).collect();
                ajwt = AttenuableJWT::with_key_manager(
                    Cow::Borrowed(&key_manager),
                    Cow::Borrowed(&JsonwebtokenEncoder),
                    jwts,
                    next_priv_key,
                );
                expect_fail = true;
            }
            Operation::Seal { issuer, audience } => {
                let sealed = ajwt
                    .seal(
                        SecondsSinceEpoch(current_time + 300),
                        SecondsSinceEpoch(current_time),
                        Some(Issuer(issuer.clone())),
                        Some(Audience(audience.clone())),
                    )
                    .unwrap();

                let verification_key_manager =
                    make_verification_key_manager(pub_root_key.clone(), move |mut m| {
                        let iss = Issuer(issuer.clone());
                        let aud = Audience(audience.clone());

                        m.expect_get_envelope_verification_requirements()
                            .returning(move || VerificationRequirements::VerifyClaims {
                                acceptable_algorithms: vec![ed25519::EDDSA_ALGORITHM.to_owned()],
                                acceptable_issuers: Some(vec![iss.clone()]),
                                acceptable_audiences: Some(vec![aud.clone()]),
                                acceptable_subject: None,
                            });
                        m
                    });
                let verified = verify(
                    verification_key_manager,
                    &JsonwebtokenDecoder,
                    sealed,
                    resolve_claims,
                );

                if expect_fail {
                    assert!(
                        verified.is_err(),
                        "expected verification failure, got: {:?}",
                        &verified
                    );
                } else {
                    assert!(
                        verified.is_ok(),
                        "expected verification success, got: {:?}",
                        &verified
                    );
                    let actual_claims = verified.unwrap();
                    assert_eq!(actual_claims, expected_claims);
                }
            }
            Operation::SealBadIssuer => {
                let exp = SecondsSinceEpoch(current_time + 300);
                let nbf = SecondsSinceEpoch(current_time);
                let iss = Issuer("bad-issuer".to_string());
                let aud = Audience(EXPECTED_AUDIENCE.to_owned());
                let token = make_envelope_jwt(
                    ajwt.private_attenuation_key().clone(),
                    exp,
                    nbf,
                    iss,
                    aud,
                    ajwt.jwts().iter().cloned().collect(),
                );
                let verification_key_manager =
                    make_verification_key_manager(pub_root_key.clone(), add_expected_verifications);
                let verified = verify(
                    verification_key_manager,
                    &JsonwebtokenDecoder,
                    token,
                    resolve_claims,
                );
                assert!(
                    verified.is_err(),
                    "expected verification failure, got: {:?}",
                    &verified
                );
            }
            Operation::SealBadExpiration => {
                let exp = SecondsSinceEpoch(current_time - 300);
                let nbf = SecondsSinceEpoch(current_time);
                let iss = Issuer(EXPECTED_ISSUER.to_owned());
                let aud = Audience(EXPECTED_AUDIENCE.to_owned());
                let token = make_envelope_jwt(
                    ajwt.private_attenuation_key().clone(),
                    exp,
                    nbf,
                    iss,
                    aud,
                    ajwt.jwts().iter().cloned().collect(),
                );
                let verification_key_manager =
                    make_verification_key_manager(pub_root_key.clone(), add_expected_verifications);
                let verified = verify(
                    verification_key_manager,
                    &JsonwebtokenDecoder,
                    token,
                    resolve_claims,
                );
                assert!(
                    verified.is_err(),
                    "expected verification failure, got: {:?}",
                    &verified
                );
            }
            Operation::SealBadNotBefore => {
                let exp = SecondsSinceEpoch(current_time + 300);
                let nbf = SecondsSinceEpoch(current_time + 300);
                let iss = Issuer(EXPECTED_ISSUER.to_owned());
                let aud = Audience(EXPECTED_AUDIENCE.to_owned());
                let token = make_envelope_jwt(
                    ajwt.private_attenuation_key().clone(),
                    exp,
                    nbf,
                    iss,
                    aud,
                    ajwt.jwts().iter().cloned().collect(),
                );
                let verification_key_manager =
                    make_verification_key_manager(pub_root_key.clone(), add_expected_verifications);
                let verified = verify(
                    verification_key_manager,
                    &JsonwebtokenDecoder,
                    token,
                    resolve_claims,
                );
                assert!(
                    verified.is_err(),
                    "expected verification failure, got: {:?}",
                    &verified
                );
            }
            Operation::SealBadAudience => {
                let exp = SecondsSinceEpoch(current_time + 300);
                let nbf = SecondsSinceEpoch(current_time);
                let iss = Issuer(EXPECTED_ISSUER.to_owned());
                let aud = Audience("bad-audience".to_owned());
                let token = make_envelope_jwt(
                    ajwt.private_attenuation_key().clone(),
                    exp,
                    nbf,
                    iss,
                    aud,
                    ajwt.jwts().iter().cloned().collect(),
                );
                let verification_key_manager =
                    make_verification_key_manager(pub_root_key.clone(), add_expected_verifications);
                let verified = verify(
                    verification_key_manager,
                    &JsonwebtokenDecoder,
                    token,
                    resolve_claims,
                );
                assert!(
                    verified.is_err(),
                    "expected verification failure, got: {:?}",
                    &verified
                );
            }
            Operation::SealBadSignature => {
                let exp = SecondsSinceEpoch(current_time + 300);
                let nbf = SecondsSinceEpoch(current_time);
                let iss = Issuer(EXPECTED_ISSUER.to_owned());
                let aud = Audience(EXPECTED_AUDIENCE.to_owned());
                let (_, bad_key) = key_manager.generate_attenuation_key().unwrap();
                let token = make_envelope_jwt(
                    bad_key,
                    exp,
                    nbf,
                    iss,
                    aud,
                    ajwt.jwts().iter().cloned().collect(),
                );
                let verification_key_manager =
                    make_verification_key_manager(pub_root_key.clone(), add_expected_verifications);
                let verified = verify(
                    verification_key_manager,
                    &JsonwebtokenDecoder,
                    token,
                    resolve_claims,
                );
                assert!(
                    verified.is_err(),
                    "expected verification failure, got: {:?}",
                    &verified
                );
            }
        }
    }
}

fn to_encoding_key<PrivKey: PrivateKey + ?Sized>(k: &PrivKey) -> sign::Result<EncodingKey> {
    let mut json: Vec<u8> = Default::default();
    erased_serde::serialize(k, &mut serde_json::Serializer::new(&mut json))
        .map_err(|err| sign::Error::KeyError(Some(Box::new(err))))?;
    let jwk: ed25519::JWK =
        serde_json::from_slice(&json).map_err(|err| sign::Error::KeyError(Some(Box::new(err))))?;
    if let Some(d) = &jwk.d {
        let x = base64::decode_config(&jwk.x, base64::URL_SAFE_NO_PAD)
            .map_err(|err| sign::Error::KeyError(Some(Box::new(err))))?;
        let d = base64::decode_config(&d, base64::URL_SAFE_NO_PAD)
            .map_err(|err| sign::Error::KeyError(Some(Box::new(err))))?;
        let der: Vec<_> = x.into_iter().chain(d.into_iter()).collect();
        let encoding_key = EncodingKey::from_ed_der(&der);
        Ok(encoding_key)
    } else {
        Err(sign::Error::KeyError(None))?
    }
}

fn make_inner_jwt<SignWith: PrivateKey, NextKeyJWK: Serialize>(
    sign_with: SignWith,
    claims: HashMap<String, String>,
    next_key_jwk: NextKeyJWK,
) -> SignedJWT {
    let header = {
        let mut header = jsonwebtoken::Header::new(
            jsonwebtoken::Algorithm::from_str(&sign_with.algorithm()).unwrap(),
        );
        header.kid = Some(sign_with.key_id().to_owned());
        header
    };
    let claims: FullClaims<NextKeyJWK, HashMap<String, String>> =
        FullClaims::new(claims, next_key_jwk);
    let inner_jwt =
        jsonwebtoken::encode(&header, &claims, &to_encoding_key(&sign_with).unwrap()).unwrap();
    SignedJWT(inner_jwt)
}

fn make_envelope_jwt<SignWith: PrivateKey>(
    sign_with: SignWith,
    exp: SecondsSinceEpoch,
    nbf: SecondsSinceEpoch,
    issuer: Issuer,
    audience: Audience,
    inner_jwts: Vec<SignedJWT>,
) -> SignedJWT {
    let header = {
        let mut header = jsonwebtoken::Header::new(
            jsonwebtoken::Algorithm::from_str(&sign_with.algorithm()).unwrap(),
        );
        header.kid = Some(sign_with.key_id().to_owned());
        header
    };
    let full_claims = SealedClaims {
        exp: Some(exp),
        nbf: Some(nbf),
        iss: Some(issuer),
        aud: Some(audience),
        jwts: inner_jwts,
    };
    let token =
        jsonwebtoken::encode(&header, &full_claims, &to_encoding_key(&sign_with).unwrap()).unwrap();
    SignedJWT(token)
}

proptest! {
    #[test]
    fn verify_operations(root_claims in any::<HashMap<String, String>>(), ops in arbitrary_operations()) {
        run_ops(root_claims, ops);
    }

    #[test]
    fn sign_and_verify(issuer in any::<Option<String>>(), root_claim in any::<String>(), claims in any::<Vec<String>>()) {
        let claim_name = "my_claim";
        let root_claims = {
            let mut claims = HashMap::new();
            claims.insert(claim_name.to_owned(), root_claim.clone());
            claims
        };
        let key_manager = SignKeyManager;
        let (pub_root_key, priv_root_key) = key_manager.generate_attenuation_key().unwrap();
        let mut ajwt = AttenuableJWT::new_with_key_manager(
            Cow::Borrowed(&key_manager),
            Cow::Borrowed(&JsonwebtokenEncoder),
            &priv_root_key,
            root_claims
        ).unwrap();

        for claim in claims.iter() {
            let attenuated_claims = {
                let mut attenuated_claims = HashMap::new();
                attenuated_claims.insert(claim_name.to_owned(), claim.clone());
                attenuated_claims
            };
            ajwt = ajwt.attenuate(attenuated_claims).unwrap();
        }

        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let sealed_jwt = ajwt.seal(SecondsSinceEpoch(current_time + 60), SecondsSinceEpoch(current_time), issuer.as_ref().map(|i| Issuer(i.clone())), None).unwrap();

        let acceptable_issuers = issuer.map(|i| vec![Issuer(i)]);
        let key_manager = VerifyKeyManager {
            pub_root_key,
            acceptable_issuers,
        };
        let verified_claims = verify(
            key_manager,
            &JsonwebtokenDecoder,
            sealed_jwt,
            |mut c1, c2| {
                c1.extend(c2);
                c1
            }
        ).unwrap();

        assert_eq!(verified_claims.get(claim_name), if claims.is_empty() { Some(&root_claim) } else { claims.last() });
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

#[derive(Clone)]
struct VerifyKeyManager {
    pub_root_key: ed25519::Ed25519PublicKey,
    acceptable_issuers: Option<Vec<Issuer>>,
}

impl VerificationKeyManager for VerifyKeyManager {
    type PublicRootKey = ed25519::Ed25519PublicKey;

    type PublicAttenuationKey = ed25519::Ed25519PublicKey;

    type PrivateAttenuationKey = ed25519::Ed25519PrivateKey;

    type Claims = std::collections::HashMap<String, String>;

    type JWK = ed25519::JWK;

    fn get_root_key(&self, key_id: &Option<String>) -> Option<Self::PublicRootKey> {
        if key_id
            .as_ref()
            .map(|kid| kid == self.pub_root_key.key_id())
            .unwrap_or(true)
        {
            Some(self.pub_root_key.clone())
        } else {
            None
        }
    }

    fn get_envelope_verification_requirements(&self) -> VerificationRequirements {
        VerificationRequirements::VerifyClaims {
            acceptable_algorithms: vec![ed25519::EDDSA_ALGORITHM.to_owned()],
            acceptable_issuers: self.acceptable_issuers.clone(),
            acceptable_audiences: None,
            acceptable_subject: None,
        }
    }

    fn default_claims(&self) -> Self::Claims {
        HashMap::new()
    }

    fn jwk_to_public_attenuation_key(&self, jwk: &Self::JWK) -> Option<Self::PublicAttenuationKey> {
        jwk.try_into().ok()
    }
}
