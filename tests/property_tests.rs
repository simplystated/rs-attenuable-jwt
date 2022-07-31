use attenuable_jwt::{
    ed25519,
    sign::{AttenuableJWT, Error as SignError},
    verify::verify,
    AttenuationKeyGenerator, Audience, Issuer, PublicKey, SecondsSinceEpoch, SigningKeyManager,
    VerificationKeyManager, VerificationRequirements,
};
use mockall::mock;
use proptest::{prelude::*, prop_oneof, proptest};
use std::{
    borrow::Cow,
    collections::HashMap,
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
    let key_manager = SignKeyManager::new();
    let (pub_root_key, priv_root_key) = key_manager.generate_attenuation_key().unwrap();
    let mut ajwt = AttenuableJWT::with_root_key_and_claims(
        Cow::Borrowed(&key_manager),
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
                // replace our private attenuation key with an incorrect attenuation key
                let (_, bad_priv_key) = key_manager.generate_attenuation_key().unwrap();
                ajwt = AttenuableJWT::with_jwts_and_attenuation_key(
                    Cow::Borrowed(&key_manager),
                    ajwt.jwts().to_vec(),
                    bad_priv_key,
                );

                // then, attenuate
                let claims = {
                    let mut claims = HashMap::new();
                    claims.insert(claim_key, claim_value);
                    claims
                };
                ajwt = ajwt.attenuate(claims).unwrap();

                // this should cause the whole chain to fail
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
                let verified = verify(verification_key_manager, sealed, resolve_claims);

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
                let token = ajwt.seal(exp, nbf, Some(iss), Some(aud)).unwrap();
                let verification_key_manager =
                    make_verification_key_manager(pub_root_key.clone(), add_expected_verifications);
                let verified = verify(verification_key_manager, token, resolve_claims);
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
                let token = ajwt.seal(exp, nbf, Some(iss), Some(aud)).unwrap();
                let verification_key_manager =
                    make_verification_key_manager(pub_root_key.clone(), add_expected_verifications);
                let verified = verify(verification_key_manager, token, resolve_claims);
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
                let token = ajwt.seal(exp, nbf, Some(iss), Some(aud)).unwrap();
                let verification_key_manager =
                    make_verification_key_manager(pub_root_key.clone(), add_expected_verifications);
                let verified = verify(verification_key_manager, token, resolve_claims);
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
                let token = ajwt.seal(exp, nbf, Some(iss), Some(aud)).unwrap();
                let verification_key_manager =
                    make_verification_key_manager(pub_root_key.clone(), add_expected_verifications);
                let verified = verify(verification_key_manager, token, resolve_claims);
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
                let bad_key_ajwt = AttenuableJWT::with_jwts_and_attenuation_key(
                    Cow::Borrowed(&key_manager),
                    ajwt.jwts().to_vec(),
                    bad_key,
                );
                let token = bad_key_ajwt.seal(exp, nbf, Some(iss), Some(aud)).unwrap();
                let verification_key_manager =
                    make_verification_key_manager(pub_root_key.clone(), add_expected_verifications);
                let verified = verify(verification_key_manager, token, resolve_claims);
                assert!(
                    verified.is_err(),
                    "expected verification failure, got: {:?}",
                    &verified
                );
            }
        }
    }
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
        let key_manager = SignKeyManager::new();
        let (pub_root_key, priv_root_key) = key_manager.generate_attenuation_key().unwrap();
        let mut ajwt = AttenuableJWT::with_root_key_and_claims(
            Cow::Borrowed(&key_manager),
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
struct SignKeyManager {
    key_gen: ed25519::EddsaKeyGen<rand::rngs::StdRng>,
}

impl SignKeyManager {
    pub fn new() -> Self {
        Self {
            key_gen: ed25519::EddsaKeyGen::new_with_std_rng(),
        }
    }
}

impl AttenuationKeyGenerator<ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey>
    for SignKeyManager
{
    fn generate_attenuation_key(
        &self,
    ) -> Result<(ed25519::Ed25519PublicKey, ed25519::Ed25519PrivateKey), SignError> {
        self.key_gen.generate_attenuation_key()
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
