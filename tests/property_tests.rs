use attenuable_jwt::{
    protocol::{
        AttenuationKeyGenerator, Issuer, PublicKey, SecondsSinceEpoch, SigningKeyManager,
        VerificationKeyManager, VerificationRequirements,
    },
    sign::{ed25519, AttenuableJWT, Error as SignError},
    verify::verify,
};
use proptest::{prelude::*, proptest};
use std::{
    borrow::Cow,
    collections::HashMap,
    time::{SystemTime, UNIX_EPOCH},
};

proptest! {
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
        let mut ajwt: AttenuableJWT<'_, SignKeyManager> = AttenuableJWT::new_with_key_manager(Cow::Owned(key_manager), &priv_root_key, root_claims).unwrap();

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

    fn get_root_verification_requirements(&self) -> VerificationRequirements {
        VerificationRequirements {
            acceptable_algorithms: vec![ed25519::EDDSA_ALGORITHM.to_owned()],
            acceptable_issuers: self.acceptable_issuers.clone(),
            acceptable_audiences: None,
            acceptable_subjects: None,
        }
    }

    fn default_claims(&self) -> Self::Claims {
        HashMap::new()
    }

    fn jwk_to_public_attenuation_key(&self, jwk: &Self::JWK) -> Option<Self::PublicAttenuationKey> {
        jwk.try_into().ok()
    }
}
