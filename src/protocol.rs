use erased_serde::Serialize as ErasedSerialize;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedJWT(pub String);

impl AsRef<str> for SignedJWT {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedClaims {
    pub exp: Option<SecondsSinceEpoch>,
    pub nbf: Option<SecondsSinceEpoch>,
    pub iss: Option<Issuer>,
    pub aud: Option<Audience>,
    pub jwts: Vec<SignedJWT>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecondsSinceEpoch(pub u64);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Issuer(pub String);

impl AsRef<str> for Issuer {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Audience(pub String);

impl AsRef<str> for Audience {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A private key
pub trait PrivateKey: ErasedSerialize {
    fn key_id(&self) -> &str;
    fn algorithm(&self) -> &str;
}

/// A public key. The [Serialize] implementation must serialize to a JWK.
pub trait PublicKey: ErasedSerialize {
    fn key_id(&self) -> &str;
    fn algorithm(&self) -> &str;
    fn key_use(&self) -> KeyUse;
}

erased_serde::serialize_trait_object!(PublicKey);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeyUse {
    #[serde(rename = "enc")]
    Encryption,
    #[serde(rename = "sig")]
    Signing,
}

pub trait VerificationKeyManager: Clone {
    type PublicRootKey: PublicKey;
    type PublicAttenuationKey: PublicKey;
    type PrivateAttenuationKey: PrivateKey;
    type Claims: Serialize + DeserializeOwned;
    type JWK: Serialize + DeserializeOwned;

    fn get_root_key(&self, key_id: &Option<String>) -> Option<Self::PublicRootKey>;
    fn get_envelope_verification_requirements(&self) -> VerificationRequirements;
    fn default_claims(&self) -> Self::Claims;
    fn jwk_to_public_attenuation_key(&self, jwk: &Self::JWK) -> Option<Self::PublicAttenuationKey>;
}

pub trait JWTDecoder {
    fn decode_jwt<Claims: DeserializeOwned, PubKey: PublicKey + ?Sized>(
        &self,
        jwt: &SignedJWT,
        verification_key: &PubKey,
        verification_reqs: &VerificationRequirements,
    ) -> crate::verify::Result<Claims>;
    fn insecurely_decode_jwt<Claims: DeserializeOwned>(
        &self,
        jwt: &SignedJWT,
    ) -> crate::verify::Result<Claims>;
    fn decode_jwt_header(&self, jwt: &SignedJWT) -> crate::verify::Result<JWTHeader>;
}

pub trait JWTEncoder {
    fn encode_jwt<Claims: Serialize, PrivKey: PrivateKey + ?Sized>(
        &self,
        header: &JWTHeader,
        claims: &Claims,
        signing_key: &PrivKey,
    ) -> crate::sign::Result<SignedJWT>;
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWTHeader {
    #[serde(rename = "kid")]
    pub key_id: Option<String>,
    #[serde(rename = "alg")]
    pub algorithm: String,
}

#[derive(Clone, Debug)]
pub enum VerificationRequirements {
    VerifyClaims {
        acceptable_algorithms: Vec<String>,
        acceptable_issuers: Option<Vec<Issuer>>,
        acceptable_audiences: Option<Vec<Audience>>,
        acceptable_subject: Option<String>,
    },
    VerifySignatureOnly {
        acceptable_algorithms: Vec<String>,
    },
}

pub trait SigningKeyManager:
    AttenuationKeyGenerator<Self::PublicAttenuationKey, Self::PrivateAttenuationKey> + Clone
{
    type JWK: Serialize;
    type PublicAttenuationKey: PublicKey;
    type PrivateAttenuationKey: PrivateKey;
    type PrivateRootKey: PrivateKey;
    type Claims: Serialize;

    fn claims_with_attenuation_key(
        claims: Self::Claims,
        attenuation_key: &Self::PublicAttenuationKey,
    ) -> FullClaims<Self::JWK, Self::Claims> {
        FullClaims::new(
            claims,
            Self::jwk_for_public_attenuation_key(attenuation_key),
        )
    }

    fn jwk_for_public_attenuation_key(
        public_attenuation_key: &Self::PublicAttenuationKey,
    ) -> Self::JWK;
}

pub trait AttenuationKeyGenerator<
    PublicAttenuationKey: PublicKey,
    PrivateAttenuationKey: PrivateKey,
>
{
    fn generate_attenuation_key(
        &self,
    ) -> Result<(PublicAttenuationKey, PrivateAttenuationKey), crate::sign::Error>;
}

#[derive(Serialize, Deserialize)]
pub struct FullClaims<JWK, Claims> {
    #[serde(flatten)]
    pub user_provided_claims: Claims,
    pub aky: JWK,
}

impl<JWK: Serialize, Claims: Serialize> FullClaims<JWK, Claims> {
    pub fn new(user_provided_claims: Claims, aky: JWK) -> Self {
        Self {
            user_provided_claims,
            aky,
        }
    }
}
