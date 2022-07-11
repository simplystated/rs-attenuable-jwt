use std::marker::PhantomData;

use erased_serde::Serialize as ErasedSerialize;
use jsonwebtoken::{DecodingKey, EncodingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedJWT(pub String);

impl AsRef<str> for SignedJWT {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Serialize, Deserialize)]
pub struct SealedClaims {
    pub exp: Option<u64>,
    pub nbf: Option<u64>,
    pub iss: Option<String>,
    pub aud: Option<String>,
    pub jwts: Vec<SignedJWT>,
}

/// A private key
pub trait PrivateKey {
    fn key_id(&self) -> &str;
    fn algorithm(&self) -> &str;
    fn to_encoding_key(&self) -> Result<EncodingKey, crate::sign::Error>;
}

/// A public key. The [Serialize] implementation must serialize to a JWK.
pub trait PublicKey: ErasedSerialize {
    fn key_id(&self) -> &str;
    fn algorithm(&self) -> &str;
    fn key_use(&self) -> KeyUse;
    fn to_decoding_key(&self) -> Result<DecodingKey, crate::verify::Error>;
}

#[derive(Serialize, Deserialize)]
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
    fn get_root_verification_requirements<'a>(&'a self) -> VerificationRequirements<'a>;
    fn default_claims(&self) -> Self::Claims;
    fn jwk_to_public_attenuation_key(jwk: &Self::JWK) -> Option<Self::PublicAttenuationKey>;
}

pub struct VerificationRequirements<'a> {
    pub acceptable_algorithms: &'a [&'a str],
    pub acceptable_issuers: Option<&'a [&'a str]>,
    pub acceptable_audiences: Option<&'a [&'a str]>,
    pub acceptable_subjects: Option<&'a str>,
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
    ) -> FullClaims<Self::JWK, Self::PublicAttenuationKey, Self::Claims> {
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
pub struct FullClaims<JWK: Serialize, Pub: PublicKey, Claims: Serialize> {
    #[serde(flatten)]
    pub user_provided_claims: Claims,
    pub aky: JWK,
    pk: PhantomData<Pub>,
}

impl<JWK: Serialize, Pub: PublicKey, Claims: Serialize> FullClaims<JWK, Pub, Claims> {
    pub fn new(user_provided_claims: Claims, aky: JWK) -> Self {
        Self {
            user_provided_claims,
            aky,
            pk: PhantomData,
        }
    }
}
