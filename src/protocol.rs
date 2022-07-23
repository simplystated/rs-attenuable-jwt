//! This module provides types and traits library users need for signing and verifying attenuable JWTs.

use erased_serde::Serialize as ErasedSerialize;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Newtype struct for a string representing a signed JWT.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SignedJWT(pub String);

impl AsRef<str> for SignedJWT {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Claims for a sealed attenuated JWT.
/// These are the claims of the JWT produced by [crate::sign::AttenuableJWT::seal].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedClaims {
    /// Expiration.
    pub exp: Option<SecondsSinceEpoch>,
    /// Not before.
    pub nbf: Option<SecondsSinceEpoch>,
    /// Issuer.
    pub iss: Option<Issuer>,
    /// Audience.
    pub aud: Option<Audience>,
    /// Inner JWTs, starting with the root JWT and ending with the most-attenuated JWT.
    pub jwts: Vec<SignedJWT>,
}

/// Newtype wrapper for the number of seconds elapsed since the unix epoch.
/// Used in the `exp` and `nbf` claims of JWTs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SecondsSinceEpoch(pub u64);

/// Newtype wrapper for issuer identifiers.
/// Used in the `iss` claim of JWTs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Issuer(pub String);

impl AsRef<str> for Issuer {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Newtype wrapper for audience identifiers.
/// Used in the `aud` claim of JWTs.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Audience(pub String);

impl AsRef<str> for Audience {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// A private key. The [ErasedSerialize] implementation must serialize to a JWK.
pub trait PrivateKey: ErasedSerialize {
    /// Key ID.
    fn key_id(&self) -> &str;
    /// Algorithm.
    fn algorithm(&self) -> &str;
    /// Sign the message.
    fn sign(&self, message: &[u8]) -> crate::sign::Result<Vec<u8>>;
}

/// A public key. The [ErasedSerialize] implementation must serialize to a JWK.
pub trait PublicKey: ErasedSerialize {
    /// Key ID.
    fn key_id(&self) -> &str;
    /// Algorithm.
    fn algorithm(&self) -> &str;
    /// Intended use for the key.
    fn key_use(&self) -> KeyUse;
    /// Verify the signature of the message.
    fn verify(&self, message: &[u8], signature: &[u8]) -> bool;
}

erased_serde::serialize_trait_object!(PublicKey);

/// Key use identifiers.
/// Used in the `use` claim of a JWK.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeyUse {
    /// Encryption.
    #[serde(rename = "enc")]
    Encryption,
    /// Signing.
    #[serde(rename = "sig")]
    Signing,
}

/// Trait containing all client-supplied information needed for verify a sealed [crate::sign::AttenuableJWT].
pub trait VerificationKeyManager: Clone {
    /// Type of the public key for the root JWT.
    /// The root JWT may be signed by a different algorithm with a different type of key than the attenuated JWTs added to it.
    /// For example, the root JWT may be signed with a secret key, whereas only asymmetric keys are suitable for attenuated JWTs.
    type PublicRootKey: PublicKey;
    /// Type of the public key for attenuated JWTs.
    /// IMPORTANT: THIS MUST BE AN ASYMMETRIC KEY.
    /// This is the public key counterpart to the [Self::PrivateAttenuationKey].
    type PublicAttenuationKey: PublicKey;
    /// Type of the private key for attenuated JWTs.
    /// IMPORTANT: THIS MUST BE AN ASYMMETRIC KEY.
    /// This is the private key counterpart to the [Self::PublicAttenuationKey].
    type PrivateAttenuationKey: PrivateKey;
    /// Type of the client-supplied attenuated claims.
    /// Any type that is serializable to/from a JSON object is suitable.
    type Claims: Serialize + DeserializeOwned;
    /// Type of the JWK that represents a [Self::PublicAttenuationKey].
    type JWK: Serialize + DeserializeOwned;

    /// Given a `key_id` if it is present in the JWT header, return the corresponding [Self::PublicRootKey].
    fn get_root_key(&self, key_id: &Option<String>) -> Option<Self::PublicRootKey>;
    /// The [VerificationRequirements] to use for verifying the sealed JWT envelope.
    fn get_envelope_verification_requirements(&self) -> VerificationRequirements;
    /// [crate::verify::verify] performs a fold over existing and new claims for each JWT in the chain, invoking the client-provided `resolve_claims` function with the existing and new claims.
    /// The `default_claims` are used as the initial value in that fold.
    fn default_claims(&self) -> Self::Claims;
    /// Given a [Self::JWK], return a [Self::PublicAttenuationKey].

    // Convert a [Self::JWK] into a [Self::PublicAttenuationKey].
    fn jwk_to_public_attenuation_key(&self, jwk: &Self::JWK) -> Option<Self::PublicAttenuationKey>;
}

/// JWT header.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JWTHeader {
    /// Key ID for the key used to sign this JWT.
    #[serde(rename = "kid")]
    pub key_id: Option<String>,
    /// Algorithm used to sign this JWT.
    #[serde(rename = "alg")]
    pub algorithm: String,
}

/// Verification requirements to use when verifying a signed JWT.
#[derive(Clone, Debug)]
pub enum VerificationRequirements {
    /// Verify the signature and provided claims for the JWT.
    VerifyClaims {
        /// Acceptable signing algorithms.
        acceptable_algorithms: Vec<String>,
        /// Acceptable issuers. None indicates any issuer is acceptable.
        acceptable_issuers: Option<Vec<Issuer>>,
        /// Acceptable audiences. None indicates any audience is acceptable.
        acceptable_audiences: Option<Vec<Audience>>,
        /// Acceptable subject. None indicates any subject is acceptable.
        acceptable_subject: Option<String>,
    },
    /// Only verify the signature of the JWT but do not verify any claims.
    VerifySignatureOnly {
        /// Acceptable signing algorithms.
        acceptable_algorithms: Vec<String>,
    },
}

impl VerificationRequirements {
    /// Acceptable signing algorithms.
    pub fn acceptable_algorithms(&self) -> &[String] {
        match self {
            VerificationRequirements::VerifyClaims {
                acceptable_algorithms,
                ..
            } => acceptable_algorithms,
            VerificationRequirements::VerifySignatureOnly {
                acceptable_algorithms,
            } => acceptable_algorithms,
        }
    }
}

/// Trait handling signing and key generation for [crate::sign::AttenuableJWT].
pub trait SigningKeyManager:
    AttenuationKeyGenerator<Self::PublicAttenuationKey, Self::PrivateAttenuationKey> + Clone
{
    /// Type of the JWK for the [Self::PublicAttenuationKey].
    type JWK: Serialize;
    /// Type of the public key for the attenuation keys.
    type PublicAttenuationKey: PublicKey;
    /// Type of the private key for the attenuation keys.
    type PrivateAttenuationKey: PrivateKey;
    /// Type of the private key for the root JWT.
    type PrivateRootKey: PrivateKey;
    /// Type to represent the claims of the JWT. Any type that serializes to a map is suitable.
    type Claims: Serialize;

    /// Return a JWK representing the provided public attenuation key.
    fn jwk_for_public_attenuation_key(
        public_attenuation_key: &Self::PublicAttenuationKey,
    ) -> Self::JWK;
}

/// Trait for generating new attenuation keys.
pub trait AttenuationKeyGenerator<
    PublicAttenuationKey: PublicKey,
    PrivateAttenuationKey: PrivateKey,
>
{
    /// Generate a new, random attenuation key.
    fn generate_attenuation_key(
        &self,
    ) -> Result<(PublicAttenuationKey, PrivateAttenuationKey), crate::sign::Error>;
}

/// The full set of claims for an attenuated JWT, combining user-provided claims with the attenuation key claim.
#[derive(Serialize, Deserialize)]
pub struct FullClaims<JWK, Claims> {
    /// User-provided claims.
    #[serde(flatten)]
    pub user_provided_claims: Claims,
    /// Attenuation key claim containing a JWK representing the public key of the next attenuation key.
    pub aky: JWK,
}

impl<JWK: Serialize, Claims: Serialize> FullClaims<JWK, Claims> {
    /// Create a FullClaims.
    pub fn new(user_provided_claims: Claims, aky: JWK) -> Self {
        Self {
            user_provided_claims,
            aky,
        }
    }
}
