use thiserror::Error;

/// An error that may occur during attenuable JWT verification.
#[derive(Debug, Error)]
pub enum Error {
    /// An error decoding or validating a JWT's claims.
    #[error("jwt error")]
    JWTError(Option<Box<dyn std::error::Error>>),
    /// An error indicating that the final attenuation key in an envelope (the key that should be used to sign the envelope itself) is missing.
    #[error("missing final attenuation key")]
    MissingFinalAttenuationKey,
    /// An invalid attenuation key was encountered somewhere in the JWT chain.
    #[error("invalid attenuation key")]
    InvalidAttenuationKey(Box<dyn std::error::Error>),
    /// The envelope key was invalid.
    #[error("invalid envelope key")]
    InvalidEnvelopeKey,
    /// No key was found for the given key id.
    #[error("missing key for key id: {0:?}")]
    MissingKey(Option<String>),
    /// A JWK representing the public key for one of the attenuation keys in the JWT chain was malformed.
    #[error("malformed jwk for attenuation key")]
    MalformedAttenuationKeyJWK,
    /// Invalid key.
    #[error("invalid key")]
    InvalidKey,
}

/// Result type for verification operations.
pub type Result<R> = std::result::Result<R, Error>;
