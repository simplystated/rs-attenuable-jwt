use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("jwt error")]
    JWTError(#[from] jsonwebtoken::errors::Error),
    #[error("missing final attenuation key")]
    MissingFinalAttenuationKey,
    #[error("invalid attenuation key")]
    InvalidAttenuationKey(Box<dyn std::error::Error>),
    #[error("invalid envelope key")]
    InvalidEnvelopeKey,
    #[error("missing key for key id: {0:?}")]
    MissingKey(Option<String>),
    #[error("malformed jwk for attenuation key")]
    MalformedAttenuationKeyJWK,
    #[error("malformed jwk")]
    MalformedJWK(#[from] base64::DecodeError),
}

pub type Result<R> = std::result::Result<R, Error>;
