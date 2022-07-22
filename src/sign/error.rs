use thiserror::Error;

/// An error that may occur during attenuable JWT signing.
#[derive(Debug, Error)]
pub enum Error {
    /// An error related to creating a JWT.
    #[error("jwt error")]
    JWTError(Option<Box<dyn std::error::Error>>),
    /// An error creating or converting a public or private key.
    #[error("key error")]
    KeyError(Option<Box<dyn std::error::Error>>),
    /// An error arising from cryptographic operations.
    #[error("crypto error")]
    CryptoError(Option<Box<dyn std::error::Error>>),
}

/// Result type for signing operations.
pub type Result<R> = std::result::Result<R, Error>;
