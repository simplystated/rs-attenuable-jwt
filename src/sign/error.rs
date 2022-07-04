use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("jwt error")]
    JWTError(#[from] jsonwebtoken::errors::Error),
    #[error("key error")]
    KeyError(#[from] ring::error::KeyRejected),
    #[error("crypto error")]
    CryptoError(#[from] ring::error::Unspecified),
}

pub type Result<R> = std::result::Result<R, Error>;
