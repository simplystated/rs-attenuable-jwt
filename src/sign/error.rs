use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("jwt error")]
    JWTError(Option<Box<dyn std::error::Error>>),
    #[error("key error")]
    KeyError(Option<Box<dyn std::error::Error>>),
    #[error("crypto error")]
    CryptoError(Option<Box<dyn std::error::Error>>),
}

pub type Result<R> = std::result::Result<R, Error>;
