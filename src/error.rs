use thiserror::Error;

#[derive(Error, Debug)]
pub enum JwtValidationError {
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
    #[error("Issuer does not match allowed values")]
    IssuerMismatch,
    #[error("AUD does not match provided client id")]
    ClientIdMismatch,
    #[error("The token start date is in the future")]
    TokenFromFuture,
    #[error("The token is expired")]
    TokenExpired,
    #[error("Kid not found")]
    KidNotPresentInList,
    #[error("Signature does not match metadata and claims")]
    SignatureDoesNotMatch,
    #[error("JWT must have three separate parts")]
    InvalidNumberOfParts,
    #[error("Error from base 64 decoder: {0}")]
    DecodingError(#[from] base64::DecodeError),
    #[error("Error from serde_json: {0}")]
    DeserializeError(#[from] serde_json::Error),
    #[error("Error from reqwest: {0}")]
    NetworkError(#[from] reqwest::Error),
    #[error("Error from rsa: {0}")]
    RsaError(#[from] rsa::Error),
    #[error("Error from rsa signature: {0}")]
    RsaSignatureError(#[from] rsa::signature::Error),
}
