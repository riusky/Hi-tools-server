use serde::Serialize;
use thiserror::Error;

#[derive(Debug, Serialize, Error)]
pub enum Error {
    #[error("An unspecified error occurred")]
    Unspecified,
    #[error("Encryption error occurred")]
    EncryptionError,
    #[error("Decryption error occurred")]
    DecryptionError,
    #[error("Key generation error occurred")]
    KeyGenerationError,
    #[error("Decoding error occurred")]
    DecodeError,
    #[error("Encoding error occurred")]
    EncodeError,
    #[error("RSA key generation error occurred")]
    RsaKeyGenerationError,
    #[error("RSA encryption error occurred")]
    RsaEncryptionError,
    #[error("RSA decryption error occurred")]
    RsaDecryptionError,
    #[error("UTF-8 conversion error occurred")]
    Utf8ConversionError,
}

pub type Result<T> = core::result::Result<T, Error>;