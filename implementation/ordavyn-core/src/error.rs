//! Error types for Ordavyn core.

use thiserror::Error;

/// Core error type for Ordavyn operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CoreError {
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),

    #[error("invalid reference: {0}")]
    InvalidReference(String),

    #[error("CBOR encoding error: {0}")]
    CborEncoding(String),

    #[error("CBOR decoding error: {0}")]
    CborDecoding(String),

    #[error("CBOR tag rejected (unknown tag {0})")]
    CborTagRejected(u64),

    #[error("CBOR nesting depth exceeded (max {max}, got {actual})")]
    CborNestingExceeded { max: usize, actual: usize },

    #[error("CBOR array length exceeded (max {max}, got {actual})")]
    CborArrayLengthExceeded { max: usize, actual: usize },

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Result type for Ordavyn core operations.
pub type Result<T> = std::result::Result<T, CoreError>;
