use thiserror::Error;

/// Errors that can occur when working with C2PA and OpenTDF integration
#[derive(Error, Debug)]
pub enum C2paOpenTdfError {
    /// C2PA signing or verification error
    #[error("C2PA error: {0}")]
    C2pa(String),

    /// OpenTDF encryption or decryption error
    #[error("OpenTDF error: {0}")]
    OpenTdf(#[from] opentdf::TdfError),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Verification failed
    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid manifest
    #[error("Invalid manifest: {0}")]
    InvalidManifest(String),
}

impl From<c2pa::Error> for C2paOpenTdfError {
    fn from(err: c2pa::Error) -> Self {
        C2paOpenTdfError::C2pa(err.to_string())
    }
}

/// Type alias for Results using C2paOpenTdfError
pub type Result<T> = std::result::Result<T, C2paOpenTdfError>;
