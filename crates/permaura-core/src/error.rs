//! Error types for the Permaura security core.
//!
//! Every fallible operation in the core returns [`PermauraError`]. The variants are intentionally coarse: the security boundary should fail closed and never leak detail about secret material, so error messages describe *what kind* of operation failed, not the bytes involved.

use thiserror::Error;

/// The single error type returned by the Permaura security core.
#[derive(Debug, Error)]
pub enum PermauraError {
    /// A cryptographic operation (seal/open, key wrap/unwrap, KDF) failed. We deliberately keep the message generic so an attacker cannot distinguish "wrong passphrase" from "tampered ciphertext" by error text alone.
    #[error("cryptographic operation failed: {0}")]
    Crypto(String),

    /// Key derivation (Argon2id) failed, e.g. invalid parameters.
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),

    /// An audit chain was found to be inconsistent or tampered with.
    #[error("audit chain integrity error: {0}")]
    AuditIntegrity(String),

    /// An artefact decrypted correctly but its authenticated contents contradict its cleartext part.
    ///
    /// Distinct from [`PermauraError::Crypto`] on purpose, and safe to distinguish: reaching this
    /// check at all means the passphrase was right, so it reveals nothing a holder of the passphrase
    /// does not already have. Collapsing the two tells someone whose file was edited to go and check
    /// their passphrase, which is the one thing that will not help them.
    #[error("tampered artefact: {0}")]
    Tampered(String),

    /// A signature failed to verify.
    #[error("signature verification failed: {0}")]
    Signature(String),

    /// A requested secret, capability, connector, or other entity was not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// The input was malformed (bad capability id, bad action string, bad schema, etc.).
    #[error("invalid input: {0}")]
    InvalidInput(String),

    /// A policy decision denied the operation. Carried so callers can surface the reason.
    #[error("denied: {0}")]
    Denied(String),

    /// Serialization or deserialization (serde_json) failed.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// An upstream connector / HTTP execution failed.
    #[error("connector execution failed: {0}")]
    Connector(String),
}

impl From<serde_json::Error> for PermauraError {
    fn from(e: serde_json::Error) -> Self {
        PermauraError::Serialization(e.to_string())
    }
}

/// Convenience result alias used throughout the core.
pub type Result<T> = std::result::Result<T, PermauraError>;
