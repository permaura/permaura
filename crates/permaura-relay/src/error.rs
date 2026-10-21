//! Relay error types: the wire [`RelayErrorCode`] and the local [`RelayError`].

use serde::{Deserialize, Serialize};

/// Wire error codes carried in [`crate::frames::RelayErrorFrame`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayErrorCode {
    /// Handshake failed (unknown worker, org mismatch, bad/expired challenge).
    AuthFailed,
    /// A signature did not verify.
    SignatureInvalid,
    /// The peer's protocol version is unsupported.
    UnsupportedVersion,
    /// An envelope `seq` regressed or repeated (replay).
    Replayed,
    /// The worker recomputed `request_hash` and it did not match.
    RequestHashMismatch,
    /// A job's deadline had already passed.
    DeadlineExceeded,
    /// The worker does not serve the requested resource.
    NotServing,
    /// The peer is shedding load.
    RateLimited,
    /// An org killswitch is active.
    KillswitchActive,
    /// The transport closed.
    ConnectionClosed,
    /// An unexpected internal failure (never secret-bearing).
    Internal,
}

/// Errors raised while handling relay frames. Distinct from a *policy* denial, which is a
/// normal [`crate::frames::RelayOutcome::Denied`], not an error.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// A signature operation failed (bad encoding, wrong length, or verification failure).
    #[error("signature error: {0}")]
    Signature(String),
    /// An envelope `seq` regressed or repeated.
    #[error("replayed seq {0}")]
    Replayed(u64),
    /// A job id is already in flight (duplicate, not yet complete).
    #[error("duplicate in-flight job '{0}'")]
    DuplicateJob(String),
    /// A protocol or encoding violation.
    #[error("protocol error: {0}")]
    Protocol(String),
    /// The transport closed.
    #[error("connection closed")]
    ConnectionClosed,
}

impl RelayError {
    /// Construct a signature error.
    pub fn signature(msg: impl Into<String>) -> Self {
        RelayError::Signature(msg.into())
    }
    /// Construct a replay error for a given `seq`.
    pub fn replayed(seq: u64) -> Self {
        RelayError::Replayed(seq)
    }
    /// Construct a protocol error.
    pub fn protocol(msg: impl Into<String>) -> Self {
        RelayError::Protocol(msg.into())
    }

    /// The wire code that best represents this error.
    pub fn code(&self) -> RelayErrorCode {
        match self {
            RelayError::Signature(_) => RelayErrorCode::SignatureInvalid,
            RelayError::Replayed(_) => RelayErrorCode::Replayed,
            RelayError::DuplicateJob(_) => RelayErrorCode::Internal,
            RelayError::Protocol(_) => RelayErrorCode::Internal,
            RelayError::ConnectionClosed => RelayErrorCode::ConnectionClosed,
        }
    }
}
