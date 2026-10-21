//! # permaura-relay
//!
//! Wire types and signing helpers for Permaura's **Mode B relay** design: a channel a worker (a
//! gateway instance) opens *outbound* to the control plane so a remote agent can reach a
//! locally-custodied secret. This crate is **pure types + crypto**: frames, a versioned
//! [`Envelope`], ed25519 signing preimages, replay guards, and a
//! [`transport::RelayTransport`] seam. It has **no async runtime, no sockets, no axum**.
//!
//! In production the gateway uses this crate's signing preimages, [`verify`],
//! [`validate_pubkey`] and approval-display digests for paired-device approvals, pairing and
//! device-control requests over REST. The frame, envelope, transport and replay types serve only
//! the gateway's dial-out worker (`services/gateway/src/relay`), which runs when
//! `PERMAURA_RELAY_URL` and a worker id and org are set; no control-plane hub that serves
//! `/v1/relay` exists yet.
//!
//! Invariants this crate encodes:
//! - **No frame carries a secret.** Plaintext never crosses the relay; the worker resolves
//!   the secret locally (inside its `SecretBackend`) and returns only a redacted result.
//! - **High-risk frames are [`sig::Signed`]**: the type system forbids an unsigned `Revoke`.
//! - The worker re-runs policy authoritatively; [`frames::SessionCtx`] carries identity only,
//!   never the control plane's bearer token and never an authorization verdict.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod display;
pub mod envelope;
pub mod error;
pub mod frames;
pub mod replay;
pub mod sig;
pub mod transport;

pub use display::{
    approval_display_digest, approval_display_digest_of, approval_display_full_digest,
    approval_display_full_digest_of, approval_shown_full_digest, ApprovalDisplay, ApprovalDisplayFull,
    DisplayContext, DisplayRow, DisplayState, APPROVAL_DISPLAY_VERSION,
};
pub use envelope::{Envelope, Frame, ProtocolVersion, RELAY_PROTOCOL_VERSION};
pub use error::{RelayError, RelayErrorCode};
pub use frames::{
    ApprovalRequest, ApprovalResult, AuthAck, Challenge, ChallengeRequest, Heartbeat, Hello,
    InvokeOrigin, InvokeRequest, InvokeResult, RelayErrorFrame, RelayOutcome, Revoke, SessionCtx,
};
pub use replay::{JobLedger, JobState, NonceWindow};
pub use sig::{
    approval_result_preimage, approval_result_preimage_v2, approval_result_preimage_v3,
    approver_pairing_preimage, device_control_preimage, device_control_preimage_v2, hello_preimage,
    sign, signing_preimage, strict_verifying_key, validate_pubkey, verify, Signed,
};
pub use transport::{CloseCode, RelayTransport};

/// The canonical request-hash binding, re-exported so relay peers compute exactly as the
/// gateway does (see [`permaura_core::request_hash`]). The worker recomputes it from the
/// received params and rejects a mismatch.
pub use permaura_core::request_hash;
