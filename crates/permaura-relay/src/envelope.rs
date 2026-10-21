//! The wire [`Envelope`] and the top-level [`Frame`] enum.

use serde::{Deserialize, Serialize};

use crate::frames::{
    ApprovalRequest, ApprovalResult, AuthAck, Challenge, ChallengeRequest, Heartbeat, Hello,
    InvokeRequest, InvokeResult, RelayErrorFrame, Revoke,
};
use crate::sig::Signed;

/// Wire protocol version. An enum (not an int) so an unknown future version fails to
/// deserialize cleanly instead of silently mis-parsing; `Hello` negotiation is the single
/// place compatibility is decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolVersion {
    /// Version 1.
    V1,
}

impl ProtocolVersion {
    /// The version this build speaks.
    pub const CURRENT: ProtocolVersion = ProtocolVersion::V1;
    /// Every version this build accepts.
    pub const SUPPORTED: &'static [ProtocolVersion] = &[ProtocolVersion::V1];
}

/// Numeric form of [`ProtocolVersion::CURRENT`], for logs/metrics.
pub const RELAY_PROTOCOL_VERSION: u16 = 1;

/// The single wire unit: exactly one per transport message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol version of THIS frame. A stale peer can read this even on a frame whose
    /// `kind` it does not recognise, and reject with `UnsupportedVersion`.
    pub v: ProtocolVersion,
    /// Per-(connection, direction) monotonic counter set by the sender, a per-channel
    /// monotonic nonce. Starts at 1 after `AuthAck`; resets each connection
    /// (the new `connection_id` re-scopes every signature, so cross-connection replay also
    /// fails signature verification).
    pub seq: u64,
    /// Sender unix-ms send time. Nothing checks it today: the worker reads only the frame.
    pub ts: i64,
    /// The payload.
    pub frame: Frame,
}

impl Envelope {
    /// Build an envelope at the current protocol version.
    pub fn new(seq: u64, ts: i64, frame: Frame) -> Self {
        Envelope {
            v: ProtocolVersion::CURRENT,
            seq,
            ts,
            frame,
        }
    }
}

/// Every frame on the wire. Internally tagged → debuggable JSON (`{"kind":"invoke_request",…}`)
/// and forward-compatible matching. `#[non_exhaustive]` so a v1 decoder fails *closed*
/// (an unknown `kind` is a deserialization error) on a future-only variant rather than
/// silently mis-handling it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Frame {
    /// W→CP, unauthenticated: claims an identity, proves nothing.
    ChallengeRequest(ChallengeRequest),
    /// CP→W: the server-issued challenge.
    Challenge(Challenge),
    /// W→CP: the signed handshake.
    Hello(Signed<Hello>),
    /// CP→W: accepts the worker, pins the version, sets the cadence.
    AuthAck(AuthAck),
    /// W↔CP: liveness.
    Heartbeat(Heartbeat),
    /// CP→W: a relayed capability invocation.
    InvokeRequest(InvokeRequest),
    /// W→CP: the redacted outcome (never a secret).
    InvokeResult(InvokeResult),
    /// W→CP: a held call needs human approval.
    ApprovalRequest(ApprovalRequest),
    /// phone→CP→W: the approval decision, signed by the approver's device key (the worker
    /// verifies `device_sig` against its local approver keyring, and the CP only relays the bytes).
    ApprovalResult(ApprovalResult),
    /// CP→W: a signed revocation / killswitch (cannot be forged).
    Revoke(Signed<Revoke>),
    /// Either direction: a structured error.
    Error(RelayErrorFrame),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frames::*;
    use crate::sig::Signed;

    fn roundtrips(frame: Frame) {
        let env = Envelope::new(1, 100, frame);
        let json = serde_json::to_value(&env).unwrap();
        let back: Envelope = serde_json::from_value(json.clone()).unwrap();
        // Re-serialise the decoded form and compare, which proves a lossless round-trip without
        // requiring PartialEq on every frame type.
        assert_eq!(json, serde_json::to_value(&back).unwrap());
    }

    #[test]
    fn frames_round_trip() {
        roundtrips(Frame::ChallengeRequest(ChallengeRequest {
            worker_id: "worker_1".into(),
            max_version: ProtocolVersion::V1,
        }));
        roundtrips(Frame::Heartbeat(Heartbeat {
            at: 1,
            inflight: 2,
            serving: Some(vec!["braintree_production".into()]),
        }));
        roundtrips(Frame::Revoke(Signed::new(
            Revoke::Killswitch { org_id: "org_1".into() },
            "c2ln".into(),
        )));
        roundtrips(Frame::Error(RelayErrorFrame {
            job_id: Some("job_9".into()),
            code: crate::RelayErrorCode::NotServing,
            message: "no such resource".into(),
            fatal: false,
            retryable: true,
        }));
    }

    #[test]
    fn unknown_frame_kind_is_rejected() {
        // Fail-closed: a future-only frame kind must not deserialize on a v1 decoder.
        let bad = serde_json::json!({"v":"v1","seq":1,"ts":1,"frame":{"kind":"from_the_future"}});
        assert!(serde_json::from_value::<Envelope>(bad).is_err());
    }

    #[test]
    fn versions_are_ordered() {
        assert_eq!(ProtocolVersion::CURRENT, ProtocolVersion::V1);
        assert!(ProtocolVersion::SUPPORTED.contains(&ProtocolVersion::V1));
    }
}
