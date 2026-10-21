//! The transport seam.
//!
//! All relay logic operates on [`Envelope`]s, never on sockets, so swapping the underlying
//! transport (WebSocket in v1 → gRPC/QUIC later) is a single new
//! implementation of [`RelayTransport`]. The one concrete WebSocket implementation is the
//! gateway's dial-out client (`services/gateway/src/relay/ws_client.rs`), not in this crate; no
//! control-plane hub exists yet.

use async_trait::async_trait;

use crate::error::RelayError;
use crate::Envelope;

/// A bidirectional, framed channel carrying [`Envelope`]s in both directions.
#[async_trait]
pub trait RelayTransport: Send {
    /// Send one envelope.
    async fn send(&mut self, env: Envelope) -> Result<(), RelayError>;
    /// Receive the next envelope; `Err(RelayError::ConnectionClosed)` once the peer hangs up.
    async fn recv(&mut self) -> Result<Envelope, RelayError>;
    /// Close the connection, signalling why.
    async fn close(&mut self, code: CloseCode) -> Result<(), RelayError>;
}

/// Why a relay connection is being closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseCode {
    /// Orderly shutdown.
    Normal,
    /// Authentication/handshake failed.
    AuthFailed,
    /// A protocol or signature violation.
    ProtocolError,
    /// The peer is going away (restart / redeploy).
    Going,
}
