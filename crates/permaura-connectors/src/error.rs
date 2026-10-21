//! The connector-layer error type.
//!
//! [`HttpClient::send`](crate::http::HttpClient::send) returns `anyhow::Result` because transport failures are open-ended, but the higher-level [`ConnectorRegistry::execute`](crate::connector::ConnectorRegistry::execute) boundary returns this typed error so callers (the gateway, the daemon) can distinguish "no such capability" from "the agent sent bad input" from "the upstream rejected us".

use thiserror::Error;

/// Errors raised while resolving or executing a capability.
#[derive(Debug, Error)]
pub enum ConnectorError {
    /// No registered capability matched the requested id.
    #[error("unknown capability: {0}")]
    UnknownCapability(String),

    /// The agent-supplied input failed validation before the request was shaped.
    #[error("invalid input: {0}")]
    BadInput(String),

    /// The upstream call failed at the transport layer (DNS, TLS, timeout, …).
    #[error("http error: {0}")]
    Http(String),

    /// The upstream returned a non-2xx status. The response body is intentionally not carried here: it is redacted and surfaced through the normal result path, never through an error string.
    #[error("upstream returned status {status}")]
    Upstream {
        /// The HTTP status code the upstream returned.
        status: u16,
    },
}

impl From<anyhow::Error> for ConnectorError {
    fn from(e: anyhow::Error) -> Self {
        ConnectorError::Http(crate::http::transport_error_text(&e))
    }
}
