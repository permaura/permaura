//! # permaura-connectors
//!
//! The connector layer for **Permaura**: *give agents permission, not keys*.
//!
//! A connector turns an authorized `(capability, params, secret)` into an upstream
//! HTTP call and returns a **redacted** result. The secret is injected here, server-side,
//! from the gateway's opened copy, and the gateway's redaction and credential scrub keep it
//! out of what the agent receives. This crate is the single source
//! of truth for that request-shaping + redaction, consumed by the gateway, the daemon, and
//! anyone authoring a custom connector.
//!
//! - [`http`]: the [`HttpClient`] seam ([`ReqwestClient`] in prod, [`MockHttpClient`]
//!   offline/in tests) plus [`HttpRequest`] / [`HttpResponse`].
//! - [`command`]: the [`CommandRunner`] seam ([`RealCommandRunner`] in prod,
//!   [`MockCommandRunner`] offline/in tests) plus [`CommandInvocation`] / [`CommandOutput`],
//!   for driving a locked-down CLI with an injected scoped token.
//! - [`connector`]: [`Capability`], [`CapabilityKind`], [`CommandSpec`], the [`Connector`]
//!   trait, the built-in [`GitHubConnector`] / [`BraintreeConnector`] / [`VercelConnector`] /
//!   [`VercelCliConnector`] / [`GenericHttpConnector`], and the [`ConnectorRegistry`] whose
//!   [`execute`](ConnectorRegistry::execute) shapes, sends, rejects non-2xx, and redacts.
//! - [`error`]: the typed [`ConnectorError`] returned at the execute boundary.
//!
//! ## Design stance
//!
//! Connectors expose *only* the verbs they define: an agent cannot invoke what no
//! capability declares (note the deliberate absence of GitHub merge/force-push/delete and
//! any `get_secret`-style capability). Destructive verbs carry a high/critical risk tier
//! and may set `requires_approval`, which the policy engine turns into a human gate.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod caps;
pub mod command;
pub mod connector;
pub mod egress;
pub mod error;
pub mod graphql;
pub mod http;
pub mod json_budget;
pub mod ssh;

pub use command::{
    CommandInvocation, CommandOutput, CommandRunner, MockCommandRunner, RealCommandRunner,
    DEFAULT_COMMAND_TIMEOUT,
};
pub use connector::{
    build_command, build_request, build_request_for, canonical_agent_params, canonicalize_agent_params, compile_path_pattern, graphql_check, is_generic_http_connector,
    json_text, project_response, request_refusal, response_alias_room, response_needs_projection, response_redact_keys, takes_agent_url, AuthScheme, BodyStyle, BraintreeConnector,
    Capability, CapabilityKind, CommandSpec, Connector, ConnectorRegistry, FalConnector, GenericHttpConnector, GitHubConnector, GraphqlCheck,
    GraphqlOperation, GraphqlSpec, HttpSpec, PathPattern, QueryStyle, RequestRefusal, ResponseRedaction, VercelCliConnector, VercelConnector, MAX_ENCODED_PARAMS_BYTES,
    MAX_RESPONSE_ALIASES, UNCHARGED_ALIAS_ROOM, family_hosts, is_method_override_header, is_method_override_param, method_override_refusal, on_family_host,
    OwnerPosture,
};
pub use caps::{
    command_max_output_bytes, http_max_response_bytes, DEFAULT_COMMAND_MAX_OUTPUT_BYTES,
    DEFAULT_HTTP_MAX_RESPONSE_BYTES,
};
pub use egress::{
    host_allowed, is_blocked_host, is_blocked_ip, parse_url, screen_host, screen_resolved, screen_url, scrub_url,
    scrub_urls, url_host, EgressError, UrlParts,
};
pub use error::ConnectorError;
pub use http::{
    is_chain_safe_header, is_diagnostic_header, non_json_text, transport_error_text, HttpClient, HttpMethod, HttpRequest, HttpResponse,
    MockHttpClient, RawHttpResponse, ReqwestClient, SecretHttpResponse,
};
pub use json_budget::{MemoryCharge, MemoryPool, PoolRefusal};
pub use ssh::{
    base64_len, build_ssh, public_dial_addrs, sftp_put_cap_for_body_limit, MockSshRunner, SftpEntry, SshConnector,
    SshCredentialKind, SshEgress, SshExecCommand, SshHostKey, SshInvocation, SshOp, SshOutcome, SshRunOp,
    SshRunner, SshSpec, SshTarget, DEFAULT_SFTP_MAX_BYTES, DEFAULT_SSH_TIMEOUT,
    SFTP_PUT_BODY_BUDGET_BYTES, SFTP_PUT_ENVELOPE_RESERVE_BYTES, SFTP_PUT_MAX_BYTES,
};
#[cfg(feature = "ssh-transport")]
pub use ssh::RealSshRunner;
