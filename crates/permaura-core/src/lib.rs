//! # permaura-core
//!
//! The security core of **Permaura**: *give agents permission, not keys*.
//!
//! This crate is the deterministic, dependency-light library that compiles into the
//! gateway, the local daemon, the CLI, and the Tauri apps. It owns the parts of the
//! enforcement loop that must never be gotten subtly wrong:
//!
//! - [`model`]: the shared vocabulary, [`Principal`], [`Resource`], [`Action`],
//!   [`RiskTier`], [`Decision`], [`Grant`].
//! - [`crypto`]: envelope encryption, Argon2id-derived KEK, random per-secret DEK,
//!   AES-256-GCM or ChaCha20-Poly1305, into a serializable [`crypto::SealedSecret`].
//!   [`crypto::open`] returns the plaintext in a [`zeroize::Zeroizing`] buffer.
//! - [`audit`]: a hash-chained, ed25519-signed, tamper-evident [`audit::AuditLog`].
//! - [`vault`]: an in-memory [`vault::Vault`] whose two access paths,
//!   [`vault::Vault::use_secret`] and [`vault::Vault::use_secret_cached`], lend the plaintext to a
//!   closure and wipe it when the closure returns or panics, and [`vault::OpenedSecret`], the handle
//!   that holds plaintext for one operation outside a closure.
//! - [`bundle`]: the sealed vault bundle a customer exports and imports, opened into an
//!   [`bundle::OpenedBundle`] whose payload is read as a typed value, never as a JSON tree.
//! - [`secret`]: [`secret::SecretString`] and a JSON writer that leaves no copy behind as it grows,
//!   for plaintext that has to live outside a closure.
//! - [`capability`]: [`capability::CapabilityId`] / [`capability::CapabilitySpec`].
//! - [`redact`]: recursive response redaction before results reach the agent.
//! - [`scrub`]: removal of an injected credential's literal value, and its encodings, from a result.
//! - [`error`]: the single [`PermauraError`] type.
//!
//! The policy engine ([`permaura-policy`]) and connectors
//! ([`permaura-connectors`]) build on these types.
//!
//! ## Design stance
//!
//! Fail closed. Deny by default. The model is untrusted; only deterministic code in
//! this crate (and the policy engine) decides what may happen.
//!
//! Every function here that decrypts returns the plaintext in a type that wipes it when dropped
//! ([`zeroize::Zeroizing`], [`OpenedSecret`], [`OpenedBundle`]), lent to a closure or held in a
//! handle, never in a plain `Vec` or `String`. A bundle's payload is read as the caller's own type
//! (one that implements [`bundle::TypedPayload`], which `serde_json::Value` cannot), so the caller's
//! type decides how each secret in it is held. That bounds how long plaintext lingers in this
//! process's freed memory; it does not confine it. The code holding it (a vault closure, a connector
//! shaping a request) is trusted, and nothing in the types stops it copying the bytes out, so each
//! copy it makes is its own to keep in a wiping type.
//!
//! Wiping covers the buffers these types own and the blocks they outgrow, not every block the process
//! frees. Out of its reach: the transport's own copies of what is sent and received (an HTTP client's
//! header, body and response buffers, a child process's environment); a request body the gateway's
//! server reads in, such as a posted credential or an import passphrase; serde_json's scratch buffer,
//! for a string with an escape that is not read through [`secret::unescaped`]; the process environment
//! and the vault KEK, both held for the process's life; stack and register copies, which
//! [`secret::clear_stack`] clears only best effort; and memory the operating system has already
//! swapped or written to a core dump.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod audit;
pub mod bundle;
pub mod capability;
pub mod crypto;
pub mod error;
pub mod hash;
pub mod health_proof;
pub mod install;
pub mod json_stream;
pub mod json_text;
pub mod model;
pub mod paths;
pub mod redact;
pub mod scrub;
pub mod secret;
pub mod secret_file;
pub mod vault;

// ---- Public prelude re-exports -------------------------------------------------

pub use error::{PermauraError, Result};

pub use model::{
    Action, ApprovalKind, ApprovalRequirement, CatalogOrigin, Connection, ConnectionSource, Decision,
    DecisionKind, ExecutionLocation, Grant, GrantAgent, GrantAgents, GrantPeriod, GrantTarget,
    Policy, Principal, Resource, RiskTier, Rung, SourceKind,
};

pub use crypto::{open, open_with_kek, seal, seal_with_params, Cipher, KdfParams, Kek, KekCache, SealedSecret};

pub use bundle::{
    bundle_kdf_params, open_bundle, seal_bundle, seal_bundle_with_params, BundleSource, OpenedBundle,
    TypedPayload, VaultBundle, BUNDLE_FORMAT, BUNDLE_VERSION,
};

pub use secret::{SecretString, WipingBuffer};

pub use hash::request_hash;

pub use json_text::JsonText;

pub use audit::{AuditEvent, AuditLog, AuditPayload, GENESIS_PREV_HASH};

pub use vault::{OpenedSecret, SecretMetadata, SecretRecord, Vault};

pub use capability::{CapabilityId, CapabilitySpec};

pub use paths::{permaura_home, permaura_path};

pub use secret_file::{replace_secret_file, write_secret_file};

pub use redact::{default_redact_keys, effective_redact_keys, redact, redact_in_place, REDACTED};
pub use scrub::{CredentialScrub, SCRUBBED};
