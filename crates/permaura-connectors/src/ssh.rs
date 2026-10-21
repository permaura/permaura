//! The SSH connector: run allow-listed remote commands and move files over SFTP under the
//! same policy / grant / approval / audit machinery as every other capability, without the
//! agent ever holding an SSH key.
//!
//! This mirrors the [`command`](crate::command) seam one layer out. Where a command capability
//! runs a pinned local argv with a token injected as an env var, an SSH capability opens a
//! network session to a **pinned** host (host, port, user and host-key fingerprint are all
//! server-side, never agent-supplied, the SSH analogue of [`HttpSpec::base_url`](crate::connector::HttpSpec)
//! being the SSRF guard), authenticates with a key resolved from the vault, and runs a pinned
//! operation. The two agent-influence surfaces are kept as narrow as the command path's:
//!
//! - **exec** reuses the exact allow-list discipline of [`build_command`](crate::connector::build_command):
//!   the remote command is a fixed argv template; an agent may fill only whitelisted `{name}`
//!   slots, each rejected if empty or carrying a shell metacharacter. There is deliberately **no**
//!   free-form command param: the policy engine has no per-argument constraint, so a single
//!   `exec` taking an arbitrary command would let an agent run a metacharacter-free-but-destructive
//!   `rm -rf /data`. Each safe command shape is its own capability with its own risk tier.
//! - **sftp** exposes structured get/put/list operations (modern `scp` runs over SFTP anyway;
//!   a raw byte pipe would bypass policy). The remote path is scoped under an operator-pinned
//!   root (relative only, no `..` traversal) and transfers are size-capped.
//!
//! The credential (an OpenSSH/PEM private key or a password) is resolved through the gateway's
//! [`SecretBackend`] like every other secret and handed to [`build_ssh`] as raw bytes; it is held
//! in a [`Zeroizing`] buffer for only the window SSH auth needs it and wiped when the invocation
//! drops. Redaction of results is the caller's job, mirroring the command path.
//!
//! ## Transport seam
//!
//! [`SshRunner`] is the swappable transport, exactly like [`CommandRunner`](crate::command::CommandRunner):
//! [`MockSshRunner`] records invocations and returns a canned outcome so the whole connector
//! (validation, host-key policy, path scoping, the gateway wiring, and every test) runs offline
//! with **no SSH dependency at all**. The real [`russh`]-backed transport lives behind the
//! `ssh-transport` cargo feature and is linked only in a deployment that must reach a host.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use permaura_core::{Action, RiskTier};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::command::CommandOutput;
use crate::connector::{Capability, CapabilityKind, Connector};
use crate::error::ConnectorError;

/// The wall-clock budget for a single SSH operation (connect + auth + run). A hung host must
/// not pin the gateway, so the real transport aborts the whole operation after this.
pub const DEFAULT_SSH_TIMEOUT: Duration = Duration::from_secs(30);

/// The default per-transfer cap for SFTP get/put (5 MiB). Bounds how many bytes a single call
/// can move (the one real cost/exfil lever for file transfer) before an operator raises it.
///
/// A put is bounded more tightly than this by [`SFTP_PUT_MAX_BYTES`], because a put's bytes have to
/// reach the gateway inside a request body and a get's do not.
pub const DEFAULT_SFTP_MAX_BYTES: u64 = 5 * 1024 * 1024;

/// The request-body budget an SFTP put has to fit inside: the gateway's execution-route body limit
/// (`PERMAURA_LIMIT_BODY_EXEC_BYTES`, 2 MiB).
///
/// A put's content arrives base64-encoded in the `/v1/invoke` body, so the put cap is not free to be
/// chosen on its own. It is stated here, in the crate that owns the cap, because
/// `permaura-connectors` sits below the gateway and cannot read the gateway's own constant; a
/// `const` assertion in `services/gateway/src/limits.rs` fails the build if the two ever disagree.
pub const SFTP_PUT_BODY_BUDGET_BYTES: u64 = 2 * 1024 * 1024;

/// What the budget reserves for everything in the body that is not the content: the capability id,
/// the path parameter, the JSON around both. 64 KiB is far more than any realistic envelope and
/// costs only headroom.
pub const SFTP_PUT_ENVELOPE_RESERVE_BYTES: u64 = 64 * 1024;

/// The cap on a single SFTP put (1 MiB), **derived** from [`SFTP_PUT_BODY_BUDGET_BYTES`] rather
/// than chosen.
///
/// Before this the put cap was [`DEFAULT_SFTP_MAX_BYTES`], 5 MiB, which base64 inflates to about
/// 6.7 MiB on the wire: every put above roughly 1.5 MiB was refused by the body limit with a bare
/// 413 and never reached the cap that was supposed to govern it. Deriving the put cap from the body
/// budget is what stops the two disagreeing again, and the direction was chosen deliberately:
/// raising the body limit to cover 5 MiB would raise the memory profile of `/v1/invoke` and `/mcp`
/// alike on a 512 MiB instance, which is the wrong direction for a worker whose peak is already
/// three copies of every payload.
///
/// 1 MiB is also [`DEFAULT_EXEC_OUTPUT_BYTES`], so the two SSH byte caps read as one decision.
pub const SFTP_PUT_MAX_BYTES: u64 = sftp_put_cap_for_body_limit(SFTP_PUT_BODY_BUDGET_BYTES);

/// The length of `raw` bytes once base64-encoded with padding.
pub const fn base64_len(raw: u64) -> u64 {
    raw.div_ceil(3) * 4
}

/// The largest put cap a request body of `body_bytes` can carry, rounded down to a whole mebibyte.
///
/// The rounding is not cosmetic. The slack it leaves is the band in which an over-cap put still
/// *arrives*, so the caller gets the connector's own message naming the cap instead of a 413 it
/// cannot read: at the shipped 2 MiB budget a put is named up to about 1.45 MiB and only a put
/// beyond that is cut off by the body limit. Below one mebibyte of usable space there is nothing to
/// round to, so the exact fit is returned.
pub const fn sftp_put_cap_for_body_limit(body_bytes: u64) -> u64 {
    let usable = body_bytes.saturating_sub(SFTP_PUT_ENVELOPE_RESERVE_BYTES);
    let exact = usable / 4 * 3;
    let whole_mib = exact / (1024 * 1024);
    if whole_mib == 0 {
        exact
    } else {
        whole_mib * 1024 * 1024
    }
}

/// The default cap on how much stdout+stderr an exec captures (1 MiB). Bounds gateway memory so a
/// command with huge (or maliciously streamed) output cannot exhaust the heap; output past the cap
/// is discarded, not buffered.
pub const DEFAULT_EXEC_OUTPUT_BYTES: u64 = 1024 * 1024;

/// The default cap on how many entries an SFTP listing returns, bounding memory against a directory
/// with a very large number of files.
pub const DEFAULT_SFTP_MAX_ENTRIES: usize = 10_000;

fn default_ssh_port() -> u16 {
    22
}
fn default_sftp_max_bytes() -> u64 {
    DEFAULT_SFTP_MAX_BYTES
}
fn default_exec_output_bytes() -> u64 {
    DEFAULT_EXEC_OUTPUT_BYTES
}

/// How the remote host's public key is verified: the MITM defense, pinned server-side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum SshHostKey {
    /// Require the server's host key to match this SHA256 fingerprint (the base64 body of the
    /// `SHA256:…` form OpenSSH prints, with or without the prefix). Any mismatch is a hard error.
    Fingerprint {
        /// The expected SHA256 host-key fingerprint.
        sha256: String,
    },
    /// Accept **any** host key without verification. Local/dev only, and logged loudly by the real
    /// transport. Never use against a host reached over an untrusted network. There is no default:
    /// an operator must opt into this explicitly, so production stays fail-closed on host identity.
    Insecure,
}

/// Which credential the resolved secret bytes represent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SshCredentialKind {
    /// An OpenSSH / PEM private key (public-key auth). The default and recommended custody.
    #[default]
    PrivateKey,
    /// A password (password auth). Weaker; supported only for legacy hosts.
    Password,
}

/// The pinned SSH target. None of this is agent-supplied: it is fixed on the capability at
/// creation, exactly as an imported HTTP capability pins its base URL.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshTarget {
    /// The host to dial (name or literal IP). Never agent-supplied.
    pub host: String,
    /// The SSH port (defaults to 22).
    #[serde(default = "default_ssh_port")]
    pub port: u16,
    /// The remote login user. Never agent-supplied.
    pub user: String,
    /// How the host key is verified.
    pub host_key: SshHostKey,
}

/// What an SSH capability does on its target. The `op` tag makes each variant self-describing on
/// the wire so the persisted capability blob round-trips.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum SshOp {
    /// Run a fixed, allow-listed remote command. `args_template` + `allowed_placeholders` mirror
    /// [`CommandSpec`](crate::connector::CommandSpec) exactly: literal elements pass through; a
    /// whole-element `{name}` token is filled from `params[name]` only when `name` is allow-listed,
    /// and every filled value is metacharacter- and whitespace-rejected. The argv is joined into a
    /// single POSIX-quoted command string for the remote shell.
    Exec {
        /// The pinned remote-command argv template.
        args_template: Vec<String>,
        /// The placeholder names an agent may fill.
        #[serde(default)]
        allowed_placeholders: Vec<String>,
        /// The cap on captured stdout+stderr bytes (each stream bounded to this).
        #[serde(default = "default_exec_output_bytes")]
        max_output_bytes: u64,
    },
    /// Read a remote file's bytes, returned base64 (capped at `max_bytes`). The agent supplies a
    /// `path` relative to `root`.
    SftpGet {
        /// The operator-pinned root the agent's path is resolved under. Never agent-supplied.
        root: String,
        /// The maximum number of bytes this capability may read in one call.
        #[serde(default = "default_sftp_max_bytes")]
        max_bytes: u64,
    },
    /// Write base64 `content` to a remote file at `path` (relative to `root`), capped at `max_bytes`.
    SftpPut {
        /// The operator-pinned root the agent's path is resolved under. Never agent-supplied.
        root: String,
        /// The maximum number of bytes this capability may write in one call.
        #[serde(default = "default_sftp_max_bytes")]
        max_bytes: u64,
    },
    /// List a remote directory. The agent may supply an optional `path` under `root`; absent, the
    /// root itself is listed.
    SftpList {
        /// The operator-pinned root the agent's path is resolved under. Never agent-supplied.
        root: String,
    },
}

/// The fixed shape of an SSH capability: the pinned target, how to read its credential, and the
/// pinned operation. Everything an agent cannot influence lives here, server-side.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshSpec {
    /// The pinned host/port/user + host-key policy.
    pub target: SshTarget,
    /// How to interpret the resolved secret bytes (private key by default).
    #[serde(default)]
    pub credential_kind: SshCredentialKind,
    /// The pinned operation this capability performs.
    pub op: SshOp,
}

// ── Resolved invocation (agent params already substituted + validated) ───────────────

/// A concrete, resolved operation ready for the transport. `params` have been substituted and
/// validated; nothing here is still a template.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshRunOp {
    /// Run this exact remote command line (already argv-built and POSIX-quoted).
    Exec {
        /// The command string handed to the remote login shell.
        command: String,
        /// The cap on captured stdout+stderr bytes (each stream bounded to this).
        max_output_bytes: u64,
    },
    /// Read this exact remote path (capped at `max_bytes`).
    Get {
        /// The resolved, root-scoped remote path.
        path: String,
        /// The read cap in bytes.
        max_bytes: u64,
    },
    /// Write `content` to this exact remote path (already length-checked against `max_bytes`).
    Put {
        /// The resolved, root-scoped remote path.
        path: String,
        /// The bytes to write.
        content: Vec<u8>,
        /// The write cap in bytes (carried for the transport to re-assert).
        max_bytes: u64,
    },
    /// List this exact remote directory path.
    List {
        /// The resolved, root-scoped remote directory.
        path: String,
    },
}

/// Where an SSH session may be opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshEgress {
    /// Wherever the host resolves, LAN and loopback included: a gateway its owner runs, where a home
    /// server or a box on the same network is what SSH is for.
    Unrestricted,
    /// Public addresses only, by the rules the HTTP egress guard applies, and the session connects to
    /// the screened addresses and nothing else: a hosted worker, which is Permaura's machine.
    PublicOnly,
}

/// The addresses a [`SshEgress::PublicOnly`] session connects to: `host` screened as written, then
/// resolved once through `lookup`, keeping only the public addresses. A name that resolves to the
/// metadata server or loopback is never dialled, and nothing re-resolves between the check and the connect.
pub async fn public_dial_addrs<F, Fut>(host: &str, port: u16, lookup: F) -> anyhow::Result<Vec<SocketAddr>>
where
    F: FnOnce(String, u16) -> Fut,
    Fut: Future<Output = std::io::Result<Vec<SocketAddr>>>,
{
    crate::egress::screen_host(host)?;
    let bare = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')).unwrap_or(host);
    let resolved = lookup(bare.to_string(), port).await?;
    Ok(crate::egress::screen_resolved(host, resolved)?)
}

/// A fully-resolved SSH operation to run: the pinned target, the credential bytes, and the
/// concrete op. The credential is held in a [`Zeroizing`] buffer: SSH auth inherently needs the
/// key/password during the network handshake (unlike an env-var copy that can be dropped before
/// I/O), so it lives here for the minimal window and is wiped the instant the invocation drops.
#[derive(Clone)]
pub struct SshInvocation {
    /// The pinned host/port/user + host-key policy.
    pub target: SshTarget,
    /// How to interpret [`credential`](Self::credential).
    pub credential_kind: SshCredentialKind,
    /// The private-key PEM or password bytes, wiped on drop.
    pub credential: Zeroizing<Vec<u8>>,
    /// The concrete operation to run.
    pub op: SshRunOp,
    /// Which addresses the session may be opened to.
    pub egress: SshEgress,
}

impl std::fmt::Debug for SshInvocation {
    /// Never renders the credential bytes.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshInvocation")
            .field("target", &self.target)
            .field("credential_kind", &self.credential_kind)
            .field("credential", &format!("[redacted; {} bytes]", self.credential.len()))
            .field("op", &self.op)
            .field("egress", &self.egress)
            .finish()
    }
}

/// One entry from an SFTP directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SftpEntry {
    /// The entry's file name (leaf, not the full path).
    pub name: String,
    /// Size in bytes (0 for directories / when unknown).
    pub size: u64,
    /// Whether the entry is a directory.
    pub is_dir: bool,
}

/// The result of running an [`SshInvocation`]. The gateway shapes this into a redacted JSON result.
#[derive(Debug, Clone)]
pub enum SshOutcome {
    /// A remote command's exit code + streams (same shape as a local command).
    Exec(CommandOutput),
    /// A file read: how many bytes, and the base64 content.
    Get {
        /// Bytes read.
        bytes: u64,
        /// The file content, base64-encoded.
        content_base64: String,
    },
    /// A file write: how many bytes were written.
    Put {
        /// Bytes written.
        bytes: u64,
    },
    /// A directory listing.
    List {
        /// The entries (capped at [`DEFAULT_SFTP_MAX_ENTRIES`]).
        entries: Vec<SftpEntry>,
        /// Whether the directory had more entries than the cap (the list was truncated).
        truncated: bool,
    },
}

// ── build_ssh: params → validated, resolved invocation ───────────────────────────────

/// Build an [`SshInvocation`] from an [`SshSpec`], the agent's `params`, and the opened `secret`
/// bytes (the private key or password). It dials [`SshEgress::PublicOnly`]; a gateway its owner runs
/// widens that to [`SshEgress::Unrestricted`].
///
/// exec reuses the connector crate's shared allow-list substitution ([`substitute_arg`](crate::connector::substitute_arg)),
/// so the exact same metacharacter/whitespace rejection and whole-element-placeholder rules that
/// guard a local command guard the remote one. SFTP paths are scoped under the pinned root
/// (relative only, no `..`) and put-content is size-checked before it ever leaves the gateway.
pub fn build_ssh(
    spec: &SshSpec,
    params: &serde_json::Value,
    secret: &[u8],
) -> Result<SshInvocation, ConnectorError> {
    let op = match &spec.op {
        SshOp::Exec { args_template, allowed_placeholders, max_output_bytes } => {
            if args_template.is_empty() {
                return Err(ConnectorError::BadInput(
                    "ssh exec capability has an empty command template".into(),
                ));
            }
            let mut argv = Vec::with_capacity(args_template.len());
            for templ in args_template {
                argv.push(crate::connector::substitute_arg(templ, allowed_placeholders, params)?);
            }
            // Join into a single command string for the remote login shell. Every element (pinned
            // literals and agent-filled values alike) is POSIX single-quoted, so nothing an agent
            // supplies can be interpreted by the remote shell, and `substitute_arg` has already
            // rejected any value that would be parsed as a flag by the target program.
            let command = argv.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ");
            SshRunOp::Exec { command, max_output_bytes: *max_output_bytes }
        }
        SshOp::SftpGet { root, max_bytes } => {
            let path = required_scoped_path(root, params)?;
            SshRunOp::Get { path, max_bytes: *max_bytes }
        }
        SshOp::SftpPut { root, max_bytes } => {
            let path = required_scoped_path(root, params)?;
            let content_b64 = params
                .get("content")
                .and_then(|v| v.as_str())
                .ok_or_else(|| ConnectorError::BadInput("sftp put requires a base64 'content' param".into()))?;
            // Refuse on the encoded length first. Decoding a body-sized string to discover it is
            // over the cap allocates the very bytes the cap exists to refuse, on an instance whose
            // peak is already three copies of every payload.
            if content_b64.len() as u64 > base64_len(*max_bytes) {
                return Err(ConnectorError::BadInput(format!(
                    "content is about {} bytes, over the {}-byte cap for this capability",
                    content_b64.len() as u64 / 4 * 3,
                    max_bytes
                )));
            }
            let content = B64
                .decode(content_b64.as_bytes())
                .map_err(|_| ConnectorError::BadInput("'content' is not valid base64".into()))?;
            if content.len() as u64 > *max_bytes {
                return Err(ConnectorError::BadInput(format!(
                    "content is {} bytes, over the {}-byte cap for this capability",
                    content.len(),
                    max_bytes
                )));
            }
            SshRunOp::Put { path, content, max_bytes: *max_bytes }
        }
        SshOp::SftpList { root } => {
            // The listing path is optional; default to the root itself.
            let path = match params.get("path").and_then(|v| v.as_str()) {
                Some(rel) if !rel.is_empty() => join_scoped(root, rel)?,
                _ => root.trim_end_matches('/').to_string(),
            };
            SshRunOp::List { path }
        }
    };

    Ok(SshInvocation {
        target: spec.target.clone(),
        credential_kind: spec.credential_kind,
        credential: Zeroizing::new(secret.to_vec()),
        op,
        egress: SshEgress::PublicOnly,
    })
}

/// Read the required `path` param and resolve it under `root`.
fn required_scoped_path(root: &str, params: &serde_json::Value) -> Result<String, ConnectorError> {
    let rel = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ConnectorError::BadInput("this SFTP operation requires a 'path' param".into()))?;
    join_scoped(root, rel)
}

/// Resolve an agent-supplied relative path under the operator-pinned `root`, rejecting anything
/// that could climb out of it. Relative only (an absolute path would ignore the root); a tight
/// character allow-list (alphanumerics plus `/ . - _`) that excludes whitespace, quotes and shell
/// metacharacters; and no `..` traversal component. (A symlink under the root that points outside
/// is a residual server-side concern; true containment needs a server realpath: noted, not solved
/// lexically here.)
fn join_scoped(root: &str, rel: &str) -> Result<String, ConnectorError> {
    if rel.is_empty() {
        return Err(ConnectorError::BadInput("'path' is empty".into()));
    }
    if rel.starts_with('/') {
        return Err(ConnectorError::BadInput(
            "'path' must be relative to the connection's root, not absolute".into(),
        ));
    }
    if let Some(bad) = rel
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '-' | '_')))
    {
        return Err(ConnectorError::BadInput(format!(
            "'path' contains a forbidden character {bad:?}"
        )));
    }
    if rel.split('/').any(|seg| seg == "..") {
        return Err(ConnectorError::BadInput(
            "'path' must not contain a '..' traversal segment".into(),
        ));
    }
    Ok(format!("{}/{}", root.trim_end_matches('/'), rel))
}

/// POSIX single-quote a value so the remote login shell treats it as one literal word. Embedded
/// single quotes are escaped with the standard `'\''` idiom.
fn shell_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

// ── The transport seam ───────────────────────────────────────────────────────────────

/// The swappable SSH transport. Production uses [`RealSshRunner`] (behind the `ssh-transport`
/// feature); everything else uses [`MockSshRunner`]. Implementors MUST verify the host key per
/// [`SshTarget::host_key`] before authenticating, and MUST NOT log the credential.
#[async_trait]
pub trait SshRunner: Send + Sync {
    /// Connect, verify the host key, authenticate, run `inv`'s op, and return its outcome.
    async fn run(&self, inv: SshInvocation) -> anyhow::Result<SshOutcome>;
}

/// A deterministic offline / test double. Records every invocation (so a test can assert on the
/// resolved command / path and confirm the credential was passed) and returns a successful outcome,
/// so the SSH path runs end-to-end with no host and no key. By default the outcome matches the op
/// (an exec returns canned stdout; sftp get/put/list return realistic shapes) so the gateway's
/// result shaping is exercised for each; [`with_outcome`](Self::with_outcome) forces a specific one.
#[derive(Clone)]
pub struct MockSshRunner {
    invocations: Arc<Mutex<Vec<SshInvocation>>>,
    forced: Arc<Mutex<Option<SshOutcome>>>,
}

impl MockSshRunner {
    /// A mock that synthesizes an op-appropriate successful outcome for every call.
    pub fn new() -> Self {
        MockSshRunner {
            invocations: Arc::new(Mutex::new(Vec::new())),
            forced: Arc::new(Mutex::new(None)),
        }
    }

    /// A mock that returns exactly `outcome` for every call, regardless of the op.
    pub fn with_outcome(outcome: SshOutcome) -> Self {
        let m = MockSshRunner::new();
        *m.forced.lock().unwrap() = Some(outcome);
        m
    }

    /// Force the outcome returned by subsequent calls.
    pub fn set_outcome(&self, outcome: SshOutcome) {
        *self.forced.lock().unwrap() = Some(outcome);
    }

    /// Every invocation captured so far, in order.
    pub fn invocations(&self) -> Vec<SshInvocation> {
        self.invocations.lock().unwrap().clone()
    }

    /// The most recently captured invocation, if any.
    pub fn last_invocation(&self) -> Option<SshInvocation> {
        self.invocations.lock().unwrap().last().cloned()
    }
}

impl Default for MockSshRunner {
    fn default() -> Self {
        MockSshRunner::new()
    }
}

/// The op-appropriate outcome the mock returns when none is forced.
fn synthesize_outcome(op: &SshRunOp) -> SshOutcome {
    match op {
        SshRunOp::Exec { .. } => SshOutcome::Exec(CommandOutput {
            code: 0,
            stdout: "permaura-bot\n".to_string(),
            stderr: String::new(),
        }),
        SshRunOp::Get { .. } => {
            let content = b"mock-content";
            SshOutcome::Get { bytes: content.len() as u64, content_base64: B64.encode(content) }
        }
        // A put echoes back exactly how many bytes it was handed.
        SshRunOp::Put { content, .. } => SshOutcome::Put { bytes: content.len() as u64 },
        SshRunOp::List { .. } => SshOutcome::List {
            entries: vec![
                SftpEntry { name: "example.txt".into(), size: 42, is_dir: false },
                SftpEntry { name: "sub".into(), size: 0, is_dir: true },
            ],
            truncated: false,
        },
    }
}

#[async_trait]
impl SshRunner for MockSshRunner {
    async fn run(&self, inv: SshInvocation) -> anyhow::Result<SshOutcome> {
        let outcome = match self.forced.lock().unwrap().clone() {
            Some(o) => o,
            None => synthesize_outcome(&inv.op),
        };
        // Record the invocation for test assertions, but NEVER retain the plaintext credential: the
        // mock is the default runtime transport, and holding the key in a lifetime-lived Vec would
        // defeat the zeroize-on-drop custody guarantee. Redacting the credential here lets the real
        // key drop (and zeroize) at the end of this call.
        self.invocations.lock().unwrap().push(SshInvocation {
            target: inv.target.clone(),
            credential_kind: inv.credential_kind,
            credential: Zeroizing::new(Vec::new()),
            op: inv.op.clone(),
            egress: inv.egress,
        });
        Ok(outcome)
    }
}

// ── The SSH connector ────────────────────────────────────────────────────────────────

/// One exec command a connector exposes as its own capability. Each is a distinct, policy-able
/// action id with its own risk tier, the safe alternative to a single free-form `exec`.
#[derive(Debug, Clone)]
pub struct SshExecCommand {
    /// The capability id suffix after `ssh.`, e.g. `uptime`, `restart-service`.
    pub action: String,
    /// Human description surfaced to agents.
    pub description: String,
    /// Risk tier (Low read-only; High for writes/restarts auto-escalates to approval).
    pub risk: RiskTier,
    /// Whether this command always escalates to human approval.
    pub requires_approval: bool,
    /// The pinned remote-command argv template.
    pub args_template: Vec<String>,
    /// The placeholder names an agent may fill.
    pub allowed_placeholders: Vec<String>,
}

/// An SSH connector: a configured host plus the exec commands and (optionally) SFTP file access it
/// exposes. Mirrors [`VercelCliConnector`](crate::connector::VercelCliConnector), the closest
/// existing analog, but for a remote host over SSH/SFTP rather than a local CLI.
pub struct SshConnector {
    /// The connection short-name used as the policy resource.
    pub resource: String,
    /// The vault secret id holding the SSH private key or password.
    pub secret_id: String,
    /// The pinned target (host/port/user/host-key).
    pub target: SshTarget,
    /// How to interpret the resolved secret.
    pub credential_kind: SshCredentialKind,
    /// The exec commands this connection exposes (each its own capability).
    pub exec_commands: Vec<SshExecCommand>,
    /// When `Some`, expose `sftp.get`/`sftp.put`/`sftp.list` scoped under this root.
    pub sftp_root: Option<String>,
    /// The per-transfer byte cap for the SFTP capabilities.
    pub sftp_max_bytes: u64,
}

impl SshConnector {
    /// A connector for `target` with no exec commands and no SFTP: build it up with
    /// [`with_exec`](Self::with_exec) / [`with_sftp`](Self::with_sftp).
    pub fn new(
        resource: impl Into<String>,
        secret_id: impl Into<String>,
        target: SshTarget,
    ) -> Self {
        SshConnector {
            resource: resource.into(),
            secret_id: secret_id.into(),
            target,
            credential_kind: SshCredentialKind::PrivateKey,
            exec_commands: Vec::new(),
            sftp_root: None,
            sftp_max_bytes: DEFAULT_SFTP_MAX_BYTES,
        }
    }

    /// Add an exec command capability.
    pub fn with_exec(mut self, command: SshExecCommand) -> Self {
        self.exec_commands.push(command);
        self
    }

    /// Expose SFTP get/put/list scoped under `root`.
    pub fn with_sftp(mut self, root: impl Into<String>, max_bytes: u64) -> Self {
        self.sftp_root = Some(root.into());
        self.sftp_max_bytes = max_bytes;
        self
    }

    fn cap(&self, action: &str, description: &str, risk: RiskTier, act: Action, approval: bool, op: SshOp) -> Capability {
        Capability {
            id: format!("ssh.{action}"),
            description: description.to_string(),
            risk,
            action: act,
            requires_approval: approval,
            resource: self.resource.clone(),
            secret_id: self.secret_id.clone(),
            kind: CapabilityKind::Ssh,
            command: None,
            http: None,
            ssh: Some(SshSpec {
                target: self.target.clone(),
                credential_kind: self.credential_kind,
                op,
            }),
        }
    }
}

impl Connector for SshConnector {
    fn id(&self) -> &str {
        "ssh"
    }
    fn capabilities(&self) -> Vec<Capability> {
        let mut caps = Vec::new();
        for cmd in &self.exec_commands {
            caps.push(self.cap(
                &cmd.action,
                &cmd.description,
                cmd.risk,
                Action::Execute,
                cmd.requires_approval,
                SshOp::Exec {
                    args_template: cmd.args_template.clone(),
                    allowed_placeholders: cmd.allowed_placeholders.clone(),
                    max_output_bytes: DEFAULT_EXEC_OUTPUT_BYTES,
                },
            ));
        }
        if let Some(root) = &self.sftp_root {
            caps.push(self.cap(
                "sftp.list",
                "List a remote directory over SFTP",
                RiskTier::Low,
                Action::List,
                false,
                SshOp::SftpList { root: root.clone() },
            ));
            caps.push(self.cap(
                "sftp.get",
                "Read a remote file over SFTP",
                RiskTier::Medium,
                Action::Read,
                false,
                SshOp::SftpGet { root: root.clone(), max_bytes: self.sftp_max_bytes },
            ));
            // A put is clamped to what the execution body limit can actually deliver, however
            // generous the connection's transfer cap is: a cap the transport cannot reach is not a
            // cap, it is a 413 wearing one.
            caps.push(self.cap(
                "sftp.put",
                "Write a remote file over SFTP",
                RiskTier::High,
                Action::Create,
                false,
                SshOp::SftpPut {
                    root: root.clone(),
                    max_bytes: self.sftp_max_bytes.min(SFTP_PUT_MAX_BYTES),
                },
            ));
        }
        caps
    }
}

// ── The real transport (russh), behind the `ssh-transport` feature ───────────────────

#[cfg(feature = "ssh-transport")]
pub use real::RealSshRunner;

#[cfg(feature = "ssh-transport")]
mod real {
    use super::*;
    use std::sync::Arc;

    use russh::client;
    use russh::keys::{HashAlg, PrivateKeyWithHashAlg, PublicKey};
    use russh::ChannelMsg;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// The production SSH/SFTP transport over [`russh`]. Verifies the host key against the pinned
    /// fingerprint before authenticating, resolves the credential inside the invocation's zeroizing
    /// buffer, and enforces the same size caps the builder set.
    pub struct RealSshRunner {
        timeout: Duration,
    }

    impl RealSshRunner {
        /// A runner with the [`DEFAULT_SSH_TIMEOUT`].
        pub fn new() -> Self {
            RealSshRunner { timeout: DEFAULT_SSH_TIMEOUT }
        }

        /// A runner with an explicit per-operation timeout.
        pub fn with_timeout(timeout: Duration) -> Self {
            RealSshRunner { timeout }
        }
    }

    impl Default for RealSshRunner {
        fn default() -> Self {
            RealSshRunner::new()
        }
    }

    /// The russh client handler: its one job is host-key verification per the pinned policy.
    struct Handler {
        host_key: SshHostKey,
    }

    impl client::Handler for Handler {
        type Error = russh::Error;

        async fn check_server_key(&mut self, server_public_key: &PublicKey) -> Result<bool, Self::Error> {
            match &self.host_key {
                SshHostKey::Insecure => {
                    tracing::warn!("SSH host-key verification is DISABLED for this connection (insecure mode): MITM is not defended");
                    Ok(true)
                }
                SshHostKey::Fingerprint { sha256 } => {
                    let got = server_public_key.fingerprint(HashAlg::Sha256).to_string();
                    Ok(normalize_fp(&got) == normalize_fp(sha256))
                }
            }
        }
    }

    /// Normalize a SHA256 fingerprint for comparison: strip an optional `SHA256:` prefix, trim
    /// surrounding whitespace, and drop trailing base64 '=' padding. Base64 is case-sensitive, so
    /// case is preserved: this only forgives a legitimately-matching but non-canonical operator
    /// paste (padded / whitespaced); a genuinely different key still mismatches (fail-closed).
    fn normalize_fp(s: &str) -> String {
        let s = s.trim();
        let s = s.strip_prefix("SHA256:").unwrap_or(s);
        s.trim_end_matches('=').to_string()
    }

    #[async_trait]
    impl SshRunner for RealSshRunner {
        async fn run(&self, inv: SshInvocation) -> anyhow::Result<SshOutcome> {
            tokio::time::timeout(self.timeout, run_inner(inv))
                .await
                .map_err(|_| anyhow::anyhow!("ssh operation exceeded the {}s timeout", self.timeout.as_secs()))?
        }
    }

    async fn system_lookup(host: String, port: u16) -> std::io::Result<Vec<SocketAddr>> {
        Ok(tokio::net::lookup_host((host.as_str(), port)).await?.collect())
    }

    async fn run_inner(inv: SshInvocation) -> anyhow::Result<SshOutcome> {
        let config = Arc::new(client::Config::default());
        let handler = Handler { host_key: inv.target.host_key.clone() };
        let (host, port) = (inv.target.host.as_str(), inv.target.port);
        let mut session = match inv.egress {
            SshEgress::Unrestricted => client::connect(config, (host, port), handler).await?,
            SshEgress::PublicOnly => {
                let addrs = public_dial_addrs(host, port, system_lookup).await?;
                client::connect(config, addrs.as_slice(), handler).await?
            }
        };

        // Authenticate. The credential lives only in the invocation's zeroizing buffer.
        let authed = match inv.credential_kind {
            SshCredentialKind::PrivateKey => {
                let pem = std::str::from_utf8(&inv.credential)
                    .map_err(|_| anyhow::anyhow!("ssh private key is not valid UTF-8 PEM"))?;
                let key = russh::keys::decode_secret_key(pem, None)?;
                session
                    .authenticate_publickey(
                        &inv.target.user,
                        PrivateKeyWithHashAlg::new(Arc::new(key), None),
                    )
                    .await?
            }
            SshCredentialKind::Password => {
                let pass = std::str::from_utf8(&inv.credential)
                    .map_err(|_| anyhow::anyhow!("ssh password is not valid UTF-8"))?;
                session.authenticate_password(&inv.target.user, pass).await?
            }
        };
        if !authed.success() {
            anyhow::bail!("ssh authentication failed for user '{}'", inv.target.user);
        }

        match inv.op {
            SshRunOp::Exec { command, max_output_bytes } => {
                exec(&mut session, &command, max_output_bytes).await
            }
            SshRunOp::Get { path, max_bytes } => sftp_get(&mut session, &path, max_bytes).await,
            SshRunOp::Put { path, content, max_bytes } => {
                sftp_put(&mut session, &path, &content, max_bytes).await
            }
            SshRunOp::List { path } => sftp_list(&mut session, &path).await,
        }
    }

    /// Append `data` to `buf` without letting `buf` exceed `cap` bytes (excess discarded).
    fn append_capped(buf: &mut Vec<u8>, data: &[u8], cap: usize) {
        if buf.len() >= cap {
            return;
        }
        let take = (cap - buf.len()).min(data.len());
        buf.extend_from_slice(&data[..take]);
    }

    async fn exec(
        session: &mut client::Handle<Handler>,
        command: &str,
        max_output_bytes: u64,
    ) -> anyhow::Result<SshOutcome> {
        let cap = max_output_bytes as usize;
        let mut channel = session.channel_open_session().await?;
        channel.exec(true, command).await?;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut code: i32 = -1;
        while let Some(msg) = channel.wait().await {
            match msg {
                // Each stream is bounded to the cap so a huge/streamed output can't exhaust the heap;
                // we keep draining (discarding the excess) so the exit status still arrives.
                ChannelMsg::Data { ref data } => append_capped(&mut stdout, data, cap),
                ChannelMsg::ExtendedData { ref data, ext: 1 } => append_capped(&mut stderr, data, cap),
                ChannelMsg::ExitStatus { exit_status } => code = exit_status as i32,
                // A signal-terminated command is a failure: surface a clearly-nonzero code rather
                // than leaving the `-1` "no status received" sentinel.
                ChannelMsg::ExitSignal { .. } => code = 128,
                ChannelMsg::Eof | ChannelMsg::Close => {}
                _ => {}
            }
        }
        Ok(SshOutcome::Exec(CommandOutput {
            code,
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            stderr: String::from_utf8_lossy(&stderr).into_owned(),
        }))
    }

    async fn sftp(session: &mut client::Handle<Handler>) -> anyhow::Result<russh_sftp::client::SftpSession> {
        let channel = session.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        Ok(russh_sftp::client::SftpSession::new(channel.into_stream()).await?)
    }

    async fn sftp_get(session: &mut client::Handle<Handler>, path: &str, max_bytes: u64) -> anyhow::Result<SshOutcome> {
        let sftp = sftp(session).await?;
        let mut file = sftp.open(path).await?;
        // Read at most max_bytes + 1 so an over-cap file is detected rather than silently truncated.
        let mut buf = Vec::new();
        let mut limited = (&mut file).take(max_bytes.saturating_add(1));
        limited.read_to_end(&mut buf).await?;
        if buf.len() as u64 > max_bytes {
            anyhow::bail!("remote file exceeds the {max_bytes}-byte read cap for this capability");
        }
        Ok(SshOutcome::Get {
            bytes: buf.len() as u64,
            content_base64: B64.encode(&buf),
        })
    }

    async fn sftp_put(session: &mut client::Handle<Handler>, path: &str, content: &[u8], max_bytes: u64) -> anyhow::Result<SshOutcome> {
        if content.len() as u64 > max_bytes {
            anyhow::bail!("content exceeds the {max_bytes}-byte write cap for this capability");
        }
        let sftp = sftp(session).await?;
        let mut file = sftp.create(path).await?;
        file.write_all(content).await?;
        file.flush().await?;
        Ok(SshOutcome::Put { bytes: content.len() as u64 })
    }

    async fn sftp_list(session: &mut client::Handle<Handler>, path: &str) -> anyhow::Result<SshOutcome> {
        let sftp = sftp(session).await?;
        let mut entries = Vec::new();
        let mut truncated = false;
        for entry in sftp.read_dir(path).await? {
            // Bound the returned listing so a directory with a very large number of entries can't
            // balloon gateway memory; report truncation rather than silently dropping the tail.
            if entries.len() >= DEFAULT_SFTP_MAX_ENTRIES {
                truncated = true;
                break;
            }
            let is_dir = entry.file_type().is_dir();
            entries.push(SftpEntry {
                name: entry.file_name(),
                size: entry.metadata().size.unwrap_or(0),
                is_dir,
            });
        }
        Ok(SshOutcome::List { entries, truncated })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> SshTarget {
        SshTarget {
            host: "db1.internal".into(),
            port: 22,
            user: "deploy".into(),
            host_key: SshHostKey::Fingerprint { sha256: "abc123".into() },
        }
    }

    fn exec_spec(args: &[&str], allowed: &[&str]) -> SshSpec {
        SshSpec {
            target: target(),
            credential_kind: SshCredentialKind::PrivateKey,
            op: SshOp::Exec {
                args_template: args.iter().map(|s| s.to_string()).collect(),
                allowed_placeholders: allowed.iter().map(|s| s.to_string()).collect(),
                max_output_bytes: DEFAULT_EXEC_OUTPUT_BYTES,
            },
        }
    }

    #[test]
    fn build_ssh_exec_quotes_fixed_command() {
        let spec = exec_spec(&["systemctl", "restart", "nginx"], &[]);
        let inv = build_ssh(&spec, &serde_json::json!({}), b"KEYBYTES").unwrap();
        match &inv.op {
            SshRunOp::Exec { command, .. } => assert_eq!(command.as_str(), "'systemctl' 'restart' 'nginx'"),
            other => panic!("expected exec, got {other:?}"),
        }
        // The credential is carried for auth but never rendered.
        assert_eq!(inv.credential.as_slice(), b"KEYBYTES");
        assert!(!format!("{inv:?}").contains("KEYBYTES"));
    }

    #[test]
    fn build_ssh_exec_substitutes_whitelisted_placeholder() {
        let spec = exec_spec(&["systemctl", "restart", "{service}"], &["service"]);
        let inv = build_ssh(&spec, &serde_json::json!({ "service": "nginx" }), b"k").unwrap();
        match inv.op {
            SshRunOp::Exec { command, .. } => assert_eq!(command, "'systemctl' 'restart' 'nginx'"),
            other => panic!("expected exec, got {other:?}"),
        }
    }

    #[test]
    fn build_ssh_exec_rejects_shell_metacharacters_in_placeholder() {
        let spec = exec_spec(&["systemctl", "restart", "{service}"], &["service"]);
        // Classic chaining attempt: a metacharacter-laden value is refused before it is ever quoted.
        let err = build_ssh(&spec, &serde_json::json!({ "service": "nginx; rm -rf /" }), b"k").unwrap_err();
        assert!(matches!(err, ConnectorError::BadInput(_)));
    }

    #[test]
    fn build_ssh_exec_rejects_non_whitelisted_placeholder() {
        let spec = exec_spec(&["run", "{evil}"], &["service"]);
        let err = build_ssh(&spec, &serde_json::json!({ "evil": "x" }), b"k").unwrap_err();
        assert!(matches!(err, ConnectorError::BadInput(_)));
    }

    #[test]
    fn build_ssh_exec_rejects_leading_dash_flag_injection() {
        // A whitelisted value that would be parsed as an option/flag by the remote program is
        // refused even though it has no shell metacharacters: argument injection is blocked.
        let spec = exec_spec(&["systemctl", "restart", "{service}"], &["service"]);
        for bad in ["--version", "-h", "--checkpoint-action=exec=/tmp/p.sh"] {
            let err = build_ssh(&spec, &serde_json::json!({ "service": bad }), b"k").unwrap_err();
            assert!(matches!(err, ConnectorError::BadInput(_)), "value {bad:?} should be rejected");
        }
    }

    #[test]
    fn build_ssh_exec_rejects_empty_template() {
        let spec = exec_spec(&[], &[]);
        assert!(matches!(build_ssh(&spec, &serde_json::json!({}), b"k"), Err(ConnectorError::BadInput(_))));
    }

    #[test]
    fn sftp_get_scopes_path_under_root() {
        let spec = SshSpec {
            target: target(),
            credential_kind: SshCredentialKind::PrivateKey,
            op: SshOp::SftpGet { root: "/var/data".into(), max_bytes: 1024 },
        };
        let inv = build_ssh(&spec, &serde_json::json!({ "path": "reports/q3.csv" }), b"k").unwrap();
        match inv.op {
            SshRunOp::Get { path, max_bytes } => {
                assert_eq!(path, "/var/data/reports/q3.csv");
                assert_eq!(max_bytes, 1024);
            }
            other => panic!("expected get, got {other:?}"),
        }
    }

    #[test]
    fn sftp_get_rejects_traversal_and_absolute_paths() {
        let spec = SshSpec {
            target: target(),
            credential_kind: SshCredentialKind::PrivateKey,
            op: SshOp::SftpGet { root: "/var/data".into(), max_bytes: 1024 },
        };
        for bad in ["../../etc/passwd", "/etc/passwd", "a/../../b", "spaced name"] {
            let err = build_ssh(&spec, &serde_json::json!({ "path": bad }), b"k").unwrap_err();
            assert!(matches!(err, ConnectorError::BadInput(_)), "path {bad:?} should be rejected");
        }
    }

    #[test]
    fn sftp_put_enforces_the_size_cap_and_decodes_base64() {
        let spec = SshSpec {
            target: target(),
            credential_kind: SshCredentialKind::PrivateKey,
            op: SshOp::SftpPut { root: "/srv".into(), max_bytes: 4 },
        };
        // 3 bytes: fine.
        let ok = build_ssh(&spec, &serde_json::json!({ "path": "a.txt", "content": B64.encode(b"abc") }), b"k").unwrap();
        match ok.op {
            SshRunOp::Put { path, content, .. } => {
                assert_eq!(path, "/srv/a.txt");
                assert_eq!(content, b"abc");
            }
            other => panic!("expected put, got {other:?}"),
        }
        // 5 bytes: over the 4-byte cap.
        let err = build_ssh(&spec, &serde_json::json!({ "path": "a.txt", "content": B64.encode(b"abcde") }), b"k").unwrap_err();
        assert!(matches!(err, ConnectorError::BadInput(_)));
        // Not base64 at all.
        let err = build_ssh(&spec, &serde_json::json!({ "path": "a.txt", "content": "!!!not-b64!!!" }), b"k").unwrap_err();
        assert!(matches!(err, ConnectorError::BadInput(_)));
    }

    /// The put cap and the execution body limit are one decision. This is the connector half of it;
    /// the gateway half is a `const` assertion in `services/gateway/src/limits.rs`.
    #[test]
    fn the_put_cap_fits_the_body_budget_once_base64_encoded() {
        assert!(
            base64_len(SFTP_PUT_MAX_BYTES) + SFTP_PUT_ENVELOPE_RESERVE_BYTES
                <= SFTP_PUT_BODY_BUDGET_BYTES,
            "a put at the cap ({SFTP_PUT_MAX_BYTES} bytes, {} base64) does not fit the \
             {SFTP_PUT_BODY_BUDGET_BYTES}-byte body budget",
            base64_len(SFTP_PUT_MAX_BYTES)
        );
        assert_eq!(SFTP_PUT_MAX_BYTES, 1024 * 1024);
    }

    /// The rounding in the derivation is what leaves a band in which an over-cap put still arrives,
    /// so the caller reads the connector's message instead of a 413. Losing the band would make the
    /// cap unreportable again without failing any other test.
    #[test]
    fn an_over_cap_put_still_fits_the_body_budget_and_so_can_be_named() {
        let largest_that_arrives = (SFTP_PUT_BODY_BUDGET_BYTES - SFTP_PUT_ENVELOPE_RESERVE_BYTES)
            / 4
            * 3;
        assert!(
            largest_that_arrives > SFTP_PUT_MAX_BYTES,
            "there is no band in which an over-cap put can be refused by name"
        );
    }

    #[test]
    fn the_put_cap_derivation_returns_an_exact_fit_below_a_mebibyte() {
        let budget = 512 * 1024;
        let cap = sftp_put_cap_for_body_limit(budget);
        assert_eq!(cap, (budget - SFTP_PUT_ENVELOPE_RESERVE_BYTES) / 4 * 3);
        assert!(base64_len(cap) + SFTP_PUT_ENVELOPE_RESERVE_BYTES <= budget);
        // And a budget smaller than the reserve yields nothing rather than underflowing.
        assert_eq!(sftp_put_cap_for_body_limit(1024), 0);
    }

    /// The connection's transfer cap governs a get; a put is clamped to what the body limit can
    /// deliver even when the connection asks for the full 5 MiB.
    #[test]
    fn a_generous_transfer_cap_does_not_raise_the_put_cap() {
        let caps = SshConnector::new("res", "sec", target())
            .with_sftp("/var/data", DEFAULT_SFTP_MAX_BYTES)
            .capabilities();
        let get = caps.iter().find(|c| c.id == "ssh.sftp.get").expect("get capability");
        let put = caps.iter().find(|c| c.id == "ssh.sftp.put").expect("put capability");
        match &get.ssh.as_ref().unwrap().op {
            SshOp::SftpGet { max_bytes, .. } => assert_eq!(*max_bytes, DEFAULT_SFTP_MAX_BYTES),
            other => panic!("expected get, got {other:?}"),
        }
        match &put.ssh.as_ref().unwrap().op {
            SshOp::SftpPut { max_bytes, .. } => assert_eq!(*max_bytes, SFTP_PUT_MAX_BYTES),
            other => panic!("expected put, got {other:?}"),
        }
    }

    /// A tighter connection cap still wins: the clamp is a ceiling, not a floor.
    #[test]
    fn a_tighter_transfer_cap_still_governs_the_put() {
        let caps = SshConnector::new("res", "sec", target())
            .with_sftp("/var/data", 4096)
            .capabilities();
        let put = caps.iter().find(|c| c.id == "ssh.sftp.put").expect("put capability");
        match &put.ssh.as_ref().unwrap().op {
            SshOp::SftpPut { max_bytes, .. } => assert_eq!(*max_bytes, 4096),
            other => panic!("expected put, got {other:?}"),
        }
    }

    /// The encoded length is checked before the decode, so a body-sized string that is going to be
    /// refused is never materialized as bytes.
    #[test]
    fn an_over_cap_put_is_refused_on_the_encoded_length() {
        let spec = SshSpec {
            target: target(),
            credential_kind: SshCredentialKind::PrivateKey,
            op: SshOp::SftpPut { root: "/srv".into(), max_bytes: 1024 },
        };
        let content = B64.encode(vec![b'x'; 4096]);
        let err = build_ssh(&spec, &serde_json::json!({ "path": "a.txt", "content": content }), b"k")
            .unwrap_err();
        let ConnectorError::BadInput(msg) = err else { panic!("expected BadInput") };
        assert!(msg.contains("1024-byte cap for this capability"), "message was {msg:?}");
    }

    #[test]
    fn sftp_list_defaults_to_root() {
        let spec = SshSpec {
            target: target(),
            credential_kind: SshCredentialKind::PrivateKey,
            op: SshOp::SftpList { root: "/var/log/".into() },
        };
        let inv = build_ssh(&spec, &serde_json::json!({}), b"k").unwrap();
        match inv.op {
            SshRunOp::List { path } => assert_eq!(path, "/var/log"),
            other => panic!("expected list, got {other:?}"),
        }
    }

    #[test]
    fn shell_quote_escapes_embedded_single_quotes() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn spec_round_trips_through_serde() {
        // The persisted capability blob carries the whole spec; it must survive a JSON round-trip.
        let spec = exec_spec(&["uptime"], &[]);
        let json = serde_json::to_string(&spec).unwrap();
        let back: SshSpec = serde_json::from_str(&json).unwrap();
        assert_eq!(spec, back);
        // Host-key mode + op tags are present on the wire.
        assert!(json.contains("\"mode\":\"fingerprint\""));
        assert!(json.contains("\"op\":\"exec\""));
    }

    #[test]
    fn ssh_target_port_defaults_to_22_on_deserialize() {
        let t: SshTarget = serde_json::from_value(serde_json::json!({
            "host": "h", "user": "u", "host_key": { "mode": "insecure" }
        }))
        .unwrap();
        assert_eq!(t.port, 22);
        assert_eq!(t.host_key, SshHostKey::Insecure);
    }

    #[test]
    fn connector_emits_graduated_risk_capabilities() {
        let conn = SshConnector::new("db1", "sec_ssh_db1", target())
            .with_exec(SshExecCommand {
                action: "uptime".into(),
                description: "Show uptime".into(),
                risk: RiskTier::Low,
                requires_approval: false,
                args_template: vec!["uptime".into()],
                allowed_placeholders: vec![],
            })
            .with_exec(SshExecCommand {
                action: "restart-service".into(),
                description: "Restart a service".into(),
                risk: RiskTier::High,
                requires_approval: true,
                args_template: vec!["systemctl".into(), "restart".into(), "{service}".into()],
                allowed_placeholders: vec!["service".into()],
            })
            .with_sftp("/var/data", 1024);
        let caps = conn.capabilities();
        // 2 exec + 3 sftp.
        assert_eq!(caps.len(), 5);
        for c in &caps {
            assert_eq!(c.kind, CapabilityKind::Ssh);
            assert!(c.ssh.is_some());
            assert_eq!(c.connector_id(), "ssh");
        }
        let restart = caps.iter().find(|c| c.id == "ssh.restart-service").unwrap();
        assert_eq!(restart.risk, RiskTier::High);
        assert!(restart.requires_approval);
        let put = caps.iter().find(|c| c.id == "ssh.sftp.put").unwrap();
        assert_eq!(put.risk, RiskTier::High);
        let list = caps.iter().find(|c| c.id == "ssh.sftp.list").unwrap();
        assert_eq!(list.risk, RiskTier::Low);
    }

    #[tokio::test]
    async fn mock_runner_records_invocation_and_returns_canned() {
        let spec = exec_spec(&["uptime"], &[]);
        let inv = build_ssh(&spec, &serde_json::json!({}), b"key").unwrap();
        let runner = MockSshRunner::new();
        let out = runner.run(inv).await.unwrap();
        match out {
            SshOutcome::Exec(o) => assert_eq!(o.stdout, "permaura-bot\n"),
            other => panic!("expected exec, got {other:?}"),
        }
        let captured = runner.last_invocation().unwrap();
        match &captured.op {
            SshRunOp::Exec { command, .. } => assert_eq!(command.as_str(), "'uptime'"),
            other => panic!("expected exec, got {other:?}"),
        }
        // The mock does not retain the plaintext credential (custody: it is zeroized after the call).
        assert!(captured.credential.as_slice().is_empty());
    }

    /// A lookup that answers `ips` for any name and counts how often it was asked.
    fn resolves_to(
        ips: &'static [&'static str],
        asked: &Arc<std::sync::atomic::AtomicUsize>,
    ) -> impl FnOnce(String, u16) -> std::future::Ready<std::io::Result<Vec<SocketAddr>>> {
        let asked = asked.clone();
        move |_, port| {
            asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::future::ready(Ok(ips.iter().map(|ip| SocketAddr::new(ip.parse().unwrap(), port)).collect()))
        }
    }

    /// At dial time, a name is judged by what it resolves to, and the session goes to the
    /// public addresses it resolved to and no others.
    #[tokio::test]
    async fn a_public_only_dial_never_reaches_a_non_public_address() {
        let asked = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for ips in [
            &["169.254.169.254"][..],
            &["127.0.0.1"],
            &["10.0.0.1"],
            &["::1"],
            &["::ffff:169.254.169.254"],
            &["fd00::1", "192.168.1.20"],
        ] {
            let err = public_dial_addrs("rebind.example", 22, resolves_to(ips, &asked)).await.expect_err(ips[0]);
            assert!(
                matches!(err.downcast_ref(), Some(crate::egress::EgressError::NoPermittedAddress(_))),
                "{ips:?}: {err}"
            );
        }
        let addrs = public_dial_addrs("mixed.example", 2222, resolves_to(&["10.0.0.1", "140.82.112.3"], &asked)).await.unwrap();
        assert_eq!(addrs, vec!["140.82.112.3:2222".parse::<SocketAddr>().unwrap()], "only the public address is dialled");

        let before = asked.load(std::sync::atomic::Ordering::SeqCst);
        for host in [
            "169.254.169.254", "metadata.google.internal", "127.0.0.1", "2130706433", "[::1]", "localhost", "10.0.0.1",
            "user@ssh.example.com", "ssh.example.com/x",
        ] {
            let err = public_dial_addrs(host, 22, resolves_to(&["140.82.112.3"], &asked)).await.expect_err(host);
            assert!(err.downcast_ref::<crate::egress::EgressError>().is_some(), "{host}: {err}");
        }
        assert_eq!(asked.load(std::sync::atomic::Ordering::SeqCst), before, "refused as written, before any lookup");

        let addrs = public_dial_addrs("ssh.example.com", 22, resolves_to(&["140.82.112.3"], &asked)).await.unwrap();
        assert_eq!(addrs, vec!["140.82.112.3:22".parse::<SocketAddr>().unwrap()]);
    }

    /// The real transport opens no TCP connection to a non-public host when it dials public-only, and still
    /// dials loopback when unrestricted (a gateway its owner runs, unchanged).
    #[cfg(feature = "ssh-transport")]
    #[tokio::test]
    async fn the_real_transport_dials_loopback_only_when_unrestricted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let invocation = move |egress| SshInvocation {
            target: SshTarget { host: "127.0.0.1".into(), port, user: "deploy".into(), host_key: SshHostKey::Insecure },
            credential_kind: SshCredentialKind::Password,
            credential: Zeroizing::new(b"synthetic".to_vec()),
            op: SshRunOp::Exec { command: "'true'".into(), max_output_bytes: 1024 },
            egress,
        };
        let err = RealSshRunner::with_timeout(Duration::from_secs(2))
            .run(invocation(SshEgress::PublicOnly))
            .await
            .expect_err("a public-only session to loopback is refused");
        assert!(err.to_string().contains("egress blocked"), "{err}");
        assert!(
            tokio::time::timeout(Duration::from_millis(300), listener.accept()).await.is_err(),
            "no TCP connection reached the loopback listener"
        );

        let dial = tokio::spawn(async move {
            RealSshRunner::with_timeout(Duration::from_secs(2)).run(invocation(SshEgress::Unrestricted)).await
        });
        let accepted = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await;
        dial.abort();
        assert!(matches!(accepted, Ok(Ok(_))), "an unrestricted session still dials loopback");
    }

    #[test]
    fn build_ssh_dials_public_only_until_the_caller_widens_it() {
        let inv = build_ssh(&exec_spec(&["uptime"], &[]), &serde_json::json!({}), b"key").unwrap();
        assert_eq!(inv.egress, SshEgress::PublicOnly);
    }
}
