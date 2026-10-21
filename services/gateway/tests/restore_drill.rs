//! The restore drill: the whole hosted recovery ceremony, in one process, against the real router.
//!
//! Every other test in this repository takes one slice of the hosted recovery design and proves it
//! in isolation. Nobody had ever run the sequence. This does, on the store that actually ships
//! (`PersistedSqliteStore` over an `ObjectStore`), with the in-memory double standing in for GCS:
//!
//! 1. a hosted worker boots with an open hold, an estate is built and used;
//! 2. a checkpoint is taken the way `checkpoint-job.sh` takes one: the live generation's bytes and
//!    its `pm-*` metadata copied to a checkpoint prefix, a manifest written through the real
//!    `manifest.sh` field mapping, and `retained.json` written through the real `hold_merge`;
//! 3. authority is then revoked, deleted and resolved, and the floor is raised again;
//! 4. the restore runs the way `restore-tenant.sh` runs it: hold object first, then layer 1, then
//!    the checkpoint bytes promoted as a new generation, then a fresh instance over the same bucket;
//! 5. and what the hold stops, the reconciliation and the audit events it writes are then read back
//!    **through the router**.
//!
//! **What stands in for what.** The object store is `MemoryObjectStore`, which has the same
//! generation and precondition semantics as GCS and no network. The hold's two layers are passed to
//! `ExecutionHold::open` rather than read from the environment, because the environment is
//! process-wide and `cargo test` runs binaries in parallel; layer 1 is exactly the string
//! `PERMAURA_EXECUTION_HOLD` would carry. `PERMAURA_TENANT` *is* set, once, for this binary, because
//! the persisted store reads it at open and a drill that faked the slug would not be drilling the
//! thing that took a worker down.
//!
//! **The hosted half.** Where `PERMAURA_HOSTED_SCRIPTS` names a directory holding the hosted
//! recovery scripts, every hold and retained document this drill writes is produced by running
//! `manifest.sh`'s own `hold_open_patch` and `hold_merge`, and every manifest by its own
//! `checkpoint_metadata_keys` and `manifest_json`. Otherwise the drill falls back to the in-tree
//! reimplementation below and **says so** on stderr, and
//! `the_in_tree_writers_still_agree_with_the_hosted_scripts` is the test that keeps the two from
//! drifting: it runs both and compares bytes.
#![cfg(feature = "sqlite")]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Value};
use tower::ServiceExt;

use permaura_gateway::backend::{AuditKeyWrap, KmsClient};
use permaura_gateway::error::GatewayError;
use permaura_gateway::objectstore::{FailingObjectStore, MemoryObjectStore, ObjectStore, PutOutcome};
use permaura_gateway::reconcile::{self, ReviewKind, Stage};
use permaura_gateway::restore::{hold_metadata, hold_object, retained_object, ExecutionHold};
use permaura_gateway::service::{ApprovalFloor, EnforcementService, InvokeOutcome};
use permaura_gateway::store::persisted::{PersistedSqliteStore, DEFAULT_OBJECT};
use permaura_gateway::store::{
    Agent, EnrolmentCode, PendingApproval, Session, SessionRole, Store, APPROVAL_FLOOR_META,
};
use common::build_router;
use permaura_gateway::{seed, AppState};

/// The secret the requester of the drill's export approvals was handed.
const DRILL_RESUME_SECRET: &str = "drill-resume-secret";

mod common;

/// The workspace slug this drill runs as. A real one: `restore-tenant.sh` and `hold-provision.sh`
/// both validate `^[a-z][a-z0-9-]{1,25}[a-z0-9]$` before anything is looked up.
const TENANT: &str = "drill-acme";

/// The control plane's gateway row id, which is deliberately *not* the slug. Stamped separately as
/// `pm-gateway-id`.
const GATEWAY_ROW: &str = "gw_drill0000000000000";

/// The account this worker is provisioned for: the only subject whose token can confirm restored
/// authority.
const OWNER_SUB: &str = "sam";

const PUBLIC_URL: &str = "https://g-drill.permaura.test";
const AS_ISSUER: &str = "https://permaura.test/api/auth";
const AS_KID: &str = "as-drill-k1";

/// The capability every execution in this drill uses. Seeded, allowed by a seeded grant, and served
/// by the mock HTTP client, so an execution is a real trip through policy, secret resolution and the
/// audit fence without a network.
const CAP: &str = "braintree.transactions.search";

// ══ the hosted writers ══════════════════════════════════════════════════════════════════════════

/// Where the hosted `manifest.sh` lives, when it can be reached at all.
///
/// Only `PERMAURA_HOSTED_SCRIPTS`, the directory holding it, so whoever has the hosted scripts can
/// name them. `None` is not an error: core builds without the hosted scripts and must keep doing so.
fn hosted_scripts() -> Option<PathBuf> {
    static FOUND: OnceLock<Option<PathBuf>> = OnceLock::new();
    FOUND
        .get_or_init(|| {
            let path = PathBuf::from(std::env::var("PERMAURA_HOSTED_SCRIPTS").ok()?);
            path.join("manifest.sh").is_file().then_some(path)
        })
        .clone()
}

/// Say once, loudly, which half of this drill is running.
fn announce_hosted_mode() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| match hosted_scripts() {
        Some(path) => eprintln!("restore drill: hold and manifest documents come from {}", path.display()),
        None => eprintln!(
            "restore drill: the hosted scripts could not be found, so every hold, retained and \
             manifest document is written by the in-tree reimplementation in this file. Set \
             PERMAURA_HOSTED_SCRIPTS to drill the real writers."
        ),
    });
}

/// Run `snippet` with `manifest.sh` sourced, and return its stdout.
fn hosted_bash(snippet: &str, env: &[(&str, &str)], stdin: &str) -> String {
    let dir = hosted_scripts().expect("the hosted scripts were checked for first");
    let mut child = std::process::Command::new("bash")
        .arg("-c")
        .arg(format!(". ./manifest.sh; {snippet}"))
        .current_dir(&dir)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .envs(env.iter().copied())
        .spawn()
        .expect("bash runs");
    child.stdin.take().expect("stdin").write_all(stdin.as_bytes()).expect("write stdin");
    let out = child.wait_with_output().expect("bash finishes");
    assert!(
        out.status.success(),
        "hosted snippet failed: {snippet}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// `manifest.sh`'s `hold_merge`: apply `patch` over `current`, stamp `hold_version`, sort keys,
/// two-space indent, trailing newline.
///
/// The one funnel every hold and retained object in the hosted repository goes through, which is why
/// reproducing this one function is enough to write every one of them.
fn hold_merge(current: &[u8], patch: &Value) -> Vec<u8> {
    announce_hosted_mode();
    if hosted_scripts().is_some() {
        return hosted_bash("hold_merge", &[("HOLD_PATCH", &patch.to_string())], &String::from_utf8_lossy(current))
            .into_bytes();
    }
    in_tree_hold_merge(current, patch)
}

/// The same merge, in-tree. Used when the hosted repository is absent, and compared against the real
/// one byte for byte by `the_in_tree_writers_still_agree_with_the_hosted_scripts`.
fn in_tree_hold_merge(current: &[u8], patch: &Value) -> Vec<u8> {
    let mut doc = match serde_json::from_slice::<Value>(current) {
        Ok(Value::Object(map)) => map,
        _ => serde_json::Map::new(),
    };
    for (k, v) in patch.as_object().expect("a patch is an object") {
        doc.insert(k.clone(), v.clone());
    }
    doc.insert("hold_version".into(), json!(1));
    let mut out = serde_json::to_vec_pretty(&Value::Object(doc)).expect("serialises");
    out.push(b'\n');
    out
}

/// `manifest.sh`'s `hold_open_patch`: what provisioning writes for a tenant that has never been
/// held. No `checkpoint_id`, which is the third of the four guards that keep an ordinary cold start
/// from reconciling.
fn open_patch(who: &str, why: &str) -> Value {
    if hosted_scripts().is_some() {
        let raw = hosted_bash(&format!("hold_open_patch {TENANT} '{who}' '{why}'"), &[], "");
        return serde_json::from_str(&raw).expect("hold_open_patch emits JSON");
    }
    json!({
        "tenant": TENANT,
        "state": "open",
        "hold_id": Value::Null,
        "reason": why,
        "set_at": "2026-09-22T00:00:00Z",
        "set_by": who,
        // Nulled rather than omitted, because `hold_merge` merges: an open document written over a
        // held one would otherwise keep the held document's and go on naming a restore that is over.
        "checkpoint_id": Value::Null,
        "retained_ref": Value::Null,
    })
}

/// `restore-tenant.sh` step 5's patch, key for key. Not in `manifest.sh`, so there is nothing to
/// source: the shape is pinned instead by `the_documents_this_drill_writes_match_the_hosted_fixtures`.
fn held_patch(hold_id: &str, checkpoint_id: &str, retained_generation: u64, refreshed_at: &str) -> Value {
    json!({
        "tenant": TENANT,
        "state": "held",
        "hold_id": hold_id,
        "set_at": "2026-09-22T00:00:00Z",
        "set_by": "operator@example.com",
        "reason": format!("restore from {checkpoint_id}"),
        "checkpoint_id": checkpoint_id,
        "retained_ref": {
            "object": retained_object(TENANT),
            "generation": retained_generation.to_string(),
            "refreshed_at": refreshed_at,
        },
    })
}

/// `checkpoint-job.sh`'s `write_retained` patch, with its three kinds of nothing intact.
///
/// `field()` there turns an empty value into `null`, an all-digit value into a JSON number and
/// anything else into the string it is; the two floors are typed instead, because reconciliation
/// ranks them and a stamped `none` cannot take part in a maximum.
fn retained_patch(stamped: &BTreeMap<String, String>, refreshed_at: &str) -> Value {
    let field = |key: &str| -> Value {
        match stamped.get(key).map(String::as_str).unwrap_or("") {
            "" => Value::Null,
            v if v.chars().all(|c| c.is_ascii_digit()) => json!(v.parse::<i64>().unwrap_or_default()),
            v => json!(v),
        }
    };
    let approval_floor = match stamped.get("pm-approval-floor").map(String::as_str).unwrap_or("") {
        v @ ("approve" | "device_signed") => json!(v),
        _ => Value::Null,
    };
    let replay_floor = match stamped.get("pm-replay-floor-ms").map(String::as_str).unwrap_or("") {
        v if !v.is_empty() && v.chars().all(|c| c.is_ascii_digit()) => {
            json!(v.parse::<i64>().unwrap_or_default())
        }
        _ => Value::Null,
    };
    json!({
        "tenant": TENANT,
        "retained": {
            "pre_restore_audit_epoch": field("pm-audit-epoch"),
            "pre_restore_audit_head_seq": field("pm-audit-head-seq"),
            "pre_restore_audit_head_hash": match stamped.get("pm-audit-head-hash").map(String::as_str) {
                None | Some("") => Value::Null,
                Some(v) => json!(v),
            },
            "pre_restore_commit_seq": field("pm-commit-seq"),
            "approval_floor": approval_floor,
            "replay_floor_ms": replay_floor,
            "revocation_journal_head": Value::Null,
            "refreshed_at": refreshed_at,
        },
    })
}

/// `manifest.sh`'s `checkpoint_metadata_keys`: `pm-*` key to dotted manifest path.
///
/// The real mapping when the scripts are reachable, and the copy below otherwise. The copy is what
/// `the_manifest_field_mapping_has_not_drifted` holds to account.
fn checkpoint_metadata_keys() -> Vec<(String, String)> {
    announce_hosted_mode();
    let raw = if hosted_scripts().is_some() {
        hosted_bash("checkpoint_metadata_keys", &[], "")
    } else {
        IN_TREE_METADATA_KEYS.to_string()
    };
    raw.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let (key, path) = l.split_once('|').unwrap_or_else(|| panic!("a key|path line: {l}"));
            (key.to_string(), path.to_string())
        })
        .collect()
}

/// `checkpoint_metadata_keys` as the hosted repository's checkpoint writer emits it.
const IN_TREE_METADATA_KEYS: &str = "\
pm-meta-version|_meta_version
pm-tenant|stamped_tenant
pm-gateway-id|gateway_id
pm-gateway-version|store.gateway_version
pm-schema-version|store.schema_version
pm-commit-seq|store.commit_seq
pm-taken-at|store.taken_at_ms
pm-upload-id|store.upload_id
pm-approval-floor|store.approval_floor
pm-replay-floor-ms|store.replay_floor_ms
pm-audit-epoch|audit.epoch
pm-audit-head-seq|audit.head_seq
pm-audit-head-hash|audit.head_hash
pm-audit-base-seq|audit.base_seq
pm-audit-base-hash|audit.base_hash
pm-audit-segment-head|audit.segment_head
pm-audit-key-wrap|keys.audit_signing_key.wrap
pm-audit-key-version|keys.audit_signing_key.reference
pm-vault-kek-version|keys.vault_kek.reference
pm-store-bytes|_store_bytes
";

/// `manifest.sh`'s `manifest_json`: `dotted.path=value` lines in, the manifest's nested document out.
fn manifest_json(lines: &str) -> Value {
    if hosted_scripts().is_some() {
        let raw = hosted_bash("manifest_json", &[], lines);
        return serde_json::from_str(&raw).expect("manifest_json emits JSON");
    }
    let numeric = [
        "store.schema_version",
        "store.commit_seq",
        "store.taken_at_ms",
        "store.replay_floor_ms",
        "audit.epoch",
        "audit.head_seq",
        "audit.base_seq",
        "source.size_bytes",
    ];
    let mut doc = Value::Object(serde_json::Map::new());
    for line in lines.lines() {
        let Some((path, value)) = line.split_once('=') else { continue };
        if path.starts_with('_') {
            continue;
        }
        let parsed = if value.is_empty() {
            Value::Null
        } else if numeric.contains(&path) {
            value.parse::<i64>().map(|n| json!(n)).unwrap_or_else(|_| json!(value))
        } else if value == "true" || value == "false" {
            json!(value == "true")
        } else {
            json!(value)
        };
        let mut node = &mut doc;
        let parts: Vec<&str> = path.split('.').collect();
        for part in &parts[..parts.len() - 1] {
            node = node
                .as_object_mut()
                .expect("object")
                .entry(part.to_string())
                .or_insert_with(|| Value::Object(serde_json::Map::new()));
        }
        node.as_object_mut().expect("object").insert(parts[parts.len() - 1].to_string(), parsed);
    }
    doc
}

// ══ the worker ══════════════════════════════════════════════════════════════════════════════════

/// A synthetic KMS, so the audit signing key is wrapped exactly as it is on a hosted worker and the
/// promoted bytes have to be unwrapped by the instance that boots over them.
struct DrillKms;

#[async_trait]
impl KmsClient for DrillKms {
    async fn decrypt(&self, _: &str, b: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, GatewayError> {
        Ok(zeroize::Zeroizing::new(b.iter().map(|x| x ^ 0x5a).collect()))
    }
    async fn encrypt(&self, _: &str, b: &[u8]) -> Result<Vec<u8>, GatewayError> {
        Ok(b.iter().map(|x| x ^ 0x5a).collect())
    }
}

fn wrap() -> AuditKeyWrap {
    AuditKeyWrap { kms: Arc::new(DrillKms), key_id: "projects/p/locations/l/keyRings/permaura/cryptoKeys/ws-drill".into(), adopt_plaintext: false }
}

/// A scratch directory for one instance's local database. Never `~/.permaura`.
fn scratch(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path =
        std::env::temp_dir().join(format!("permaura-restore-drill-{}-{tag}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&path).expect("scratch directory");
    path
}

/// Set once, for this binary only: the slug the persisted store stamps and the OAuth resource server
/// the reconciliation routes authenticate against.
///
/// `PERMAURA_TENANT` is deliberately real rather than passed through `with_identity`. It is the
/// variable whose absence made a worker read a prefix its IAM condition does not cover, and a drill
/// that routed around it would not be drilling the thing that broke.
fn drill_environment() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        common::isolate_from_the_real_install();
        std::env::set_var("PERMAURA_TENANT", TENANT);
        std::env::set_var("PERMAURA_GATEWAY_ID", GATEWAY_ROW);
        let jwks = json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": AS_KID,
                "use": "sig",
                "alg": "EdDSA",
                "x": URL_SAFE_NO_PAD.encode(as_signing_key().verifying_key().to_bytes()),
            }]
        })
        .to_string();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a local JWKS listener");
        let port = listener.local_addr().expect("JWKS listener address").port();
        std::thread::spawn(move || serve_jwks(listener, jwks));
        std::env::set_var("PERMAURA_PUBLIC_URL", PUBLIC_URL);
        std::env::set_var("PERMAURA_AS_ISSUER", AS_ISSUER);
        std::env::set_var("PERMAURA_AS_JWKS", format!("http://127.0.0.1:{port}/jwks"));
        std::env::set_var("PERMAURA_OWNER_SUB", OWNER_SUB);
    });
}

fn as_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[41u8; 32])
}

fn serve_jwks(listener: TcpListener, body: String) {
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let mut scratch = [0u8; 2048];
        let _ = stream.read(&mut scratch);
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }
}

fn mint(claims: Value) -> String {
    let header = json!({ "alg": "EdDSA", "kid": AS_KID, "typ": "JWT" });
    let h = URL_SAFE_NO_PAD.encode(header.to_string().as_bytes());
    let p = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let signing_input = format!("{h}.{p}");
    let sig = as_signing_key().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// Unix milliseconds. `store::now_ms` is crate-private, so the drill keeps its own.
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The confirmation authority: an operator token for the bound owner, from the real AS.
fn owner_jwt() -> String {
    mint(json!({
        "iss": AS_ISSUER,
        "sub": OWNER_SUB,
        "aud": format!("{PUBLIC_URL}/mcp"),
        "exp": now_secs() + 600,
        "scope": "permaura:operator",
    }))
}

/// The two buckets a hosted worker sees: its own store bucket, and the holds bucket it can read one
/// prefix of.
struct Buckets {
    store: Arc<MemoryObjectStore>,
    holds: Arc<MemoryObjectStore>,
}

impl Buckets {
    fn new() -> Self {
        Buckets { store: Arc::new(MemoryObjectStore::new()), holds: Arc::new(MemoryObjectStore::new()) }
    }

    /// Replace an object in the holds bucket under its own generation, the way both hosted writers
    /// do. Panics on a conflict, because in this drill nothing races.
    fn write_hold(&self, object: &str, bytes: &[u8]) -> u64 {
        let current = self.holds.head(object).expect("head").unwrap_or(0);
        match self.holds.put_if_generation(object, bytes, current, &hold_metadata()).expect("put") {
            PutOutcome::Stored(generation) => generation,
            other => panic!("the holds bucket refused a write: {other:?}"),
        }
    }

    /// `hold-provision.sh` step 2: the explicit open object, create-only.
    fn provision_open_hold(&self) {
        let doc = hold_merge(b"", &open_patch("cp-hold-granter", "provisioned open: this tenant has never been held"));
        assert!(
            matches!(
                self.holds
                    .put_if_generation(&hold_object(TENANT), &doc, 0, &hold_metadata())
                    .expect("put"),
                PutOutcome::Stored(_)
            ),
            "the provisioning object is created, never replaced: cp-hold-granter holds create without delete"
        );
    }
}

/// One booted instance: the local database, the store over the bucket, and the router state.
struct Instance {
    state: AppState,
    store: Arc<dyn Store>,
    #[allow(dead_code)]
    dir: PathBuf,
}

/// Boot a hosted worker over `buckets`, with layer 1 as `env_hold`.
///
/// A new local directory each time, because a cold start on Cloud Run has an empty filesystem and
/// restores the database from the bucket. That is the path a promotion has to survive.
async fn boot(buckets: &Buckets, env_hold: Option<&str>, tag: &str) -> Instance {
    drill_environment();
    let dir = scratch(tag);
    let path = dir.join("gateway.db").to_string_lossy().to_string();
    let persisted = PersistedSqliteStore::open(&path, buckets.store.clone(), DEFAULT_OBJECT, Some(wrap()))
        .unwrap_or_else(|e| panic!("the worker boots over its bucket: {e}"))
        // Production exits the process on a 412; a test process cannot be allowed to.
        .with_on_stale(Box::new(|message| panic!("this instance was declared stale: {message}")));
    let store: Arc<dyn Store> = Arc::new(persisted);
    let hold = Arc::new(
        ExecutionHold::open(
            env_hold.map(str::to_string),
            buckets.holds.clone(),
            TENANT,
            // Ten minutes, so no recheck can fire inside a test and make an assertion depend on how
            // fast the machine ran the batch. Lifting the hold is modelled as the cold start it is.
            Duration::from_secs(600),
        )
        .unwrap_or_else(|e| panic!("the hold object reads at boot: {e}")),
    );
    let oauth = permaura_gateway::oauth::RsConfig::from_env()
        .map(|cfg| Arc::new(permaura_gateway::oauth::OAuthRs::new(cfg)))
        .expect("PERMAURA_PUBLIC_URL makes this gateway a resource server");
    oauth.refresh().await;
    let backend = permaura_gateway::backend::build_backend(store.clone());
    let service = EnforcementService::from_components(
        store.clone(),
        Arc::new(permaura_gateway::connectors::MockHttpClient::new()),
        Arc::new(permaura_gateway::connectors::MockCommandRunner::new()),
        backend,
        Some(oauth),
    )
    .with_execution_hold(hold);
    Instance { state: AppState::new(service), store, dir }
}

fn app(instance: &Instance) -> axum::Router {
    build_router(instance.state.clone(), "127.0.0.1:7376".parse().unwrap())
}

fn request(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    request_with(method, uri, token, body, &[])
}

/// The same, plus extra headers: a step-up ticket or a recovery code, which is how both of those
/// credentials are presented.
fn request_with(
    method: &str,
    uri: &str,
    token: &str,
    body: Value,
    extra: &[(&str, &str)],
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json");
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    builder.body(Body::from(body.to_string())).unwrap()
}

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(Value::Null)
}

/// An operator bearer, written straight to the store the way `common::operator_token` does.
fn operator_bearer(store: &dyn Store, id: &str, token: &str) -> String {
    store
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: id.into(),
            agent_id: "operator".into(),
            user_id: None,
            device_id: None,
            token: token.into(),
            role: SessionRole::Operator,
            created_at: now_ms(),
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .expect("the store accepts a session");
    token.to_string()
}

fn agent_session(store: &dyn Store, id: &str, token: &str, agent_id: &str) -> Session {
    let session = Session {
        class: Default::default(),
        opened_by: None,
        id: id.into(),
        agent_id: agent_id.into(),
        user_id: None,
        device_id: None,
        token: token.into(),
        role: SessionRole::Agent,
        created_at: now_ms(),
        revoked: false,
        expires_at: None,
        last_used_at: None,
        actor: None,
    };
    store.put_session(session.clone()).expect("the store accepts a session");
    session
}

async fn execute(instance: &Instance, session: &Session) -> Result<InvokeOutcome, GatewayError> {
    instance
        .state
        .service
        .invoke(
            session,
            CAP,
            &json!({ "status": "settled" }),
            None,
            permaura_core::ExecutionLocation::LocalOnly,
        )
        .await
}

/// Every `recovery.*` action in the chain, in order.
fn recovery_actions(store: &dyn Store) -> Vec<String> {
    store
        .audit_events(None)
        .expect("the chain reads")
        .into_iter()
        .map(|e| e.payload.action)
        .filter(|a| a.starts_with("recovery."))
        .collect()
}

fn recovery_event(store: &dyn Store, action: &str) -> Value {
    let event = store
        .audit_events(None)
        .expect("the chain reads")
        .into_iter()
        .rev()
        .find(|e| e.payload.action == action)
        .unwrap_or_else(|| panic!("no {action} in the chain"));
    serde_json::to_value(event.payload).expect("serialises")
}

// ══ the checkpoint job, as checkpoint-job.sh runs it ════════════════════════════════════════════

/// What one pass of `checkpoint-job.sh` produced.
struct Checkpoint {
    id: String,
    object: String,
    /// The live generation of `store.db` the copy was pinned to.
    source_generation: u64,
    /// The `pm-*` metadata the gateway stamped on those bytes.
    stamped: BTreeMap<String, String>,
    /// The generation `retained.json` landed at, which is what the hold's `retained_ref` names.
    retained_generation: u64,
    retained_refreshed_at: String,
    manifest: Value,
}

/// `checkpoint_one` for one tenant, with `gcloud storage` replaced by the object store double.
///
/// The three things worth saying it really does: the source is pinned to the generation read a
/// moment earlier, the destination is create-only, and the `pm-*` metadata is re-stamped explicitly
/// on the copy rather than relied on to survive a server-side rewrite.
fn checkpoint(buckets: &Buckets, stamp: &str, reason: &str) -> Checkpoint {
    let head = buckets
        .store
        .head_full(DEFAULT_OBJECT)
        .expect("describe the source")
        .expect("a live store object: a tenant with none has never committed anything");
    let bytes = buckets.store.get(DEFAULT_OBJECT, head.generation).expect("read the pinned generation");

    let id = format!("cp_{TENANT}_{stamp}_g{}", head.generation);
    let object = format!("tenants/{TENANT}/{}/{}/{}/{id}.db", &stamp[0..4], &stamp[4..6], &stamp[6..8], id = id);
    assert!(
        matches!(
            buckets
                .store
                .put_if_generation(&object, &bytes, 0, &head.metadata)
                .expect("copy the checkpoint"),
            PutOutcome::Stored(_)
        ),
        "a checkpoint is written create-only: cp-writer holds create without delete, so a retry can never overwrite one"
    );

    // The manifest, through the real field mapping: every fact is either a property of the
    // object or a value the gateway stamped on it. Nothing here opens the database.
    let mut lines = String::new();
    lines.push_str("manifest_version=1\n");
    lines.push_str(&format!("checkpoint_id={id}\n"));
    lines.push_str(&format!("tenant={TENANT}\n"));
    lines.push_str(&format!("reason={reason}\n"));
    lines.push_str("created_at=2026-09-22T00:00:00Z\n");
    lines.push_str(&format!("source.bucket=pw-store-{TENANT}\n"));
    lines.push_str(&format!("source.object={DEFAULT_OBJECT}\n"));
    lines.push_str(&format!("source.generation={}\n", head.generation));
    lines.push_str(&format!("source.size_bytes={}\n", head.size));
    lines.push_str(&format!("destination.object={object}\n"));
    for (key, path) in checkpoint_metadata_keys() {
        if path.starts_with('_') {
            continue;
        }
        lines.push_str(&format!("{path}={}\n", head.metadata.get(&key).map(String::as_str).unwrap_or("")));
    }
    lines.push_str("keys.vault_kek.escrowed=false\n");
    lines.push_str("keys.audit_signing_key.escrowed=false\n");
    let manifest = manifest_json(&lines);
    let manifest_object = object.replace(".db", ".json");
    buckets
        .store
        .put_if_generation(
            &manifest_object,
            serde_json::to_string_pretty(&manifest).expect("manifest").as_bytes(),
            0,
            &BTreeMap::new(),
        )
        .expect("write the manifest");

    // `write_retained`, into the HOLDS bucket and never the checkpoint prefix: the checkpoint job
    // reads every tenant bucket in the fleet, so if it could write `state.json` it could clear a hold.
    let refreshed_at = format!("2026-09-22T00:00:{:02}Z", &stamp[13..15].parse::<u32>().unwrap_or(0) % 60);
    let current = buckets
        .holds
        .head(&retained_object(TENANT))
        .expect("head")
        .map(|g| buckets.holds.get(&retained_object(TENANT), g).expect("read"))
        .unwrap_or_default();
    let retained = hold_merge(&current, &retained_patch(&head.metadata, &refreshed_at));
    let retained_generation = buckets.write_hold(&retained_object(TENANT), &retained);

    Checkpoint {
        id,
        object,
        source_generation: head.generation,
        stamped: head.metadata,
        retained_generation,
        retained_refreshed_at: refreshed_at,
        manifest,
    }
}

// ══ the drill ═══════════════════════════════════════════════════════════════════════════════════

/// The whole ceremony, once, end to end.
///
/// One test rather than twelve because the thing being proved is the *sequence*: every assertion
/// below depends on the exact state the steps before it left, and splitting them would mean twelve
/// re-runs of a six-second setup that each re-derived a state this one already holds. The failure
/// legs are separate tests below, because each of those is a different first step.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_whole_restore_ceremony() {
    let buckets = Buckets::new();
    buckets.provision_open_hold();

    // ── 1. a hosted worker, an estate, and some history ─────────────────────────────────────────
    let live = boot(&buckets, None, "live").await;
    assert!(live.state.service.refuse_if_held().is_ok(), "a provisioned worker executes");
    assert!(
        live.state.service.execution_hold().unwrap().restore_trigger().is_none(),
        "and the open object carries no checkpoint id, so it is not a restore"
    );
    seed::seed(live.store.as_ref()).expect("the estate seeds");

    // An approver device, paired durably so it is in the snapshot rather than only in this process.
    let device_key = SigningKey::from_bytes(&[11u8; 32]);
    let device_pubkey = STANDARD.encode(device_key.verifying_key().to_bytes());
    assert!(
        live.state
            .service
            .trust_approver_key_durable("device:drill-phone", &device_pubkey)
            .expect("the pairing persists"),
        "the device is paired"
    );

    // An agent with a session bearer, a grant, and a pending approval.
    live.store
        .put_agent(Agent {
            id: "drill-agent".into(),
            name: "Drill agent".into(),
            status: Default::default(),
            enrolled_at: now_ms(),
        })
        .expect("the agent is created");
    let doomed_bearer = "tok_revoked_after_the_checkpoint";
    agent_session(live.store.as_ref(), "sess_doomed", doomed_bearer, "codex-cli");
    let mut doomed_grant = live
        .store
        .get_grant("gr_braintree_readonly")
        .expect("read")
        .expect("the seeded grant");
    doomed_grant.grant_id = "gr_drill_doomed".into();
    doomed_grant.name = "Deleted after the checkpoint".into();
    doomed_grant.is_default = false;
    live.store.put_grant(doomed_grant).expect("the grant is created");
    live.store
        .put_approval(PendingApproval {
            id: "appr_drill".into(),
            session_id: "sess_doomed".into(),
            capability: "braintree.transactions.refund".into(),
            resource: "braintree_production".into(),
            message: "Refund 100?".into(),
            status: "pending".into(),
            grant_id: None,
            policy_id: None,
            params: json!({ "amount": 100 }).into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at: now_ms(),
            expires_at: None,
            risk: None,
            action_description: None,
            intent: None,
            required_tier: "approve".into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        })
        .expect("the approval is raised");
    live.store
        .put_enrolment_code(EnrolmentCode {
            code: "ENRL-DRILL-0001".into(),
            label: None,
            created_at: now_ms(),
            expires_at: i64::MAX,
            used: false,
        })
        .expect("the code is minted");

    // The floor its owner raised. `max(restored, retained)` is taken over exactly this stored row.
    live.state
        .service
        .set_approval_floor(Some(ApprovalFloor::Approve))
        .expect("the floor is set");

    // Real executions, so the chain holds attempt/allow pairs rather than synthetic events.
    let agent = agent_session(live.store.as_ref(), "sess_agent", "tok_agent", "codex-cli");
    for _ in 0..2 {
        assert!(
            matches!(execute(&live, &agent).await.expect("answered"), InvokeOutcome::Allowed { .. }),
            "the seeded capability executes before anything is held"
        );
    }
    let events_at_checkpoint = live.store.audit_events(None).expect("chain").len();

    // ── 2. the checkpoint ───────────────────────────────────────────────────────────────────────
    let cp = checkpoint(&buckets, "20260922T140000Z", "scheduled");
    assert_eq!(
        cp.stamped.get("pm-tenant").map(String::as_str),
        Some(TENANT),
        "the gateway stamped the SLUG, not the row id: reading the wrong one is a 403 at boot"
    );
    assert_eq!(cp.stamped.get("pm-gateway-id").map(String::as_str), Some(GATEWAY_ROW));
    assert_eq!(
        cp.stamped.get("pm-approval-floor").map(String::as_str),
        Some("approve"),
        "the floor travels with the bytes"
    );
    assert!(
        cp.id.ends_with(&format!("_g{}", cp.source_generation)),
        "a checkpoint id names the source generation it was pinned to: {}",
        cp.id
    );
    assert_eq!(cp.manifest["tenant"], json!(TENANT));
    assert_eq!(cp.manifest["stamped_tenant"], json!(TENANT));
    assert_eq!(cp.manifest["store"]["approval_floor"], json!("approve"));
    assert!(
        cp.manifest["store"]["upload_id"].as_str().is_some_and(|v| v.len() == 32),
        "every upload carries its own nonce: {}",
        cp.manifest["store"]["upload_id"]
    );

    // ── 3. what the restore must NOT bring back ─────────────────────────────────────────────────
    live.state.service.revoke_approver_key("device:drill-phone").expect("the device is revoked");
    assert!(live.store.revoke_session("sess_doomed").expect("revoke"), "the bearer is revoked");
    assert!(live.store.delete_grant("gr_drill_doomed").expect("delete"), "the grant is deleted");
    let resolved = live
        .state
        .service
        .resolve_approval("appr_drill", false, "bearer", Some("sam"))
        .await
        .expect("the approval resolves");
    assert_eq!(resolved.status, "denied", "a human said no");
    live.state
        .service
        .set_approval_floor(Some(ApprovalFloor::DeviceSigned))
        .expect("the floor is raised again");
    for _ in 0..2 {
        execute(&live, &agent).await.expect("answered");
    }
    let abandoned_events = live.store.audit_events(None).expect("chain").len();
    assert!(abandoned_events > events_at_checkpoint, "the abandoned generation moved on");

    // The checkpoint job's next pass, thirty minutes later: a second checkpoint, and a retained
    // record refreshed from the newer stamps. This is what carries the raised floor out of reach of
    // the party performing the restore.
    let fresh = checkpoint(&buckets, "20260922T143000Z", "scheduled");
    assert_eq!(
        fresh.stamped.get("pm-approval-floor").map(String::as_str),
        Some("device_signed"),
        "the retained record is refreshed from the state being abandoned"
    );
    let abandoned_head_seq: i64 = fresh
        .stamped
        .get("pm-audit-head-seq")
        .and_then(|v| v.parse().ok())
        .expect("the abandoned head is a number");

    // ── 4. the restore, in restore-tenant.sh's order ────────────────────────────────────────────
    let hold_id = "hold_20260922T150000Z";
    // 5/8: layer 2 first, before a single byte moves, because it is the layer a compromised runtime
    // cannot clear.
    let current = buckets
        .holds
        .get(&hold_object(TENANT), buckets.holds.head(&hold_object(TENANT)).unwrap().unwrap())
        .expect("read the open object");
    let held = hold_merge(
        &current,
        &held_patch(hold_id, &cp.id, fresh.retained_generation, &fresh.retained_refreshed_at),
    );
    buckets.write_hold(&hold_object(TENANT), &held);

    // 7/8: promote the checkpoint bytes under a generation precondition. Nothing is deleted; the
    // abandoned generation stays in the bucket's history.
    let cp_bytes = buckets.store.get(&cp.object, buckets.store.head(&cp.object).unwrap().unwrap()).expect("read");
    let live_generation = buckets.store.head(DEFAULT_OBJECT).unwrap().expect("a live object");
    assert!(
        matches!(
            buckets
                .store
                .put_if_generation(DEFAULT_OBJECT, &cp_bytes, live_generation, &cp.stamped)
                .expect("promote"),
            PutOutcome::Stored(_)
        ),
        "the promotion binds to the generation read a moment earlier"
    );
    // The pre-restore instance is finished with. Dropping it here is the `gcloud run services
    // update` restart: nothing may serve from the abandoned database.
    drop(live);

    // 6/8 and 8/8: layer 1, and the cold start onto the promoted store.
    let restore_began = now_ms();
    let restored = boot(&buckets, Some(hold_id), "restored").await;
    let record = reconcile::run_at_boot(&restored.state.service)
        .expect("reconciliation runs")
        .expect("a promoted checkpoint with a hold id and a checkpoint id is a restore");
    assert_eq!(record.stage, Stage::Reviewing);
    assert_eq!(record.hold_id, hold_id);
    assert_eq!(record.checkpoint_id, cp.id);

    // ── 5. what the router says ─────────────────────────────────────────────────────────────────

    // 5a. Execution, approval resolution and vault export all answer 423 while held.
    let restored_bearer = operator_bearer(restored.store.as_ref(), "sess_op_restored", "tok_op_restored");
    let held_agent = agent_session(restored.store.as_ref(), "sess_agent_2", "tok_agent_2", "codex-cli");
    let err = match execute(&restored, &held_agent).await {
        Err(err) => err,
        Ok(_) => panic!("a held tenant executes nothing"),
    };
    assert!(matches!(err, GatewayError::ExecutionHeld { .. }), "{err}");
    let resp = app(&restored)
        .oneshot(request("POST", "/v1/invoke", "tok_agent_2", json!({ "capability": CAP, "params": {} })))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::LOCKED, "/v1/invoke is 423, not 403 and not 503");
    let body = body_json(resp).await;
    assert_eq!(body["hold_id"], json!(hold_id));
    assert_eq!(body["state"], json!("held"));
    assert!(body["reason"].as_str().is_some_and(|r| !r.is_empty()));
    assert!(
        !body.to_string().contains("set_by"),
        "who set the hold is not an agent's business: {body}"
    );
    let resp = app(&restored)
        .oneshot(request(
            "POST",
            "/v1/vault/export",
            &restored_bearer,
            json!({ "passphrase": "correct horse battery staple" }),
        ))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::LOCKED,
        "the one route that concentrates every credential is held too"
    );

    // 5b. The invalidation: the revoked bearer, the resolved approval, the enrolment code, the floor.
    assert!(
        restored.state.service.authenticate(doomed_bearer).is_err(),
        "the bearer somebody revoked after the checkpoint came back unrevoked in the snapshot and is now gone outright"
    );
    assert!(
        restored.store.get_session("sess_doomed").expect("read").is_none(),
        "deleted rather than revoked: a restore rolls a `revoked` flag back with everything else"
    );
    let approval = restored.store.get_approval("appr_drill").expect("read").expect("the row survives");
    assert_eq!(approval.status, "denied");
    assert_eq!(approval.resolution_reason.as_deref(), Some(reconcile::DENIED_BY_RESTORE));
    assert!(
        restored.store.consume_enrolment_code("ENRL-DRILL-0001", 1).expect("consume").is_none(),
        "the unconsumed enrolment code the snapshot brought back is gone"
    );
    assert_eq!(
        restored.store.get_meta(APPROVAL_FLOOR_META).expect("read").as_deref(),
        Some("device_signed"),
        "the floor the owner raised AFTER the checkpoint is preserved: max(restored, retained), never lowered"
    );
    assert_eq!(record.approval_floor.as_deref(), Some("device_signed"));
    // The replay floor binds on a FIRST restore, which is the only kind anybody has yet had to
    // perform. This tenant's checkpoints stamped `pm-replay-floor-ms: none` (nothing has ever
    // restored it) and `write_retained` typed that to null, so there is nothing to carry forward;
    // the floor is the instant this reconciliation ran, because every one-time token alive at that
    // instant was issued against a `one_time_claims` table the promotion rolled back.
    // `no_one_time_token_issued_before_a_first_restore_can_be_spent_after_it` drives all four kinds
    // of token through the router against exactly this state.
    let floor = record.replay_floor_ms.expect("a restore always sets a floor");
    assert!(
        floor >= restore_began,
        "the floor is the restore instant, not the checkpoint's: {floor} < {restore_began}"
    );
    assert_eq!(
        record.replay_floor_source.as_deref(),
        Some("restore_time"),
        "and the record says which of the three inputs it came from"
    );
    assert_eq!(
        permaura_gateway::restore::replay_floor(restored.store.as_ref()).expect("read"),
        Some(floor),
        "written to gateway_meta in the same atomic scope as the sessions, approvals and codes"
    );
    assert!(
        record.notes.iter().any(|n| n.contains("no replay floor")),
        "and the owner is still told the checkpoint job stamped none: {:?}",
        record.notes
    );
    let invalidated = recovery_event(restored.store.as_ref(), "recovery.invalidated");
    assert_eq!(invalidated["summary"]["replay_floor_ms"], json!(floor));
    assert_eq!(invalidated["summary"]["replay_floor_source"], json!("restore_time"));

    // 5c. The reconciliation list holds every kind, and the deleted grant is not in it.
    for kind in [ReviewKind::Device, ReviewKind::Grant, ReviewKind::Connection, ReviewKind::Secret, ReviewKind::Agent] {
        assert!(
            record.items.iter().any(|i| i.kind == kind),
            "the restored estate's {kind:?} entries are all in the list: {:?}",
            record.items
        );
    }
    assert!(
        record.items.iter().any(|i| i.kind == ReviewKind::Device && i.id == "device:drill-phone"),
        "the device revoked after the checkpoint came back with the snapshot and must be reviewed"
    );
    assert!(
        record.items.iter().any(|i| i.kind == ReviewKind::Agent && i.id == "drill-agent"),
        "and so is the agent"
    );
    assert!(
        record.items.iter().any(|i| i.kind == ReviewKind::Grant && i.id == "gr_drill_doomed"),
        "a grant DELETED after the checkpoint is back in the database, which is the whole hazard: it \
         is in the list and cannot act until its owner decides about it"
    );
    assert!(
        restored.store.get_grant("gr_drill_doomed").expect("read").is_some(),
        "and it really is a live row again, not only a line in a list"
    );

    // 5d. The restored device cannot approve.
    let keyring = restored.state.service.approver_keyring_snapshot();
    let outcome = restored.state.service.verify_signed_approval(
        &keyring,
        &permaura_relay::ApprovalResult {
            job_id: "job_drill".into(),
            approval_id: "appr_drill".into(),
            approve: true,
            request_hash: "deadbeef".into(),
            approver: "device:drill-phone".into(),
            decided_at: now_secs() * 1000,
            approver_pubkey: None,
            audience: None,
            display_digest: None,
            device_sig: String::new(),
        },
    );
    match outcome {
        permaura_gateway::service::SignedApprovalOutcome::Refused(why) => {
            assert!(why.contains("restored snapshot"), "refused for being unreviewed: {why}")
        }
        _ => panic!("a device awaiting review must not approve"),
    }

    // 5e. A session bearer cannot drive the reconciliation; the owner's operator token can.
    for (token, what) in [(restored_bearer.as_str(), "a gateway session bearer"), ("", "nothing at all")] {
        let resp = app(&restored)
            .oneshot(request("GET", "/v1/recovery/reconciliation", token, json!({})))
            .await
            .unwrap();
        assert!(
            resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::UNAUTHORIZED,
            "{what} must not reach the reconciliation: {}",
            resp.status()
        );
    }
    let owner = owner_jwt();
    let resp = app(&restored)
        .oneshot(request("GET", "/v1/recovery/reconciliation", &owner, json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let listed = body_json(resp).await;
    assert_eq!(listed["hold_id"], json!(hold_id));
    assert_eq!(listed["checkpoint_id"], json!(cp.id));
    assert!(listed["unreviewed"].as_u64().unwrap() > 0);

    // 5f. The fork record and an honest gap.
    let fork = recovery_event(restored.store.as_ref(), "recovery.restored");
    assert_eq!(fork["summary"]["checkpoint_id"], json!(cp.id));
    assert_eq!(
        fork["summary"]["abandoned_head_seq"],
        json!(abandoned_head_seq),
        "the abandoned head comes from the retained record the restore was planned against"
    );
    let restored_head_seq = fork["summary"]["restored_head_seq"].as_i64().expect("a number");
    assert_eq!(
        fork["summary"]["gap_events"],
        json!(abandoned_head_seq - restored_head_seq),
        "gap_events is the honest count of records this restore threw away, never zero and never unknown here"
    );
    assert!(
        fork["summary"]["gap_events"].as_i64().expect("a number") > 0,
        "the abandoned generation really did move on past the checkpoint"
    );
    assert_eq!(fork["summary"]["epoch"], json!(1), "the chain forked");
    assert_eq!(
        restored.store.verify_audit().expect("verify"),
        None,
        "and it still verifies after the fork"
    );

    // 5g. A second cold start resumes rather than re-reconciling.
    let survivor = operator_bearer(restored.store.as_ref(), "sess_after_restore", "tok_after_restore");
    let actions_after_first = recovery_actions(restored.store.as_ref());
    drop(restored);
    // The restoration authority moved the object to `reconciling` when the worker asked it to, which
    // is the state a second cold start actually meets.
    let current = buckets
        .holds
        .get(&hold_object(TENANT), buckets.holds.head(&hold_object(TENANT)).unwrap().unwrap())
        .expect("read");
    let reconciling = hold_merge(&current, &json!({ "state": "reconciling" }));
    buckets.write_hold(&hold_object(TENANT), &reconciling);
    let second = boot(&buckets, Some(hold_id), "second-cold-start").await;
    let resumed = reconcile::run_at_boot(&second.state.service)
        .expect("reconciliation runs")
        .expect("the same restore");
    assert_eq!(resumed.opened_at, record.opened_at, "the same record, resumed");
    assert_eq!(
        recovery_actions(second.store.as_ref()),
        actions_after_first,
        "and no second set of recovery events was appended"
    );
    assert!(
        second.state.service.authenticate(&survivor).is_ok(),
        "a session opened after the restore survives, so the invalidation did not run twice"
    );

    // 5h. Confirm some, remove one, confirm-all, and close.
    let a_grant = resumed.items.iter().find(|i| i.kind == ReviewKind::Grant).expect("a grant").clone();
    // Not the secret the drill's capability resolves: `remove` deletes the credential itself, so
    // removing that one would make the "execution resumes" assertion below fail for the right
    // reason and prove nothing about the hold.
    let a_secret = resumed
        .items
        .iter()
        .find(|i| i.kind == ReviewKind::Secret && i.id != "sec_braintree_prod")
        .expect("a secret other than the one under test")
        .clone();
    let resp = app(&second)
        .oneshot(request(
            "POST",
            "/v1/recovery/reconciliation/confirm",
            &owner,
            json!({ "kind": "grant", "id": a_grant.id }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let resp = app(&second)
        .oneshot(request(
            "POST",
            "/v1/recovery/reconciliation/remove",
            &owner,
            json!({ "kind": "secret", "id": a_secret.id }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        second.store.get_secret(&a_secret.id).expect("read").is_none(),
        "removing an item deletes the thing, not just the row about it"
    );

    // Close refuses while anything is outstanding.
    let resp = app(&second)
        .oneshot(request("POST", "/v1/recovery/reconciliation/close", &owner, json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert!(
        !recovery_actions(second.store.as_ref()).contains(&"recovery.reconciled".to_string()),
        "and nothing was recorded"
    );

    // The device the owner revoked after the checkpoint is REMOVED rather than confirmed, which is
    // the whole point of the list: the restore brought its key back, nothing in the gateway knows
    // it was revoked, and only the owner can say so. Confirming it would trust it again, and that is
    // the owner's right (the annotation is a hint, never a decision).
    let resp = app(&second)
        .oneshot(request(
            "POST",
            "/v1/recovery/reconciliation/remove",
            &owner,
            json!({ "kind": "device", "id": "device:drill-phone" }),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        !second.state.service.approver_key_trusted("device:drill-phone"),
        "removing a device revokes the key itself, so a record saying `removed` is never the only \
         thing between a restored credential and an agent"
    );

    let resp = app(&second)
        .oneshot(request("POST", "/v1/recovery/reconciliation/confirm-all", &owner, json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(body_json(resp).await["unreviewed"], json!(0));

    let resp = app(&second)
        .oneshot(request("POST", "/v1/recovery/reconciliation/close", &owner, json!({})))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "and succeeds when nothing is outstanding");
    let closed = body_json(resp).await;
    assert_eq!(closed["state"], json!("closed"));
    assert_eq!(closed["hold"]["cleared"], json!(false), "the gateway never writes the hold object");
    let actions = recovery_actions(second.store.as_ref());
    assert_eq!(actions.iter().filter(|a| *a == "recovery.confirm_all").count(), 1);
    assert_eq!(actions.iter().filter(|a| *a == "recovery.confirm").count(), 1);
    assert_eq!(actions.iter().filter(|a| *a == "recovery.remove").count(), 2);
    assert_eq!(actions.iter().filter(|a| *a == "recovery.reconciled").count(), 1);
    assert_eq!(recovery_event(second.store.as_ref(), "recovery.reconciled")["summary"]["reviewed_by"], json!(OWNER_SUB));
    drop(second);

    // ── 5i. the hold is lifted, object first, then the environment ──────────────────────────────
    let current = buckets
        .holds
        .get(&hold_object(TENANT), buckets.holds.head(&hold_object(TENANT)).unwrap().unwrap())
        .expect("read");
    let reopened = hold_merge(&current, &open_patch("cp-restorer", "hold lifted: reconciliation closed"));
    buckets.write_hold(&hold_object(TENANT), &reopened);
    // `hold_merge` merges rather than replaces, so the open patch has to null every field that names
    // the restore. A stale `checkpoint_id` here was inert to the gateway (`restore_trigger` needs the
    // state AND a checkpoint id) but a human reading the object during the next incident would see
    // one beside `state: "open"` and conclude a restore was under way. This drill found it, and the
    // hosted scripts were fixed to match.
    let lifted: Value = serde_json::from_slice(&reopened).expect("json");
    assert_eq!(lifted["state"], json!("open"));
    assert_eq!(lifted["hold_id"], Value::Null, "the hold id goes");
    assert_eq!(lifted["checkpoint_id"], Value::Null, "and so does the checkpoint it was promoting");
    assert_eq!(lifted["retained_ref"], Value::Null, "and the retained record that named");
    assert_eq!(
        lifted["reason"],
        json!("hold lifted: reconciliation closed"),
        "and the reason describes the lift rather than the restore"
    );

    // Object cleared, variable still set: layer 1 alone holds, which is why the runbook clears it
    // second. Clearing the variable first leaves a window that reads as a deploy that dropped it.
    let half = boot(&buckets, Some(hold_id), "half-lifted").await;
    let err = half
        .state
        .service
        .refuse_if_held()
        .expect_err("layer 1 alone is still a hold");
    assert!(matches!(err, GatewayError::ExecutionHeld { .. }), "{err}");
    drop(half);

    let free = boot(&buckets, None, "free").await;
    assert!(free.state.service.refuse_if_held().is_ok(), "both layers read open");
    assert!(
        reconcile::run_at_boot(&free.state.service).expect("runs").is_none(),
        "an open object carries no checkpoint id, so a lifted worker never reconciles again"
    );

    // Execution resumes, but only for what was confirmed.
    let working_agent = agent_session(free.store.as_ref(), "sess_agent_3", "tok_agent_3", "codex-cli");
    match execute(&free, &working_agent).await.expect("answered") {
        InvokeOutcome::Allowed { .. } => {}
        InvokeOutcome::Denied { decision } => {
            panic!("a confirmed estate executes once the hold is lifted: {}", decision.reason)
        }
        InvokeOutcome::RequiresApproval { .. } => panic!("no approval was expected here"),
    }
    assert!(
        !free.state.service.approver_key_trusted("device:drill-phone"),
        "the device revoked after the checkpoint came back with the snapshot and was removed during \
         the reconciliation; the lift does not bring it back"
    );
    let keyring = free.state.service.approver_keyring_snapshot();
    let outcome = free.state.service.verify_signed_approval(
        &keyring,
        &permaura_relay::ApprovalResult {
            job_id: "job_after".into(),
            approval_id: "appr_drill".into(),
            approve: true,
            request_hash: "deadbeef".into(),
            approver: "device:drill-phone".into(),
            decided_at: now_secs() * 1000,
            approver_pubkey: None,
            audience: None,
            display_digest: None,
            device_sig: String::new(),
        },
    );
    assert!(
        matches!(outcome, permaura_gateway::service::SignedApprovalOutcome::Refused(_)),
        "and it still cannot approve"
    );
    assert!(
        free.state.service.authenticate(doomed_bearer).is_err(),
        "and the bearer revoked before the checkpoint's generation was abandoned never comes back"
    );
}

// ══ the failure legs ════════════════════════════════════════════════════════════════════════════

/// `retained.json` missing altogether. Not fatal, and not silent: the approval floor comes from the
/// restored value and is never invented, the replay floor is still the restore's own instant, and
/// the notes say both.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restore_with_no_retained_record_keeps_the_restored_approval_floor() {
    let restore_began = now_ms();
    let buckets = Buckets::new();
    buckets.provision_open_hold();
    let live = boot(&buckets, None, "no-retained-live").await;
    seed::seed(live.store.as_ref()).expect("seeds");
    live.state.service.set_approval_floor(Some(ApprovalFloor::Approve)).expect("floor");
    let cp = checkpoint(&buckets, "20260922T140000Z", "scheduled");
    drop(live);

    // The restoration authority writes the hold naming a retained record that is not there. The
    // drill removes it by writing the hold with a `retained_ref` the bucket has nothing at.
    let current = buckets
        .holds
        .get(&hold_object(TENANT), buckets.holds.head(&hold_object(TENANT)).unwrap().unwrap())
        .expect("read");
    let held = hold_merge(&current, &held_patch("hold_no_retained", &cp.id, 0, ""));
    buckets.write_hold(&hold_object(TENANT), &held);
    // `retained.json` is what `checkpoint()` wrote; a tenant that has never been checkpointed by a
    // gateway that stamps floors has none at all, which is the case this leg is for.
    let empty = Arc::new(MemoryObjectStore::new());
    empty
        .put_if_generation(&hold_object(TENANT), &held, 0, &hold_metadata())
        .expect("the hold object alone");
    let holds_without_retained = Buckets { store: buckets.store.clone(), holds: empty };

    let restored = boot(&holds_without_retained, Some("hold_no_retained"), "no-retained").await;
    let record = reconcile::run_at_boot(&restored.state.service).expect("runs").expect("a restore");
    let floor = record.replay_floor_ms.expect("a restore always sets a floor");
    assert!(floor >= restore_began, "the restore's own instant is the floor: {floor}");
    assert_eq!(record.replay_floor_source.as_deref(), Some("restore_time"));
    assert_eq!(
        permaura_gateway::restore::replay_floor(restored.store.as_ref()).expect("read"),
        Some(floor),
        "and it was written to the store, not only to the record"
    );
    assert_eq!(
        record.approval_floor.as_deref(),
        Some("approve"),
        "the approval floor is whatever the promoted snapshot carried: that one is never invented"
    );
    assert!(
        record.notes.iter().any(|n| n.contains("no replay floor")),
        "and the owner is told the checkpoint job stamped none: {:?}",
        record.notes
    );
    assert_eq!(record.gap_events, None, "the gap cannot be computed and is not reported as zero");
    assert_eq!(
        recovery_event(restored.store.as_ref(), "recovery.restored")["summary"]["gap_events"],
        json!("unknown")
    );
}

/// A checkpoint belonging to another tenant, refused twice over: by the hosted tool from the
/// manifest, and by the gateway from the hold object.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_tenant_checkpoint_is_refused() {
    let buckets = Buckets::new();
    buckets.provision_open_hold();
    let live = boot(&buckets, None, "wrong-tenant-live").await;
    seed::seed(live.store.as_ref()).expect("seeds");
    let cp = checkpoint(&buckets, "20260922T140000Z", "scheduled");
    drop(live);

    // `restore-tenant.sh` step 2, run for real where the scripts are reachable: the manifest names
    // the tenant it was taken from, so the refusal survives a directory somebody moved by hand.
    if hosted_scripts().is_some() {
        let manifest = serde_json::to_string(&cp.manifest).expect("manifest");
        let ours = hosted_bash(
            &format!("manifest_tenant_is {TENANT} && echo MATCH || echo REFUSED"),
            &[],
            &manifest,
        );
        assert_eq!(ours.trim(), "MATCH");
        let theirs = hosted_bash("manifest_tenant_is some-other-tenant && echo MATCH || echo REFUSED", &[], &manifest);
        assert_eq!(
            theirs.trim(),
            "REFUSED",
            "promoting one tenant's database into another's worker would hand it somebody else's grants and sealed credentials"
        );
        // The stronger of the two checks: `pm-tenant`, written by the gateway itself.
        assert_eq!(cp.manifest["stamped_tenant"], json!(TENANT));
    } else {
        assert!(
        cp.id.ends_with(&format!("_g{}", cp.source_generation)),
        "a checkpoint id names the source generation it was pinned to: {}",
        cp.id
    );
    assert_eq!(cp.manifest["tenant"], json!(TENANT));
        assert_eq!(cp.manifest["stamped_tenant"], json!(TENANT));
    }

    // And the gateway's own half: a hold object naming another tenant is unreadable, not a hold to
    // be obeyed and not an open to be trusted. This is the object a restore of the wrong workspace
    // would leave behind.
    let foreign = hold_merge(
        b"",
        &json!({ "tenant": "some-other-tenant", "state": "open", "hold_id": Value::Null, "reason": "copied" }),
    );
    let strays = Arc::new(MemoryObjectStore::new());
    strays.put_if_generation(&hold_object(TENANT), &foreign, 0, &hold_metadata()).expect("put");
    let hold = ExecutionHold::open(None, strays, TENANT, Duration::from_secs(600))
        .expect("an unparseable object is an answer, not a boot failure");
    let err = hold.refuse_if_held().expect_err("a foreign tenant's hold document refuses execution");
    assert!(matches!(err, GatewayError::ExecutionHeld { .. }), "{err}");
}

/// The hold object unreadable at boot. Not "probably open": a worker that cannot tell whether it is
/// held must not decide that it is not, and there is nothing useful it can do, so it refuses to
/// start at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_unreadable_hold_object_refuses_to_start() {
    drill_environment();
    let unreachable: Arc<dyn ObjectStore> =
        Arc::new(FailingObjectStore { reason: "synthetic: the holds bucket is unreachable".into() });
    let err = match ExecutionHold::open(None, unreachable, TENANT, Duration::from_secs(600)) {
        Err(err) => err,
        Ok(_) => panic!("an unreachable hold bucket aborts startup"),
    };
    let message = format!("{err}");
    assert!(
        message.contains("unreachable") || message.contains("holds"),
        "and the error says what could not be read: {message}"
    );
}

/// An ordinary hold: somebody held this tenant by hand, with no restore behind it. Execution is
/// refused and **nothing reconciles**, because the document carries no checkpoint id.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hold_with_no_checkpoint_id_is_an_ordinary_hold_and_never_reconciles() {
    let buckets = Buckets::new();
    let doc = hold_merge(
        b"",
        &json!({
            "tenant": TENANT,
            "state": "held",
            "hold_id": "hold_by_hand",
            "reason": "an operator held this tenant during an incident",
        }),
    );
    buckets
        .holds
        .put_if_generation(&hold_object(TENANT), &doc, 0, &hold_metadata())
        .expect("put");
    let instance = boot(&buckets, None, "ordinary-hold").await;
    seed::seed(instance.store.as_ref()).expect("seeds");

    assert!(instance.state.service.refuse_if_held().is_err(), "execution is refused");
    assert!(
        instance.state.service.execution_hold().unwrap().restore_trigger().is_none(),
        "but there is no checkpoint id, so this is not a restore"
    );
    assert!(reconcile::run_at_boot(&instance.state.service).expect("runs").is_none());
    assert!(
        instance.state.service.reconciliation().expect("read").is_none(),
        "and no reconciliation record was written"
    );
    let agent = agent_session(instance.store.as_ref(), "sess_ordinary", "tok_ordinary", "codex-cli");
    assert!(
        execute(&instance, &agent).await.is_err(),
        "an ordinary hold stops execution exactly as a restore's hold does"
    );
}

/// The replay floor a previous restore left behind: the whole chain, stored row to stamp to retained
/// record to refusal.
///
/// The restore instant now dominates that carried value in any ordinary run, so what this pins is
/// the *carriage*: that the stored row travels with the bytes as a decimal string, lands in
/// `retained.json` as a JSON number, is ranked rather than ignored, and that the floor in force
/// afterwards refuses a token issued at it. Keep it: it is the only test that walks the whole
/// stamp-to-retained-to-rank path, and the only one that would notice the hosted scripts'
/// `pm-replay-floor-ms` mapping breaking.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replay_floor_a_previous_restore_stamped_travels_into_the_next_one() {
    let buckets = Buckets::new();
    buckets.provision_open_hold();
    let live = boot(&buckets, None, "replay-floor-live").await;
    seed::seed(live.store.as_ref()).expect("seeds");

    // What an EARLIER restore would have left behind, and the only thing that ever writes this row.
    let armed = now_ms();
    permaura_gateway::restore::raise_replay_floor(live.store.as_ref(), armed).expect("armed");
    // A mutation, so the snapshot carrying the row reaches the bucket.
    live.store
        .put_agent(Agent { id: "nudge".into(), name: "n".into(), status: Default::default(), enrolled_at: armed })
        .expect("write");

    let cp = checkpoint(&buckets, "20260922T140000Z", "scheduled");
    assert_eq!(
        cp.stamped.get("pm-replay-floor-ms").map(String::as_str),
        Some(armed.to_string().as_str()),
        "the stored row travels with the bytes as a decimal string"
    );
    let retained: Value = serde_json::from_slice(
        &buckets
            .holds
            .get(&retained_object(TENANT), cp.retained_generation)
            .expect("read the retained record"),
    )
    .expect("json");
    assert_eq!(
        retained["retained"]["replay_floor_ms"],
        json!(armed),
        "and lands in the retained record as a NUMBER, which is the shape reconciliation ranks"
    );
    drop(live);

    let current = buckets
        .holds
        .get(&hold_object(TENANT), buckets.holds.head(&hold_object(TENANT)).unwrap().unwrap())
        .expect("read");
    let held = hold_merge(
        &current,
        &held_patch("hold_armed", &cp.id, cp.retained_generation, &cp.retained_refreshed_at),
    );
    buckets.write_hold(&hold_object(TENANT), &held);
    let cp_bytes =
        buckets.store.get(&cp.object, buckets.store.head(&cp.object).unwrap().unwrap()).expect("read");
    let generation = buckets.store.head(DEFAULT_OBJECT).unwrap().expect("live");
    buckets
        .store
        .put_if_generation(DEFAULT_OBJECT, &cp_bytes, generation, &cp.stamped)
        .expect("promote");

    let restored = boot(&buckets, Some("hold_armed"), "replay-floor-restored").await;
    let record = reconcile::run_at_boot(&restored.state.service).expect("runs").expect("a restore");
    let floor = record.replay_floor_ms.expect("a restore always sets a floor");
    assert!(
        floor >= armed,
        "max(restored, retained, restore instant) is never below the carried floor: {floor} < {armed}"
    );
    assert!(
        !record.notes.iter().any(|n| n.contains("no replay floor")),
        "and nothing is said about a missing one: {:?}",
        record.notes
    );

    // What the floor is for: the one-time ledger came back rolled up with the database, so the claim
    // itself succeeds and the floor is the only thing left that can refuse.
    assert!(
        restored.store.claim_once("step-up", "jti-pre-restore", i64::MAX).expect("claim"),
        "the rolled-back ledger has never seen this token"
    );
    let refused = permaura_gateway::restore::refuse_if_replayed_across_a_restore(
        restored.store.as_ref(),
        floor,
        "step-up ticket",
    )
    .expect_err("a token issued AT the floor is one nobody can vouch for");
    assert!(matches!(refused, GatewayError::Unauthorized(_)), "{refused}");
    assert!(permaura_gateway::restore::refuse_if_replayed_across_a_restore(
        restored.store.as_ref(),
        floor + 1,
        "step-up ticket",
    )
    .is_ok());
}

// ══ the four one-time tokens, through the router ════════════════════════════════════════════════

/// The router as a **hosted** worker sees it: the same service, the same store, the same hold, with
/// `PERMAURA_HOSTED` set.
///
/// A field on the state rather than the variable, for the reason the hold's two layers are passed to
/// `ExecutionHold::open` rather than read from the environment: the environment is process-wide and
/// `cargo test` runs binaries in parallel, so one test's hosted flag would be every other test's.
/// What it changes is exactly what the variable changes: `compute_is_remote` reports every request
/// as remote, which is what closes the loopback anchor and makes a step-up ticket the authority.
fn hosted_app(instance: &Instance) -> axum::Router {
    let mut state = instance.state.clone();
    state.hosted = true;
    build_router(state, "127.0.0.1:7376".parse().unwrap())
}

/// The gateway's public-key fingerprint scheme, replicated because `service::key_fingerprint` is
/// crate-internal. Byte-identical or a ticket is refused for the very key it was minted for.
fn key_fingerprint(pubkey_b64: &str) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(pubkey_b64.as_bytes()).iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// A well-formed `approval-floor-lower` step-up ticket, asserting a re-authentication at `auth_time`.
fn floor_ticket(jti: &str, auth_time: i64) -> String {
    mint(json!({
        "sub": OWNER_SUB,
        "iss": AS_ISSUER,
        "exp": now_secs() + 180,
        "aud": format!("{PUBLIC_URL}/v1/approval-floor"),
        "jti": jti,
        "purpose": "approval-floor-lower",
        "amr": ["pwd", "otp"],
        "auth_time": auth_time,
    }))
}

/// A well-formed `approver-pair` ticket, pinned to this exact approver id and key.
fn pair_ticket(jti: &str, approver_id: &str, pubkey_b64: &str, auth_time: i64) -> String {
    mint(json!({
        "sub": OWNER_SUB,
        "iss": AS_ISSUER,
        "exp": now_secs() + 180,
        "aud": format!("{PUBLIC_URL}/v1/approver-keys/pair"),
        "jti": jti,
        "purpose": "approver-pair",
        "approver_id": approver_id,
        "pubkey_fp": key_fingerprint(pubkey_b64),
        "amr": ["pwd", "passkey"],
        "auth_time": auth_time,
    }))
}

/// The pairing blob a device exports: a real Ed25519 signature over the canonical preimage, verified
/// by the endpoint before any ticket is spent.
fn pair_body(approver_id: &str, sk: &SigningKey) -> Value {
    let pubkey = STANDARD.encode(sk.verifying_key().to_bytes());
    let issued_at = now_ms();
    let preimage = permaura_relay::approver_pairing_preimage(approver_id, &pubkey, issued_at);
    json!({
        "approver_id": approver_id,
        "approver_pubkey": pubkey,
        "issued_at": issued_at,
        "sig": permaura_relay::sign(sk, &preimage),
    })
}

/// Whether this response is the replay floor refusing, rather than any of the other things that can
/// refuse the same request. Matched on the sentence the owner is shown, because the status alone
/// (401) is shared with every other step-up refusal.
fn refused_as_a_replay(status: StatusCode, body: &Value) -> bool {
    status == StatusCode::UNAUTHORIZED
        && body
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|e| e.contains("issued before this gateway was restored from a checkpoint"))
}

/// Wait until a whole-second `auth_time` claim lands strictly above `floor`.
///
/// A ticket carries its re-authentication instant in SECONDS and the floor is milliseconds, so a
/// ticket minted in the same second as the restore presents `auth_time * 1000`, which is at or below
/// the floor, and is refused. In production that costs an owner one retry inside one second; here it
/// would be a flake, so the test waits rather than inventing a future `auth_time`.
async fn past_the_floor_in_whole_seconds(floor: i64) {
    while now_secs() * 1000 <= floor {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// The restore's replay floor doing its job on a FIRST restore, for all four kinds of one-time
/// token, driven through `build_router`.
///
/// The tenant has never been restored, so every checkpoint stamped `pm-replay-floor-ms: none` and
/// `retained.json` carries null: there is nothing to carry forward and the floor is the instant the
/// reconciliation ran. What the four assertions pin is that the floor is not decorative. Each token
/// is presented to the route that spends it, with the `one_time_claims` ledger rolled back exactly
/// as a promotion leaves it, and the floor is the only thing standing between the token and the
/// write it authorises.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_one_time_token_issued_before_a_first_restore_can_be_spent_after_it() {
    let buckets = Buckets::new();
    buckets.provision_open_hold();
    let live = boot(&buckets, None, "tokens-live").await;
    seed::seed(live.store.as_ref()).expect("seeds");

    // A durably paired device. It is what makes a recovery code consumable at all
    // (`with_recovery_code` needs a trusted device) and what makes a vault export hold for a
    // signature, so both of the STORED token kinds below exist only because of it.
    let device = SigningKey::from_bytes(&[23u8; 32]);
    let device_pubkey = STANDARD.encode(device.verifying_key().to_bytes());
    assert!(
        live.state
            .service
            .trust_approver_key_durable("device:tokens-phone", &device_pubkey)
            .expect("the pairing persists"),
        "the device is paired before the checkpoint"
    );

    // Token 3: a recovery code set, minted before the checkpoint, so the snapshot carries it.
    let pre_codes =
        permaura_gateway::recovery::issue(live.store.as_ref(), now_ms()).expect("a code set");

    // Token 4: an approval a human already signed, whose vault-export claim had NOT yet been spent
    // when the checkpoint was taken. Step 5 denies every PENDING approval, so an already-approved
    // one is the approval claim a restore genuinely brings back live.
    let export_approval = |id: &str| PendingApproval {
        id: id.into(),
        // What `hold_vault_export_approval` writes: the gateway's own control-plane path names no session.
        session_id: String::new(),
        capability: "permaura.vault.export".into(),
        resource: "vault".into(),
        message: "Confirm a vault export".into(),
        status: "approved".into(),
        grant_id: None,
        policy_id: None,
        params: json!({ "resume_sha256": permaura_gateway::service::export_resume_digest(DRILL_RESUME_SECRET) }).into(),
        result: None,
        result_status: None,
        resolution_reason: None,
        created_at: now_ms(),
        expires_at: None,
        risk: None,
        action_description: None,
        intent: None,
        required_tier: "device_signed".into(),
        required_signatures: 1,
        signatures: Vec::new(),
        requested_by: None,
    };
    live.store.put_approval(export_approval("appr_export_pre")).expect("the approval is signed");

    let cp = checkpoint(&buckets, "20260922T140000Z", "scheduled");
    assert_eq!(
        cp.stamped.get("pm-replay-floor-ms").map(String::as_str),
        Some("none"),
        "this tenant has never been restored, so there is no floor to stamp and none is invented"
    );
    drop(live);

    // The restore: hold, promote, cold start.
    let restore_began = now_ms();
    let current = buckets
        .holds
        .get(&hold_object(TENANT), buckets.holds.head(&hold_object(TENANT)).unwrap().unwrap())
        .expect("read");
    let held = hold_merge(
        &current,
        &held_patch("hold_tokens", &cp.id, cp.retained_generation, &cp.retained_refreshed_at),
    );
    buckets.write_hold(&hold_object(TENANT), &held);
    let cp_bytes =
        buckets.store.get(&cp.object, buckets.store.head(&cp.object).unwrap().unwrap()).expect("read");
    let generation = buckets.store.head(DEFAULT_OBJECT).unwrap().expect("live");
    buckets
        .store
        .put_if_generation(DEFAULT_OBJECT, &cp_bytes, generation, &cp.stamped)
        .expect("promote");

    let restored = boot(&buckets, Some("hold_tokens"), "tokens-restored").await;
    let record = reconcile::run_at_boot(&restored.state.service).expect("runs").expect("a restore");
    let floor = record.replay_floor_ms.expect("a first restore sets a floor");
    assert!(floor >= restore_began, "and it is the restore's own instant: {floor}");
    assert_eq!(record.replay_floor_source.as_deref(), Some("restore_time"));
    drop(restored);

    // The hold is lifted, which is the moment these tokens would be presented: an owner has
    // reconciled, execution is back, and somebody still holds credentials minted before any of it.
    let current = buckets
        .holds
        .get(&hold_object(TENANT), buckets.holds.head(&hold_object(TENANT)).unwrap().unwrap())
        .expect("read");
    let reopened = hold_merge(&current, &open_patch("cp-restorer", "reconciled"));
    buckets.write_hold(&hold_object(TENANT), &reopened);
    let free = boot(&buckets, None, "tokens-free").await;
    assert!(free.state.service.refuse_if_held().is_ok(), "both layers read open");
    let op = operator_bearer(free.store.as_ref(), "sess_op_tokens", "tok_op_tokens");

    // The ledger really is rolled back: nothing here is refused because it was already spent.
    assert!(
        free.store.claim_once("proof", "the-ledger-is-empty", i64::MAX).expect("claim"),
        "a restore brings back an empty one_time_claims table, which is the whole hazard"
    );

    // ── 1. an approval claim ────────────────────────────────────────────────────────────────────
    // The vault-export claim. `resolve_approval` takes the same floor against the same
    // `approval.created_at`, but every PENDING approval was denied by step 5 and returns before it;
    // an approval a human already signed is the one a restore really does hand back unclaimed.
    let resp = app(&free)
        .oneshot(request(
            "POST",
            "/v1/vault/export",
            &op,
            json!({ "passphrase": "correct horse battery staple", "approval_id": "appr_export_pre", "resume_secret": DRILL_RESUME_SECRET }),
        ))
        .await
        .unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert!(
        refused_as_a_replay(status, &body),
        "a signature given before the restore cannot produce a second complete copy of the vault: {status} {body}"
    );
    assert!(
        free.store
            .get_approval("appr_export_pre")
            .expect("read")
            .expect("the row came back with the snapshot")
            .result
            .is_none(),
        "and the claim was never burned, so nothing records an export that did not happen"
    );

    free.store.put_approval(export_approval("appr_export_post")).expect("signed after the restore");
    let resp = app(&free)
        .oneshot(request(
            "POST",
            "/v1/vault/export",
            &op,
            json!({ "passphrase": "correct horse battery staple", "approval_id": "appr_export_post", "resume_secret": DRILL_RESUME_SECRET }),
        ))
        .await
        .unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert!(!refused_as_a_replay(status, &body), "an approval signed after it is spendable: {status} {body}");
    assert_eq!(
        free.store
            .get_approval("appr_export_post")
            .expect("read")
            .expect("the row")
            .result
            .and_then(|r| r.to_value_unbounded().get("vault_export").and_then(Value::as_str).map(str::to_string)),
        Some("consumed".to_string()),
        "and its claim was burned, which is what the floor let through"
    );
    // ── 2. a step-up ticket ─────────────────────────────────────────────────────────────────────
    let stale = floor_ticket("tkt-floor-pre", floor / 1000 - 1);
    let resp = hosted_app(&free)
        .oneshot(request_with(
            "PUT",
            "/v1/approval-floor",
            &op,
            json!({ "floor": "approve" }),
            &[("x-permaura-pairing-ticket", stale.as_str())],
        ))
        .await
        .unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert!(
        refused_as_a_replay(status, &body),
        "a step-up ticket whose re-authentication predates the restore is refused: {status} {body}"
    );

    past_the_floor_in_whole_seconds(floor).await;
    let fresh = floor_ticket("tkt-floor-post", now_secs());
    let resp = hosted_app(&free)
        .oneshot(request_with(
            "PUT",
            "/v1/approval-floor",
            &op,
            json!({ "floor": "approve" }),
            &[("x-permaura-pairing-ticket", fresh.as_str())],
        ))
        .await
        .unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert!(!refused_as_a_replay(status, &body), "and one re-authenticated after it is not: {status} {body}");
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "it was spent and the lowering is now waiting on the co-signature this keyring requires: {body}"
    );

    // ── 3. a pairing ticket ─────────────────────────────────────────────────────────────────────
    let newcomer = SigningKey::from_bytes(&[24u8; 32]);
    let newcomer_pubkey = STANDARD.encode(newcomer.verifying_key().to_bytes());
    let stale =
        pair_ticket("tkt-pair-pre", "device:newcomer", &newcomer_pubkey, floor / 1000 - 1);
    let resp = hosted_app(&free)
        .oneshot(request_with(
            "POST",
            "/v1/approver-keys/pair",
            &op,
            pair_body("device:newcomer", &newcomer),
            &[("x-permaura-pairing-ticket", stale.as_str())],
        ))
        .await
        .unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert!(
        refused_as_a_replay(status, &body),
        "a pairing ticket from before the restore reaches no keyring: {status} {body}"
    );
    assert!(
        !free.state.service.approver_key_trusted("device:newcomer"),
        "and nothing was enrolled"
    );

    let fresh = pair_ticket("tkt-pair-post", "device:newcomer", &newcomer_pubkey, now_secs());
    let resp = hosted_app(&free)
        .oneshot(request_with(
            "POST",
            "/v1/approver-keys/pair",
            &op,
            pair_body("device:newcomer", &newcomer),
            &[("x-permaura-pairing-ticket", fresh.as_str())],
        ))
        .await
        .unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert!(!refused_as_a_replay(status, &body), "and one minted after it is not: {status} {body}");
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "it was spent and the enrolment is now waiting on the co-signature this keyring requires: {body}"
    );

    // ── 4. a recovery code claim ────────────────────────────────────────────────────────────────
    // Loopback, because a hosted worker takes no recovery codes at all: this is the self-run and
    // tunnelled path, and the code set is the one the snapshot brought back with every code unspent.
    let resp = app(&free)
        .oneshot(request_with(
            "PUT",
            "/v1/approval-floor",
            &op,
            json!({ "floor": "approve" }),
            &[(permaura_gateway::recovery::RECOVERY_CODE_HEADER, pre_codes[0].as_str())],
        ))
        .await
        .unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert!(
        refused_as_a_replay(status, &body),
        "a recovery code set issued before the restore is dead, however unspent its rows look: {status} {body}"
    );

    let post_codes =
        permaura_gateway::recovery::issue(free.store.as_ref(), now_ms()).expect("a fresh set");
    let resp = app(&free)
        .oneshot(request_with(
            "PUT",
            "/v1/approval-floor",
            &op,
            json!({ "floor": "approve" }),
            &[(permaura_gateway::recovery::RECOVERY_CODE_HEADER, post_codes[0].as_str())],
        ))
        .await
        .unwrap();
    let status = resp.status();
    let body = body_json(resp).await;
    assert!(!refused_as_a_replay(status, &body), "and a set reissued after it is not: {status} {body}");
    assert_eq!(
        status,
        StatusCode::OK,
        "a set reissued after the restore works, which is what the owner has to do: {body}"
    );

}

// ══ the cross-repo checks ═══════════════════════════════════════════════════════════════════════

/// The in-tree reimplementation of `hold_merge` and `manifest_json` has to produce what the hosted
/// scripts produce, byte for byte, or the fallback this drill uses in core CI is drilling a fiction.
///
/// Skipped with a message when the hosted repository is not reachable, which is the only honest
/// thing a cross-repository check can do from inside one of them.
#[test]
fn the_in_tree_writers_still_agree_with_the_hosted_scripts() {
    announce_hosted_mode();
    let Some(_) = hosted_scripts() else {
        eprintln!("the hosted scripts are not reachable: nothing to compare against");
        return;
    };
    let cases: &[(&[u8], Value)] = &[
        (b"", json!({ "tenant": TENANT, "state": "open", "hold_id": Value::Null })),
        (
            b"{\"hold_version\":1,\"state\":\"open\",\"tenant\":\"drill-acme\"}",
            json!({ "state": "held", "hold_id": "hold_x", "checkpoint_id": "cp_x",
                    "retained_ref": { "object": "holds/drill-acme/retained.json", "generation": "17", "refreshed_at": "2026-09-22T00:00:00Z" } }),
        ),
        (b"not json at all", json!({ "state": "reconciling" })),
    ];
    for (current, patch) in cases {
        let real = hosted_bash("hold_merge", &[("HOLD_PATCH", &patch.to_string())], &String::from_utf8_lossy(current));
        let ours = String::from_utf8(in_tree_hold_merge(current, patch)).expect("utf8");
        assert_eq!(real, ours, "hold_merge has drifted for patch {patch}");
    }

    let lines = "manifest_version=1\ntenant=drill-acme\nstore.commit_seq=41\nstore.approval_floor=none\naudit.head_seq=\nkeys.vault_kek.escrowed=false\n";
    let real: Value = serde_json::from_str(&hosted_bash("manifest_json", &[], lines)).expect("json");
    assert_eq!(real["store"]["commit_seq"], json!(41), "digits become numbers");
    assert_eq!(real["store"]["approval_floor"], json!("none"), "and `none` stays the statement it is");
    assert_eq!(real["audit"]["head_seq"], Value::Null, "while absent is null");
    assert_eq!(real["keys"]["vault_kek"]["escrowed"], json!(false));
}

/// The manifest field mapping, which is what decides where every stamped fact lands. A key added or
/// moved in `manifest.sh` and not here means this drill is writing a manifest no restore tool reads.
#[test]
fn the_manifest_field_mapping_has_not_drifted() {
    announce_hosted_mode();
    let Some(_) = hosted_scripts() else {
        eprintln!("the hosted scripts are not reachable: the in-tree copy cannot be checked");
        return;
    };
    let real = hosted_bash("checkpoint_metadata_keys", &[], "");
    assert_eq!(
        real.trim(),
        IN_TREE_METADATA_KEYS.trim(),
        "checkpoint_metadata_keys has moved in the hosted repository; update IN_TREE_METADATA_KEYS"
    );
}

/// The documents this drill writes have to be the documents the gateway's own fixtures were written
/// by, key for key. The fixtures came from the hosted scripts; this is what stops the
/// drill from quietly agreeing with itself about a shape nothing hosted produces.
#[test]
fn the_documents_this_drill_writes_match_the_hosted_fixtures() {
    let fixture = |name: &str| -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/hold").join(name);
        serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display())))
            .expect("the fixture is JSON")
    };
    let keys = |v: &Value| -> Vec<String> {
        v.as_object().expect("object").keys().cloned().collect()
    };

    let open = serde_json::from_slice::<Value>(&in_tree_hold_merge(b"", &open_patch("who", "why"))).expect("json");
    assert_eq!(keys(&open), keys(&fixture("state-open.json")), "the open document");

    let held = serde_json::from_slice::<Value>(&in_tree_hold_merge(
        &in_tree_hold_merge(b"", &open_patch("who", "why")),
        &held_patch("hold_x", "cp_x", 17, "2026-09-22T00:00:00Z"),
    ))
    .expect("json");
    let held_fixture = fixture("state-held.json");
    for key in keys(&held_fixture) {
        assert!(held.get(&key).is_some(), "the held document is missing `{key}`");
    }
    assert_eq!(
        keys(&held["retained_ref"]),
        keys(&held_fixture["retained_ref"]),
        "and its retained_ref block"
    );

    let mut stamped = BTreeMap::new();
    stamped.insert("pm-audit-epoch".to_string(), "0".to_string());
    stamped.insert("pm-audit-head-seq".to_string(), "100987".to_string());
    stamped.insert("pm-audit-head-hash".to_string(), "c71e".to_string());
    stamped.insert("pm-commit-seq".to_string(), "91801".to_string());
    stamped.insert("pm-approval-floor".to_string(), "device_signed".to_string());
    stamped.insert("pm-replay-floor-ms".to_string(), "1758376682117".to_string());
    let retained =
        serde_json::from_slice::<Value>(&in_tree_hold_merge(b"", &retained_patch(&stamped, "2026-09-22T00:00:00Z")))
            .expect("json");
    let retained_fixture = fixture("retained-floors.json");
    assert_eq!(keys(&retained["retained"]), keys(&retained_fixture["retained"]));
    assert_eq!(retained["retained"]["pre_restore_audit_head_seq"], json!(100_987), "digits are numbers");
    assert_eq!(retained["retained"]["approval_floor"], json!("device_signed"));
    assert_eq!(retained["retained"]["replay_floor_ms"], json!(1_758_376_682_117i64));

    // The two nothings, which `write_retained` keeps apart and a reader must not collapse.
    let mut none_stamped = BTreeMap::new();
    none_stamped.insert("pm-audit-head-seq".to_string(), "none".to_string());
    none_stamped.insert("pm-approval-floor".to_string(), "none".to_string());
    let with_none =
        serde_json::from_slice::<Value>(&in_tree_hold_merge(b"", &retained_patch(&none_stamped, "x"))).expect("json");
    assert_eq!(
        with_none["retained"]["pre_restore_audit_head_seq"],
        json!("none"),
        "a gateway looked and there was nothing there"
    );
    assert_eq!(
        with_none["retained"]["approval_floor"],
        Value::Null,
        "but no floor cannot take part in a maximum, so the typed field is null"
    );
    assert_eq!(
        with_none["retained"]["pre_restore_commit_seq"],
        Value::Null,
        "and an absent key is a third nothing: no gateway stamped it"
    );
}
