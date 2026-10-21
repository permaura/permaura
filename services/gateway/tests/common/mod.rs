//! Shared setup for the gateway's integration tests.
#![allow(dead_code)]

pub mod synthetic_oauth;

use permaura_gateway::store::{Session, SessionRole};
use permaura_gateway::AppState;

/// [`permaura_gateway::build_router`] with this binary's vault bundle requests taking turns. The gateway derives one bundle key at a time per process (`vault_bundle::BUNDLE_KDF`) and answers a seal or open still waiting after 15 s with a 429, a gate sized for one gateway that every test in a binary shares, so on a loaded machine bundle tests queued past it and failed with 429 where they assert something else. `bundle_open_gate.rs` tests that gate and builds the gateway's own router.
pub fn build_router(state: AppState, bind_addr: std::net::SocketAddr) -> axum::Router {
    permaura_gateway::build_router(state, bind_addr).layer(axum::middleware::from_fn(bundle_turn))
}

static BUNDLE_ROUTES: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn bundle_turn(req: axum::extract::Request, next: axum::middleware::Next) -> axum::response::Response {
    let path = req.uri().path();
    let _turn = if path.starts_with("/v1/vault/export") || path.starts_with("/v1/vault/import") {
        Some(BUNDLE_ROUTES.lock().await)
    } else {
        None
    };
    next.run(req).await
}

/// Cut this test binary off from the machine's real Permaura install, before anything resolves a
/// path or a key. Every fixture in the suite goes through it.
///
/// Two halves, and the suite needs both:
///
/// - **`PERMAURA_DEV=1`.** `vault_passphrase()` takes its dev path on `cfg!(test)`, and that is
///   FALSE inside the library when the library is compiled as a dependency of an *integration*
///   test: the `cfg` belongs to the crate being compiled, and here that is the test binary, not the
///   library. So without it every test resolves REAL per-install custody: it mints a KEK into a
///   machine that has none, and on a machine whose gateway has adopted into the OS credential store
///   it refuses to start outright, because an ad-hoc test binary cannot prove the code identity the
///   Keychain ACL wants. Both were observed; the second took out 64 tests across four binaries the
///   day the published gateway was first signed.
/// - **`PERMAURA_HOME`, pointed at a scratch directory.** The KEK is not the only thing under the
///   home: the store path, `operator.token`, `config.toml`, the relay worker key and the
///   credential-store marker all resolve through `permaura_core::permaura_home()`. The dev signal
///   on its own is also a race with the clock rather than a guarantee, because it only counts if it
///   lands before the `OnceLock` that caches the KEK: `audit_archive.rs` opened its SQLite store
///   without it and panicked on `~/.permaura/vault-kek.in-os-store` whenever its fixture ran first,
///   which is how a suite that is green on CI became one that could not be run at all on a machine
///   with a real gateway on it. A pinned home makes that failure impossible rather than unlikely.
///
/// Set ONCE per binary and never restored, which is the whole of the concurrency design here. The
/// variables are process-global and the suite runs in parallel, so a helper that set a value and
/// put the old one back would hand every other thread a window in which the home is the real one.
/// `crates/permaura-credential-store/src/lib.rs` records what that window costs: "a suite that
/// raced `PERMAURA_HOME` deleted a live vault KEK with it". One value for the life of the process
/// cannot race, so a test needing isolation from its neighbours buys it with a scratch *store path*
/// of its own, as every fixture here already does, and never with a home of its own.
///
/// Whatever `PERMAURA_HOME` held on the way in is overwritten rather than honoured. The suite owns
/// its home: one rule with no branches, and [`assert_isolated`] then has one thing to check.
///
/// Call it before the first `AppState` or store. `seeded()` and the fixtures do that for you.
pub fn isolate_from_the_real_install() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::env::set_var("PERMAURA_DEV", "1");
        // The OS temp directory rather than `CARGO_TARGET_TMPDIR`, because the guard below refuses
        // any home under the user's own directory and a checkout normally lives in one.
        let scratch = std::env::temp_dir().join(format!("permaura-test-home-{}", std::process::id()));
        std::fs::create_dir_all(&scratch).expect("a scratch Permaura home");
        std::env::set_var("PERMAURA_HOME", &scratch);
    });
    assert_isolated();
}

/// Panic, naming what it found, if this process would resolve the developer's own install.
///
/// Checked on every call rather than once inside the `Once`, because the regression worth catching
/// is not "the pin was never made" but "something moved it afterwards", and only a check that runs
/// after the move can see that.
///
/// The refusal is deliberately wider than `~/.permaura`: ANY home under the user's home directory
/// fails. A scratch home is in the OS temp directory, so nothing legitimate is refused, and the
/// narrower rule (refuse only the exact default) would let `PERMAURA_HOME=$HOME/.permaura-test`
/// through to sit beside a live install and be reached by the next thing that globs.
pub fn assert_isolated() {
    let pinned = std::env::var_os("PERMAURA_HOME").filter(|v| !v.is_empty()).unwrap_or_else(|| {
        panic!(
            "PERMAURA_HOME is unset, so this test resolves the machine's REAL Permaura home: its \
             store, its operator token and its vault KEK. Call \
             common::isolate_from_the_real_install() in the fixture before opening anything."
        )
    });
    let resolved = permaura_core::permaura_home().expect("PERMAURA_HOME is set, so a home resolves");
    assert_eq!(
        resolved,
        std::path::PathBuf::from(&pinned),
        "PERMAURA_HOME and the home that resolves from it disagree"
    );
    if let Some(user_home) = real_user_home() {
        assert!(
            !resolved.starts_with(&user_home),
            "this test resolves {} as the Permaura home, and that is inside the user's own home \
             directory ({}). A test home belongs in the OS temp directory: a real install lives \
             here, and a suite has already destroyed one.",
            resolved.display(),
            user_home.display(),
        );
    }
}

/// The user's home directory as `permaura_home()`'s fallback would read it: `dirs::home_dir()` is
/// `$HOME` on Unix and the profile on Windows. Read from the environment because this crate has no
/// `dirs` dependency of its own and a guard does not earn one.
fn real_user_home() -> Option<std::path::PathBuf> {
    let key = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var_os(key).filter(|v| !v.is_empty()).map(std::path::PathBuf::from)
}

/// The seeded in-memory state every integration test wants, already cut off from the real install.
pub fn seeded() -> AppState {
    isolate_from_the_real_install();
    AppState::in_memory_seeded()
}

/// The same estate with an execution hold attached.
///
/// Assembled here rather than through `AppState::in_memory_seeded` because the hold is a property
/// of the service, and a test must be able to hand it one it built itself: reading it from the
/// environment would make one test's hold every other test's, since the variables are process-wide
/// and the suite runs in parallel.
pub fn seeded_with_hold(hold: std::sync::Arc<permaura_gateway::restore::ExecutionHold>) -> AppState {
    isolate_from_the_real_install();
    let store: std::sync::Arc<dyn permaura_gateway::store::Store> =
        std::sync::Arc::new(permaura_gateway::store::memory::MemoryStore::new());
    permaura_gateway::seed::seed(store.as_ref()).expect("the demo estate seeds");
    let http = std::sync::Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    AppState::new(
        permaura_gateway::service::EnforcementService::new(store, http)
            .with_execution_hold(hold),
    )
}

/// The same estate with a hot-audit ceiling the test chose.
///
/// For the same reason as [`seeded_with_hold`]: `PERMAURA_AUDIT_HOT_CEILING` is process-wide and
/// the suite runs in parallel, so a test that set it would set it for every other test in the
/// binary. The builder is how a test gets a ceiling of its own.
pub fn seeded_with_audit_ceiling(
    ceiling: std::sync::Arc<permaura_gateway::audit_ceiling::AuditCeiling>,
) -> AppState {
    isolate_from_the_real_install();
    let store: std::sync::Arc<dyn permaura_gateway::store::Store> =
        std::sync::Arc::new(permaura_gateway::store::memory::MemoryStore::new());
    permaura_gateway::seed::seed(store.as_ref()).expect("the demo estate seeds");
    let http = std::sync::Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    AppState::new(
        permaura_gateway::service::EnforcementService::new(store, http)
            .with_audit_ceiling(ceiling),
    )
}

/// The same estate with plan allowances the test chose.
///
/// For the same reason as [`seeded_with_hold`]: `PERMAURA_LIMIT_MAX_*` is process-wide and the suite
/// runs in parallel, so a test that set one would set it for every other test in the binary.
pub fn seeded_with_allowances(
    allowances: std::sync::Arc<permaura_gateway::allowances::Allowances>,
) -> AppState {
    isolate_from_the_real_install();
    let store: std::sync::Arc<dyn permaura_gateway::store::Store> =
        std::sync::Arc::new(permaura_gateway::store::memory::MemoryStore::new());
    permaura_gateway::seed::seed(store.as_ref()).expect("the demo estate seeds");
    let http = std::sync::Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    AppState::new(
        permaura_gateway::service::EnforcementService::new(store, http)
            .with_allowances(allowances),
    )
}

/// A state whose store is a real SQLite file and whose archive is one the test built.
///
/// A file store rather than `:memory:`, because a prune re-signs the boundary and a store with no
/// persisted audit key refuses to. The archive is passed in for the reason
/// [`seeded_with_audit_ceiling`] takes a ceiling: `PERMAURA_AUDIT_ARCHIVE*` is process-wide.
#[cfg(feature = "sqlite")]
pub fn seeded_with_archive(
    path: &str,
    archive: std::sync::Arc<permaura_gateway::archive::AuditArchive>,
) -> AppState {
    isolate_from_the_real_install();
    let store: std::sync::Arc<dyn permaura_gateway::store::Store> =
        std::sync::Arc::new(permaura_gateway::store::sqlite::SqliteStore::open(path).expect("store opens"));
    permaura_gateway::seed::seed(store.as_ref()).expect("the demo estate seeds");
    let http = std::sync::Arc::new(permaura_gateway::connectors::MockHttpClient::new());
    AppState::new(
        permaura_gateway::service::EnforcementService::new(store, http).with_audit_archive(archive),
    )
}

/// An operator bearer for a seeded state.
///
/// Written straight to the store rather than posted to `/v1/sessions`, because that route is itself
/// operator-authenticated: a test cannot bootstrap through it without already holding the thing it
/// is trying to obtain.
///
/// Needed by any test reading a route that distinguishes an authenticated caller from a stranger.
/// `/health` does now: its full document fingerprints the build, so only a caller that can prove
/// who it is gets more than liveness.
pub async fn operator_token(state: AppState) -> String {
    let token = "tok_test_operator".to_string();
    state
        .service
        .store()
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: "sess_test_operator".into(),
            agent_id: "operator".into(),
            user_id: None,
            device_id: None,
            token: token.clone(),
            role: SessionRole::Operator,
            created_at: 0,
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .expect("seeded store accepts a session");
    token
}

/// The seeded estate, taking the device signatures approver apps made before the audience and the
/// display binding: v1 signatures, and approves that bind no rendering. The gateway refuses both by
/// default; this is for suites about something else (a quorum, the relay framing) whose
/// fixtures sign that way, so a refusal they assert is still the one they mean.
pub fn seeded_accepting_legacy_signatures() -> AppState {
    let state = seeded();
    state.service.set_accept_v1_device_signatures(true);
    state.service.set_require_display_bound_approvals(false);
    state
}

/// File the seeded connection behind `capability` as an imported one, for a fixture that re-points a seeded GitHub or Braintree capability at a local upstream: a connection of a family the gateway pins to a fixed host sends its credential to that host only.
pub fn file_as_imported(store: &dyn permaura_gateway::store::Store, capability: &str) {
    let cap = store.get_capability(capability).unwrap().expect("the seeded capability");
    let mut connection = store.get_connection(&cap.resource).unwrap().expect("the seeded connection");
    connection.connector = "openapi".into();
    store.put_connection(connection).unwrap();
}
