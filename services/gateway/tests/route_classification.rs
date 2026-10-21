//! Every route `build_router` owns must have a stated auth class, and the code must agree with it.
//!
//! This exists for one failure class, and it is the one with the worst record: an authz boundary
//! regression from a handler a sweep missed. One was four `/v1` handlers using `authed` where they
//! needed `operator_authed`: four of eight, so every spot check passed. Another was operator writes
//! accepting a garbage token. A third published an Operator bearer on a public URL.
//!
//! The tempting fix (a nightly script that walks a list of endpoints) reproduces the bug inside the
//! checker: the list is hand-maintained, so the handler nobody classified is also the handler nobody
//! added to the list. So the table below is checked **both ways** against the route table itself:
//! a new route with no entry fails, and an entry for a route that no longer exists fails too.
//!
//! Then each entry is checked against what the handler actually does, statically (does it call the
//! guard its class implies) and, where a route takes no body, behaviourally through the real router.
//! Stating a class is therefore a claim the suite verifies, not a comment.
//!
//! **Adding a route?** Add its `(method, path)` here with the class you intend, then make the handler
//! call the matching guard. There is no way to merge one without saying what it is.

use std::sync::LazyLock;
use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_gateway::store::{Session, SessionRole};
use common::build_router;
use permaura_gateway::AppState;
use tower::ServiceExt;

/// What a caller must present to reach a route.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Class {
    /// No credential at all. Every one of these is a deliberate, argued exception.
    Open,
    /// Answers everyone, but says less to a stranger. `/health` is the case: liveness has to stay
    /// reachable for an uptime probe, while the fields that fingerprint the install (version, build,
    /// whether it is behind, how much is on it) sit behind a session. Distinct from `Open` because
    /// the handler does call a guard, and an entry claiming otherwise would make the static check
    /// below read a deliberate gate as a mistake.
    OpenNarrowedWithoutAuth,
    /// Any live session: an agent token is enough. The agent plane: invoke, and the reads an agent
    /// needs to know what it may invoke.
    AgentAllowed,
    /// An **operator** session. Agent tokens are refused with 403, which is the gate that stops a
    /// self-enrolled agent approving itself or granting itself access.
    OperatorOnly,
    /// The **restoration operator**: a permaura.com token whose `sub` equals `PERMAURA_OWNER_SUB`,
    /// and deliberately not a session of any kind.
    ///
    /// Its own class rather than `OperatorOnly`, because the difference is the whole argument. Every
    /// session in a restored database is one a restore rolled back, so an operator session is
    /// exactly what must NOT be able to confirm restored authority; the authority has to live
    /// outside the tenant database, which is what the OAuth subject does. A route here that started
    /// calling `operator_authed` would be a working route and a defeated control.
    RestorationOperator,
    /// `/mcp` carries its own JSON-RPC-level authentication (opaque session token, or a
    /// permaura.com-issued access token once the OAuth RS is armed), decided per method inside the
    /// handler rather than by a guard at the top. Called out rather than folded into `AgentAllowed`
    /// so nobody reads a missing `authed(` in `mcp.rs` as a gap.
    McpJsonRpc,
}

/// One route, and what reaching it requires.
struct Route {
    method: &'static str,
    path: &'static str,
    class: Class,
    /// Additionally refused when the request arrives from off-host (`reject_if_remote`). This is the
    /// credential-free operator plane: it is safe only because a remote caller cannot reach it, so
    /// losing the flag is a critical regression rather than a tightening.
    loopback_only: bool,
    /// Why, for the classes where the answer is not obvious. Read by a human, not by the test.
    #[allow(dead_code)]
    note: &'static str,
}

const fn r(method: &'static str, path: &'static str, class: Class) -> Route {
    Route { method, path, class, loopback_only: false, note: "" }
}

const fn loopback(method: &'static str, path: &'static str, class: Class, note: &'static str) -> Route {
    Route { method, path, class, loopback_only: true, note }
}

const fn open(method: &'static str, path: &'static str, note: &'static str) -> Route {
    Route { method, path, class: Class::Open, loopback_only: false, note }
}

use Class::{AgentAllowed as AGENT, McpJsonRpc as MCP, OperatorOnly as OP};

mod common;

#[rustfmt::skip]
const ROUTES: &[Route] = &[
    Route { method: "GET", path: "/health", class: Class::OpenNarrowedWithoutAuth, loopback_only: false,
            note: "Liveness for anyone; the health document (version, build, counts, postures) only for a caller holding a session. `/health` and not `/healthz`, which Google's frontend intercepts on Cloud Run." },
    open("GET", "/", "The landing page a browser gets on the gateway itself. Says only that a gateway is here (never the version, build or counts `/health` withholds from an anonymous caller) and links the console."),
    open("GET", "/oauth/callback", "The provider redirects a browser here. The unguessable, single-use, expiring `state` minted by an operator-authed `start` is what authenticates it."),
    open("GET", "/.well-known/oauth-protected-resource", "OAuth RS discovery. Public by specification."),
    open("GET", "/.well-known/oauth-protected-resource/mcp", "OAuth RS discovery. Public by specification."),
    open("GET", "/.well-known/oauth-authorization-server", "Redirect to the AS metadata. Public by specification."),
    open("GET", "/.well-known/openid-configuration", "Redirect to the AS metadata. Public by specification."),

    // The credential-free operator plane. This mints an OPERATOR bearer to whoever asks, so the
    // loopback refusal is the entire control: a public tunnel in front of this without it was a live
    // critical hole.
    loopback("POST", "/v1/sessions", Class::OperatorOnly, "Mints an operator bearer. Loopback-only AND operator-authed: it used to be credential-free, resting entirely on the loopback guard, which is how an operator bearer was once published on a public URL. Both are now required, so reclassifying this down to Open would describe the route as it was when it was the hole."),

    r("GET", "/v1/capabilities", AGENT),
    r("GET", "/v1/agents", AGENT),
    r("GET", "/v1/connections/:id", AGENT),
    r("GET", "/v1/broker", AGENT),
    r("POST", "/v1/invoke", AGENT),
    r("POST", "/mcp", MCP),

    r("GET", "/v1/sessions", OP),
    r("POST", "/v1/sessions/:id/revoke", OP),
    r("DELETE", "/v1/agents/:id", OP),
    r("PUT", "/v1/agents/:id", OP),
    r("POST", "/v1/grants", OP),
    r("GET", "/v1/grants", OP),
    r("PUT", "/v1/grants/:id", OP),
    r("PATCH", "/v1/grants/:id", OP),
    r("DELETE", "/v1/grants/:id", OP),
    r("POST", "/v1/grants/rebuild-usage", OP),
    r("GET", "/v1/grants/:id/usage", OP),
    r("GET", "/v1/audit/verify-full", OP),
    r("GET", "/v1/audit/export", OP),
    r("POST", "/v1/secrets", OP),
    r("GET", "/v1/secrets", OP),
    r("DELETE", "/v1/secrets/:id", OP),
    r("POST", "/v1/secrets/:id/rotate", OP),
    r("GET", "/v1/connections", OP),
    r("POST", "/v1/connections", OP),
    r("POST", "/v1/connections/import-openapi", OP),
    r("GET", "/v1/presets", OP),
    r("POST", "/v1/connections/from-preset", OP),
    r("POST", "/v1/connections/discover", OP),
    r("POST", "/v1/connections/import-wordpress", OP),
    r("POST", "/v1/connections/:id/resync", OP),
    r("POST", "/v1/connections/:id/oauth/start", OP),
    r("PATCH", "/v1/connections/:id", OP),
    r("DELETE", "/v1/connections/:id", OP),
    r("POST", "/v1/connections/:id/credential", OP),
    r("POST", "/v1/connections/:id/capabilities", OP),
    r("POST", "/v1/connections/:id/capability-posture", OP),
    r("POST", "/v1/connectors/install", OP),
    r("GET", "/v1/connectors/installed", OP),
    r("DELETE", "/v1/connectors/:id", OP),
    r("GET", "/v1/policies", OP),
    r("POST", "/v1/policies", OP),
    r("PUT", "/v1/policies/:id", OP),
    r("DELETE", "/v1/policies/:id", OP),
    r("POST", "/v1/broker/pause", OP),
    r("POST", "/v1/broker/require-approval", OP),
    r("POST", "/v1/approvals", OP),
    r("GET", "/v1/approvals", OP),
    r("GET", "/v1/approvals/:id", OP),
    r("GET", "/v1/audit-events", OP),
    r("DELETE", "/v1/audit/diagnostics", OP),
    r("POST", "/v1/vault/export", OP),
    r("POST", "/v1/vault/import/preview", OP),
    r("POST", "/v1/vault/import", OP),
    r("POST", "/v1/devices/enroll", OP),
    r("GET", "/v1/devices", OP),
    r("DELETE", "/v1/devices/:id", OP),
    r("POST", "/v1/devices/push-token", OP),
    r("GET", "/v1/approver-keys", OP),
    r("POST", "/v1/approver-keys/pair", OP),
    r("DELETE", "/v1/approver-keys/:approver_id", OP),
    r("PUT", "/v1/approval-floor", OP),
    r("GET", "/v1/announce", OP),
    r("PUT", "/v1/announce", OP),
    r("DELETE", "/v1/announce", OP),
    r("GET", "/v1/recovery", OP),
    r("POST", "/v1/recovery-codes", OP),
    r("GET", "/v1/recovery/reconciliation", Class::RestorationOperator),
    r("POST", "/v1/recovery/reconciliation/confirm", Class::RestorationOperator),
    r("POST", "/v1/recovery/reconciliation/remove", Class::RestorationOperator),
    r("POST", "/v1/recovery/reconciliation/confirm-all", Class::RestorationOperator),
    r("POST", "/v1/recovery/reconciliation/close", Class::RestorationOperator),
    r("POST", "/v1/agents/register", OP),
    r("POST", "/v1/agents/enroll", OP),
    r("POST", "/v1/agents/:id/approve", OP),

    // Authenticated AND loopback-only: the portable stop path the desktop supervisor and the npm CLI
    // call before a hard kill. A tunnelled caller with a valid operator token must not be able to
    // stop someone's gateway.
    loopback("POST", "/v1/shutdown", OP, "Terminates the process. Operator token plus same-host."),
    loopback("POST", "/v1/remote/disable", OP, "Stops the tunnel connector and refuses permaura.com tokens: a kill switch nothing arriving through the tunnel or permaura.com may pull. Operator token plus same-host."),
];

// ── The route table, read out of the source that owns it ────────────────────────────────────────

/// The gateway's own source, read as text, with line endings normalised.
///
/// Normalised because this suite searches for patterns that pin a newline against a character:
/// `"\n}\n"` is how it finds where `build_router` ends. Git hands a Windows checkout CRLF unless
/// told otherwise, so `}` is followed by `\r` there and the search finds nothing, failing the whole
/// suite on a platform difference that has nothing to do with what it asserts.
///
/// `.gitattributes` pins these files to LF, which fixes it at the source. This is the belt to that
/// braces: a working copy made before that landed still has CRLF on disk, and a test that reads
/// source should not care how the source arrived.
static LIB_SRC: LazyLock<String> = LazyLock::new(|| normalise(include_str!("../src/lib.rs")));
static REST_SRC: LazyLock<String> = LazyLock::new(|| normalise(include_str!("../src/rest.rs")));
static MCP_SRC: LazyLock<String> = LazyLock::new(|| normalise(include_str!("../src/mcp.rs")));

fn normalise(src: &str) -> String {
    src.replace("\r\n", "\n")
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Mounted {
    method: String,
    path: String,
    handler: String,
}

/// `build_router`'s body: from its signature to the next item at column 0. Everything this test
/// asserts is scoped to it, so a `.route(` anywhere else in the crate cannot smuggle an entry in or
/// out.
fn build_router_body() -> &'static str {
    let start = LIB_SRC
        .find("pub fn build_router(")
        .expect("build_router must exist; it is the single source of truth for the route table");
    let rest = &LIB_SRC[start + 1..];
    let end = rest
        .find("\n}\n")
        .expect("build_router must be a well-formed item ending at column 0");
    &rest[..end]
}

/// Every `(method, path, handler)` `build_router` mounts.
///
/// Lexical on purpose. The alternative (asking the built `Router`) is not available (axum exposes
/// no route iteration), and a hand-kept second list is the very thing this test refuses to trust.
fn mounted_routes() -> Vec<Mounted> {
    let body = build_router_body();
    let mut out = Vec::new();
    let mut rest = body;
    while let Some(i) = rest.find(".route(") {
        rest = &rest[i + ".route(".len()..];
        let (path, after) = string_literal(rest).unwrap_or_else(|| {
            panic!(
                "a `.route(` in build_router is not followed by a string-literal path. Every route \
                 must be a literal so this test can see it; a computed path cannot be classified. \
                 Near: {:?}",
                &rest[..rest.len().min(120)]
            )
        });
        let expr = balanced_to_close(after);
        let mut verbs = method_handlers(expr);
        assert!(
            !verbs.is_empty(),
            "no method handler found for route {path:?}; the extractor needs updating for: {expr:?}"
        );
        for (method, handler) in verbs.drain(..) {
            out.push(Mounted { method, path: path.to_string(), handler });
        }
        // Resume *after* this route's closing paren, not inside it: scanning the inner expression
        // again would stop at the first route and leave the whole test asserting nothing.
        rest = &after[expr.len() + 1..];
    }
    assert!(
        out.len() > 40,
        "only {} routes extracted: the extractor has stopped seeing the table, which would make \
         this whole test silently vacuous",
        out.len()
    );
    out
}

/// Read a `"..."` starting at `s`, returning its contents and the text after the closing quote.
/// Route paths contain no escapes, so a plain scan is exact.
fn string_literal(s: &str) -> Option<(&str, &str)> {
    let s = s.trim_start();
    let rest = s.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some((&rest[..end], &rest[end + 1..]))
}

/// The text from `s` up to the paren that closes the `.route(` we are inside.
fn balanced_to_close(s: &str) -> &str {
    let mut depth = 1usize;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return &s[..i];
                }
            }
            _ => {}
        }
    }
    s
}

/// `get(rest::foo).post(rest::bar)` → `[("GET","foo"), ("POST","bar")]`.
fn method_handlers(expr: &str) -> Vec<(String, String)> {
    const VERBS: [&str; 5] = ["get", "post", "put", "patch", "delete"];
    let mut out = Vec::new();
    for (i, _) in expr.match_indices('(') {
        let before = &expr[..i];
        let Some(verb) = VERBS.iter().find(|v| {
            before.ends_with(*v)
                && !before[..before.len() - v.len()]
                    .ends_with(|c: char| c.is_alphanumeric() || c == '_')
        }) else {
            continue;
        };
        let inner = balanced_to_close(&expr[i + 1..]);
        let handler = inner.trim().rsplit("::").next().unwrap_or("").trim().to_string();
        if handler.is_empty() || handler.contains(|c: char| !(c.is_alphanumeric() || c == '_')) {
            continue;
        }
        out.push((verb.to_uppercase(), handler));
    }
    out
}

/// A handler's source: from `fn <name>(` to the next item at column 0. Handlers do not define
/// column-0 items inside themselves, so this is exact, and it never bleeds into the next handler.
fn handler_src(name: &str) -> String {
    for src in [&*REST_SRC, &*MCP_SRC] {
        for marker in [
            format!("\npub async fn {name}("),
            format!("\npub fn {name}("),
            format!("\nasync fn {name}("),
            format!("\nfn {name}("),
        ] {
            if let Some(i) = src.find(&marker) {
                let tail = &src[i + 1..];
                let end = ["\npub async fn ", "\npub fn ", "\nasync fn ", "\nfn ", "\n#[cfg(test)]"]
                    .iter()
                    .filter_map(|m| tail.find(m))
                    .min()
                    .unwrap_or(tail.len());
                return strip_comments(&tail[..end]);
            }
        }
    }
    panic!("handler `{name}` is mounted but its source was not found in rest.rs or mcp.rs");
}

/// Strip comments, so a guard that has been commented out (or merely mentioned in a note) is not
/// mistaken for one that runs. Tracks string literals, because a `//` inside a URL is not a comment
/// and eating the rest of that line could delete a real call.
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let (mut i, mut in_str) = (0usize, false);
    while i < b.len() {
        if in_str {
            if b[i] == b'\\' && i + 1 < b.len() {
                out.push(b[i] as char);
                out.push(b[i + 1] as char);
                i += 2;
                continue;
            }
            if b[i] == b'"' {
                in_str = false;
            }
            out.push(b[i] as char);
            i += 1;
            continue;
        }
        match (b[i], b.get(i + 1)) {
            (b'"', _) => {
                in_str = true;
                out.push('"');
                i += 1;
            }
            (b'/', Some(b'/')) => {
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }
            (b'/', Some(b'*')) => {
                i += 2;
                while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(b.len());
            }
            _ => {
                out.push(b[i] as char);
                i += 1;
            }
        }
    }
    out
}

/// Whether a handler's body calls `authed(...)`, not `operator_authed(...)`, which contains it.
fn calls_authed(src: &str) -> bool {
    src.match_indices("authed(").any(|(i, _)| {
        !src[..i].ends_with(|c: char| c.is_alphanumeric() || c == '_')
    })
}

fn calls_operator_authed(src: &str) -> bool {
    src.contains("operator_authed(")
}

fn calls_restoration_operator(src: &str) -> bool {
    src.contains("restoration_operator(")
}

// ── 1. Completeness ─────────────────────────────────────────────────────────────────────────────

#[test]
fn every_mounted_route_is_classified_and_every_classification_is_mounted() {
    let mounted: BTreeSet<(String, String)> = mounted_routes()
        .into_iter()
        .map(|m| (m.method, m.path))
        .collect();
    let classified: BTreeSet<(String, String)> = ROUTES
        .iter()
        .map(|r| (r.method.to_string(), r.path.to_string()))
        .collect();

    let unclassified: Vec<_> = mounted.difference(&classified).collect();
    assert!(
        unclassified.is_empty(),
        "these routes are mounted by build_router with no stated auth class: {unclassified:#?}\n\
         Add each to ROUTES in this file with the class you intend. A handler nobody classified is \
         exactly how four `/v1` handlers once shipped with the agent guard."
    );

    // The other direction matters just as much: a stale entry is a claim about a route that no
    // longer exists, and it makes the table read as covering more than it does.
    let phantom: Vec<_> = classified.difference(&mounted).collect();
    assert!(
        phantom.is_empty(),
        "these routes are classified here but no longer mounted by build_router: {phantom:#?}"
    );
}

// ── 2. The code agrees with the class ───────────────────────────────────────────────────────────

#[test]
fn each_handler_calls_the_guard_its_class_implies() {
    let mounted = mounted_routes();
    let mut problems = Vec::new();

    for route in ROUTES {
        let Some(m) = mounted
            .iter()
            .find(|m| m.method == route.method && m.path == route.path)
        else {
            continue; // the completeness test owns this failure
        };
        let src = handler_src(&m.handler);
        let (op, any) = (calls_operator_authed(&src), calls_authed(&src));
        let where_ = format!("{} {} → {}", route.method, route.path, m.handler);

        match route.class {
            Class::OperatorOnly if !op => problems.push(format!(
                "{where_}: classified operator-only but never calls operator_authed. This is the \
                 regression this test exists for: an agent token would drive the console."
            )),
            Class::AgentAllowed if op => problems.push(format!(
                "{where_}: classified agent-allowed but calls operator_authed. Either the class or \
                 the guard is wrong; an agent plane route that refuses agents is a silent outage."
            )),
            Class::AgentAllowed if !any => problems.push(format!(
                "{where_}: classified agent-allowed but authenticates nobody."
            )),
            // Expected to call `authed`, and expected not to refuse anyone: both halves are checked
            // behaviourally below, since the static view cannot tell a narrowed answer from a denial.
            Class::OpenNarrowedWithoutAuth if !any => problems.push(format!(
                "{where_}: classified as narrowing without auth but authenticates nobody; then \
                 there is nothing to narrow and it is simply open."
            )),
            Class::RestorationOperator if !calls_restoration_operator(&src) => problems.push(format!(
                "{where_}: classified as needing the restoration operator but never calls \
                 restoration_operator. The authority for confirming restored authority has to be \
                 outside the restored database."
            )),
            Class::RestorationOperator if op || any => problems.push(format!(
                "{where_}: classified as needing the restoration operator but also accepts a \
                 session. A session in a restored database is one the restore rolled back, so \
                 accepting one undoes the whole bootstrap argument."
            )),
            Class::Open if op || any => problems.push(format!(
                "{where_}: classified open but calls an auth guard. Reclassify it: an entry that \
                 understates what a route requires is how a working route reads as a hole."
            )),
            _ => {}
        }

        if route.loopback_only && !src.contains("reject_if_remote") {
            problems.push(format!(
                "{where_}: classified loopback-only but never calls reject_if_remote. Losing that \
                 call on a credential-free route is how an operator bearer became mintable over a \
                 public tunnel."
            ));
        }
        if !route.loopback_only && src.contains("reject_if_remote") {
            problems.push(format!(
                "{where_}: calls reject_if_remote but is not marked loopback_only here. Say so: a \
                 remote caller silently losing an endpoint is a support ticket nobody can diagnose."
            ));
        }
    }

    assert!(problems.is_empty(), "auth class does not match the code:\n  {}", problems.join("\n  "));
}

// ── 3. And the router really behaves that way ───────────────────────────────────────────────────

/// A live session whose role is Agent, alongside the seeded operator. The seeded demo session is an
/// *operator*; using it to probe the operator gate would prove nothing.
const AGENT_TOKEN: &str = "route-class-agent-token";

fn state_with_agent() -> AppState {
    let state = common::seeded();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0);
    state
        .service
        .store()
        .put_session(Session {
            class: Default::default(),
            opened_by: None,
            id: "sess_route_class_agent".into(),
            agent_id: "codex-cli".into(),
            user_id: None,
            device_id: None,
            token: AGENT_TOKEN.into(),
            role: SessionRole::Agent,
            created_at: now,
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        })
        .unwrap();
    state
}

/// One GET through the real router. `AppState` is cloned rather than rebuilt per request: seeding
/// the demo estate seals secrets, and paying for that once per probe made the suite slower than
/// everything else in the crate put together.
async fn get(state: &AppState, path: &str, bearer: Option<&str>) -> StatusCode {
    let mut req = Request::builder().method("GET").uri(path);
    if let Some(t) = bearer {
        req = req.header("authorization", format!("Bearer {t}"));
    }
    build_router(state.clone(), "127.0.0.1:7376".parse().unwrap())
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap()
        .status()
}

/// A concrete URL for a route pattern. The auth guard runs before any lookup, so a path parameter
/// that resolves to nothing still exercises exactly the check under test.
fn concrete(path: &str) -> String {
    path.split('/')
        .map(|seg| if seg.starts_with(':') { "route-class-probe" } else { seg })
        .collect::<Vec<_>>()
        .join("/")
}

#[tokio::test]
async fn anonymous_callers_are_refused_everywhere_a_credential_is_required() {
    // Only GETs: a POST/PUT/PATCH body is extracted before the handler runs, so an anonymous write
    // answers 4xx for body reasons and the probe would prove nothing about auth. Those routes are
    // covered by the static guard check above, which does not have that blind spot.
    let state = state_with_agent();
    for route in ROUTES
        .iter()
        .filter(|r| r.method == "GET" && !matches!(r.class, Class::Open | Class::OpenNarrowedWithoutAuth))
    {
        let status = get(&state, &concrete(route.path), None).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "GET {} answered {status} to an anonymous caller; expected 401",
            route.path
        );
    }
}

#[tokio::test]
async fn an_agent_token_cannot_drive_the_operator_plane() {
    // The assertion the four-handler regression needed. A 200 here is an agent reading or writing the console.
    let state = state_with_agent();
    // The restoration routes are probed here too: an agent token must not reach them either, and
    // on a gateway with no Authorization Server they are refused for a second reason as well.
    for route in ROUTES.iter().filter(|r| {
        r.method == "GET" && matches!(r.class, Class::OperatorOnly | Class::RestorationOperator)
    }) {
        let status = get(&state, &concrete(route.path), Some(AGENT_TOKEN)).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "GET {} answered {status} to an AGENT token; expected 403",
            route.path
        );
    }
}

#[tokio::test]
async fn an_agent_token_still_reaches_the_agent_plane() {
    // The inverse regression, and the cheaper one to ship: a peer check tightened a guard
    // and took phone LAN pairing with it. A gate that refuses everyone passes every deny test.
    let state = state_with_agent();
    for route in ROUTES.iter().filter(|r| r.method == "GET" && r.class == Class::AgentAllowed) {
        let status = get(&state, &concrete(route.path), Some(AGENT_TOKEN)).await;
        assert!(
            status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
            "GET {} answered {status} to a valid AGENT token; the agent plane must admit agents",
            route.path
        );
    }
}

#[tokio::test]
async fn open_routes_really_are_open() {
    let state = state_with_agent();
    for route in ROUTES
        .iter()
        .filter(|r| r.method == "GET" && matches!(r.class, Class::Open | Class::OpenNarrowedWithoutAuth))
    {
        let status = get(&state, &concrete(route.path), None).await;
        assert!(
            status != StatusCode::UNAUTHORIZED && status != StatusCode::FORBIDDEN,
            "GET {} answered {status} anonymously, but is classified open",
            route.path
        );
    }
}
