//! Implementations of the `permaura` subcommands. HTTP calls go through `reqwest`
//! against the gateway's REST v1 surface; `policy test` evaluates locally through
//! [`permaura_policy`] so it works with no daemon running.

use std::io::{IsTerminal, Read};
use std::str::FromStr;

use anyhow::{anyhow, Context};
use permaura_core::{Action, Decision, Grant, GrantAgents, GrantPeriod, Policy, RiskTier};
use permaura_policy::{DecisionInput, PolicyEngine, RequestContext};
use serde_json::json;
use time::OffsetDateTime;

/// Shared invocation context: the gateway base URL and the bearer token to present.
pub struct Ctx {
    /// Base URL of the gateway/daemon (e.g. `http://127.0.0.1:7376`).
    pub url: String,
    /// Bearer token from `--token` / `PERMAURA_TOKEN`, if the caller gave one.
    pub token: Option<String>,
}

impl Ctx {
    /// Build a context over a gateway URL and an optional explicit bearer token.
    pub fn new(url: String, token: Option<String>) -> Self {
        Ctx { url: super::port::reachable_url(&url), token }
    }

    fn explicit(&self) -> Option<String> {
        self.token.clone().filter(|t| !t.is_empty())
    }

    /// The bearer to present on a request to `url` right now, or why nothing may be sent there.
    /// Decided per request, because the listener on a loopback port can change between two of them.
    ///
    /// The token is an explicit `--token` / `PERMAURA_TOKEN` first, otherwise the per-gateway operator
    /// token a clean bootstrap wrote to `$PERMAURA_HOME/operator.token`, the same file the npm
    /// launcher reads, read afresh because the gateway rotates it. It used to fall back to the
    /// published [`DEMO_TOKEN`] constant, which is the shape to avoid: a tool quietly presenting a
    /// globally-known bearer. Against a real gateway that was merely a confusing 401; against a
    /// seeded one it was an authentication bypass. Sending nothing is the honest failure.
    pub(super) async fn bearer(&self) -> Result<Option<String>, super::port::Refused> {
        super::port::bearer_for(&self.url, self.explicit().as_deref(), super::port::operator_token).await
    }

    fn request(&self, method: reqwest::Method, path: &str) -> Req {
        Req {
            builder: super::port::client_for(&self.url, None)
                .expect("an HTTP client can be built")
                .request(method, format!("{}{path}", self.url)),
            url: self.url.clone(),
            explicit: self.explicit(),
        }
    }

    /// A GET request to `path` carrying the bearer token, so authenticated endpoints
    /// (e.g. `/v1/capabilities`) work straight from the CLI.
    pub(super) fn get(&self, path: &str) -> Req {
        self.request(reqwest::Method::GET, path)
    }

    /// A POST request to `path` carrying the bearer token.
    pub(super) fn post(&self, path: &str) -> Req {
        self.request(reqwest::Method::POST, path)
    }

    /// A DELETE request to `path` carrying the bearer token.
    fn delete(&self, path: &str) -> Req {
        self.request(reqwest::Method::DELETE, path)
    }

    /// A PUT request to `path` carrying the bearer token.
    fn put(&self, path: &str) -> Req {
        self.request(reqwest::Method::PUT, path)
    }
}

/// A request to the gateway. What it may carry is decided at [`Req::send`], where a refusal to send
/// it at all surfaces too.
pub(super) struct Req {
    builder: reqwest::RequestBuilder,
    url: String,
    explicit: Option<String>,
}

impl Req {
    fn json<T: serde::Serialize + ?Sized>(self, body: &T) -> Self {
        Req { builder: self.builder.json(body), ..self }
    }

    fn header(self, name: &'static str, value: impl AsRef<str>) -> Self {
        Req { builder: self.builder.header(name, value.as_ref()), ..self }
    }

    pub(super) async fn send(self) -> anyhow::Result<reqwest::Response> {
        let bearer =
            super::port::bearer_for(&self.url, self.explicit.as_deref(), super::port::operator_token).await?;
        let req = match bearer {
            Some(t) => self.builder.bearer_auth(t),
            None => self.builder,
        };
        super::port::refuse_redirect(req.send().await?)
    }
}

/// Print a heading in a bold-ish, dependency-free style (ANSI bold + cyan).
pub(super) fn heading(text: &str) {
    println!("\x1b[1;36m{text}\x1b[0m");
}

pub(super) fn ok(text: &str) {
    println!("\x1b[1;32m✓\x1b[0m {text}");
}

pub(super) fn deny(text: &str) {
    println!("\x1b[1;31m✗\x1b[0m {text}");
}

/// The exit status of a command whose write the gateway is holding for a paired device to approve: accepted, not applied and not refused, so a script can tell it from done (0) and from failed (1).
pub const EXIT_PENDING_APPROVAL: u8 = 3;

/// A command that ended with a write held for approval. [`report_held`] has already said so on stdout, so this carries only the approval ids.
#[derive(Debug)]
pub struct Pending(pub Vec<String>);

impl std::fmt::Display for Pending {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "held for approval {}; not applied yet", self.0.join(", "))
    }
}

impl std::error::Error for Pending {}

/// How the gateway answered a write.
enum Written {
    /// Applied. The body is its answer, still to be checked for whatever the caller reports from it.
    Applied(serde_json::Value),
    /// Held for a paired device to approve.
    Held { approval_id: String, body: serde_json::Value },
}

/// Read a write's answer by its status rather than by the fact that one came back: a 202 is a hold, any other 2xx is applied, and anything else is an error carrying the gateway's own reason.
async fn written(resp: reqwest::Response, what: &str) -> anyhow::Result<Written> {
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    judge_written(status, body, what)
}

/// [`written`] for an answer already read.
fn judge_written(status: reqwest::StatusCode, body: serde_json::Value, what: &str) -> anyhow::Result<Written> {
    if status == reqwest::StatusCode::ACCEPTED {
        let approval_id = held_approval(&body, what)?;
        return Ok(Written::Held { approval_id, body });
    }
    if status.is_success() {
        return Ok(Written::Applied(body));
    }
    let detail = body["error"]
        .as_str()
        .or_else(|| body["message"].as_str())
        .unwrap_or("no reason given");
    let hint = if status == reqwest::StatusCode::UNAUTHORIZED {
        ". Set PERMAURA_TOKEN, or run this on the gateway host where the operator token lives ($PERMAURA_HOME/operator.token)"
    } else {
        ""
    };
    Err(anyhow!("{what} failed: the gateway answered {status}: {}{hint}", terminal_safe(detail)))
}

/// The approval a 202 names. One that names none cannot be followed up, and may never apply, so it is reported as neither pending nor done.
fn held_approval(body: &serde_json::Value, what: &str) -> anyhow::Result<String> {
    body["approval_id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            anyhow!("{what}: the gateway answered 202 Accepted without naming an approval, so nothing can follow it up and it may never apply")
        })
}

/// The id an applied answer names. A success status with no id in it is no evidence that anything was created.
fn applied_id(body: &serde_json::Value, field: &str, what: &str) -> anyhow::Result<String> {
    body[field]
        .as_str()
        .filter(|id| !id.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow!("{what}: the gateway answered success without a {field}, so whether it applied is unconfirmed"))
}

/// Say that a write is held rather than done. Printed rather than returned, so a command with independent later steps can report each hold and still end pending.
fn report_held(what: &str, body: &serde_json::Value) {
    print_recovery_hold(body);
    println!("  Nothing has been applied yet: {what} takes effect once a paired device approves it.");
    println!("  `permaura pending` lists it until then.");
}

/// [`report_held`] for a command whose only write was held.
fn held(what: &str, approval_id: String, body: &serde_json::Value) -> anyhow::Error {
    report_held(what, body);
    Pending(vec![approval_id]).into()
}

/// Render a Unix-millisecond timestamp as a compact "age" string (e.g. `12s`, `3m`, `1h2m`). Approvals carry `created_at` as Unix millis, and the pending queue is most useful when you can see at a glance how long a call has been waiting on a human.
fn age_since(created_at_ms: i64) -> String {
    if created_at_ms <= 0 {
        return "-".to_string();
    }
    let now_ms = OffsetDateTime::now_utc().unix_timestamp() * 1000;
    let secs = ((now_ms - created_at_ms).max(0)) / 1000;
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else if secs < 86_400 {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    } else {
        format!("{}d{}h", secs / 86_400, (secs % 86_400) / 3600)
    }
}

// ── init ──────────────────────────────────────────────────────────────────────

/// Create the Permaura home directory. The `config.json` and `vault/` it writes are read by nothing;
/// the gateway's settings live in `~/.permaura/config.toml`.
pub fn init() -> anyhow::Result<()> {
    let dir = permaura_core::permaura_home()
        .context("could not resolve a home directory: set PERMAURA_HOME or HOME")?;
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let config_path = dir.join("config.json");
    if !config_path.exists() {
        let config = json!({
            "gateway_addr": "127.0.0.1:7376",
            "execution_location": "local_only",
            "store": "memory",
            "vault": { "cipher": "aes256_gcm" }
        });
        std::fs::write(&config_path, serde_json::to_string_pretty(&config)?)
            .with_context(|| format!("writing {}", config_path.display()))?;
    }
    // Secrets / db live under here too; create the dirs so later commands can use them.
    std::fs::create_dir_all(dir.join("vault"))?;

    heading("Permaura initialized");
    ok(&format!("config: {}", config_path.display()));
    ok(&format!("vault dir: {}", dir.join("vault").display()));
    println!("\nNext: \x1b[1mpermaura start\x1b[0m to run the gateway on this machine.");
    Ok(())
}

// ── stop ──────────────────────────────────────────────────────────────────────

/// `permaura pair <code>`: hand a gateway that is already serving to a permaura.com account.
///
/// The counterpart to `start --pair`, and the one that fits how a gateway actually gets installed.
/// A machine's gateway is normally brought up by the desktop app, a LaunchAgent or a systemd unit,
/// long before anyone asks the console for a pairing code; until this existed the only route was to
/// stop that gateway and start a fresh one carrying the code, which drops every in-flight call.
///
/// Health is checked first, and a failure here is the command failing rather than a warning: enrolling
/// a gateway that is not answering spends a single-use code on a row the console can never drive, and
/// unlike the boot path there is no gateway of ours still coming up to wait for.
pub async fn pair(ctx: &Ctx, code: &str) -> anyhow::Result<()> {
    heading("Connect this gateway");
    // The token is the bearer for handing the link's announce secret to `ctx.url`, so it is the same
    // decision as any request there: this machine's token only for this machine's gateway.
    let token = ctx.bearer().await?.unwrap_or_default();
    if !ctx.is_healthy().await {
        return Err(anyhow!(
            "nothing is answering at {}: start the gateway first with `permaura start`, or name a \
             different one with --url",
            ctx.url
        ));
    }
    // The bearer this gateway published, or whatever `PERMAURA_TOKEN` or `--token` named, used only to
    // give the gateway its announce secret; permaura.com never receives it.
    if token.is_empty() {
        return Err(anyhow!(
            "no operator token to give this gateway its announce secret with: expected one in \
             ~/.permaura/operator.token, or set PERMAURA_TOKEN"
        ));
    }
    if let Err(e) = super::enroll::enroll(&ctx.url, &token, code).await {
        eprintln!("\x1b[33m!\x1b[0m Could not connect this gateway to your account: {e}");
        super::enroll::manual_fallback(&ctx.url);
        return Err(e);
    }
    Ok(())
}

/// Ask a running gateway to drain and exit, via the authenticated loopback `POST /v1/shutdown` the
/// binary arms on `start`.
///
/// There is deliberately no pidfile and no signal here. The gateway may have been started by the
/// desktop supervisor, a systemd unit, launchd or a bare shell, and only one of those leaves a pid
/// this process could find, but all of them answer the same endpoint, and asking it lets in-flight
/// calls finish instead of cutting a store write in half. The answer names the gateway's pid, and when
/// this machine can confirm that pid as the listener or the store's holder, "stopped" is said only once
/// that process has exited, since it stops answering as its drain begins and goes on writing its store
/// until the drain ends; otherwise the stop is judged by `/health` alone.
pub async fn stop(ctx: &Ctx, force: bool) -> anyhow::Result<()> {
    heading("Gateway stop");
    let local = super::port::local_addr_of(&ctx.url);
    // Who holds the port before it is given up, to check the pid the gateway names is the listener this command reached.
    let listener = local.and_then(|addr| super::port::holder_of(addr.port())).map(|h| h.pid);
    // And who holds this home's store, asked before the stop for the same reason: the lock is what still names a gateway whose listener this command cannot see.
    let lock_holder = permaura_gateway::store_path_from_env()
        .filter(|db| db != ":memory:")
        .and_then(|db| permaura_gateway::store::lock::holder(&db).ok().flatten().flatten());
    let resp = match ctx.post("/v1/shutdown").send().await {
        Ok(resp) => resp,
        Err(e) if e.is::<super::port::Refused>() => {
            // Sent nothing because it did not prove it is this home's; `--force` may still end one running as this user (a gateway on a deleted store, or one too old to prove itself), and `force_stop` refuses anything not answering as a Permaura gateway.
            let Some(addr) = local.filter(|&a| force && super::port::listener_is_this_users(a)) else {
                return Err(e);
            };
            deny(&e.to_string());
            println!("Forcing: checking that it answers /health as a Permaura gateway before signalling it.");
            return report_forced(addr, super::port::force_stop(addr).await?);
        }
        Err(e) => {
            // Nothing listening is the ordinary case for `stop`, not a failure worth a stack of
            // reqwest detail.
            if force && local.is_some_and(super::port::is_free) {
                println!("\x1b[2m·\x1b[0m Nothing is listening at {}: already stopped.", ctx.url);
                return Ok(());
            }
            println!("\x1b[2m·\x1b[0m Nothing is answering at {}: already stopped?", ctx.url);
            return Err(anyhow!("could not reach {}: {e}", ctx.url));
        }
    };
    let status = resp.status();
    if status == reqwest::StatusCode::ACCEPTED {
        println!("\x1b[2m·\x1b[0m {} accepted the request and is draining in-flight calls.", ctx.url);
        let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
        let named = body["pid"].as_u64().and_then(|p| u32::try_from(p).ok());
        return confirm_stopped(ctx, trusted_stop_pid(named, listener, lock_holder)).await;
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        let Some(addr) = local else {
            return Err(anyhow!(
                "the gateway at {} rejected this home's operator token, so it is not the gateway this home's store belongs to. \
                 It is not on this machine, so there is nothing here to force; stop it where it runs",
                ctx.url
            ));
        };
        let holder = super::port::holder_of(addr.port());
        deny(&super::port::explain_rejected_shutdown(addr, holder.as_ref(), !force));
        if !force {
            return Err(anyhow!("the gateway on {addr} is not this home's; nothing was stopped"));
        }
        println!("Forcing: checking that it answers /health as a Permaura gateway before signalling it.");
        return report_forced(addr, super::port::force_stop(addr).await?);
    }
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    let detail = body["error"].as_str().unwrap_or("");
    let refusal = format!(
        "the gateway refused to stop ({status}){}{detail}",
        if detail.is_empty() { "" } else { ": " }
    );
    // Any other answer means the graceful path cannot be used; with --force the same verified kill
    // applies, and it is the verification that refuses to touch something that is not ours.
    if let (true, Some(addr)) = (force, local) {
        println!("{refusal}; forcing.");
        return report_forced(addr, super::port::force_stop(addr).await?);
    }
    Err(anyhow!(refusal))
}

/// The pid a stop waits on: the one the gateway named in its 202, only when this machine can confirm it
/// as the local listener or as the holder of this home's store. A pid from another pid namespace (WSL2, a
/// container, a forwarded port) names some other process here, so it is not waited on and the stop is
/// judged by `/health` alone.
fn trusted_stop_pid(named: Option<u32>, listener: Option<u32>, lock_holder: Option<u32>) -> Option<u32> {
    named.filter(|p| listener == Some(*p) || lock_holder == Some(*p))
}

/// What a forced stop did.
fn report_forced(addr: std::net::SocketAddr, stopped: Option<super::port::Holder>) -> anyhow::Result<()> {
    match stopped {
        Some(h) => ok(&format!("sent TERM to {}; {addr} is free.", h.describe())),
        None => ok(&format!("nothing is listening on {addr} any more.")),
    }
    Ok(())
}

// ── status ────────────────────────────────────────────────────────────────────

/// GET /health and print a summary.
impl Ctx {
    /// Whether a gateway is answering on this URL right now.
    ///
    /// Exists for `upgrade`, which has to ask BEFORE it swaps the binary: afterwards a gateway that
    /// is down looks the same as one that was never up, and those want different endings. Any
    /// failure answers "no" rather than propagating: the question is only ever used to decide
    /// whether there is something to restart, and an upgrade must not fail because a probe did.
    ///
    /// Asked with no bearer, since a listener that has not proved itself is sent nothing.
    pub async fn is_healthy(&self) -> bool {
        let Ok(client) = super::port::client_for(&self.url, Some(std::time::Duration::from_secs(5))) else {
            return false;
        };
        matches!(client.get(format!("{}/health", self.url)).send().await, Ok(r) if r.status().is_success())
    }

    /// The health document, asked for by both of its names.
    ///
    /// A gateway is a SEPARATE, independently-versioned process from the CLI driving it: an installed
    /// one keeps serving across upgrades, and commands like `pair`, `status` and `upgrade` exist
    /// precisely to act on one that is already running. So the path this reaches for cannot be
    /// whichever name the CLI's own source tree knows about.
    ///
    /// `/health`, and only `/health`.
    ///
    /// `/healthz` was cut from the gateway deliberately rather than aliased, and a client-side
    /// fallback to it would have quietly restored the second name it was cut to remove: one
    /// endpoint with two names is the thing that decision was against. It is also the one a hosted
    /// worker can answer at all: on Cloud Run, Google's frontend serves `/healthz` itself and the
    /// container never sees the request.
    ///
    /// The cost is real and accepted: a pre-1.3.8 gateway serves only `/healthz`, so this CLI reads
    /// one as down. Upgrading it is the fix, and this release ships to a fleet with no users on it.
    async fn health(&self) -> anyhow::Result<reqwest::Response> {
        self.get("/health").send().await
    }
}

/// How long to watch for the gateway to actually go, after it accepted the request, and the least time
/// to watch for a supervisor putting it back.
const STOP_CONFIRM_WINDOW: std::time::Duration = std::time::Duration::from_secs(6);

/// How long to go on watching once the process has exited, for a supervisor that starts it again.
const RESTART_WATCH: std::time::Duration = std::time::Duration::from_secs(2);

/// Report what the gateway DID, not what it agreed to do.
///
/// `stop` used to print "is draining in-flight calls and will exit" the moment the request was
/// accepted, and say nothing further. Under the desktop app that reads as a lie: the supervisor
/// restarts the gateway within a second of it exiting, so the port answers again and `permaura status`
/// shows it up, having reported success twice. The request really was accepted and the process really
/// did exit; what was missing is that something put it back.
///
/// With the gateway's `pid` it waits for that process to exit, for up to [`super::port::STOP_EXIT_WINDOW`]:
/// a gateway stops answering as its drain begins and goes on executing and writing its store until the
/// drain ends, so a quiet `/health` alone said "stopped" while calls were still being recorded, and a
/// `permaura start` run straight after opened the store beside it. A gateway too old to name its pid is
/// judged by `/health` alone, as before.
async fn confirm_stopped(ctx: &Ctx, pid: Option<u32>) -> anyhow::Result<()> {
    let started = tokio::time::Instant::now();
    let window = if pid.is_some() { super::port::STOP_EXIT_WINDOW } else { STOP_CONFIRM_WINDOW };
    let deadline = started + window;
    let mut went_away = false;
    let mut exited_at: Option<tokio::time::Instant> = None;
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        let answering = ctx.health().await.is_ok();
        if !answering {
            went_away = true;
        } else if went_away {
            // It exited and is answering again: something is supervising it.
            break;
        }
        let now = tokio::time::Instant::now();
        if let (Some(pid), None) = (pid, exited_at) {
            if !super::port::process_alive(pid) {
                exited_at = Some(now);
            }
        }
        if exited_at.is_some_and(|at| now >= (at + RESTART_WATCH).max(started + STOP_CONFIRM_WINDOW)) {
            break;
        }
        if now >= deadline {
            break;
        }
    }
    let still_up = ctx.health().await.is_ok();
    if !still_up {
        if let Some(pid) = pid.filter(|_| exited_at.is_none()) {
            deny(&format!(
                "{} stopped answering, but its process (pid {pid}) has not exited after {} s: it is still finishing calls, or it is stuck.",
                ctx.url,
                window.as_secs()
            ));
            return Err(anyhow!(
                "the gateway at {} has not exited yet (pid {pid}); a `permaura start` on this home waits for it to let the store go",
                ctx.url
            ));
        }
        ok(&format!("{} has stopped.", ctx.url));
        return Ok(());
    }
    let hint = supervisor_hint();
    let what = if went_away {
        "it exited and something started it again"
    } else {
        "it is still answering"
    };
    deny(&format!("{} did not stay stopped: {what}.", ctx.url));
    Err(anyhow!("the gateway at {} is running again{hint}", ctx.url))
}

/// Who is likely to be restarting a gateway on this machine, for the message that says it came back.
fn supervisor_hint() -> String {
    if cfg!(target_os = "macos") && std::path::Path::new("/Applications/Permaura.app").exists() {
        return ". The Permaura app supervises the gateway and starts it again when it exits: quit \
                the app, or use its own stop, if you meant to leave it off"
            .to_string();
    }
    ". Something is supervising it (a desktop app, launchd or systemd) and starts it again when it \
      exits: stop it there if you meant to leave it off"
        .to_string()
}

pub async fn status(ctx: &Ctx) -> anyhow::Result<()> {
    let resp = match ctx.health().await {
        Ok(resp) => resp,
        Err(e) if e.is::<super::port::Refused>() => return Err(e),
        // Nothing listening on a local address is an ANSWER, not a failure to be rendered as a stack
        // of transport detail: the gateway is off on this machine, which is a thing a person can act
        // on. A remote address that will not connect keeps the detail, because there the cause
        // genuinely could be the network.
        Err(e) => {
            heading("Gateway status");
            let local = super::port::local_addr_of(&ctx.url);
            if local.is_some_and(super::port::is_free) {
                println!("\x1b[2m·\x1b[0m No gateway is running at {}: nothing is listening.", ctx.url);
                println!("  start one with `permaura start`, or from the Permaura app.");
                return Err(anyhow!("no gateway is running at {}", ctx.url));
            }
            if let Some(addr) = local {
                let holder = super::port::holder_of(addr.port());
                println!(
                    "\x1b[1;31m✗\x1b[0m {} did not answer, and {} is held by {}.",
                    ctx.url,
                    addr,
                    holder.map(|h| h.describe()).unwrap_or_else(|| "something this tool cannot name".into()),
                );
                return Err(anyhow!("{} did not answer as a gateway", ctx.url));
            }
            return Err(anyhow!("could not reach {}: {e}", ctx.url));
        }
    };
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    heading("Gateway status");
    if status.is_success() {
        ok(&format!("{}: {}", ctx.url, body["status"].as_str().unwrap_or("?")));
        println!("  version:           {}", body["version"].as_str().unwrap_or("?"));
        println!("  agents:            {}", body["agents"]);
        println!("  capabilities:      {}", body["capabilities"]);
        println!("  grants:            {}", body["grants"]);
        println!(
            "  audit chain verifies: {} (edits inside the chain would show; events removed from the end would not)",
            body["audit_chain_intact"]
        );
    } else {
        println!("\x1b[1;31m✗\x1b[0m gateway returned {status}");
    }
    Ok(())
}

// ── agent add ───────────────────────────────────────────────────────────────────

/// Register an agent via POST /v1/agents/register.
pub async fn agent_add(ctx: &Ctx, name: &str) -> anyhow::Result<()> {
    let what = format!("registering agent '{name}'");
    let resp = ctx
        .post("/v1/agents/register")
        .json(&json!({ "name": name }))
        .send()
        .await?;
    let id = match written(resp, &what).await? {
        Written::Held { approval_id, body } => return Err(held(&what, approval_id, &body)),
        Written::Applied(body) => applied_id(&body, "agent_id", &what)?,
    };
    heading("Agent registered");
    ok(&format!("{name} → {id}"));
    Ok(())
}

/// `permaura agent enroll`: mint a one-time enrolment code and print it, or write it to `out`, a new file only its owner can read.
///
/// The request goes through [`Ctx`] like every other, so the operator token goes only to a listener on this machine that proves it holds it, and no example needs the token in a `curl` argument.
pub async fn agent_enroll(ctx: &Ctx, label: Option<&str>, out: Option<&std::path::Path>) -> anyhow::Result<()> {
    let out = out.map(expand_home);
    let out = out.as_deref();
    if let Some(path) = out {
        if path.symlink_metadata().is_ok() {
            return Err(anyhow!("{} already exists; name a new file, so a code never overwrites one", path.display()));
        }
    }
    let resp = ctx.post("/v1/agents/enroll").json(&json!({ "label": label })).send().await?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    if !status.is_success() {
        let why = terminal_safe(body.get("error").and_then(|v| v.as_str()).unwrap_or("no reason given"));
        return Err(anyhow!("the gateway refused to mint an enrolment code ({}): {why}", status.as_u16()));
    }
    let code = body["code"]
        .as_str()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| anyhow!("the gateway answered success without a code"))?;
    match out {
        None => println!("{code}"),
        Some(path) => {
            permaura_core::write_secret_file(path, format!("{code}\n").as_bytes())
                .with_context(|| format!("writing the code to {}", path.display()))?;
            ok(&format!(
                "Wrote a one-time enrolment code to {}. Give the agent's bridge that path in PERMAURA_AGENT_TOKEN_FILE; it is single-use, lives 15 minutes, and from its first call on it is that agent's own token.",
                path.display()
            ));
        }
    }
    Ok(())
}

/// `path` with a leading `~` (alone or before a separator) made the home directory: PowerShell and cmd hand `~` to a program as it is, where a POSIX shell would expand it.
fn expand_home(path: &std::path::Path) -> std::path::PathBuf {
    let text = path.to_string_lossy();
    let rest = match text.strip_prefix('~') {
        Some(rest) if rest.is_empty() || rest.starts_with(['/', '\\']) => rest.trim_start_matches(['/', '\\']).to_string(),
        _ => return path.to_path_buf(),
    };
    match std::env::var_os("HOME").filter(|h| !h.is_empty()).or_else(|| std::env::var_os("USERPROFILE")) {
        Some(home) => std::path::PathBuf::from(home).join(rest),
        None => path.to_path_buf(),
    }
}

/// `permaura agent list`: the gateway's agents, with their ids and status.
pub async fn agent_list(ctx: &Ctx) -> anyhow::Result<()> {
    let resp = ctx.get("/v1/agents").send().await.with_context(|| format!("connecting to {}", ctx.url))?;
    if !resp.status().is_success() {
        return Err(anyhow!("gateway returned {} for /v1/agents", resp.status()));
    }
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    let agents = body["agents"].as_array().cloned().unwrap_or_default();
    heading("Agents");
    if agents.is_empty() {
        println!("  No agents yet.");
        return Ok(());
    }
    for line in agent_list_lines(&agents) {
        println!("{line}");
    }
    Ok(())
}

/// The lines `permaura agent list` prints for `agents`, a header first: the id last and whole, since `agent approve` and `grant --agent` take it as printed, and every field with its control characters made visible, since an agent's name is whatever registered it chose.
fn agent_list_lines(agents: &[serde_json::Value]) -> Vec<String> {
    let mut lines = vec![format!("\n{:<10}  {:<32}  {}", "STATUS", "NAME", "ID")];
    for a in agents {
        lines.push(format!(
            "{:<10}  {:<32}  {}",
            truncate(&terminal_safe(a["status"].as_str().unwrap_or("?")), 10),
            truncate(&terminal_safe(a["name"].as_str().unwrap_or("-")), 32),
            terminal_safe(a["id"].as_str().unwrap_or("?")),
        ));
    }
    lines
}

/// `permaura agent approve <id>`: approve a pending agent. Held for a paired device where the gateway holds that change.
pub async fn agent_approve(ctx: &Ctx, id: &str) -> anyhow::Result<()> {
    let what = format!("approving agent '{id}'");
    let path = format!("/v1/agents/{}/approve", urlencoding_path(id));
    let resp = ctx.post(&path).send().await?;
    match written(resp, &what).await? {
        Written::Held { approval_id, body } => Err(held(&what, approval_id, &body)),
        Written::Applied(_) => {
            ok(&format!("{id} is approved; its calls are now judged by its grants"));
            Ok(())
        }
    }
}

/// `id` with every byte other than the unreserved set and `:` percent-encoded, for one path segment.
fn urlencoding_path(id: &str) -> String {
    id.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b':' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

// ── connections ─────────────────────────────────────────────────────────────

/// Arguments for `permaura connection add-ssh`.
pub struct SshConnSpec {
    /// Connection id (capabilities are namespaced under it).
    pub id: String,
    /// SSH host (pinned server-side).
    pub host: String,
    /// SSH port.
    pub port: u16,
    /// Remote login user.
    pub user: String,
    /// Expected SHA256 host-key fingerprint (required unless `insecure`).
    pub host_key_sha256: Option<String>,
    /// Disable host-key verification (dev only).
    pub insecure: bool,
    /// Path to a private key to seal in the vault.
    pub key_file: Option<String>,
    /// Env var holding a password (password auth) instead of a key.
    pub password_env: Option<String>,
    /// Expose SFTP get/put/list under this root.
    pub sftp_root: Option<String>,
    /// Exec commands as `action:program,arg,arg` (`{name}` args become placeholders).
    pub exec: Vec<String>,
    /// Optionally allow the declared actions + grant them to this agent.
    pub agent: Option<String>,
    /// Mark exec commands as requiring approval (High risk).
    pub require_approval: bool,
}

/// `permaura connection list`: print configured connections.
pub async fn connection_list(ctx: &Ctx) -> anyhow::Result<()> {
    let resp = ctx.get("/v1/connections").send().await?;
    // Without this an unauthorised call printed "Connections / (none)" and exited 0, so a wrong or
    // missing token read as "you have no connections", indistinguishable from data loss.
    if !resp.status().is_success() {
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
            return Err(anyhow!(
                "not authorised to list connections ({status}). Set PERMAURA_TOKEN, or run this on the gateway host where the operator token lives ($PERMAURA_HOME/operator.token)"
            ));
        }
        return Err(anyhow!("gateway returned {status} for /v1/connections"));
    }
    let body: serde_json::Value = resp.json().await.unwrap_or(json!([]));
    let conns = body
        .as_array()
        .cloned()
        .or_else(|| body["connections"].as_array().cloned())
        .unwrap_or_default();
    heading("Connections");
    if conns.is_empty() {
        println!("  (none)");
    }
    for c in conns {
        println!(
            "  {} [{}]: {}",
            c["id"].as_str().unwrap_or("?"),
            c["connector"].as_str().unwrap_or("?"),
            c["name"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

/// `permaura connection add-ssh`: create an SSH connection, seal its credential, and (optionally)
/// grant it to an agent. Mirrors the two REST calls the console form would make, plus the grant.
pub async fn connection_add_ssh(ctx: &Ctx, spec: SshConnSpec) -> anyhow::Result<()> {
    if spec.host_key_sha256.is_none() && !spec.insecure {
        return Err(anyhow!(
            "provide --host-key-sha256 <fp> (from `ssh-keyscan {} | ssh-keygen -lf -`), or --insecure for dev",
            spec.host
        ));
    }

    // Parse each `action:program,arg,arg` into the SshExecReq shape, deriving allow-listed
    // placeholders from any `{name}` argv elements.
    let mut exec_json: Vec<serde_json::Value> = Vec::new();
    let mut actions: Vec<String> = Vec::new();
    for e in &spec.exec {
        let (action, rest) = e
            .split_once(':')
            .ok_or_else(|| anyhow!("--exec must be 'action:program,arg,...' (got '{e}')"))?;
        let argv: Vec<String> = rest
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if argv.is_empty() {
            return Err(anyhow!("--exec '{e}' has no command after the ':'"));
        }
        let placeholders: Vec<String> = argv
            .iter()
            .filter_map(|a| a.strip_prefix('{').and_then(|x| x.strip_suffix('}')).map(str::to_string))
            .collect();
        actions.push(action.to_string());
        exec_json.push(json!({
            "action": action,
            "args_template": argv,
            "allowed_placeholders": placeholders,
            "risk": if spec.require_approval { "high" } else { "low" },
            "requires_approval": spec.require_approval,
        }));
    }

    let mut ssh = json!({
        "host": spec.host,
        "port": spec.port,
        "user": spec.user,
        "exec": exec_json,
        "password_auth": spec.password_env.is_some(),
    });
    if let Some(fp) = &spec.host_key_sha256 {
        ssh["host_key_sha256"] = json!(fp);
    }
    if spec.insecure {
        ssh["insecure"] = json!(true);
    }
    if let Some(root) = &spec.sftp_root {
        ssh["sftp_root"] = json!(root);
        actions.extend(["sftp.list".to_string(), "sftp.get".to_string(), "sftp.put".to_string()]);
    }

    // 1. Create the connection (pins host/user/host-key + registers capabilities).
    let what = format!("creating connection '{}'", spec.id);
    let resp = ctx
        .post("/v1/connections")
        .json(&json!({ "id": spec.id, "connector": "ssh", "name": format!("SSH: {}", spec.host), "ssh": ssh }))
        .send()
        .await?;
    let created = match written(resp, &what).await? {
        Written::Held { approval_id, body } => {
            report_held(&what, &body);
            println!("  Nothing else was attempted: its credential and grant need the connection to exist.");
            return Err(Pending(vec![approval_id]).into());
        }
        Written::Applied(body) => applied_id(&body, "connection_id", &what)?,
    };
    heading("Connection created");
    ok(&format!("{created} → ssh {}@{}:{}", spec.user, spec.host, spec.port));
    let mut holds: Vec<String> = Vec::new();

    // 2. Seal the credential (the key/password never comes back out).
    let value: Option<String> = if let Some(path) = &spec.key_file {
        Some(std::fs::read_to_string(path).with_context(|| format!("reading key file {path}"))?)
    } else if let Some(var) = &spec.password_env {
        Some(std::env::var(var).with_context(|| format!("reading password from ${var}"))?)
    } else {
        None
    };
    if let Some(v) = value {
        let what = format!("sealing the credential for '{}'", spec.id);
        let without = |e: anyhow::Error| anyhow!("{e:#}. Connection '{}' exists without a credential", spec.id);
        let cresp = ctx
            .post(&format!("/v1/connections/{}/credential", spec.id))
            .json(&json!({ "value": v }))
            .send()
            .await
            .map_err(without)?;
        match written(cresp, &what).await.map_err(without)? {
            Written::Held { approval_id, body } => {
                report_held(&what, &body);
                holds.push(approval_id);
            }
            Written::Applied(body) => {
                applied_id(&body, "connection_id", &what).map_err(without)?;
                ok("credential sealed in the vault");
            }
        }
    } else {
        deny("no credential (--key-file / --password-env): connection stays Disconnected");
    }

    // 3. Optionally allow the declared actions and grant them to an agent.
    if let Some(agent) = &spec.agent {
        let what = format!("allowing the declared actions on '{}'", spec.id);
        let presp = ctx
            .post("/v1/policies")
            .json(&json!({ "connection_id": spec.id, "name": format!("{} ssh", spec.id), "allow": actions, "deny": [], "requires_approval": [] }))
            .send()
            .await?;
        match written(presp, &what).await? {
            Written::Held { approval_id, body } => {
                report_held(&what, &body);
                println!("  No grant was made: a grant binds a policy that exists. Once this one is approved, grant it to {agent} from the console.");
                holds.push(approval_id);
            }
            Written::Applied(body) => {
                let policy_id = applied_id(&body, "policy_id", &what)?;
                let what = format!("granting '{}' to {agent}", spec.id);
                let unbound = |e: anyhow::Error| anyhow!("{e:#}. Policy {policy_id} was created and is bound to no agent until a grant names it");
                let gresp = ctx
                    .post("/v1/grants")
                    .json(&json!({ "name": format!("{} ssh", spec.id), "policy_ids": [policy_id], "agents": [{ "agent_id": agent }] }))
                    .send()
                    .await
                    .map_err(unbound)?;
                match written(gresp, &what).await.map_err(unbound)? {
                    Written::Held { approval_id, body } => {
                        report_held(&what, &body);
                        println!("  Policy {policy_id} was created; it applies to {agent} once this grant is approved.");
                        holds.push(approval_id);
                    }
                    Written::Applied(body) => {
                        let grant_id = applied_id(&body, "grant_id", &what).map_err(unbound)?;
                        ok(&format!("granted to {agent} (policy {policy_id}, grant {grant_id})"));
                    }
                }
            }
        }
    }

    heading("Capabilities (MCP tool ids)");
    for a in &actions {
        println!("  {}.{}", spec.id, a);
    }
    if !holds.is_empty() {
        return Err(Pending(holds).into());
    }
    Ok(())
}

// ── grant ──────────────────────────────────────────────────────────────────────

/// Parameters for `permaura grant`.
pub struct GrantSpec {
    /// The agent the grant is for.
    pub agent: String,
    /// The resource short name.
    pub resource: String,
    /// Allowed capability actions.
    pub allow: Vec<String>,
    /// Denied capability actions.
    pub deny: Vec<String>,
    /// Optional RFC3339 expiry.
    pub expires: Option<String>,
    /// Optional call budget.
    pub max_calls: Option<u64>,
}

/// Create a connection-scoped policy from the allow/deny lists, then bind it to the agent
/// with a grant. In the redesigned model a policy holds *what* is allowed and a grant binds
/// *who* under limits, so `permaura grant` does both in one step.
pub async fn grant(ctx: &Ctx, spec: GrantSpec) -> anyhow::Result<()> {
    if let Some(exp) = &spec.expires {
        // Validate it parses as RFC3339 before sending.
        OffsetDateTime::parse(exp, &time::format_description::well_known::Rfc3339)
            .map_err(|e| anyhow!("--expires must be RFC3339: {e}"))?;
    }

    // 1. Create the policy scoped to the connection (resource).
    let policy_payload = json!({
        "connection_id": spec.resource,
        "name": format!("{} policy", spec.agent),
        "allow": spec.allow,
        "deny": spec.deny,
        "requires_approval": [],
    });
    let what = format!("creating the policy for {} on {}", spec.agent, spec.resource);
    let presp = ctx.post("/v1/policies").json(&policy_payload).send().await?;
    let policy_id = match written(presp, &what).await? {
        Written::Held { approval_id, body } => {
            report_held(&what, &body);
            println!(
                "  No grant was created: a grant binds a policy that exists. Once this one is approved, grant it to {} from the console.",
                spec.agent
            );
            return Err(Pending(vec![approval_id]).into());
        }
        Written::Applied(body) => applied_id(&body, "policy_id", &what)?,
    };

    // 2. Bind it to the agent with the optional limits.
    let grant_payload = json!({
        "policy_id": policy_id,
        "target_agent": spec.agent,
        "max_calls": spec.max_calls,
        "expires_at": spec.expires,
    });
    let what = format!("granting {} on {}", spec.agent, spec.resource);
    let unbound = |e: anyhow::Error| anyhow!("{e:#}. Policy {policy_id} was created and is bound to no agent until a grant names it");
    let resp = ctx.post("/v1/grants").json(&grant_payload).send().await.map_err(unbound)?;
    let grant_id = match written(resp, &what).await.map_err(unbound)? {
        Written::Held { approval_id, body } => {
            report_held(&what, &body);
            println!("  Policy {policy_id} was created; it applies to {} once this grant is approved.", spec.agent);
            return Err(Pending(vec![approval_id]).into());
        }
        Written::Applied(body) => applied_id(&body, "grant_id", &what).map_err(unbound)?,
    };
    heading("Grant created");
    ok(&format!("{} on {} (policy {}) → {}", spec.agent, spec.resource, policy_id, grant_id));
    Ok(())
}

// ── audit ──────────────────────────────────────────────────────────────────────

/// GET /v1/audit-events and render as a table.
pub async fn audit(ctx: &Ctx, limit: usize) -> anyhow::Result<()> {
    let resp = ctx
        .get(&format!("/v1/audit-events?limit={limit}"))
        .send()
        .await?;
    // An answer that is not the audit log says nothing about the chain. This used to render every
    // failure as "chain intact: false" over an empty table, which reads as tamper-evidence having
    // fired when the truth was a wrong address or a missing token: a 404 from whatever else happens
    // to hold the port looks exactly like a broken chain.
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    if !status.is_success() {
        anyhow::bail!("{}", unreadable_log(ctx, status, &body));
    }
    let events = body["events"].as_array().cloned().unwrap_or_default();

    heading("Audit log");
    match body["chain_intact"].as_bool() {
        Some(intact) => println!(
            "  audit chain verifies: {intact} (edits inside the chain would show; events removed from the end would not)"
        ),
        // Answered, but said nothing about the chain: too old to be asked, or not a gateway at all.
        None => println!("  audit chain verifies: unknown (this gateway did not say)"),
    }
    if let Some(fork) = body.get("key_fork").filter(|f| !f.is_null()) {
        println!("  {}", describe_key_transition(fork));
    }
    println!(
        "\n{:>4}  {:<14}  {:<10}  {:<32}  {:<22}  {}",
        "SEQ", "DECISION", "RESULT", "ACTION", "RESOURCE", "AGENT"
    );
    println!("  {}", "-".repeat(98));
    for e in &events {
        let p = &e["payload"];
        let summary = &p["summary"];
        println!(
            "{:>4}  {:<14}  {:<10}  {:<32}  {:<22}  {}",
            e["seq"].as_u64().unwrap_or(0),
            p["decision"].as_str().unwrap_or("?"),
            audit_result(p["decision"].as_str().unwrap_or(""), summary),
            truncate(p["action"].as_str().unwrap_or("?"), 32),
            truncate(p["resource"].as_str().unwrap_or("?"), 22),
            p["agent_id"].as_str().unwrap_or("-"),
        );
        if let Some(by) = audit_approver(summary) {
            println!("{:>6}{}", "", terminal_safe(&by));
        }
        let seq = e["seq"].as_u64().unwrap_or(0).to_string();
        if let Some(message) = body["diagnostics"][&seq]["message"].as_str() {
            println!("{:>6}error: {}", "", terminal_safe(&truncate(message, 120)));
        } else if summary["diagnostic"].as_bool() == Some(true) {
            println!("{:>6}error detail no longer retained", "");
        }
    }
    if events.is_empty() {
        println!("  (no events yet)");
    }
    Ok(())
}

/// One sentence for a recorded rekey, as `/v1/audit-events` reports it under `key_fork`.
fn describe_key_transition(fork: &serde_json::Value) -> String {
    let seq = fork["seq"].as_u64().unwrap_or(0);
    format!(
        "re-keyed at seq {seq} (permaura audit rekey): the events before it are hash-linked to it, continuing from seq {} (hash {}), but were signed under a key this store no longer holds, so their signatures cannot be checked",
        fork["prior_head_seq"].as_u64().map_or_else(|| "none".to_string(), |s| s.to_string()),
        terminal_safe(fork["prior_head_hash"].as_str().unwrap_or("?")),
    )
}

/// `permaura audit verify`: whether the running gateway's audit chain verifies, over which window, and any recorded rekey. A break is the command failing.
pub async fn audit_verify(ctx: &Ctx) -> anyhow::Result<()> {
    let resp = ctx.get("/v1/audit-events?limit=1").send().await?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    if !status.is_success() {
        anyhow::bail!("{}", unreadable_log(ctx, status, &body));
    }
    heading("Audit chain");
    if let (Some(from), Some(to)) = (body["verified_from"].as_u64(), body["verified_to"].as_u64()) {
        println!("  checked: seq {from} to {to}, the events this gateway holds");
    }
    if let Some(fork) = body.get("key_fork").filter(|f| !f.is_null()) {
        println!("  {}", describe_key_transition(fork));
    }
    match body["chain_intact"].as_bool() {
        Some(true) => {
            ok("the chain verifies");
            Ok(())
        }
        Some(false) => {
            deny("the chain does not verify");
            Err(anyhow!("the audit chain at {} is broken; `permaura audit` shows its events", ctx.url))
        }
        None => Err(anyhow!("the gateway at {} did not say whether its chain verifies", ctx.url)),
    }
}

/// `permaura audit rekey --yes`: give a store whose audit key is gone for good a new one, with the gateway stopped, recording the fork in the chain.
pub async fn audit_rekey(ctx: &Ctx, yes: bool) -> anyhow::Result<()> {
    heading("Rekey the audit chain");
    if !yes {
        println!("This mints a new audit signing key for a store whose gateway.db.auditkey is gone.");
        println!("Every event already recorded keeps its hash and its link, but the key that signed it is");
        println!("gone, so its signature can never be checked again. The new key's first event records the");
        println!("fork. Restoring the original key file is always the better repair.");
        return Err(anyhow!("nothing was changed. Re-run with --yes if that is what you want"));
    }
    if ctx.is_healthy().await {
        return Err(anyhow!(
            "a gateway is answering at {} and holds this store. Stop it first with `permaura stop`, then run this again",
            ctx.url
        ));
    }
    let Some(db) = permaura_gateway::store_path_from_env() else {
        return Err(anyhow!("no PERMAURA_HOME or home directory, so there is no gateway.db to rekey"));
    };
    rekey_store(&db)
}

#[cfg(feature = "sqlite")]
fn rekey_store(db: &str) -> anyhow::Result<()> {
    use permaura_gateway::store::Store;
    let (store, event) = permaura_gateway::store::sqlite::SqliteStore::rekey(db, permaura_gateway::service::now_ms())
        .map_err(|e| match e {
            permaura_gateway::error::GatewayError::StoreHeld(m) => {
                anyhow!("{m} Stop the gateway first with `permaura stop`, then run this again")
            }
            other => anyhow!("{other}"),
        })?;
    let summary = &event.payload.summary;
    ok(&format!("minted a new audit key at {db}.auditkey"));
    println!(
        "Recorded the fork as event {}, continuing from seq {} (hash {}).",
        event.seq,
        summary["prior_head_seq"].as_u64().map_or_else(|| "none".to_string(), |s| s.to_string()),
        summary["prior_head_hash"].as_str().unwrap_or("?"),
    );
    println!("The events before it keep their hashes and links; their signatures can never be checked again.");
    match store.verify_audit()? {
        None => ok("the chain verifies, with the fork recorded"),
        Some(seq) => deny(&format!("the chain does not verify at seq {seq}, which a rekey does not repair")),
    }
    Ok(())
}

#[cfg(not(feature = "sqlite"))]
fn rekey_store(_db: &str) -> anyhow::Result<()> {
    Err(anyhow!("this build has no persistent store to rekey"))
}

/// What an executed call's terminal event says happened upstream: the status and whether it
/// succeeded, or `failed` for an execution that never got an answer. Blank for everything else.
fn audit_result(decision: &str, summary: &serde_json::Value) -> String {
    if decision == "error" && summary.get("outcome").is_some() {
        return "failed".into();
    }
    let Some(status) = summary["status"].as_u64() else { return String::new() };
    let ok = summary["ok"].as_bool().unwrap_or((200..300).contains(&status));
    format!("{status} {}", if ok { "ok" } else { "failed" })
}

/// Who resolved an approval, for the line under its row.
fn audit_approver(summary: &serde_json::Value) -> Option<String> {
    let method = summary["method"].as_str()?;
    let approver = summary["approver"].as_str();
    let name = summary["approver_name"].as_str();
    // A bearer approval through permaura.com carries the owner's id in `approver` for every member,
    // so the member's name is paired with their own id, never with that one.
    if method == "bearer" {
        if let Some(member) = summary["approver_actor"].as_str() {
            let who = name.unwrap_or("a workspace member");
            return Some(format!("by {who} (member {member}), permaura.com sign-in"));
        }
    }
    let who = match (method, name, approver) {
        ("device_signed", Some(name), Some(id)) => format!("{name} ({id})"),
        ("bearer", _, Some("operator")) => "the operator token".to_string(),
        ("bearer", _, Some(id)) if id.starts_with("operator:") => "a permaura.com sign-in".to_string(),
        (_, _, Some(id)) => id.to_string(),
        _ => "an unrecorded approver".to_string(),
    };
    let how = match method {
        "device_signed" => "signed on a device",
        "bearer" => "operator token",
        _ => return None,
    };
    Some(format!("by {who}, {how}"))
}

/// Why the audit log could not be read, in the terms an operator can act on. Never a claim about the
/// chain: the whole point is that this path has not seen it.
fn unreadable_log(ctx: &Ctx, status: reqwest::StatusCode, body: &serde_json::Value) -> String {
    let hint = match status.as_u16() {
        401 | 403 => "check the operator token (PERMAURA_TOKEN, or $PERMAURA_HOME/operator.token)",
        404 => "check --url: that address answered, but not as a gateway (a gateway before 1.3.2 listened on :8787)",
        _ => "check that this is the gateway you meant and that it is healthy",
    };
    let detail = body["error"].as_str().map(|e| format!(": {}", terminal_safe(e))).unwrap_or_default();
    format!(
        "could not read the audit log from {}: the gateway answered {status}{detail}. {hint}. This says nothing about whether the chain is intact.",
        ctx.url
    )
}

/// Text from the chain or an upstream, made safe to print: a control character in a device name,
/// a member name or an error message must not be able to move the cursor or rewrite the table.
fn terminal_safe(text: &str) -> String {
    text.chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let kept: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{kept}…")
    }
}

// ── approvals: pending / approve / deny ──────────────────────────────────────────

/// GET /v1/approvals?status=pending and render the queue as a table. This is the human
/// side of the loop: every held call (e.g. a HIGH-risk `github.pull_requests.create`)
/// shows up here waiting for a yes/no. Empty queue prints a friendly note.
pub async fn pending(ctx: &Ctx) -> anyhow::Result<()> {
    let resp = ctx
        .get("/v1/approvals?status=pending")
        .send()
        .await
        .with_context(|| format!("connecting to {}", ctx.url))?;
    if !resp.status().is_success() {
        return Err(anyhow!("gateway returned {} for /v1/approvals", resp.status()));
    }
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    let approvals = body["approvals"].as_array().cloned().unwrap_or_default();

    heading("Pending approvals");
    if approvals.is_empty() {
        println!("  No pending approvals.");
        return Ok(());
    }

    println!(
        "\n{:<16}  {:<30}  {:<20}  {:<8}  {:<6}  {}",
        "ID", "CAPABILITY", "RESOURCE", "RISK", "AGE", "MESSAGE"
    );
    println!("  {}", "-".repeat(106));
    for a in &approvals {
        println!(
            "{:<16}  {:<30}  {:<20}  {:<8}  {:<6}  {}",
            truncate(&terminal_safe(a["id"].as_str().unwrap_or("?")), 16),
            truncate(&terminal_safe(a["capability"].as_str().unwrap_or("?")), 30),
            truncate(&terminal_safe(a["resource"].as_str().unwrap_or("-")), 20),
            // The gateway's word, including its "unknown". A dash here would read as "no risk".
            truncate(&terminal_safe(a["risk"].as_str().unwrap_or("unknown")), 8),
            age_since(a["created_at"].as_i64().unwrap_or(0)),
            truncate(&terminal_safe(a["message"].as_str().unwrap_or("-")), 48),
        );
        if let Some(intent) = a["intent"].as_str() {
            println!("    agent says: {}", terminal_safe(intent));
        }
        for line in param_lines(&a["params_display"]) {
            println!("    {line}");
        }
    }
    // The binary is `permaura`, not `perma`. It was renamed when the CLI and the gateway became one
    // command, and three hints like this one were left naming a binary that no longer exists, this
    // one telling a reader to resolve a pending approval with something their shell cannot find.
    println!(
        "\n{} pending. Resolve with \x1b[1mpermaura approve <id>\x1b[0m or \x1b[1mpermaura deny <id>\x1b[0m.",
        approvals.len()
    );
    Ok(())
}

/// The held call's parameters as the gateway rendered them, one line each and never cut further,
/// so `permaura approve` is not a decision about a call the operator has not seen.
fn param_lines(display: &serde_json::Value) -> Vec<String> {
    let Ok(d) = serde_json::from_value::<permaura_relay::ApprovalDisplay>(display.clone()) else {
        return vec!["parameters not sent by this gateway".into()];
    };
    if d.version != permaura_relay::APPROVAL_DISPLAY_VERSION {
        return vec!["parameters in a format this CLI cannot show".into()];
    }
    if d.rows.is_empty() && d.omitted == 0 {
        return vec!["no parameters".into()];
    }
    let mut lines: Vec<String> = d
        .rows
        .iter()
        .map(|r| match r.state {
            permaura_relay::DisplayState::Shown => format!("{} = {}", r.path, r.value),
            state => format!("{} = {}  [{}]", r.path, r.value, state.as_str()),
        })
        .collect();
    if d.omitted > 0 {
        lines.push(format!("and {} more not shown", d.omitted));
    }
    if !d.complete {
        lines.push("not the whole call: GET /v1/approvals/<id> serves every parameter (params_display_full)".into());
    }
    lines
}

/// POST /v1/approvals with `approve: true`. This is the human saying yes: the gateway
/// runs the held upstream call and populates a redacted `result` (never the secret),
/// which we pretty-print so the operator sees exactly what executed.
pub async fn approve(ctx: &Ctx, approval_id: &str) -> anyhow::Result<()> {
    let approval = resolve_approval(ctx, approval_id, true).await?;
    let status = resolved_status(&approval, approval_id)?;
    if status != "approved" {
        return Err(not_as_asked(approval_id, "approved", status, &approval));
    }

    heading("Approval resolved");
    ok(&format!("{approval_id} → {status}"));

    if let Some(code) = approval["upstream_status"].as_u64() {
        println!("  upstream status: {code}");
    }
    match approval.get("result") {
        Some(serde_json::Value::Null) | None => {
            println!("  (no result returned)");
        }
        Some(result) => {
            heading("\nRedacted result");
            println!("{}", serde_json::to_string_pretty(result)?);
        }
    }
    Ok(())
}

/// POST /v1/approvals with `approve: false`. The held call is dropped; nothing executes
/// upstream. We confirm the resulting `denied` status.
pub async fn deny_approval(ctx: &Ctx, approval_id: &str) -> anyhow::Result<()> {
    let approval = resolve_approval(ctx, approval_id, false).await?;
    let status = resolved_status(&approval, approval_id)?;
    // A decision already made is returned as it stands, so a deny can come back approved, and by then the call has run.
    if status != "denied" {
        return Err(not_as_asked(approval_id, "denied", status, &approval));
    }

    heading("Approval resolved");
    deny(&format!("{approval_id} → {status}"));
    println!("  The held call was dropped; nothing ran upstream.");
    Ok(())
}

/// The status a resolved approval came back with, which is what `approve` and `deny` report rather than what they asked for.
fn resolved_status<'a>(approval: &'a serde_json::Value, approval_id: &str) -> anyhow::Result<&'a str> {
    approval["status"].as_str().filter(|s| !s.is_empty()).ok_or_else(|| {
        anyhow!("the gateway answered for approval '{approval_id}' without its status, so what became of it is unknown: `permaura pending` shows whether it is still waiting")
    })
}

fn not_as_asked(approval_id: &str, asked: &str, status: &str, approval: &serde_json::Value) -> anyhow::Error {
    let reason = approval["resolution_reason"]
        .as_str()
        .map(|r| format!(" ({})", terminal_safe(r)))
        .unwrap_or_default();
    anyhow!("approval '{approval_id}' was not {asked}: it is {}{reason}", terminal_safe(status))
}

/// POST /v1/approvals shared by `approve`/`deny`. Returns the approval JSON the gateway
/// echoes back (including the redacted `result` once an approval executes).
async fn resolve_approval(
    ctx: &Ctx,
    approval_id: &str,
    approve: bool,
) -> anyhow::Result<serde_json::Value> {
    let resp = ctx
        .post("/v1/approvals")
        .json(&json!({ "approval_id": approval_id, "approve": approve }))
        .send()
        .await
        .with_context(|| format!("connecting to {}", ctx.url))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    if !status.is_success() {
        let detail = body["error"]
            .as_str()
            .or_else(|| body["message"].as_str())
            .unwrap_or("unknown error");
        return Err(anyhow!(
            "gateway returned {status} resolving approval '{approval_id}': {detail}"
        ));
    }
    Ok(body)
}

// ── approver pair / revoke ──────────────────────────────────────────────────────

/// How long a pairing blob stays valid. Mirrors `PAIRING_FRESHNESS_MS` in the gateway's rest.rs.
/// Checked here too so a stale blob fails with "regenerate it on the device" rather than a 403.
const PAIRING_FRESHNESS_MS: i64 = 2 * 60 * 1000;

/// The header `POST /v1/approver-keys/pair` reads a hosted step-up ticket from. Mirrors
/// `PAIRING_TICKET_HEADER` in the gateway's rest.rs; header names are case-insensitive, so the
/// canonical casing here and the lowercase constant there name the same header.
const PAIRING_TICKET_HEADER: &str = "X-Permaura-Pairing-Ticket";

/// Shown for every malformed-blob failure: the operator's fix is the same in all of them.
const CORRUPT_BLOB: &str =
    "that is not a readable pairing blob: copy the whole base64url string the device showed \
     (or pipe it on stdin with --yes)";

/// The decoded pairing blob, exactly the body `POST /v1/approver-keys/pair` takes.
#[derive(Debug, serde::Deserialize, serde::Serialize)]
struct PairingBlob {
    approver_id: String,
    approver_pubkey: String,
    issued_at: i64,
    sig: String,
    /// Who the device approves for, when the device named someone. Outside the possession proof: the
    /// operator relaying the blob at the host is who vouches for it, which is why it is shown before
    /// they confirm.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    person: Option<String>,
}

/// `--person` over the blob's own: a name replaces it, and an empty one sends none, which a hosted gateway needs when the blob names someone other than the account whose ticket pairs it.
fn with_person(blob: &mut PairingBlob, person: Option<String>) {
    if let Some(person) = person {
        let person = person.trim();
        blob.person = (!person.is_empty()).then(|| person.to_string());
    }
}

/// `permaura approver pair --blob <base64url>`: trust a signing key that another device produced.
///
/// On a self-run or tunnelled gateway `/v1/approver-keys/pair` is refused from any non-loopback
/// caller, because a compromised control plane must never be able to enrol its own key and forge
/// approvals. That guard is about **who may call the endpoint**, not the integrity of the payload:
/// the blob carries a possession proof the gateway verifies against the very public key being
/// trusted, so relaying one that a phone or watch produced preserves the property exactly: a human
/// on the gateway's own host still performs the consent.
///
/// This is the only pairing path for a device that can never be loopback, and since the peer check
/// in `compute_is_remote` began classifying LAN callers as remote it is also the path a phone needs.
///
/// A hosted worker has no loopback client for anyone to be, so there the positional anchor is
/// replaced by an identity one: `--ticket` carries a single-use, device-bound proof that
/// permaura.com has just re-authenticated the account owning this gateway. That anchor enrols the
/// first device on an empty keyring by itself; every device after it is additionally held until a
/// device this gateway already trusts co-signs. Hence the third outcome this command has to speak
/// for: an approval id rather than a trusted key.
pub async fn approver_pair(
    ctx: &Ctx,
    blob: Option<String>,
    ticket: Option<String>,
    person: Option<String>,
    yes: bool,
) -> anyhow::Result<()> {
    // Reading the blob from stdin consumes it, so the confirmation prompt below would see EOF and
    // silently abort. Require the explicit --yes in that case: piping plus a typed --yes is itself
    // the deliberate act, and a consent prompt that can never be answered is worse than none.
    let from_stdin = blob.is_none();
    if from_stdin && !yes {
        return Err(anyhow!(
            "pass --yes when piping the blob on stdin: the prompt cannot read a reply from a \
             stdin that already carried the blob"
        ));
    }
    let raw = match blob {
        Some(b) => b,
        None => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading the pairing blob from stdin")?;
            buf
        }
    };
    let mut parsed = decode_pairing_blob(raw.trim())?;
    with_person(&mut parsed, person);

    let age_ms = now_ms() - parsed.issued_at;
    if age_ms.abs() > PAIRING_FRESHNESS_MS {
        return Err(anyhow!(
            "this pairing blob is {}s old and the gateway only accepts proofs within {}s: \
             generate a fresh one on the device and run this again",
            age_ms / 1000,
            PAIRING_FRESHNESS_MS / 1000
        ));
    }

    // Verify the possession proof locally as well. The gateway is the authority, but checking here
    // turns a truncated paste or a wrong-device blob into a precise message instead of a 403.
    let preimage = permaura_relay::approver_pairing_preimage(
        &parsed.approver_id,
        &parsed.approver_pubkey,
        parsed.issued_at,
    );
    permaura_relay::verify(&parsed.approver_pubkey, &preimage, &parsed.sig)
        .map_err(|_| anyhow!("the pairing proof did not verify: the blob is corrupt or truncated"))?;

    heading("Pair an approver device");
    println!("  approver id: {}", parsed.approver_id);
    println!("  public key:  {}", parsed.approver_pubkey);
    println!("  issued:      {}s ago", age_ms.max(0) / 1000);
    match parsed.person.as_deref() {
        Some(person) => println!("  person:      {person}"),
        None => {
            println!("  person:      none named, so it never counts as a second person toward a");
            println!("               two-person rule (pass --person to name who it approves for)");
        }
    }
    println!();
    println!("Your policies decide what needs a signature. Trusting this key lets that device");
    println!("provide one, so actions on the device-signed rung become resolvable from it; the rest");
    println!("can still be approved from the console and the CLI.");
    println!();
    println!("To require a signature for EVERY approval instead, raise the floor:");
    println!("  permaura approver floor device_signed");
    println!("Lowering it again has to be signed off from a paired device.");

    if !yes {
        print!("\nTrust this key? [y/N] ");
        std::io::Write::flush(&mut std::io::stdout()).ok();
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .context("reading confirmation")?;
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Aborted; nothing was trusted.");
            return Ok(());
        }
    }

    let ticket = TICKET_INPUT.input(ticket);
    answering_before_asking(ctx, &[&ticket]).await?;
    let ticket = ticket.read(TICKET_INPUT)?;
    let mut request = ctx.post("/v1/approver-keys/pair").json(&parsed);
    // Mirror the gateway's own filter on an empty header: sending one would turn "you need a
    // ticket" into "your ticket is unreadable", pointing the operator at the wrong problem.
    if let Some(t) = ticket.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        request = request.header(PAIRING_TICKET_HEADER, t);
    }
    let resp = request
        .send()
        .await
        .with_context(|| format!("connecting to {}", ctx.url))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));

    // 202 is a *success* status, so this has to be answered before the success path below: falling
    // through would announce a trusted approver for a device that is not trusted and may never be.
    if status.as_u16() == 202 {
        let approval_id = held_approval(&body, &format!("pairing {}", parsed.approver_id))?;
        heading("\nHeld for a co-signature");
        println!("  approval id: {approval_id}");
        println!();
        println!("This gateway already trusts a device, so the account alone cannot add");
        println!("another: a device already paired here has to confirm this enrolment from");
        println!("its own approval queue. `permaura approve` cannot stand in for it: the");
        println!("confirmation has to carry that device's signature, which is the whole");
        println!("point of the co-signature.");
        println!();
        if body["already_trusted"] == true {
            println!(
                "  {} stays trusted meanwhile, as nobody in particular, so it is not yet a second\n  person toward a two-person rule; `permaura pending` lists the hold.",
                parsed.approver_id
            );
        } else {
            println!(
                "  {} stays untrusted until then; `permaura pending` lists the hold.",
                parsed.approver_id
            );
        }
        return Err(Pending(vec![approval_id]).into());
    }

    if !status.is_success() {
        let detail = body["error"]
            .as_str()
            .or_else(|| body["message"].as_str())
            .unwrap_or("unknown error");
        // A plain auth failure and a step-up demand both render as 401. Only the second is fixed by
        // fetching a ticket, and telling someone whose bearer token is simply wrong to go and
        // re-authenticate a device pairing sends them a long way in the wrong direction.
        if status.as_u16() == 401 && detail.starts_with("step-up required") {
            let next = if ticket.is_some() {
                "That ticket was not accepted. Each one is single use, expires within minutes, \
                 and is bound to this exact device and key. Obtain a fresh one for this device \
                 and run this again."
            } else {
                "This gateway wants a pairing ticket. The Permaura phone app runs this step-up for \
                 you and is the easier route. To stay in the terminal, ask \
                 permaura.com for a ticket with an account session, then run this again with --ticket on its own and paste it when asked (or set PERMAURA_TICKET):\n  \
                 curl -X POST https://permaura.com/api/pairing-ticket \\\n    \
                 -H 'Authorization: Bearer <account token>' -H 'Content-Type: application/json' \\\n    \
                 -d '{\"gateway_id\":\"<id>\",\"purpose\":\"approver-pair\",\"approver_id\":\"<id>\",\
                 \"approver_pubkey\":\"<key>\",\"password\":\"<your password>\",\"totp_code\":\"<authenticator code>\"}'"
            };
            return Err(anyhow!("gateway returned 401: {detail}\n{next}"));
        }
        if status.as_u16() == 403 {
            return Err(anyhow!(
                "gateway returned 403: {detail}\n\
                 Trusting a signing key is anchored to something only this gateway's owner has, \
                 and which anchor applies depends on where the gateway runs.\n\
                 Self-run or tunnelled: the anchor is the gateway's own host. Run this there, \
                 against its 127.0.0.1 address; a tunnel, a reverse proxy or a LAN address is \
                 refused however good the token is, precisely so that reaching the control plane \
                 is not enough to enrol a key.\n\
                 Hosted: there is no host to run it on, so the anchor is a fresh re-authentication \
                 as the owning account. Obtain a pairing ticket from permaura.com and pass it \
                 with --ticket."
            ));
        }
        return Err(anyhow!("gateway returned {status} pairing the key: {detail}"));
    }

    ok(&format!("{} is now a trusted approver", parsed.approver_id));
    if let Some(codes) = body["recovery_codes"].as_array() {
        print_recovery_codes(codes);
    }
    Ok(())
}

/// Show freshly issued recovery codes. They are returned exactly once, so this is the owner's only
/// chance to copy them; the gateway keeps hashes.
fn print_recovery_codes(codes: &[serde_json::Value]) {
    heading("\nRecovery codes");
    println!("While this gateway trusts a device, lowering the approval floor and revoking that last");
    println!("device need its signature, and so do a vault export and every destructive change unless");
    println!("the floor has been lowered to `approve`. If the device is lost, ONE of these codes stands");
    println!("in for it, once each. Any earlier set is now dead.");
    println!("Write them down somewhere that is not this machine; they are not shown again.");
    println!();
    for code in codes {
        if let Some(c) = code.as_str() {
            println!("  {c}");
        }
    }
    println!();
    println!("Lost the device and the codes too? Where this gateway has remote access configured,");
    println!("re-authenticate at permaura.com for a recovery ticket and give it to --ticket. Where it");
    println!("does not, there is no third route: stop the gateway and edit its approver keyring on");
    println!("this host. `permaura approver floor --help` has the details.");
    println!();
    println!("Spent your codes while the device still works? `permaura approver codes` issues a fresh");
    println!("set on that device's signature, which is also how a gateway that was already paired");
    println!("before codes existed gets its first set.");
}

/// What `permaura approver codes` was given: one of the two authorities, or neither.
pub struct RecoveryCodesSpec {
    /// One of the current codes.
    pub recovery_code: Option<String>,
    /// The approver id whose trusted key signed the request.
    pub approver_id: Option<String>,
    /// Unix ms the signature was made at.
    pub issued_at: Option<i64>,
    /// base64 ed25519 signature over the device-control preimage.
    pub sig: Option<String>,
    /// The gateway audience a v2 signature binds; absent for a v1 signature.
    pub audience: Option<String>,
    /// A `recovery-codes-issue` step-up ticket, for a request from off the gateway's machine.
    pub ticket: Option<String>,
}

/// Issue a fresh set of recovery codes and print them once.
///
/// The signature fields are relayed rather than produced: the private key lives on the paired device,
/// so the CLI can carry a signature somebody hands it and cannot make one.
pub async fn approver_codes(ctx: &Ctx, spec: RecoveryCodesSpec) -> anyhow::Result<()> {
    let ticket = TICKET_INPUT.input(spec.ticket);
    let code = RECOVERY_CODE_INPUT.input(spec.recovery_code);
    answering_before_asking(ctx, &[&ticket, &code]).await?;
    let ticket = ticket.read(TICKET_INPUT)?;
    let recovery_code = code.read(RECOVERY_CODE_INPUT)?;
    let signed = spec.approver_id.is_some() || spec.issued_at.is_some() || spec.sig.is_some() || spec.audience.is_some();
    if signed && recovery_code.as_deref().is_some_and(|c| !c.trim().is_empty()) {
        return Err(anyhow!(
            "give a recovery code or a device signature (--approver-id, --issued-at, --sig), not both: the gateway reads only one of them"
        ));
    }
    let mut body = json!({});
    for (key, value) in [
        ("approver_id", spec.approver_id.as_deref().map(|v| json!(v.trim()))),
        ("issued_at", spec.issued_at.map(|v| json!(v))),
        ("sig", spec.sig.as_deref().map(|v| json!(v.trim()))),
        ("audience", spec.audience.as_deref().map(|v| json!(v.trim()))),
    ] {
        if let Some(value) = value {
            body[key] = value;
        }
    }
    let mut request = ctx.post("/v1/recovery-codes").json(&body);
    if let Some(t) = ticket.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        request = request.header(PAIRING_TICKET_HEADER, t);
    }
    let resp = with_recovery_headers(request, recovery_code.as_deref())
        .send()
        .await
        .with_context(|| format!("connecting to {}", ctx.url))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    if !status.is_success() {
        let detail = body["error"].as_str().unwrap_or("unknown error");
        if status.as_u16() == 401 && detail.starts_with("step-up required") {
            let next = if ticket.is_some() {
                "That ticket was not accepted: each one is single use and expires within minutes. Obtain a fresh `recovery-codes-issue` ticket and run this again."
            } else {
                "Issuing recovery codes from anywhere but the gateway's own machine takes a fresh `recovery-codes-issue` ticket from permaura.com: run this again with --ticket on its own and paste it when asked (or set PERMAURA_TICKET), or run it on the gateway's own machine."
            };
            return Err(anyhow!("gateway returned 401: {detail}\n{next}"));
        }
        return Err(anyhow!("gateway returned {status}: {detail}"));
    }
    match body["recovery_codes"].as_array() {
        Some(codes) => print_recovery_codes(codes),
        None => return Err(anyhow!("the gateway returned no codes: {body}")),
    }
    Ok(())
}

/// Attach the recovery headers a recovery control accepts. A blank code is dropped rather than sent,
/// for the same reason a blank ticket is: it would turn "you need a code" into "your code is
/// unreadable".
fn with_recovery_headers(mut request: Req, recovery_code: Option<&str>) -> Req {
    if let Some(code) = recovery_code.map(str::trim).filter(|c| !c.is_empty()) {
        request = request.header("X-Permaura-Recovery-Code", code);
    }
    request
}

/// A one-time credential a command can be handed: a recovery code or a step-up ticket. Typed after its flag it sits in shell history and, while the command runs, in the process list, where anything running as the owner can read it, so the flag on its own asks for it instead.
#[derive(Clone, Copy)]
struct OneTime {
    flag: &'static str,
    env: &'static str,
    what: &'static str,
    prompt: &'static str,
}

const RECOVERY_CODE_INPUT: OneTime = OneTime {
    flag: "--recovery-code",
    env: "PERMAURA_RECOVERY_CODE",
    what: "recovery code",
    prompt: "Recovery code (input hidden): ",
};

const TICKET_INPUT: OneTime = OneTime {
    flag: "--ticket",
    env: "PERMAURA_TICKET",
    what: "ticket",
    prompt: "Ticket from permaura.com (input hidden): ",
};

/// Where a [`OneTime`] value comes from, decided before anything is asked.
enum OneTimeInput {
    Given(String),
    Ask,
    Absent,
}

impl OneTime {
    /// Read the parsed flag: a value typed after it is used and warned about, the flag on its own is the environment variable or else a masked prompt, and no flag is the environment variable alone.
    fn input(self, flag: Option<String>) -> OneTimeInput {
        let env = std::env::var(self.env).ok().map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
        match flag.map(|v| v.trim().to_string()) {
            Some(typed) if !typed.is_empty() => {
                eprintln!(
                    "\x1b[33m!\x1b[0m warning: a {what} typed after {flag} is in your shell history and, while this runs, in the process list. Give {flag} on its own to be asked for it with the input hidden, or set {env}. If this run does not spend it, remove it from your history.",
                    what = self.what,
                    flag = self.flag,
                    env = self.env,
                );
                OneTimeInput::Given(typed)
            }
            Some(_) => env.map_or(OneTimeInput::Ask, OneTimeInput::Given),
            None => env.map_or(OneTimeInput::Absent, OneTimeInput::Given),
        }
    }
}

impl OneTimeInput {
    fn asks(&self) -> bool {
        matches!(self, OneTimeInput::Ask)
    }

    /// The value, asking for it now when the flag was given on its own. A blank answer is no value, as a blank flag value always was.
    fn read(self, kind: OneTime) -> anyhow::Result<Option<String>> {
        match self {
            OneTimeInput::Given(value) => Ok(Some(value)),
            OneTimeInput::Absent => Ok(None),
            OneTimeInput::Ask => {
                if !std::io::stdin().is_terminal() {
                    return Err(anyhow!(
                        "{} on its own asks for the {}, and there is no terminal to ask on: set {} instead",
                        kind.flag,
                        kind.what,
                        kind.env
                    ));
                }
                let value = prompt_masked(kind.prompt)?;
                Ok(Some(value.trim().to_string()).filter(|v| !v.is_empty()))
            }
        }
    }
}

/// Refuse before asking for a one-time value when nothing is answering, so a typed code is never left unspent for a reason that was knowable first.
async fn answering_before_asking(ctx: &Ctx, inputs: &[&OneTimeInput]) -> anyhow::Result<()> {
    if inputs.iter().any(|i| i.asks()) && !ctx.is_healthy().await {
        return Err(anyhow!(
            "nothing is answering at {}: start the gateway, or name it with --url, then run this again",
            ctx.url
        ));
    }
    Ok(())
}

/// Render a 202 from a recovery control: what is held, and every way out of it.
fn print_recovery_hold(body: &serde_json::Value) {
    heading("Held for a device signature");
    println!(
        "  {}",
        body["message"]
            .as_str()
            .unwrap_or("Confirm this change on a device this gateway already trusts.")
    );
    if let Some(id) = body["approval_id"].as_str() {
        println!("  approval: {id}");
    }
    if let Some(hint) = body["recovery"].as_str() {
        println!();
        println!("  {hint}");
    }
    // The gateway's own words about who it told, which is deliberately not "everyone".
    if let Some(notified) = body["notified"].as_str() {
        println!();
        println!("  {notified}");
    }
}

/// Decode the base64url pairing blob a device rendered (as a QR code or a paste). Accepts the
/// padded and unpadded forms, and a bare JSON blob for anyone assembling one by hand.
fn decode_pairing_blob(raw: &str) -> anyhow::Result<PairingBlob> {
    use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
    use base64::Engine as _;

    if raw.starts_with('{') {
        return serde_json::from_str(raw).context("parsing the pairing blob as JSON");
    }
    let compact: String = raw.split_whitespace().collect();
    let bytes = URL_SAFE_NO_PAD
        .decode(compact.trim_end_matches('='))
        .or_else(|_| URL_SAFE.decode(&compact))
        .map_err(|_| anyhow!(CORRUPT_BLOB))?;
    // A truncated or mistyped blob usually breaks here rather than at the signature check, and the
    // underlying serde message ("invalid unicode code point at line 1 column 224") tells the
    // operator nothing they can act on.
    serde_json::from_slice(&bytes).map_err(|_| anyhow!(CORRUPT_BLOB))
}

/// `permaura approver list`: every approver key the gateway trusts, from the KEYRING.
///
/// Deliberately not the device list. A device joins the push registry by calling
/// `POST /v1/devices/enroll`, which the phone does only after push registration succeeds and an
/// Apple Watch never does; a key joins the keyring by being paired. So a key can be fully trusted to
/// sign approvals and invisible everywhere that reads the registry, and a key nobody can see is a
/// key nobody revokes, which on a hosted worker with the sticky device-signed floor is how a lost
/// phone turns into a control plane no one can reach. Revocation takes an approver id and needs no
/// device row, so this listing is the whole of what was missing.
pub async fn approver_list(ctx: &Ctx) -> anyhow::Result<()> {
    let resp = ctx
        .get("/v1/approver-keys")
        .send()
        .await
        .with_context(|| format!("connecting to {}", ctx.url))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    if !status.is_success() {
        let detail = body["error"].as_str().unwrap_or("unknown error");
        return Err(anyhow!("gateway returned {status} listing approver keys: {detail}"));
    }

    heading("Approver keys");
    let keys = body["keys"].as_array().cloned().unwrap_or_default();
    if keys.is_empty() {
        println!("  Nothing paired. Every relayed approval fails closed until a device is enrolled.");
        return Ok(());
    }
    for k in &keys {
        let approver_id = k["approver_id"].as_str().unwrap_or("?");
        let key_fp = k["key_fp"].as_str().unwrap_or("?");
        let trusted = k["trusted"].as_bool().unwrap_or(false);
        let name = k["name"].as_str().unwrap_or("");
        let label = if name.is_empty() { String::new() } else { format!("  {name}") };
        if trusted {
            ok(&format!("{approver_id}  {key_fp}{label}"));
        } else {
            deny(&format!("{approver_id}  {key_fp}  revoked{label}"));
        }
        if k["device_id"].is_null() {
            println!("      no device registered for notifications: manage it from here");
        }
    }
    println!();
    println!("  approval floor: {}", body["approval_floor"].as_str().unwrap_or("?"));
    Ok(())
}

/// `permaura approver revoke <id>`: untrust a device's signing key.
///
/// From anywhere but a self-run gateway's own machine this takes an `approver-revoke` ticket bound to
/// the approver id (`oauth::TicketPurpose::ApproverRevoke`), so a pairing ticket cannot be spent here.
/// Revoking the last trusted key on a self-run gateway also takes recovery authority (see
/// `--recovery-code`).
///
/// The owner of a hosted worker whose only device is lost recovers with two step-ups: revoke the
/// dead device with one ticket, then pair its replacement with another.
pub async fn approver_revoke(
    ctx: &Ctx,
    approver_id: &str,
    ticket: Option<String>,
    recovery_code: Option<String>,
) -> anyhow::Result<()> {
    let ticket = TICKET_INPUT.input(ticket);
    let recovery_code = RECOVERY_CODE_INPUT.input(recovery_code);
    answering_before_asking(ctx, &[&ticket, &recovery_code]).await?;
    let ticket = ticket.read(TICKET_INPUT)?;
    let recovery_code = recovery_code.read(RECOVERY_CODE_INPUT)?;
    // Mirror the gateway's own filter on an empty header: sending one would turn "you need a
    // ticket" into "your ticket is unreadable", pointing the operator at the wrong problem.
    let ticket = ticket.as_deref().map(str::trim).filter(|t| !t.is_empty());
    let mut request = ctx.delete(&format!("/v1/approver-keys/{approver_id}"));
    if let Some(t) = ticket {
        request = request.header(PAIRING_TICKET_HEADER, t);
    }
    let request = with_recovery_headers(request, recovery_code.as_deref());
    let resp = request
        .send()
        .await
        .with_context(|| format!("connecting to {}", ctx.url))?;
    let status = resp.status();
    if status.as_u16() == 202 {
        let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
        let approval_id = held_approval(&body, &format!("revoking '{approver_id}'"))?;
        print_recovery_hold(&body);
        println!("  {approver_id} stays trusted until then.");
        return Err(Pending(vec![approval_id]).into());
    }
    if !status.is_success() {
        let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
        let detail = body["error"]
            .as_str()
            .or_else(|| body["message"].as_str())
            .unwrap_or("unknown error");
        // A plain auth failure and a step-up demand both render as 401. Only the second is fixed by
        // fetching a ticket, and telling someone whose bearer token is simply wrong to go and
        // re-authenticate for a revocation sends them a long way in the wrong direction.
        if status.as_u16() == 401 && detail.starts_with("step-up required") {
            let next = if ticket.is_some() {
                "That ticket was not accepted. Each one is single use, expires within minutes and \
                 names one approver id, and a pairing ticket cannot stand in for it. Obtain a fresh \
                 revocation ticket for this device and run this again."
            } else {
                "Revoking a device from anywhere but the gateway's own machine takes a fresh \
                 step-up. The console (Workspace > Devices) and the phone app both run this ceremony \
                 for you. To stay in the terminal, ask permaura.com for a ticket, then run this again \
                 with --ticket on its own and paste it when asked (or set PERMAURA_TICKET):\n  \
                 curl -X POST https://permaura.com/api/pairing-ticket \\\n    \
                 -H 'Authorization: Bearer <account token>' -H 'Content-Type: application/json' \\\n    \
                 -d '{\"gateway_id\":\"<id>\",\"purpose\":\"approver-revoke\",\"approver_id\":\"<approver id>\",\"password\":\"<your password>\",\"totp_code\":\"<authenticator code>\"}'\n\
                 Pairing a replacement needs a second, separate ticket."
            };
            return Err(anyhow!("gateway returned 401: {detail}\n{next}"));
        }
        return Err(anyhow!("gateway returned {status} revoking '{approver_id}': {detail}"));
    }
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    deny(&format!("{approver_id} is no longer a trusted approver"));
    if let Some(note) = body["note"].as_str() {
        println!("  {}", terminal_safe(note));
    }
    println!("  Unsigned approvals stay refused: pair a replacement device to keep approving.");
    Ok(())
}

/// `permaura approver floor <approve|device_signed|default>`: set what a bare operator bearer may
/// resolve on this gateway.
///
/// The write half of the floor that `approver_list` already prints. Lowering is the reason it
/// exists: pairing any device flips the floor to `device_signed`, and the enrolment flag that does
/// it stays set through revocation, so unpairing never restores console and CLI approvals on its
/// own. Until this command there was no way back that did not involve hand-rolling a request against
/// an endpoint nothing mentioned.
///
/// Raising is fail-safe and accepted from anywhere. Lowering is a trust-root relaxation and on a
/// self-run or tunnelled gateway is loopback-only, which is why the 403 below spells out where to
/// run it rather than just relaying the refusal.
pub async fn approver_floor(
    ctx: &Ctx,
    floor: &str,
    recovery_code: Option<String>,
    ticket: Option<String>,
) -> anyhow::Result<()> {
    let floor = floor.trim();
    if !matches!(floor, "approve" | "device_signed" | "default") {
        return Err(anyhow!(
            "unknown floor '{floor}': expected one of: approve, device_signed, default"
        ));
    }
    let ticket = TICKET_INPUT.input(ticket);
    let recovery_code = RECOVERY_CODE_INPUT.input(recovery_code);
    answering_before_asking(ctx, &[&ticket, &recovery_code]).await?;
    let ticket = ticket.read(TICKET_INPUT)?;
    let recovery_code = recovery_code.read(RECOVERY_CODE_INPUT)?;
    let mut request = ctx.put("/v1/approval-floor").json(&json!({ "floor": floor }));
    if let Some(t) = ticket.as_deref().map(str::trim).filter(|t| !t.is_empty()) {
        request = request.header(PAIRING_TICKET_HEADER, t);
    }
    let resp = with_recovery_headers(request, recovery_code.as_deref())
        .send()
        .await
        .with_context(|| format!("connecting to {}", ctx.url))?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    if !status.is_success() {
        let detail = body["error"]
            .as_str()
            .or_else(|| body["message"].as_str())
            .unwrap_or("unknown error");
        if status.as_u16() == 403 && floor != "device_signed" {
            return Err(anyhow!(
                "gateway returned 403: {detail}\nLowering the floor re-opens approvals to anything \
                 holding an operator token, so a self-run or tunnelled gateway takes it only from \
                 its own host. Run this on the machine the gateway is on, against its loopback \
                 address:\n  permaura --url http://127.0.0.1:7376 approver floor {floor}"
            ));
        }
        return Err(anyhow!("gateway returned {status} setting the approval floor: {detail}"));
    }
    // 202: a device is trusted, so the lowering is held for it and nothing has moved yet. Reporting
    // the requested floor here would be a lie the operator only catches when the next console
    // approval is still refused.
    if status.as_u16() == 202 {
        let approval_id = held_approval(&body, &format!("setting the approval floor to {floor}"))?;
        print_recovery_hold(&body);
        return Err(Pending(vec![approval_id]).into());
    }
    let effective = applied_id(&body, "approval_floor", &format!("setting the approval floor to {floor}"))?;
    if body["signed_approvals_required"].as_bool().unwrap_or(false) {
        ok(&format!("approval floor: {effective}"));
        println!("  Every approval now needs a signature from a paired device.");
    } else {
        ok(&format!("approval floor: {effective}"));
        println!(
            "  The web console, CLI and phone can resolve approve-tier approvals again. Actions a \
             policy puts on the device_signed rung still need a paired device."
        );
    }
    Ok(())
}

fn now_ms() -> i64 {
    (OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000) as i64
}

// ── secret / passphrase input ────────────────────────────────────────────────────

/// Read one secret line from the terminal with the input masked.
///
/// Terminal echo is off for the duration, so nothing lands on screen, in a scrollback buffer, or in
/// a screen recording. Fails rather than falling back to an echoing read: a prompt that promises not
/// to show what you type and then shows it is worse than no promise.
fn prompt_masked(prompt: &str) -> anyhow::Result<String> {
    if !std::io::stdin().is_terminal() {
        return Err(anyhow!(
            "{prompt}cannot be read: stdin is not a terminal, so the input could not be masked"
        ));
    }
    rpassword::prompt_password(prompt).context("reading masked input from the terminal")
}

/// Prompt for a passphrase that will protect something, asking twice.
///
/// A mistyped passphrase here produces a file nobody can ever open, and there is no copy on our side
/// to fall back to, so the confirmation is not ceremony.
fn prompt_new_passphrase() -> anyhow::Result<String> {
    let first = prompt_masked("Choose a passphrase for the bundle: ")?;
    if first.trim().is_empty() {
        return Err(anyhow!("the passphrase cannot be empty: it is the only thing protecting the bundle"));
    }
    let again = prompt_masked("Repeat the passphrase: ")?;
    if first != again {
        return Err(anyhow!("the two passphrases do not match; nothing was written"));
    }
    Ok(first)
}

/// The environment variable that supplies the bundle passphrase to `vault verify` without a terminal.
const BUNDLE_PASSPHRASE_ENV: &str = "PERMAURA_BUNDLE_PASSPHRASE";

/// Resolve the passphrase for `vault verify`: the env var if set, otherwise the masked terminal
/// prompt. Only `verify` reads it; export stays interactive-only, because a mistyped export
/// passphrase seals a file nobody can ever open and there is no copy on our side to fall back to.
///
/// Verify is the read-only, repeatable check a backup deserves, so it has to run from CI or a cron
/// script where there is no tty. When neither source is available the error names the env var, so a
/// script that hit the old "stdin is not a terminal" wall is told the way past it rather than left to
/// drive a PTY, which is what the export/restore drill had to do.
fn verify_passphrase() -> anyhow::Result<String> {
    match std::env::var(BUNDLE_PASSPHRASE_ENV) {
        Ok(value) => {
            if value.trim().is_empty() {
                return Err(anyhow!(
                    "{BUNDLE_PASSPHRASE_ENV} is set but empty; it must hold the bundle passphrase"
                ));
            }
            Ok(value)
        }
        Err(_) if std::io::stdin().is_terminal() => prompt_masked("Bundle passphrase: "),
        Err(_) => Err(anyhow!(
            "no passphrase to try: stdin is not a terminal, so it cannot be typed. Set \
             {BUNDLE_PASSPHRASE_ENV} to verify a bundle from a script or from CI."
        )),
    }
}

/// Ask the operator to type `yes` before something irreversible happens. Anything else is a no.
pub(super) fn confirm(question: &str) -> anyhow::Result<bool> {
    use std::io::Write;
    print!("{question} [type 'yes' to continue]: ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer).context("reading confirmation from stdin")?;
    Ok(answer.trim().eq_ignore_ascii_case("yes"))
}

// ── vault add / list ────────────────────────────────────────────────────────────

/// Add a secret. The value is read from `--env-var <NAME>` or, failing that, stdin.
/// It is never accepted as a CLI argument and never echoed.
pub async fn vault_add(ctx: &Ctx, id: &str, env_var: Option<String>) -> anyhow::Result<()> {
    let value = match env_var {
        Some(name) => std::env::var(&name)
            .with_context(|| format!("environment variable {name} is not set"))?,
        // Interactively the terminal echoes a plain stdin read, so the old "it will not be echoed"
        // promise was false; masked input is what makes it true. A pipe still reads straight through.
        None if std::io::stdin().is_terminal() => prompt_masked("Secret value (input hidden): ")?,
        None => {
            eprintln!("Reading the secret value from stdin…");
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .context("reading secret from stdin")?;
            buf.trim_end_matches(['\n', '\r']).to_string()
        }
    };
    if value.is_empty() {
        return Err(anyhow!("refusing to store an empty secret value"));
    }

    let what = format!("storing secret '{id}'");
    let keep = |e: anyhow::Error| anyhow!("{e:#}. Keep your copy of the value: the gateway did not confirm storing it");
    let resp = ctx
        .post("/v1/secrets")
        .json(&json!({ "id": id, "value": value }))
        .send()
        .await
        .map_err(keep)?;
    let stored = match written(resp, &what).await.map_err(keep)? {
        Written::Held { approval_id, body } => {
            report_held(&what, &body);
            println!("  The value already stored under {id} stays in use meanwhile; keep your copy of the new one until it is approved.");
            return Err(Pending(vec![approval_id]).into());
        }
        Written::Applied(body) => applied_id(&body, "secret_id", &what).map_err(keep)?,
    };
    heading("Secret stored");
    ok(&format!("{stored} (value sealed, never echoed)"));
    Ok(())
}

/// `GET /v1/secrets`: every secret an operator can name, by the id `vault add`, a connection's credential and a rotation take, with where it is held when that is not this gateway's own vault. Values are never listed: the route carries none.
pub async fn vault_list(ctx: &Ctx) -> anyhow::Result<()> {
    let resp = ctx.get("/v1/secrets").send().await?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    if !status.is_success() {
        return Err(anyhow!(
            "gateway returned {status} listing secrets: {}",
            body["error"].as_str().unwrap_or("unknown error")
        ));
    }
    let secrets = body["secrets"]
        .as_array()
        .ok_or_else(|| anyhow!("the gateway's answer named no secrets list: {body}"))?;
    heading("Vault");
    if secrets.is_empty() {
        println!("  No secrets are stored. Use `permaura vault add <id>` to store one (value from stdin or an env var).");
        return Ok(());
    }
    for secret in secrets {
        let id = terminal_safe(secret["id"].as_str().unwrap_or("?"));
        let labels: Vec<String> = secret["labels"]
            .as_array()
            .map(|l| l.iter().filter_map(|v| v.as_str()).map(terminal_safe).collect())
            .unwrap_or_default();
        let held = match secret["location"].as_str() {
            Some("kms") => "  (held by KMS)".to_string(),
            Some("infisical") => "  (held by Infisical)".to_string(),
            Some("local_vault") | None => String::new(),
            Some(other) => format!("  (held by {})", terminal_safe(other)),
        };
        let labels = if labels.is_empty() { String::new() } else { format!("  [{}]", labels.join(", ")) };
        println!("  {id}{labels}{held}");
    }
    println!("  Values are never listed: a secret in this gateway's vault is sealed there, and one held by KMS or Infisical is fetched only at call time.");
    Ok(())
}

// ── vault export / import ───────────────────────────────────────────────────────

/// What an operator is told before a bundle is written.
/// Printed at the point of export rather than left to a changelog, because it is a real change in
/// posture rather than a footnote.
fn print_export_posture_warning() {
    println!(
        "  A bundle takes your credentials out of whatever is protecting them today.\n\
         \n\
         Secrets held in a cloud KMS or an external vault are resolved to plaintext to build the\n\
         bundle and then re-sealed under your passphrase alone. Once the file exists, the KMS no\n\
         longer stands between an attacker and those credentials: your passphrase does. That is\n\
         inherent, not a shortcut. You cannot take a secret out of the cloud and leave its key\n\
         behind.\n\
         \n\
         Keep the file where you would keep the credentials themselves, and keep the passphrase\n\
         somewhere else. Permaura stores neither, so a lost passphrase is a lost bundle.\n"
    );
}

/// `permaura vault export --out <file>`: prompt for a passphrase, ask the gateway to seal a bundle,
/// and write it out owner-only.
pub async fn vault_export(ctx: &Ctx, out: &str) -> anyhow::Result<()> {
    let path = std::path::Path::new(out);
    if path.exists() {
        return Err(anyhow!(
            "{out} already exists: choose another path. A bundle is never written over in place."
        ));
    }

    heading("Export the vault");
    print_export_posture_warning();
    let passphrase = prompt_new_passphrase()?;

    let (mut status, mut body) = request_export(ctx, json!({ "passphrase": passphrase })).await?;
    if status == reqwest::StatusCode::ACCEPTED {
        let approval_id = body["approval_id"].as_str().unwrap_or_default().to_string();
        let resume_secret = body["resume_secret"].as_str().unwrap_or_default().to_string();
        if approval_id.is_empty() || resume_secret.is_empty() {
            return Err(anyhow!("the gateway held the export but did not say how to collect it; nothing was written"));
        }
        wait_for_export_approval(ctx, &approval_id, body["expires_at"].as_i64()).await?;
        (status, body) = request_export(
            ctx,
            json!({ "passphrase": passphrase, "approval_id": approval_id, "resume_secret": resume_secret }),
        )
        .await?;
    }
    if status != reqwest::StatusCode::OK || body["format"] != permaura_core::BUNDLE_FORMAT {
        return Err(anyhow!(
            "export failed ({status}): {}; nothing was written",
            body["error"].as_str().unwrap_or("the gateway did not return a bundle")
        ));
    }

    let bytes = serde_json::to_vec_pretty(&body)?;
    permaura_core::write_secret_file(path, &bytes)
        .with_context(|| format!("writing {out}"))?;

    ok(&format!("bundle written to {out}"));
    println!("  Owner-only permissions; the passphrase was not stored anywhere.");
    println!("  Restore it with \x1b[1mpermaura vault import {out}\x1b[0m.");
    Ok(())
}

async fn request_export(ctx: &Ctx, request: serde_json::Value) -> anyhow::Result<(reqwest::StatusCode, serde_json::Value)> {
    let resp = ctx
        .post("/v1/vault/export")
        .json(&request)
        .send()
        .await
        .with_context(|| format!("connecting to {}", ctx.url))?;
    let status = resp.status();
    Ok((status, resp.json().await.unwrap_or(json!({}))))
}

/// Wait while a paired device decides a held export, and return once it is approved.
async fn wait_for_export_approval(ctx: &Ctx, approval_id: &str, expires_at: Option<i64>) -> anyhow::Result<()> {
    println!("  This gateway has a paired device, so the export waits for it.");
    println!("  Confirm it there (approval {approval_id}). Waiting...");
    let deadline = expires_at.unwrap_or_else(|| permaura_gateway::service::now_ms() + permaura_gateway::service::EXPORT_APPROVAL_TTL_MS);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let resp = ctx
            .get(&format!("/v1/approvals/{approval_id}"))
            .send()
            .await
            .with_context(|| format!("connecting to {}", ctx.url))?;
        let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
        match body["status"].as_str() {
            Some("approved") => return Ok(()),
            Some("pending") if permaura_gateway::service::now_ms() < deadline => continue,
            Some("pending") => {
                return Err(anyhow!("the export was not confirmed before approval {approval_id} expired; nothing was written"))
            }
            Some(other) => return Err(anyhow!("the export was {other} on the device; nothing was written")),
            None => {
                return Err(anyhow!(
                    "could not read approval {approval_id}: {}; nothing was written",
                    body["error"].as_str().unwrap_or("unexpected response")
                ))
            }
        }
    }
}

/// Options for `permaura vault import`.
pub struct VaultImportSpec {
    /// Path to the bundle file.
    pub file: String,
    /// Overwrite ids that already exist here, instead of leaving them alone.
    pub replace: bool,
    /// Opt in to importing capabilities that run a local program.
    pub allow_command_capabilities: bool,
}

/// `permaura vault import <file>`: preview the bundle, show what would change, and apply it only
/// after the operator confirms. The preview is a separate request, so a wrong passphrase fails
/// before anything is written.
pub async fn vault_import(ctx: &Ctx, spec: VaultImportSpec) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(&spec.file)
        .with_context(|| format!("reading {}", spec.file))?;
    let bundle: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("{} is not a Permaura vault bundle (invalid JSON)", spec.file))?;

    heading("Import a vault bundle");
    let passphrase = prompt_masked("Bundle passphrase: ")?;

    let resp = ctx
        .post("/v1/vault/import/preview")
        .json(&json!({ "bundle": bundle, "passphrase": passphrase }))
        .send()
        .await
        .with_context(|| format!("connecting to {}", ctx.url))?;
    let status = resp.status();
    let manifest: serde_json::Value = resp.json().await.unwrap_or(json!({}));
    if !status.is_success() {
        return Err(anyhow!(
            "the bundle was not imported: {}",
            manifest["error"].as_str().unwrap_or("unknown error")
        ));
    }
    let risky = print_manifest(&manifest, spec.replace);

    if risky && !spec.allow_command_capabilities {
        return Err(anyhow!(
            "this bundle carries capabilities that run a program on this machine. Re-run with \
             --allow-command-capabilities if that is what you intend."
        ));
    }
    if !confirm("\nImport this bundle?")? {
        println!("Nothing was imported.");
        return Ok(());
    }

    let resp = ctx
        .post("/v1/vault/import")
        .json(&json!({
            "bundle": bundle,
            "passphrase": passphrase,
            "on_conflict": if spec.replace { "replace" } else { "skip" },
            "allow_command_capabilities": spec.allow_command_capabilities,
        }))
        .send()
        .await?;
    let what = format!("importing {}", spec.file);
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    // An import that holds credentials for a device still writes the rest of the bundle, so its 202 lists every hold under `held` rather than naming the one approval other writes do.
    if status == reqwest::StatusCode::ACCEPTED && body["held"].is_array() {
        return partly_held_import(&what, &body);
    }
    let outcome = match judge_written(status, body, &what)? {
        Written::Held { approval_id, body } => return Err(held(&what, approval_id, &body)),
        Written::Applied(outcome) => outcome,
    };
    if !outcome["written"].is_object() {
        return Err(anyhow!("{what}: the gateway answered success without saying what it wrote, so what was imported is unconfirmed"));
    }

    heading("\nImported");
    print_import_outcome(&outcome);
    Ok(())
}

fn print_import_outcome(outcome: &serde_json::Value) {
    print_counts("  written", &outcome["written"]);
    print_counts("  skipped", &outcome["skipped"]);
    for reason in outcome["refused"].as_array().unwrap_or(&vec![]) {
        deny(&terminal_safe(reason.as_str().unwrap_or("?")));
    }
}

/// Report an import that wrote what it could and held each credential that fills a connection already here: what was written, skipped and refused, then every hold by credential and approval, ending pending. A hold naming no approval cannot be followed up, so the answer is then reported as unconfirmed rather than pending.
fn partly_held_import(what: &str, body: &serde_json::Value) -> anyhow::Result<()> {
    let entries = body["held"].as_array().map(Vec::as_slice).unwrap_or_default();
    let holds: Vec<(String, Option<String>)> = entries
        .iter()
        .filter_map(|entry| {
            let approval_id = entry["approval_id"].as_str().filter(|id| !id.is_empty())?;
            Some((terminal_safe(approval_id), entry["secret_id"].as_str().map(terminal_safe)))
        })
        .collect();
    let named: Vec<&str> = holds.iter().map(|(id, _)| id.as_str()).collect();
    let followed_up = if named.is_empty() {
        "`permaura pending` lists whatever it holds".to_string()
    } else {
        format!("approvals {} are held; `permaura pending` lists them", named.join(", "))
    };
    if !body["written"].is_object() {
        return Err(anyhow!(
            "{what}: the gateway answered 202 Accepted without saying what it wrote, so what was imported is unconfirmed ({followed_up})"
        ));
    }
    if entries.is_empty() || holds.len() != entries.len() {
        let missing = if entries.is_empty() { "without listing anything it held" } else { "with a held credential that names no approval" };
        return Err(anyhow!(
            "{what}: the gateway answered 202 Accepted {missing}, so nothing can follow it up and it may never apply ({followed_up})"
        ));
    }

    heading("\nImported in part");
    print_import_outcome(body);
    heading("\nHeld for a device signature");
    println!("  Confirm each credential below on a device this gateway already trusts.");
    for (approval_id, secret_id) in &holds {
        match secret_id {
            Some(secret_id) => println!("  credential {secret_id}: approval {approval_id}"),
            None => println!("  approval {approval_id}"),
        }
    }
    if let Some(notified) = entries[0]["notified"].as_str() {
        println!();
        println!("  {}", terminal_safe(notified));
    }
    println!("  Not applied yet: each held credential takes effect once a paired device approves it.");
    println!("  `permaura pending` lists them until then.");
    Err(Pending(holds.into_iter().map(|(id, _)| id).collect()).into())
}

/// Open a bundle offline and describe what is in it. Writes nothing and talks to no gateway.
///
/// The gateway cannot tell a wrong passphrase from a damaged file, and says so in one sentence
/// covering both, so "is my file good, or is my passphrase wrong?" had no answer short of running an
/// import against a live gateway. This answers it on the machine holding the file.
pub fn vault_verify(file: &str) -> anyhow::Result<()> {
    let raw = std::fs::read_to_string(file).with_context(|| format!("reading {file}"))?;
    let bundle: permaura_core::VaultBundle = serde_json::from_str(&raw)
        .with_context(|| format!("{file} is not a Permaura vault bundle"))?;

    heading("Verify a vault bundle");
    println!("  format     {} v{}", bundle.format, bundle.version);
    println!("  created    {}", rfc3339_ms(bundle.created_at_ms));
    println!(
        "  source     {} ({})",
        some_or(&bundle.source.gateway_id, "unidentified"),
        some_or(&bundle.source.mode, "unknown mode"),
    );
    println!();

    // Trimmed to match the console, which trims at both ends on export and on import. A phrase copied
    // by eye or by OCR arrives padded, a masked prompt renders the padding as nothing at all, and a
    // value read from a CI secret store or a file arrives with a trailing newline as often as not.
    let passphrase = zeroize::Zeroizing::new(verify_passphrase()?);
    use permaura_gateway::vault_bundle::OpenPayloadError;
    let payload = permaura_gateway::vault_bundle::open_payload(&bundle, passphrase.trim().as_bytes()).map_err(|e| match e {
        // Only reachable once the passphrase has already worked, so it is a statement about the file.
        OpenPayloadError::Open(permaura_core::PermauraError::Tampered(m)) => anyhow!("{m}"),
        OpenPayloadError::Open(_) => anyhow!(
            "the bundle did not open. The passphrase is wrong, or the sealed contents have been \
             damaged. Nothing else about the bundle can be read without the passphrase."
        ),
        OpenPayloadError::Unreadable(reason) => {
            anyhow!("the bundle opened, but its payload is not readable by this build: {reason}")
        }
    })?;

    ok("The passphrase opens this bundle and its contents are intact.");
    print_counts(
        "  holds",
        &json!({
            "connections": payload.connections.len(),
            "policies": payload.policies.len(),
            "grants": payload.grants.len(),
            "capabilities": payload.capabilities.len(),
            "credentials": payload.secrets.len(),
            "agents": payload.agents.len(),
        }),
    );

    heading("\nConnections");
    if payload.connections.is_empty() {
        println!("  (none)");
    }
    for c in &payload.connections {
        println!("  {} [{}] {}", c.id, c.connector, c.name);
    }

    // Ids only, and only ids. The values are in memory at this point and this is a terminal.
    heading("\nCredentials");
    if payload.secrets.is_empty() {
        println!("  (none)");
    }
    for secret in &payload.secrets {
        println!("  {} (held as {} at the source)", secret.id, some_or(&secret.custody, "local vault"));
    }

    if !payload.excluded.is_empty() {
        heading("\nDeliberately not in the bundle");
        for (what, why) in &payload.excluded {
            println!("  {what}: {why}");
        }
    }
    Ok(())
}

// ── approver reset ────────────────────────────────────────────────────────────

/// Untrust every paired device and clear the approval-floor override, from the host, with the gateway
/// stopped.
///
/// The host-side recovery route, with the gateway stopped, for an owner who still holds a recovery code or whose devices are already untrusted; with neither device nor code nothing here keeps the vault.
/// It reopens bearer-only approvals, which is both the point and the risk, so `--yes` is required and a running gateway is refused: a live process would go on serving the trust it already loaded, and the next write would put it back.
pub async fn approver_reset(ctx: &Ctx, yes: bool, recovery_code: Option<String>) -> anyhow::Result<()> {
    if !yes {
        heading("Reset approver trust");
        println!("This untrusts every paired device and clears the approval-floor override, so");
        println!("approvals fall back to the operator token until a device is paired again.");
        println!("While a device is trusted it takes one of the recovery codes shown when it was paired.");
        return Err(anyhow!("nothing was reset. Re-run with --yes if that is what you want"));
    }
    // Read only past the refusal below, so a reset that cannot run never takes a code.
    let code = RECOVERY_CODE_INPUT.input(recovery_code);
    if let Some(at) = this_homes_gateway_answering(ctx).await {
        return Err(anyhow!(
            "a gateway is answering at {at} and would keep the trust it already loaded. Stop it first with `permaura stop{}`, then run this again",
            url_flag(ctx, &at)
        ));
    }
    reset_approver_trust(code.read(RECOVERY_CODE_INPUT)?.as_deref())
}

/// Where a gateway that may be this home's answers: at `--url`, or at an address this home's gateway is set to listen on (see [`this_homes_addresses`]), none of which need be `--url`. `None` when nothing answers.
pub(super) async fn this_homes_gateway_answering(ctx: &Ctx) -> Option<String> {
    if ctx.is_healthy().await {
        return Some(ctx.url.clone());
    }
    let asked = super::port::local_addr_of(&ctx.url);
    for addr in this_homes_addresses() {
        if Some(addr) == asked {
            continue;
        }
        let url = format!("http://{addr}");
        if Ctx::new(url.clone(), None).is_healthy().await {
            return Some(url);
        }
    }
    None
}

/// The addresses this home's gateway may listen on: `PERMAURA_ADDR` in this process (which `config.toml`'s `addr` sets), in the installer's `/etc/permaura/gateway.env` and in this home's `gateway.env`, and the port the Permaura app keeps in this home's `settings.json` once it has moved the gateway off its default.
fn this_homes_addresses() -> Vec<std::net::SocketAddr> {
    let read = |path: Option<std::path::PathBuf>| path.and_then(|p| std::fs::read_to_string(p).ok());
    let home_file = |name: &str| permaura_core::paths::permaura_path(name);
    homes_addresses(
        std::env::var("PERMAURA_ADDR").ok().as_deref(),
        &[read(Some("/etc/permaura/gateway.env".into())), read(home_file("gateway.env"))],
        read(home_file("settings.json")).as_deref(),
    )
}

/// [`this_homes_addresses`] from what it read, each as the loopback address the CLI reaches it on, without repeats.
fn homes_addresses(process_env: Option<&str>, env_files: &[Option<String>], app_settings: Option<&str>) -> Vec<std::net::SocketAddr> {
    let mut found = Vec::new();
    let named = process_env
        .map(str::to_string)
        .into_iter()
        .chain(env_files.iter().flatten().filter_map(|text| super::env_file_value(text, "PERMAURA_ADDR")))
        .filter_map(|addr| addr.trim().parse::<std::net::SocketAddr>().ok());
    let app_port = app_settings
        .and_then(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        .and_then(|settings| settings.get("gatewayPort")?.as_u64())
        .and_then(|port| u16::try_from(port).ok())
        .map(|port| std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, port)));
    for addr in named.chain(app_port).map(reachable) {
        if !found.contains(&addr) {
            found.push(addr);
        }
    }
    found
}

/// The address the CLI reaches a gateway bound to `addr` on: an unspecified bind (`0.0.0.0`, `::`) listens on loopback too, and loopback is the only plain-HTTP address the CLI sends to.
fn reachable(addr: std::net::SocketAddr) -> std::net::SocketAddr {
    match addr.ip() {
        std::net::IpAddr::V4(ip) if ip.is_unspecified() => (std::net::Ipv4Addr::LOCALHOST, addr.port()).into(),
        std::net::IpAddr::V6(ip) if ip.is_unspecified() => (std::net::Ipv6Addr::LOCALHOST, addr.port()).into(),
        _ => addr,
    }
}

/// ` --url <at>` when the gateway answers somewhere other than `--url`, so the stop it suggests reaches it.
fn url_flag(ctx: &Ctx, at: &str) -> String {
    if at == ctx.url {
        String::new()
    } else {
        format!(" --url {at}")
    }
}

/// Why a reset was refused while a device is still trusted, and what is left.
const RESET_NEEDS_A_CODE: &str = "a paired device is still trusted here, so removing it from the host takes one of the recovery codes shown when it was paired: re-run with --recovery-code on its own and enter the code when asked, or set PERMAURA_RECOVERY_CODE. Anything running as you can stop the gateway, so a stopped gateway is not proof that you are the one asking. With neither the device nor a code, no reset keeps the vault: `permaura uninstall --purge-data` starts this gateway over and destroys every credential it holds";

/// Let a reset through when nothing is trusted, or when `recovery_code` is one of this store's unspent
/// codes. Checked here and not yet spent: the reset is recorded first, then [`spend_reset_code`] spends
/// it, so a record that fails costs no code. Returns the code to spend.
fn authorize_reset<'a>(
    store: &dyn permaura_gateway::store::Store,
    trusted: bool,
    recovery_code: Option<&'a str>,
) -> anyhow::Result<Option<&'a str>> {
    if !trusted {
        return Ok(None);
    }
    let Some(code) = recovery_code.map(str::trim).filter(|c| !c.is_empty()) else {
        return Err(anyhow!(RESET_NEEDS_A_CODE));
    };
    match permaura_gateway::recovery::check(store, code)? {
        Some(_) => Ok(Some(code)),
        None => Err(anyhow!(
            "that recovery code was refused: unknown, already spent, or from an earlier pairing. Nothing was reset"
        )),
    }
}

/// Spend the code [`authorize_reset`] checked, after the reset is recorded and before anything is cleared.
fn spend_reset_code(store: &dyn permaura_gateway::store::Store, code: Option<&str>) -> anyhow::Result<()> {
    let Some(code) = code else { return Ok(()) };
    match permaura_gateway::recovery::consume(store, code, permaura_gateway::service::now_ms())? {
        Some(_) => Ok(()),
        None => Err(anyhow!(
            "the recovery code passed its check but was refused when it was spent (spent in between, or issued before a restore). Nothing was reset; the audit chain records that the reset was asked for"
        )),
    }
}

/// Whether a stored keyring trusts any device. A keyring that does not parse counts as trusting one,
/// so a damaged row cannot be the way around the code.
fn keyring_trusts_a_device(raw: &str) -> bool {
    !raw.trim().is_empty()
        && permaura_gateway::relay::approver::ApproverKeyring::from_json(raw).is_none_or(|k| !k.is_empty())
}

/// The reset itself, against whichever backend this host's gateway persists trust in: the keyring
/// file and its floor sibling when `PERMAURA_APPROVER_KEYS_PATH` is set, else the two rows in the store.
/// Recovery codes live in the store either way.
fn reset_approver_trust(recovery_code: Option<&str>) -> anyhow::Result<()> {
    heading("Reset approver trust");
    let file = std::env::var("PERMAURA_APPROVER_KEYS_PATH")
        .ok()
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .map(std::path::PathBuf::from);
    if let Some(keys) = file {
        let db = permaura_gateway::store_path_from_env().filter(|db| db != ":memory:" && std::path::Path::new(db).exists());
        let removed = clear_file_trust(&keys, db.as_deref(), recovery_code)?;
        if removed.is_empty() {
            println!("Nothing to reset: no keyring file at {}.", keys.display());
        } else {
            for path in removed {
                ok(&format!("removed {path}"));
            }
            println!("Approvals are bearer-only until a device is paired again.");
        }
        return Ok(());
    }
    let Some(db) = permaura_gateway::store_path_from_env() else {
        return Err(anyhow!("no PERMAURA_HOME or home directory, so there is no gateway.db to reset"));
    };
    if db == ":memory:" || !std::path::Path::new(&db).exists() {
        println!("Nothing to reset: no store at {db}.");
        return Ok(());
    }
    clear_store_trust(&db, recovery_code)?;
    ok(&format!("cleared the approver keyring and floor override in {db}"));
    println!("Approvals are bearer-only until a device is paired again.");
    Ok(())
}

#[cfg(feature = "sqlite")]
fn open_reset_store(db: &str) -> anyhow::Result<Box<dyn permaura_gateway::store::Store>> {
    let store = permaura_gateway::store::sqlite::SqliteStore::open(db).map_err(|e| match e {
        permaura_gateway::error::GatewayError::StoreHeld(m) => {
            anyhow!("{m} Stop the gateway first with `permaura stop`, then run this again")
        }
        other => anyhow!("could not open {db}: {other}"),
    })?;
    Ok(Box::new(store))
}

#[cfg(not(feature = "sqlite"))]
fn open_reset_store(_db: &str) -> anyhow::Result<Box<dyn permaura_gateway::store::Store>> {
    Err(anyhow!("this build has no persistent store to reset"))
}

fn clear_store_trust(db: &str, recovery_code: Option<&str>) -> anyhow::Result<()> {
    use permaura_gateway::store::{APPROVAL_FLOOR_META, APPROVER_KEYRING_META};
    let store = open_reset_store(db)?;
    let keyring = store.get_meta(APPROVER_KEYRING_META)?;
    let trusted = keyring.as_deref().is_some_and(keyring_trusts_a_device);
    let code = authorize_reset(store.as_ref(), trusted, recovery_code)?;
    let floor = store.get_meta(APPROVAL_FLOOR_META)?;
    let set = |row: &Option<String>| row.as_deref().is_some_and(|v| !v.trim().is_empty());
    if set(&keyring) || set(&floor) {
        record_reset(store.as_ref(), "store", keyring.as_deref(), floor.as_deref(), trusted)?;
    }
    spend_reset_code(store.as_ref(), code)?;
    store.put_meta(APPROVER_KEYRING_META, "")?;
    store.put_meta(APPROVAL_FLOOR_META, "")?;
    Ok(())
}

/// The keyring-file reset: remove the keyring file `keys` and its floor sibling, recording the reset in the store at `db` first when there is one. Returns the paths removed.
fn clear_file_trust(
    keys: &std::path::Path,
    db: Option<&str>,
    recovery_code: Option<&str>,
) -> anyhow::Result<Vec<String>> {
    let floor = keys.with_extension("floor");
    if !keys.exists() && !floor.exists() {
        return Ok(Vec::new());
    }
    let keyring = std::fs::read_to_string(keys).ok();
    let trusted = keyring.as_deref().is_some_and(keyring_trusts_a_device);
    match db {
        Some(db) => {
            let store = open_reset_store(db)?;
            let code = authorize_reset(store.as_ref(), trusted, recovery_code)?;
            let floor_value = std::fs::read_to_string(&floor).ok();
            record_reset(store.as_ref(), "file", keyring.as_deref(), floor_value.as_deref(), trusted)?;
            spend_reset_code(store.as_ref(), code)?;
        }
        None if trusted => return Err(anyhow!(RESET_NEEDS_A_CODE)),
        // No store, so no chain to record into and no recovery code to ask for.
        None => {}
    }
    let mut removed = Vec::new();
    for path in [keys, floor.as_path()] {
        match std::fs::remove_file(path) {
            Ok(()) => removed.push(path.display().to_string()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(anyhow!("could not remove {}: {e}", path.display())),
        }
    }
    Ok(removed)
}

/// Append the reset's record before anything is cleared, so a reset whose record cannot be written does not happen: what it untrusts, whether it clears a floor override, and whether it takes a recovery code (never the code). The record goes in before the code is spent, so a code refused at that point leaves a record of a reset that was asked for and did not happen, as that refusal says.
fn record_reset(
    store: &dyn permaura_gateway::store::Store,
    backend: &str,
    keyring: Option<&str>,
    floor: Option<&str>,
    code_spent: bool,
) -> anyhow::Result<()> {
    let devices = keyring.filter(|raw| !raw.trim().is_empty()).map(|raw| {
        permaura_gateway::relay::approver::ApproverKeyring::from_json(raw)
            .map(|k| k.entries().iter().filter(|(_, _, revoked)| !revoked).count())
    });
    let mut payload = permaura_core::AuditPayload::new("permaura.approver.reset", "approver-keyring", "allow");
    payload.summary = json!({
        "method": "host",
        "keyring": backend,
        // `null` when the stored keyring could not be read; it was cleared all the same.
        "devices_untrusted": match devices { None => json!(0), Some(Some(n)) => json!(n), Some(None) => json!(null) },
        "floor_override_cleared": floor.is_some_and(|f| !f.trim().is_empty()),
        "recovery_code_spent": code_spent,
    });
    store
        .append_audit(payload)
        .map_err(|e| anyhow!("the reset could not be recorded in the audit chain, so nothing was reset: {e}"))?;
    Ok(())
}

// ── vault forget-key ──────────────────────────────────────────────────────────

/// Remove this machine's copy of the vault KEK: the OS credential-store entry, the fallback file,
/// and the marker that records which of the two holds it.
///
/// The last step of a complete removal, and the one that was missing. Deleting `gateway.db` and then
/// the binary left the key behind in the Keychain, in Credential Manager or in the Secret Service,
/// where nothing afterwards could reach it, because the binary whose code identity the entry is bound
/// to had already gone.
///
/// **`--yes` is required and there is no prompt.** The desktop invokes this on the installed binary
/// during a deep removal, where there is no terminal to read a reply from, and a prompt that cannot
/// be answered is a hang. The flag is the confirmation; the desktop's own dialog is where the human
/// says yes.
pub async fn vault_forget_key(ctx: &Ctx, yes: bool) -> anyhow::Result<()> {
    if !yes {
        heading("Forget the vault key");
        println!("This removes the key that seals this gateway's vault, from the OS credential");
        println!("store, the fallback file under the Permaura home and a TPM-sealed copy beside");
        println!("it. Every secret in gateway.db becomes unreadable, here and in any copy of it.");
        println!("There is no undo, and Permaura holds no escrow copy to restore from.");
        return Err(anyhow!("nothing was removed. Re-run with --yes if that is what you want"));
    }
    // A running gateway holds the KEK in memory and reseals on write, so forgetting it underneath one
    // leaves a live process able to read a vault that nothing can open again once it exits. Asked twice:
    // whether this home's gateway answers, and then whether anything holds its store, which a gateway
    // that is draining or serving another port still does.
    if let Some(at) = this_homes_gateway_answering(ctx).await {
        return Err(anyhow!(
            "a gateway is answering at {at} and still holds this key. Stop it first with `permaura stop{}`, then run this again",
            url_flag(ctx, &at)
        ));
    }
    refuse_while_store_held("still holds this key")?;
    forget_vault_kek()
}

/// Refuse while any gateway holds this home's store, naming it: one that is draining stops answering its address as the drain begins and one on another port of this home never answers the default address, but both hold the store lock until they exit. `what` says what the holder still has.
pub(super) fn refuse_while_store_held(what: &str) -> anyhow::Result<()> {
    let Some(db) = permaura_gateway::store_path_from_env().filter(|db| db != ":memory:") else {
        return Ok(());
    };
    match permaura_gateway::store::lock::holder(&db) {
        Ok(None) => Ok(()),
        Ok(Some(pid)) => Err(anyhow!(
            "{} holds this home's store ({db}) and {what}. Stop it first (`permaura stop`, or end that process), then run this again",
            permaura_gateway::store::lock::describe(pid)
        )),
        Err(e) => Err(anyhow!("could not tell whether a gateway holds this home's store, so nothing was done: {e}")),
    }
}

/// The file a root install's installer seals the vault key into with `systemd-creds`, in the Permaura
/// home (or `/etc/permaura` for a `--service-user` install, whose home the account owns).
pub(super) const SEALED_VAULT_KEK: &str = "vault-kek.cred";

/// The removal itself, with no gateway and no flags left to check, so a test can assert what it takes
/// away without standing up an HTTP client first.
pub(super) fn forget_vault_kek() -> anyhow::Result<()> {
    let custody = permaura_gateway::service::VAULT_KEK_CUSTODY;
    let file = custody.path().map_err(|e| anyhow!("{e}"))?;
    let marker = custody.marker().map_err(|e| anyhow!("{e}"))?;
    let systemd_marker = custody.systemd_marker().map_err(|e| anyhow!("{e}"))?;
    // Recorded before the removal, because afterwards "absent" cannot be told from "was never here",
    // and saying which copies were actually found and taken away is most of this command's job.
    let had_file = file.exists();
    let had_marker = marker.exists();
    let mut outcome = custody.forget();
    let (sealed_removed, sealed_failures) = forget_sealed_copy(&file, &systemd_marker);
    if !sealed_failures.is_empty() {
        let mut why: Vec<String> = outcome.err().into_iter().collect();
        why.extend(sealed_failures);
        outcome = Err(why.join("; "));
    }

    heading("Forget the vault key");
    let mut removed: Vec<String> = Vec::new();
    if had_marker && !marker.exists() {
        removed.push(format!("{} (the marker recording OS-store custody)", marker.display()));
    }
    if had_file && !file.exists() {
        removed.push(format!("{} (the fallback key file)", file.display()));
    }
    removed.extend(sealed_removed);
    if outcome.is_ok() {
        // Unlike the two files, the entry cannot be probed without reading the secret out of it, so
        // this says what was asked of the store rather than what it turned out to be holding.
        removed.push(format!(
            "the '{}' entry under '{}' in this machine's credential store, if it had one",
            custody.account, custody.service
        ));
    }

    if removed.is_empty() {
        println!("Nothing to remove: this machine holds no copy of the vault key.");
    } else {
        for line in &removed {
            ok(line);
        }
    }

    match outcome {
        Ok(()) => {
            println!();
            println!("Anything still sealed under this key is now unreadable. A vault bundle you");
            println!("exported earlier is unaffected: it opens with the passphrase you chose for it.");
            Ok(())
        }
        Err(e) => {
            deny(&format!("could not remove everything: {e}"));
            Err(anyhow!("the vault key was not fully removed: {e}"))
        }
    }
}

/// Remove the TPM-sealed copy beside the fallback file `file` and systemd's claim on it, returning what
/// was removed and what could not be. The claim goes with the copy: left behind, it makes the next start
/// refuse for a missing credential instead of beginning a new vault. Paths in, so a test never has to
/// ask the OS credential store anything.
fn forget_sealed_copy(file: &std::path::Path, systemd_marker: &std::path::Path) -> (Vec<String>, Vec<String>) {
    let sealed = file.with_file_name(SEALED_VAULT_KEK);
    let mut removed = Vec::new();
    let mut failures = Vec::new();
    for (path, what) in [
        (sealed.as_path(), "the copy sealed to this machine's TPM"),
        (systemd_marker, "the marker recording systemd custody"),
    ] {
        match std::fs::remove_file(path) {
            Ok(()) => removed.push(format!("{} ({what})", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => failures.push(format!("{} ({e})", path.display())),
        }
    }
    (removed, failures)
}

/// A field the exporter may have left blank, rendered as a stand-in rather than as nothing.
fn some_or<'a>(value: &'a str, fallback: &'a str) -> &'a str {
    if value.is_empty() {
        fallback
    } else {
        value
    }
}

/// A Unix-millisecond instant as RFC 3339 UTC, falling back to the raw number if it is out of range.
fn rfc3339_ms(ms: i64) -> String {
    OffsetDateTime::from_unix_timestamp(ms / 1000)
        .ok()
        .and_then(|t| t.format(&time::format_description::well_known::Rfc3339).ok())
        .unwrap_or_else(|| ms.to_string())
}

/// Render an import preview. Returns whether the bundle carries Command capabilities, which the
/// caller gates on: they are the one entry in a bundle that runs a program on this machine.
fn print_manifest(manifest: &serde_json::Value, replace: bool) -> bool {
    println!(
        "\n  From gateway {} ({})",
        manifest["source_gateway_id"].as_str().filter(|s| !s.is_empty()).unwrap_or("unidentified"),
        manifest["source_mode"].as_str().unwrap_or("?")
    );
    print_counts("  contains", &manifest["counts"]);

    heading("\nConnections");
    let connections = manifest["connections"].as_array().cloned().unwrap_or_default();
    if connections.is_empty() {
        println!("  (none)");
    }
    for c in &connections {
        let mut notes: Vec<&str> = Vec::new();
        if c["conflict"].as_bool().unwrap_or(false) {
            notes.push(if replace { "exists here, will be REPLACED" } else { "exists here, will be skipped" });
        }
        if c["disabled"].as_bool().unwrap_or(false) {
            notes.push("paused at the source");
        }
        println!(
            "  {} [{}]: {} ({} capabilities){}",
            c["id"].as_str().unwrap_or("?"),
            c["connector"].as_str().unwrap_or("?"),
            c["name"].as_str().unwrap_or(""),
            c["capability_count"].as_u64().unwrap_or(0),
            if notes.is_empty() { String::new() } else { format!("  ← {}", notes.join(", ")) }
        );
    }

    let conflicts = manifest["conflicts"].as_object().cloned().unwrap_or_default();
    let clashing: Vec<String> = conflicts
        .iter()
        .filter(|(_, v)| !v.as_array().map(|a| a.is_empty()).unwrap_or(true))
        .map(|(k, v)| {
            let ids: Vec<&str> = v.as_array().unwrap().iter().filter_map(|i| i.as_str()).collect();
            format!("{k}: {}", ids.join(", "))
        })
        .collect();
    if !clashing.is_empty() {
        heading("\nAlready on this gateway");
        for line in &clashing {
            println!("  {line}");
        }
        if replace {
            deny("--replace was given: these will be overwritten with the bundle's version.");
        } else {
            println!("  These will be left exactly as they are. Pass --replace to overwrite them.");
        }
    }

    let commands = manifest["command_capabilities"].as_array().cloned().unwrap_or_default();
    if !commands.is_empty() {
        heading("\nCapabilities that run a program on this machine");
        for c in &commands {
            deny(&format!(
                "{} ({}) runs: {}",
                c["id"].as_str().unwrap_or("?"),
                c["connection_id"].as_str().unwrap_or("?"),
                c["target"].as_str().unwrap_or("?")
            ));
        }
    }
    let ssh = manifest["ssh_capabilities"].as_array().cloned().unwrap_or_default();
    if !ssh.is_empty() {
        heading("\nCapabilities that open an SSH session");
        for c in &ssh {
            println!(
                "  {} ({}) → {}",
                c["id"].as_str().unwrap_or("?"),
                c["connection_id"].as_str().unwrap_or("?"),
                c["target"].as_str().unwrap_or("?")
            );
        }
    }
    let missing = manifest["missing_agents"].as_array().cloned().unwrap_or_default();
    if !missing.is_empty() {
        heading("\nGrants naming agents that do not exist here");
        println!(
            "  {}: those grants import but stay inert until the agents re-enrol.",
            missing.iter().filter_map(|a| a.as_str()).collect::<Vec<_>>().join(", ")
        );
    }

    !commands.is_empty()
}

/// Print a `{ "connections": 4, ... }` map as one aligned line, or a dash when it is empty.
fn print_counts(label: &str, counts: &serde_json::Value) {
    let Some(map) = counts.as_object() else {
        println!("{label}: -");
        return;
    };
    if map.is_empty() {
        println!("{label}: nothing");
        return;
    }
    let rendered: Vec<String> = map.iter().map(|(k, v)| format!("{v} {k}")).collect();
    println!("{label}: {}", rendered.join(", "));
}

// ── policy test ─────────────────────────────────────────────────────────────────

/// Parameters for `permaura policy test`.
pub struct PolicyTestSpec {
    /// The capability action id (e.g. `transactions.refund`).
    pub capability: String,
    /// The normalized action verb (e.g. `refund`).
    pub action: String,
    /// The resource short name.
    pub resource: String,
    /// The risk tier string (low|medium|high|critical).
    pub risk: String,
    /// Allowed actions on the synthetic grant.
    pub allow: Vec<String>,
    /// Denied actions on the synthetic grant.
    pub deny: Vec<String>,
    /// Optional monetary amount.
    pub amount: Option<f64>,
}

/// Evaluate a decision locally through the real policy engine and print the verdict.
/// This needs no running gateway; it is the fast inner loop for authoring policy.
pub fn policy_test(spec: PolicyTestSpec) -> anyhow::Result<()> {
    let action = Action::from_str(&spec.action)
        .map_err(|e| anyhow!("invalid --action '{}': {e}", spec.action))?;
    let risk = parse_risk(&spec.risk)?;

    // Build a synthetic grant from the allow/deny lists. If the caller gave no allow
    // list but did name the capability, allow it so the decision exercises escalation
    // rather than trivially denying for "no grant".
    let mut allow = spec.allow.clone();
    if allow.is_empty() && spec.deny.iter().all(|d| d != &spec.capability) {
        allow.push(spec.capability.clone());
    }

    // Build a synthetic connection-scoped policy + an all-agents grant binding it, then run
    // the real engine, the same resolution the gateway uses.
    let policy = Policy {
        id: "pol_cli_synthetic".into(),
        connection_id: spec.resource.clone(),
        name: "CLI simulation".into(),
        allow,
        deny: spec.deny.clone(),
        requires_approval: vec![],
        notify: vec![],
        device_signed: vec![],
        device_signed_quorum: 1,
        redact_fields: Vec::new(),
    };
    let grant = Grant {
        grant_id: "gr_cli_synthetic".into(),
        name: "CLI simulation".into(),
        enabled: true,
        is_default: false,
        policy_ids: vec!["pol_cli_synthetic".into()],
        agents: GrantAgents::AllAgents,
        period: GrantPeriod::Total,
        overall_limit: None,
        default_per_agent_limit: None,
        expires_at: None,
    };

    let engine = PolicyEngine::with(vec![grant], vec![policy]);
    let input = DecisionInput {
        capability_id: spec.capability.clone(),
        action,
        connection_id: spec.resource.clone(),
        risk,
        capability_requires_approval: false,
        agent_id: "cli".into(),
        context: RequestContext {
            session_id: "sess_cli".into(),
            requested_at: OffsetDateTime::now_utc(),
            execution_location: Default::default(),
            amount: spec.amount,
        },
    };

    let decision: Decision = engine.evaluate(&input);
    heading("Policy decision");
    let color = match decision.kind {
        permaura_core::DecisionKind::Allow => "\x1b[1;32m",
        permaura_core::DecisionKind::Deny => "\x1b[1;31m",
        permaura_core::DecisionKind::RequiresApproval => "\x1b[1;33m",
    };
    println!(
        "  verdict: {color}{}\x1b[0m",
        serde_json::to_value(decision.kind)?.as_str().unwrap_or("?")
    );
    println!("  reason:  {}", decision.reason);
    if let Some(a) = &decision.approval {
        println!(
            "  approval: {} (single_use={}): {}",
            serde_json::to_value(a.kind)?.as_str().unwrap_or("?"),
            a.single_use,
            a.message
        );
    }
    println!("\n{}", serde_json::to_string_pretty(&decision)?);
    Ok(())
}

fn parse_risk(s: &str) -> anyhow::Result<RiskTier> {
    match s.to_lowercase().as_str() {
        "low" => Ok(RiskTier::Low),
        "medium" => Ok(RiskTier::Medium),
        "high" => Ok(RiskTier::High),
        "critical" => Ok(RiskTier::Critical),
        other => Err(anyhow!("invalid risk tier '{other}' (low|medium|high|critical)")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn pending_lists_each_parameter_as_the_gateway_rendered_it() {
        let served = serde_json::json!({
            "version": 1,
            "rows": [
                { "path": "effective_from", "state": "shown", "value": "\"immediately\"" },
                { "path": "value", "state": "redacted", "value": "set, 42 characters" },
            ],
            "omitted": 2,
            "complete": false,
            "digest": "00",
        });
        assert_eq!(
            super::param_lines(&served),
            vec![
                "effective_from = \"immediately\"",
                "value = set, 42 characters  [redacted]",
                "and 2 more not shown",
                "not the whole call: GET /v1/approvals/<id> serves every parameter (params_display_full)",
            ]
        );
        assert_eq!(super::param_lines(&serde_json::Value::Null), vec!["parameters not sent by this gateway"]);
        let empty = serde_json::json!({ "version": 1, "rows": [], "omitted": 0, "complete": true, "digest": "00" });
        assert_eq!(super::param_lines(&empty), vec!["no parameters"]);
    }

    use super::*;

    /// A member approving through permaura.com is named with their own id, never paired with the
    /// owner's id that every console token carries.
    #[test]
    fn the_audit_table_names_who_approved_and_prints_it_safely() {
        let member = json!({ "method": "bearer", "approver": "operator:user_owner",
            "approver_actor": "user_priya", "approver_name": "Priya Raman" });
        assert_eq!(audit_approver(&member).as_deref(), Some("by Priya Raman (member user_priya), permaura.com sign-in"));
        let unnamed = json!({ "method": "bearer", "approver": "operator:user_owner", "approver_actor": "user_priya" });
        assert_eq!(
            audit_approver(&unnamed).as_deref(),
            Some("by a workspace member (member user_priya), permaura.com sign-in")
        );
        let nobody = json!({ "method": "bearer", "approver": "operator:user_owner" });
        assert_eq!(audit_approver(&nobody).as_deref(), Some("by a permaura.com sign-in, operator token"));
        let device = json!({ "method": "device_signed", "approver": "device:a", "approver_name": "iPhone",
            "approver_actor": "user_priya" });
        assert_eq!(audit_approver(&device).as_deref(), Some("by iPhone (device:a), signed on a device"));
        assert_eq!(terminal_safe("Pri\u{1b}[2Aya\n"), "Pri?[2Aya?");
    }
    use crate::cli::with_permaura_home;

    /// A stand-in gateway that answers only the paths named, and 404s everything else.
    ///
    /// Both halves of the health fallback need a server that behaves like a REAL older or newer
    /// gateway, and "older" is defined entirely by which path 404s.
    async fn gateway_answering(paths: &'static [&'static str]) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let app = axum::Router::new().fallback(move |req: axum::http::Request<axum::body::Body>| async move {
            if paths.contains(&req.uri().path()) {
                (axum::http::StatusCode::OK, r#"{"status":"ok"}"#)
            } else {
                (axum::http::StatusCode::NOT_FOUND, r#"{"error":"not found"}"#)
            }
        });
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}")
    }

    fn ctx_for(url: String) -> Ctx {
        Ctx::new(url, Some("tok_test".into()))
    }

    /// `/healthz` is gone on purpose, so a box serving only the old name is NOT a gateway this CLI
    /// can drive. Pinned as a decision rather than left to be rediscovered as a bug.
    #[tokio::test]
    async fn a_gateway_that_only_knows_healthz_is_not_reachable() {
        let url = gateway_answering(&["/healthz"]).await;
        assert!(!ctx_for(url).is_healthy().await);
    }

    /// The one name there is. On Cloud Run, Google's frontend answers `/healthz` itself and the
    /// container never sees it, so a hosted worker can only ever be found at `/health`.
    #[tokio::test]
    async fn a_gateway_that_only_knows_health_is_alive() {
        let url = gateway_answering(&["/health"]).await;
        assert!(ctx_for(url).is_healthy().await);
    }

    /// Something answering on the port while serving neither name is not a gateway.
    #[tokio::test]
    async fn something_that_answers_neither_name_is_not_a_gateway() {
        let url = gateway_answering(&[]).await;
        assert!(!ctx_for(url).is_healthy().await);
    }

    #[tokio::test]
    async fn nothing_listening_is_not_healthy() {
        // Bound and dropped, so the port is real and free: a connection refusal rather than a timeout.
        let url = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
            format!("http://{}", l.local_addr().expect("addr"))
        };
        assert!(!ctx_for(url).is_healthy().await);
    }

    const BLOB_JSON: &str = r#"{"approver_id":"device:a1b2c3d4e5f6","approver_pubkey":"C0i1WLM87OnAu1lyBjioZTq0QvuISHDC9ix+UuZtQBw=","issued_at":1753440000000,"sig":"AA=="}"#;

    /// A scratch Permaura home, and the two files the vault KEK can live in beneath it. The home is
    /// scratch rather than shared for a reason beyond hygiene: a non-default home also scopes the OS
    /// credential-store account name, so nothing here can reach the developer's own KEK entry.
    fn scratch_kek_home() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let custody = permaura_gateway::service::VAULT_KEK_CUSTODY;
        let dir = std::env::temp_dir()
            .join(format!("permaura-forget-{}-{:?}", std::process::id(), std::thread::current().id()));
        std::fs::create_dir_all(&dir).expect("scratch home");
        let file = dir.join(custody.file_name);
        let marker = dir.join(format!("{}.in-os-store", custody.file_name));
        (dir, file, marker)
    }

    /// A store at a scratch path with one trusted device and a fresh set of recovery codes.
    #[cfg(feature = "sqlite")]
    fn paired_store() -> (std::path::PathBuf, String, Vec<String>) {
        use permaura_gateway::store::{Store, APPROVER_KEYRING_META};
        let dir = std::env::temp_dir().join(format!("permaura-reset-{}-{}", std::process::id(), permaura_gateway::service::short_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("gateway.db").to_string_lossy().into_owned();
        // Opening a store resolves the vault KEK: keep it off this machine's real custody.
        std::env::set_var("PERMAURA_DEV", "1");
        let store = with_permaura_home(&dir, || permaura_gateway::store::sqlite::SqliteStore::open(&db).unwrap());
        let mut keyring = permaura_gateway::relay::approver::ApproverKeyring::new();
        let device = ed25519_dalek::SigningKey::from_bytes(&[5u8; 32]).verifying_key();
        let pubkey = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, device.to_bytes());
        assert!(keyring.add("device:owner", pubkey), "a well-formed device key");
        store.put_meta(APPROVER_KEYRING_META, &keyring.to_json().unwrap()).unwrap();
        let codes = permaura_gateway::recovery::issue(&store, permaura_gateway::service::now_ms()).unwrap();
        (dir, db, codes)
    }

    #[cfg(feature = "sqlite")]
    fn trusted_devices(db: &str) -> usize {
        use permaura_gateway::store::{Store, APPROVER_KEYRING_META};
        let store = permaura_gateway::store::sqlite::SqliteStore::open(db).unwrap();
        let raw = store.get_meta(APPROVER_KEYRING_META).unwrap().unwrap_or_default();
        permaura_gateway::relay::approver::ApproverKeyring::from_json(&raw)
            .map_or(0, |k| k.entries().iter().filter(|(_, _, revoked)| !revoked).count())
    }

    /// An agent running as the owner can stop the gateway, so a stopped gateway is not evidence of a
    /// human. Once a device is trusted, removing it from the host takes one of the recovery codes.
    #[cfg(feature = "sqlite")]
    #[test]
    fn a_reset_with_a_device_trusted_needs_a_recovery_code() {
        let (dir, db, codes) = paired_store();
        with_permaura_home(&dir, || {
            assert_eq!(trusted_devices(&db), 1);
            let refused = clear_store_trust(&db, None).unwrap_err().to_string();
            assert!(refused.contains("--recovery-code") && refused.contains("--purge-data"), "{refused}");
            assert!(clear_store_trust(&db, Some("AAAA-BBBB-CCCC-DDDD")).is_err(), "a wrong code resets nothing");
            assert_eq!(trusted_devices(&db), 1, "the device is still trusted");

            clear_store_trust(&db, Some(&codes[0])).expect("a real code resets");
            assert_eq!(trusted_devices(&db), 0);
            clear_store_trust(&db, None).expect("with nothing trusted, no code is needed");
        });
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(feature = "sqlite")]
    fn reset_events(db: &str) -> Vec<permaura_core::AuditEvent> {
        use permaura_gateway::store::Store;
        let store = permaura_gateway::store::sqlite::SqliteStore::open(db).unwrap();
        assert_eq!(store.verify_audit().unwrap(), None, "the chain verifies with the reset in it");
        store.audit_events(None).unwrap().into_iter().filter(|e| e.payload.action == "permaura.approver.reset").collect()
    }

    /// The reset is in the chain, saying what it untrusted and whether it took a recovery code; a reset refused before its record is written (no code, or one that fails its check) records nothing.
    #[cfg(feature = "sqlite")]
    #[test]
    fn a_reset_is_recorded_in_the_audit_chain() {
        use permaura_gateway::store::{Store, APPROVAL_FLOOR_META};
        let (dir, db, codes) = paired_store();
        with_permaura_home(&dir, || {
            permaura_gateway::store::sqlite::SqliteStore::open(&db).unwrap().put_meta(APPROVAL_FLOOR_META, "device_signed").unwrap();
            clear_store_trust(&db, None).unwrap_err();
            assert!(reset_events(&db).is_empty(), "a refused reset records nothing");

            clear_store_trust(&db, Some(&codes[0])).expect("a real code resets");
            let events = reset_events(&db);
            assert_eq!(events.len(), 1, "one record of the reset");
            let summary = &events[0].payload.summary;
            assert_eq!(events[0].payload.decision, "allow");
            assert_eq!(summary["devices_untrusted"], 1, "{summary}");
            assert_eq!(summary["recovery_code_spent"], true, "{summary}");
            assert_eq!(summary["floor_override_cleared"], true, "{summary}");
            assert!(!summary.to_string().contains(&codes[0]), "the code itself is not recorded");
        });
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A reset whose record cannot be written spends no recovery code: the code is checked, the reset recorded, and only then the code spent.
    #[cfg(feature = "sqlite")]
    #[test]
    fn a_reset_that_cannot_be_recorded_spends_no_recovery_code() {
        let (dir, db, codes) = paired_store();
        with_permaura_home(&dir, || {
            let conn = rusqlite::Connection::open(&db).unwrap();
            conn.execute_batch(
                "CREATE TRIGGER refuse BEFORE INSERT ON audit_events BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END;",
            )
            .unwrap();
            clear_store_trust(&db, Some(&codes[0])).expect_err("the record cannot be written");
            conn.execute_batch("DROP TRIGGER refuse;").unwrap();
            drop(conn);
            assert_eq!(trusted_devices(&db), 1, "nothing was reset");
            clear_store_trust(&db, Some(&codes[0])).expect("the same code still resets: it was never spent");
            assert_eq!(trusted_devices(&db), 0);
        });
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A reset refused because a gateway holds the store says to stop it, not to give the reset a home of its own, which would reset nothing.
    #[cfg(feature = "sqlite")]
    #[test]
    fn a_reset_refused_by_a_held_store_gives_advice_that_fits_a_reset() {
        let (dir, db, _codes) = paired_store();
        let _held = permaura_gateway::store::lock::StoreLock::acquire(&db, std::time::Duration::ZERO).unwrap();
        with_permaura_home(&dir, || {
            let refused = clear_store_trust(&db, None).unwrap_err().to_string();
            assert!(!refused.contains("its own PERMAURA_HOME"), "{refused}");
            assert!(refused.contains("permaura stop"), "{refused}");
        });
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The 202's pid is waited on only when the listener or this home's store lock confirms it; one this machine cannot see is another namespace's.
    #[test]
    fn a_stop_waits_only_on_a_pid_this_machine_confirms() {
        assert_eq!(trusted_stop_pid(Some(42), None, None), None, "unseen listener and no lock: judged by /health alone");
        assert_eq!(trusted_stop_pid(Some(42), Some(7), Some(9)), None, "named by neither");
        assert_eq!(trusted_stop_pid(Some(42), Some(42), None), Some(42), "the local listener");
        assert_eq!(trusted_stop_pid(Some(42), None, Some(42)), Some(42), "the store's holder, listener unseen");
        assert_eq!(trusted_stop_pid(None, Some(42), Some(42)), None, "a gateway too old to name its pid");
    }

    /// Forget-key asks the store lock, not only the default address, so a gateway that is draining or serving another port still stops it.
    #[cfg(feature = "sqlite")]
    #[test]
    fn forget_key_is_refused_while_a_gateway_holds_the_store() {
        let (home, file, _marker) = scratch_kek_home();
        std::fs::write(&file, "a-real-looking-kek").unwrap();
        let db = home.join("gateway.db").to_string_lossy().into_owned();
        let _held = permaura_gateway::store::lock::StoreLock::acquire(&db, std::time::Duration::ZERO).unwrap();
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let refused = with_permaura_home(&home, || {
            tokio::runtime::Runtime::new()
                .unwrap()
                .block_on(vault_forget_key(&ctx_for(format!("http://127.0.0.1:{free}")), true))
        });
        let refused = refused.expect_err("a held store refuses forget-key").to_string();
        assert!(refused.contains(&std::process::id().to_string()), "it names the holder: {refused}");
        assert!(file.exists(), "the key file is still there");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The keyring-file backend records its reset in the store too, before removing the files.
    #[cfg(feature = "sqlite")]
    #[test]
    fn a_keyring_file_reset_is_recorded_in_the_audit_chain() {
        use permaura_gateway::store::{Store, APPROVER_KEYRING_META};
        let (dir, db, codes) = paired_store();
        let keys = dir.join("approver-keys.json");
        with_permaura_home(&dir, || {
            let keyring = permaura_gateway::store::sqlite::SqliteStore::open(&db).unwrap().get_meta(APPROVER_KEYRING_META).unwrap().unwrap();
            std::fs::write(&keys, keyring).unwrap();
            std::fs::write(keys.with_extension("floor"), "device_signed").unwrap();
            assert!(clear_file_trust(&keys, Some(&db), None).is_err(), "a trusted device still needs a code");
            assert!(keys.exists() && reset_events(&db).is_empty(), "and a refused reset records and removes nothing");

            let removed = clear_file_trust(&keys, Some(&db), Some(&codes[1])).expect("a real code resets");
            assert_eq!(removed.len(), 2, "{removed:?}");
            let events = reset_events(&db);
            assert_eq!(events.len(), 1);
            assert_eq!(events[0].payload.summary["keyring"], "file", "{}", events[0].payload.summary);
            assert_eq!(events[0].payload.summary["floor_override_cleared"], true);
            assert!(clear_file_trust(&keys, Some(&db), None).unwrap().is_empty(), "nothing left to reset");
            assert_eq!(reset_events(&db).len(), 1, "and nothing to record");
        });
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The removal a deep uninstall was missing. Afterwards nothing on this machine can open the
    /// vault, which is the point. Deleting `gateway.db` while the key stayed in the Keychain left a
    /// secret behind that no later run of anything could even reach to remove.
    #[test]
    fn forget_key_leaves_no_key_and_no_marker() {
        let custody = permaura_gateway::service::VAULT_KEK_CUSTODY;
        let (home, file, marker) = scratch_kek_home();
        std::fs::write(&file, "a-real-looking-kek").expect("seed the fallback key file");
        std::fs::write(&marker, "").expect("seed the marker");

        with_permaura_home(&home, || {
            forget_vault_kek().expect("forgetting must succeed on a machine that has the key");

            assert!(
                custody.load().expect("load must not error after a clean forget").is_none(),
                "the vault key must be unreachable afterwards"
            );
            assert!(!marker.exists(), "the OS-store marker must go with it");
            assert!(!file.exists(), "and so must the fallback file");
        });

        std::fs::remove_dir_all(&home).ok();
    }

    /// A root install keeps the key sealed to the TPM in the home, with a claim beside it. Both go: the
    /// sealed copy is the key, and a claim with nothing to claim stops the next start cold.
    #[test]
    fn forget_key_takes_a_sealed_copy_and_its_claim_too() {
        let (home, file, _marker) = scratch_kek_home();
        let sealed = file.with_file_name(SEALED_VAULT_KEK);
        let claim = file.with_file_name("vault-kek.in-systemd-credential");
        let neighbour = file.with_file_name("gateway.db");
        for path in [&sealed, &claim, &neighbour] {
            std::fs::write(path, "").expect("seed the scratch home");
        }

        let (removed, failures) = forget_sealed_copy(&file, &claim);
        assert!(failures.is_empty(), "{failures:?}");
        assert_eq!(removed.len(), 2, "{removed:?}");
        assert!(!sealed.exists() && !claim.exists());
        assert!(neighbour.exists(), "forgetting the key deletes nothing else");

        let (removed, failures) = forget_sealed_copy(&file, &claim);
        assert!(removed.is_empty() && failures.is_empty(), "nothing there is not a failure");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The claim's name comes from the custody itself, so the two cannot drift apart.
    #[test]
    fn the_systemd_claim_sits_beside_the_fallback_file() {
        let custody = permaura_gateway::service::VAULT_KEK_CUSTODY;
        let (home, file, _marker) = scratch_kek_home();
        with_permaura_home(&home, || {
            assert_eq!(custody.systemd_marker().unwrap(), file.with_file_name("vault-kek.in-systemd-credential"));
        });
        std::fs::remove_dir_all(&home).ok();
    }

    /// There is no undo, so the flag is the confirmation and the absence of it removes nothing at
    /// all. The desktop passes it from its own dialog; a person typing the command has to mean it.
    #[tokio::test]
    async fn forget_key_without_yes_removes_nothing() {
        let (home, file, marker) = scratch_kek_home();
        std::fs::write(&file, "a-real-looking-kek").expect("seed the fallback key file");
        std::fs::write(&marker, "").expect("seed the marker");

        // A port nothing answers on: the refusal must land before any liveness probe, so this never
        // reaches the network at all.
        let ctx = Ctx::new("http://127.0.0.1:1".into(), None);
        let err = vault_forget_key(&ctx, false).await.expect_err("must refuse without --yes");

        assert!(err.to_string().contains("--yes"), "the refusal must say how to proceed: {err}");
        assert!(file.exists(), "the key file must be untouched");
        assert!(marker.exists(), "and so must the marker");

        std::fs::remove_dir_all(&home).ok();
    }

    /// A loopback gateway stand-in that proves it holds `token` on `/health` and answers an enrolment with `code`, keeping each request it got.
    fn enrolling_gateway(token: &'static str, code: &'static str) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 8192];
                let n = stream.read(&mut buf).unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();
                log.lock().unwrap().push(request.clone());
                let challenge = request
                    .lines()
                    .find_map(|l| l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(permaura_core::health_proof::CHALLENGE_HEADER)).map(|(_, v)| v.trim().to_string()))
                    .unwrap_or_default();
                let (proof, body) = if request.starts_with("GET /health ") {
                    let proof = permaura_core::health_proof::proof(token, addr.port(), &challenge)
                        .map(|p| format!("{}: {p}\r\n", permaura_core::health_proof::PROOF_HEADER))
                        .unwrap_or_default();
                    (proof, r#"{"status":"ok","service":"permaura-gateway"}"#.to_string())
                } else {
                    (String::new(), format!(r#"{{"code":"{code}","expires_at":0}}"#))
                };
                let _ = write!(stream, "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{proof}connection: close\r\n\r\n{body}", body.len());
            }
        });
        (format!("http://{addr}"), seen)
    }

    /// An agent's name is whatever registered it chose (an OAuth client's registered name), so it reaches the terminal with its control characters made visible; and each id is printed whole, since `agent approve` and `grant --agent` take it as printed.
    #[test]
    fn agent_list_prints_ids_whole_and_names_without_control_sequences() {
        let long_id = format!("{}-a1b2c3d4", "a-label-long-enough-to-pass-forty-characters");
        let agents = vec![json!({ "id": long_id, "status": "pending", "name": "Claude\u{1b}]52;c;cGF3bmVk\u{7}\u{1b}[2A" })];
        let lines = agent_list_lines(&agents);
        assert!(lines.iter().any(|l| l.contains(&long_id)), "the id is whole: {lines:?}");
        assert!(lines.iter().all(|l| !l.chars().any(|c| c.is_control() && c != '\n')), "no control character reaches the terminal: {lines:?}");
    }

    /// A leading `~` is the home directory even when no shell expanded it, as in PowerShell and cmd.
    #[test]
    fn an_out_path_under_a_tilde_is_the_home_directory() {
        let home = std::path::PathBuf::from(std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).expect("a home"));
        assert_eq!(expand_home(std::path::Path::new("~/.permaura/a.token")), home.join(".permaura/a.token"));
        assert_eq!(expand_home(std::path::Path::new("~")), home);
        assert_eq!(expand_home(std::path::Path::new("~other/a.token")), std::path::PathBuf::from("~other/a.token"), "another user's home is not guessed");
        assert_eq!(expand_home(std::path::Path::new("/tmp/a.token")), std::path::PathBuf::from("/tmp/a.token"));
    }

    /// `permaura agent enroll --out` mints a code through the proven path, the operator token going only to the listener that proves it holds it, and writes the code to a new file only its owner can read, so neither the token nor the code is ever in a command's arguments.
    #[test]
    fn agent_enroll_writes_the_code_to_an_owner_only_file_after_the_proof() {
        const TOKEN: &str = "pgt_enroll_test_operator";
        const CODE: &str = "ENRL-0123-4567-89AB-CDEF-0123-4567-89AB-CDEF";
        let (url, seen) = enrolling_gateway(TOKEN, CODE);
        let dir = std::env::temp_dir().join(format!("pm-agent-enroll-{}-{}", std::process::id(), permaura_gateway::service::short_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let out = dir.join("claude-code.token");
        let ctx = Ctx::new(url, Some(TOKEN.into()));
        tokio::runtime::Runtime::new().unwrap().block_on(agent_enroll(&ctx, Some("claude-code"), Some(&out))).expect("the code is minted");
        assert_eq!(std::fs::read_to_string(&out).unwrap().trim(), CODE);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
        }
        let requests = seen.lock().unwrap().clone();
        assert!(requests[0].starts_with("GET /health ") && !requests[0].contains(TOKEN), "the proof first, with no token");
        let enroll = requests.iter().find(|r| r.starts_with("POST /v1/agents/enroll ")).expect("the enrolment was asked");
        assert!(enroll.to_ascii_lowercase().contains(&format!("authorization: bearer {TOKEN}")));
        assert!(enroll.contains(r#""label":"claude-code""#));

        let again = tokio::runtime::Runtime::new().unwrap().block_on(agent_enroll(&ctx, None, Some(&out)));
        assert!(again.is_err(), "an existing file is never overwritten");

        // Through the crate's owner-only create, which also makes a missing parent directory private, and on Windows supplies the owner-only ACL at creation rather than narrowing it after.
        let nested = dir.join("agents").join("claude-code.token");
        tokio::runtime::Runtime::new().unwrap().block_on(agent_enroll(&ctx, None, Some(&nested))).expect("a missing parent is made");
        assert_eq!(std::fs::read_to_string(&nested).unwrap().trim(), CODE);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.join("agents")).unwrap().permissions().mode() & 0o777, 0o700);
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    fn b64url(s: &str, pad: bool) -> String {
        use base64::engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD};
        use base64::Engine as _;
        if pad { URL_SAFE.encode(s) } else { URL_SAFE_NO_PAD.encode(s) }
    }

    #[test]
    fn decodes_padded_unpadded_and_raw_json() {
        for raw in [b64url(BLOB_JSON, true), b64url(BLOB_JSON, false), BLOB_JSON.to_string()] {
            let parsed = decode_pairing_blob(&raw).expect("blob should decode");
            assert_eq!(parsed.approver_id, "device:a1b2c3d4e5f6");
            assert_eq!(parsed.issued_at, 1_753_440_000_000);
        }
    }

    #[test]
    fn a_blob_carries_its_person_to_the_gateway_and_omits_it_when_unnamed() {
        let unnamed = decode_pairing_blob(BLOB_JSON).expect("blob should decode");
        assert_eq!(unnamed.person, None);
        assert!(serde_json::to_value(&unnamed).unwrap().get("person").is_none());
        let named = BLOB_JSON.replacen('}', r#","person":"user_sam"}"#, 1);
        let parsed = decode_pairing_blob(&b64url(&named, false)).expect("blob should decode");
        assert_eq!(parsed.person.as_deref(), Some("user_sam"));
        assert_eq!(serde_json::to_value(&parsed).unwrap()["person"], "user_sam");
    }

    /// `--person` replaces the blob's person, and an empty one sends none: a hosted gateway refuses a person other than the account whose ticket pairs the key.
    #[test]
    fn person_replaces_or_clears_the_blobs_own() {
        let named = BLOB_JSON.replacen('}', r#","person":"user_teammate"}"#, 1);
        let blob = || decode_pairing_blob(&b64url(&named, false)).unwrap();
        let mut kept = blob();
        with_person(&mut kept, None);
        assert_eq!(kept.person.as_deref(), Some("user_teammate"));
        let mut replaced = blob();
        with_person(&mut replaced, Some("user_owner".into()));
        assert_eq!(replaced.person.as_deref(), Some("user_owner"));
        let mut cleared = blob();
        with_person(&mut cleared, Some(" ".into()));
        assert_eq!(cleared.person, None);
        assert!(serde_json::to_value(&cleared).unwrap().get("person").is_none(), "and the request names nobody");
    }

    #[test]
    fn decodes_a_blob_broken_across_lines() {
        // A QR scan or a terminal paste can wrap the string; whitespace must not defeat it.
        let encoded = b64url(BLOB_JSON, false);
        let (a, b) = encoded.split_at(40);
        assert!(decode_pairing_blob(&format!("{a}\n  {b}\n")).is_ok());
    }

    #[test]
    fn rejects_garbage_with_an_actionable_message() {
        // Truncation is the common failure and breaks at the JSON parse, not the base64 decode;
        // both paths must produce the same guidance rather than a serde internal.
        let encoded = b64url(BLOB_JSON, false);
        for bad in ["", "not a blob!!", &encoded[..encoded.len() / 2]] {
            let err = decode_pairing_blob(bad).expect_err("must reject").to_string();
            assert!(err.contains("readable pairing blob"), "unhelpful error: {err}");
        }
    }

    /// Set `PERMAURA_BUNDLE_PASSPHRASE` for the closure and restore it after. The environment is
    /// process-wide, so the whole set/read/restore runs under one lock: the same reason
    /// `with_home_var` exists, applied to the one variable these tests move.
    fn with_bundle_passphrase<T>(value: &str, f: impl FnOnce() -> T) -> T {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let prev = std::env::var_os(BUNDLE_PASSPHRASE_ENV);
        std::env::set_var(BUNDLE_PASSPHRASE_ENV, value);
        let out = f();
        match prev {
            Some(v) => std::env::set_var(BUNDLE_PASSPHRASE_ENV, v),
            None => std::env::remove_var(BUNDLE_PASSPHRASE_ENV),
        }
        out
    }

    /// The reason this change exists: a backup deserves a repeatable check, and the check has to run
    /// where there is no terminal to type the passphrase into. A restore drill could only reach it by
    /// driving a PTY from Python; this proves the env var opens a real bundle with no tty at all.
    #[test]
    fn verify_opens_a_bundle_without_a_terminal() {
        let pass = "correct horse battery staple";
        let source = permaura_core::BundleSource { gateway_id: "gw_test".into(), mode: "hosted".into() };
        // Sealed at the open floor, not the export default, so the test does not pay a 256 MiB KDF.
        let params = permaura_core::KdfParams {
            salt: permaura_core::KdfParams::generate().salt,
            mem_cost_kib: 32 * 1024,
            time_cost: 1,
            parallelism: 1,
        };
        let bundle =
            permaura_core::seal_bundle_with_params(pass.as_bytes(), json!({}), 1_754_500_000_000, source, params)
                .expect("sealing a bundle");

        let path = std::env::temp_dir()
            .join(format!("permaura-verify-{}-{:?}.json", std::process::id(), std::thread::current().id()));
        std::fs::write(&path, serde_json::to_vec(&bundle).expect("serialize")).expect("write bundle");
        let file = path.to_str().expect("utf-8 path").to_string();

        // A trailing newline is exactly what a CI secret store or a `$(cat file)` hands over, and the
        // trim on the open path has to absorb it as the interactive prompt and the console both do.
        with_bundle_passphrase(&format!("{pass}\n"), || {
            vault_verify(&file).expect("the env-var passphrase must open the bundle with no terminal");
        });

        std::fs::remove_file(&path).ok();
    }

    /// A set-but-empty variable is a misconfigured CI secret, not a passphrase. Naming it beats the
    /// generic "the passphrase is wrong" the open would otherwise produce a second later.
    #[test]
    fn verify_rejects_an_empty_passphrase_env() {
        with_bundle_passphrase("   ", || {
            let err = verify_passphrase().expect_err("an empty env var is not a passphrase").to_string();
            assert!(err.contains(BUNDLE_PASSPHRASE_ENV) && err.contains("empty"), "unhelpful error: {err}");
        });
    }
}
