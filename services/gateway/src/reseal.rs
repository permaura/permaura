//! Keeping permaura.com's sealed console bearer current for a loopback-only gateway.
//!
//! permaura.com seals a bearer on the link's row for the console's browser-direct path to a gateway it cannot reach itself. That bearer is a console session ([`crate::CONSOLE_TOKEN_PREFIX`]), never the operator token in `operator.token`: the request path classes a console session remote wherever it arrives from, so a copy permaura.com holds is never the owner at the keyboard, even delivered by a configuration permaura.com's Cloudflare account pushed to the tunnel connector or by private-network traffic it routed through it. It lives twelve hours, so this task mints a replacement before then and hands it to each link's row, proving itself with the install identity the link was stamped with at enrolment (`PATCH /api/gateways/:id/operator-token`).
//!
//! A gateway with a public URL hands permaura.com nothing: the console reaches it with the owner's own short-lived token, so a sealed bearer would be authority nothing uses. Its console sessions are revoked at boot, and a boot without the public URL seals a fresh one.
//!
//! This machine's `permaura pair` and `start --pair` hand permaura.com no token at enrolment, but a desktop build that puts `operator.token` in the enrolment body does, and an earlier build kept re-sealing that token there; it is local wherever it arrives from. So `operator.token` is replaced, and the token it named revoked after a short grace ([`crate::OperatorTokenRotation`]), once at the first poll that has a link and a console session to offer it, and again within a poll of every pairing this machine completes ([`crate::announce::Pairings`]), before that poll's offers go out. The trigger is this gateway's own clock and its own pairings, never permaura.com's answer: a permaura.com that never acknowledged the seal, held an offer open, or re-used a link id would otherwise decide for itself when the token it was handed dies, and one that revoked its own console session to get a new one offered could churn the file at will. A boot with a public URL retires every earlier operator token once it holds its address ([`crate::republish_operator_token_once_bound`]).
//!
//! A hand-over this gateway never hears of is beyond it: a desktop pairing that permaura.com answers with no link leaves the token to its twelve-hour expiry, and the desktop starts its tunnel connector before it relaunches the gateway with the public URL, so for those seconds the loopback-only process, and that token, can be reached through the tunnel, and from loopback by a configuration permaura.com's Cloudflare account pushes to the connector, or private-network traffic it routes through it, until the desktop stops it. Both are the desktop's to close, by handing over no token and by relaunching before it starts the connector.
//!
//! The bearer goes to the control plane this gateway's links announce to and nowhere else: https only, never to a literal loopback or unspecified address or a localhost name, and never along a redirect, which would carry the body with it.
//!
//! It runs on its own task, so a slow or failing permaura.com delays the re-seal and holds up nothing else.
//!
//! permaura.com deletes its copy when a link moves back to loopback-only (a tunnel removed, a public URL cleared), and a gateway that already sealed the current bearer, or had the link closed by a 409 while the row had a public URL, would otherwise never send another until it restarted. So it asks: every fifteen minutes the task checks in for each link (`POST /api/gateways/:id/checkin`, carrying the link's announce credential and never the bearer), and a `needs_reseal: true` on that answer, on any `/api/notify/*` answer or on a re-seal's own answer reopens the link and seals the current console session again.
//!
//! A gateway with a public URL checks in too, for a different answer: `owner_sub`, the account the organization's owner is now. After a hand-over permaura.com mints every token for the new owner, and a headless gateway pinned to the old one refused them all until someone re-ran `permaura remote enable` on the machine; now it moves its binding to the owner the check-in names, audits the move and writes it to its config file.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use permaura_core::install::Install;
use tokio::time::Instant;

use crate::announce::RowAddress;
use crate::store::Store;

/// The control plane this gateway is linked to, and each link's id there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Linked {
    pub(crate) base: String,
    pub(crate) gateway_ids: Vec<String>,
    /// Each link's announce-secret fingerprint by gateway id: a pairing that names a link already held hands it a new secret, which is how a link paired again in place is told from one left alone.
    pub(crate) fingerprints: HashMap<String, String>,
}

impl Linked {
    /// The links this gateway announces to, which every pairing path sets as its last step, or `None` when it has none.
    pub(crate) fn from_announce(links: &[crate::announce::Config]) -> Option<Self> {
        let base = links.first()?.base_url().to_string();
        Some(Linked {
            base,
            gateway_ids: links.iter().map(|l| l.gateway_id().to_string()).collect(),
            fingerprints: links.iter().map(|l| (l.gateway_id().to_string(), l.fingerprint())).collect(),
        })
    }
}

/// What the task reads on every poll, and where it says what permaura.com may hold.
pub(crate) struct Sources {
    /// The console bearer to hold sealed now, read only while a link exists.
    pub(crate) token: Box<dyn Fn() -> Option<String> + Send + Sync>,
    pub(crate) linked: Box<dyn Fn() -> Option<Linked> + Send + Sync>,
    pub(crate) install: Box<dyn Fn() -> Option<Install> + Send + Sync>,
    /// The links permaura.com asked to have re-sealed since the last poll.
    pub(crate) asked: Arc<crate::announce::ResealRequests>,
    /// The pairings this machine has completed, each of which may have handed permaura.com `operator.token`.
    pub(crate) pairings: Arc<crate::announce::Pairings>,
    /// Replaces `operator.token` at the first poll with a link and once per pairing after it, whatever permaura.com answers, when this gateway publishes one.
    pub(crate) rotation: Option<crate::OperatorTokenRotation>,
    pub(crate) held: Arc<HeldConsoleSessions>,
}

/// The console sessions permaura.com may hold for this gateway, newest first, which `/health` proves beside the operator token ([`permaura_core::health_proof::CONSOLE_PROOF_HEADER`]): the browser-direct console is handed one of these by permaura.com and never the operator token, so a proof keyed on the operator token alone is one it cannot check.
///
/// The current session from the moment it is minted, while any open link has it sealed or on its way (a re-seal that timed out may still have landed), then each open link's last acknowledged one. Empty while nothing is linked, once every link has closed, and on a gateway with a public URL, which hands permaura.com none.
#[derive(Default)]
pub struct HeldConsoleSessions(std::sync::RwLock<Vec<String>>);

impl HeldConsoleSessions {
    /// The sessions, newest first.
    pub fn get(&self) -> Vec<String> {
        self.0.read().map(|held| held.clone()).unwrap_or_default()
    }

    /// Replace them, newest first.
    pub fn set(&self, held: Vec<String>) {
        if let Ok(mut slot) = self.0.write() {
            *slot = held;
        }
    }
}


/// The console session permaura.com should hold: the one minted last while it has life left, otherwise a new one.
pub(crate) struct ConsoleSession {
    store: Arc<dyn Store>,
    held: std::sync::Mutex<Option<String>>,
}

impl ConsoleSession {
    pub(crate) fn new(store: Arc<dyn Store>) -> Self {
        ConsoleSession { store, held: std::sync::Mutex::new(None) }
    }

    pub(crate) fn current(&self) -> Option<String> {
        let mut held = self.held.lock().ok()?;
        if let Some(token) = held.as_deref() {
            if crate::console_token_is_fresh(self.store.as_ref(), token) {
                return Some(token.to_string());
            }
        }
        match crate::mint_console_session(self.store.as_ref()) {
            Ok(token) => {
                *held = Some(token.clone());
                Some(token)
            }
            Err(e) => {
                tracing::warn!(error = %e, "could not mint the console session permaura.com holds for this gateway");
                None
            }
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Timing {
    pub(crate) poll: Duration,
    /// The wait after each consecutive failure; the last step repeats.
    pub(crate) backoff: Vec<Duration>,
    pub(crate) request_timeout: Duration,
    /// How often each link checks in to ask whether permaura.com still holds its bearer.
    pub(crate) check_in: Duration,
    /// How long after boot the first check-in is sent. One interval on a loopback-only gateway, which seals at boot anyway; soon after boot on one with a public URL, so a restart after an ownership change learns the new owner at once rather than fifteen minutes later.
    pub(crate) first_check_in: Duration,
    /// The least time between two reopenings of one link, however often permaura.com asks.
    pub(crate) reopen_every: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            poll: Duration::from_secs(5),
            // A token is replaced with at least three and a half hours left on the old one, so an outage can be waited out without hurrying.
            backoff: [5, 30, 120, 300, 900].map(Duration::from_secs).to_vec(),
            request_timeout: Duration::from_secs(20),
            check_in: Duration::from_secs(15 * 60),
            first_check_in: Duration::from_secs(15 * 60),
            reopen_every: Duration::from_secs(60),
        }
    }
}

impl Timing {
    /// The same timing for a gateway with a public URL: its first check-in comes within [`PUBLIC_FIRST_CHECK_IN`] of boot, and no later than it would have anyway.
    fn for_public_url(self) -> Self {
        Timing { first_check_in: self.first_check_in.min(PUBLIC_FIRST_CHECK_IN), ..self }
    }
}

/// How soon after boot a gateway with a public URL first checks in: long enough for the boot to settle, short enough that a restart after a hand-over is answered before anyone notices the old pin.
const PUBLIC_FIRST_CHECK_IN: Duration = Duration::from_secs(5);

/// The longest `Retry-After` honoured, so a confused answer cannot park the re-seal past the old token's expiry.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(60 * 60);

/// What came back: the status, how long permaura.com asked us to wait, if it did, whether it asked for the link's bearer again, who it says the organization's owner is now, whether the link's row says it holds a public URL, and which one when it says.
pub(crate) struct Reply {
    pub(crate) status: u16,
    pub(crate) retry_after: Option<Duration>,
    pub(crate) needs_reseal: bool,
    pub(crate) owner_sub: Option<String>,
    pub(crate) public_url: bool,
    pub(crate) row_public_url: RowAddress,
}

/// One re-seal or check-in on the wire. A trait so a test can stand a fake permaura.com behind it.
#[async_trait::async_trait]
pub(crate) trait Transport: Send + Sync {
    /// `PATCH` a re-seal.
    async fn send(&self, url: &reqwest::Url, body: &serde_json::Value) -> Result<Reply, String>;
    /// `POST` a check-in.
    async fn check_in(&self, url: &reqwest::Url, body: &serde_json::Value) -> Result<Reply, String>;
}

/// The production transport: https only, no redirects.
pub(crate) struct Https {
    client: reqwest::Client,
}

impl Https {
    pub(crate) fn new(timeout: Duration) -> Result<Self, String> {
        Ok(Https { client: client(true, timeout)? })
    }
}

#[async_trait::async_trait]
impl Transport for Https {
    async fn send(&self, url: &reqwest::Url, body: &serde_json::Value) -> Result<Reply, String> {
        patch(&self.client, url.clone(), body).await
    }

    async fn check_in(&self, url: &reqwest::Url, body: &serde_json::Value) -> Result<Reply, String> {
        post(&self.client, url.clone(), body).await
    }
}

fn client(https_only: bool, timeout: Duration) -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .https_only(https_only)
        // A 307 or 308 resends the body, install secret and token included, wherever it points.
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .map_err(|e| e.to_string())
}

async fn patch(client: &reqwest::Client, url: reqwest::Url, body: &serde_json::Value) -> Result<Reply, String> {
    reply(client.patch(url).json(body).send().await).await
}

async fn post(client: &reqwest::Client, url: reqwest::Url, body: &serde_json::Value) -> Result<Reply, String> {
    reply(client.post(url).json(body).send().await).await
}

async fn reply(sent: reqwest::Result<reqwest::Response>) -> Result<Reply, String> {
    let resp = sent.map_err(|e| e.without_url().to_string())?;
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(|secs| Duration::from_secs(secs).min(MAX_RETRY_AFTER));
    let status = resp.status().as_u16();
    let answer = crate::announce::read_answer(resp).await;
    Ok(Reply {
        status,
        retry_after,
        needs_reseal: answer.needs_reseal,
        owner_sub: answer.owner_sub,
        public_url: answer.public_url,
        row_public_url: answer.row_public_url,
    })
}

/// The re-seal URL for one link, or why the token may not go there.
pub(crate) fn endpoint(base: &str, gateway_id: &str) -> Result<reqwest::Url, String> {
    link_url(base, gateway_id, "operator-token")
}

/// The check-in URL for one link, held to the same rules as the re-seal's, since it carries the link's announce credential.
pub(crate) fn checkin_endpoint(base: &str, gateway_id: &str) -> Result<reqwest::Url, String> {
    link_url(base, gateway_id, "checkin")
}

fn link_url(base: &str, gateway_id: &str, leaf: &str) -> Result<reqwest::Url, String> {
    let mut url =
        reqwest::Url::parse(base.trim()).map_err(|_| "the control plane address is not a URL".to_string())?;
    if url.scheme() != "https" {
        return Err(format!("the control plane address is {}, not https", url.scheme()));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("the control plane address carries credentials".into());
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err("the control plane address is not a bare origin".into());
    }
    let host = url.host_str().unwrap_or_default();
    if is_this_machine(host.trim_start_matches('[').trim_end_matches(']').trim_end_matches('.')) {
        return Err("the control plane address is this machine".into());
    }
    if !crate::announce::is_gateway_id(gateway_id) {
        return Err("the link's gateway id has an unexpected shape".into());
    }
    url.set_path(&format!("/api/gateways/{gateway_id}/{leaf}"));
    Ok(url)
}

fn is_this_machine(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    if host.is_empty() || host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback() || ip.is_unspecified(),
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        }
        Err(_) => false,
    }
}

/// The body `PATCH /api/gateways/:id/operator-token` takes.
pub(crate) fn body(install: &Install, token: &str) -> serde_json::Value {
    serde_json::json!({ "installId": install.install_id, "installSecret": install.secret, "token": token })
}

/// Where one link stands.
#[derive(Default)]
struct LinkState {
    /// The token permaura.com last accepted for this link.
    sealed: Option<String>,
    /// The fingerprint of the announce secret this state was kept for, kept across a reopening and a seal.
    fingerprint: Option<String>,
    /// A token this link refused, not offered again.
    refused: Option<String>,
    /// permaura.com said this link is not this machine's to re-seal; nothing more goes to it.
    closed: bool,
    failures: usize,
    not_before: Option<Instant>,
    sealed_at: Option<Instant>,
    /// When permaura.com's request last reopened this link.
    reopened_at: Option<Instant>,
}

enum Verdict {
    Landed,
    Retry(Option<Duration>, String),
    RefuseToken(u16),
    CloseLink(u16),
}

fn judge(sent: Result<Result<Reply, String>, tokio::time::error::Elapsed>) -> Verdict {
    match sent {
        Err(_) => Verdict::Retry(None, "no answer in time".into()),
        Ok(Err(e)) => Verdict::Retry(None, e),
        Ok(Ok(Reply { status, retry_after, .. })) => match status {
            200..=299 => Verdict::Landed,
            403 | 409 | 410 => Verdict::CloseLink(status),
            // A permaura.com that predates the re-seal route answers 404 too, and closing the link on it would leave the console's copy to lapse until the gateway restarts.
            404 | 408 | 425 | 429 | 500..=599 => Verdict::Retry(retry_after, format!("permaura.com answered {status}")),
            _ => Verdict::RefuseToken(status),
        },
    }
}

fn refusal(status: u16) -> &'static str {
    match status {
        403 => "permaura.com says this is not this machine's link (made without an install identity, or by another machine), so its console bearer is not re-sealed; pair again if the console cannot reach this gateway",
        410 => "permaura.com no longer has this link, so its console bearer is not re-sealed",
        409 => "permaura.com holds this link as a hosted gateway or one with a public address, which it reaches with the owner's own token, so it keeps no sealed bearer for it",
        300..=399 => "permaura.com answered the re-seal with a redirect, which is never followed with a credential in the body",
        _ => "permaura.com refused this console bearer for the link; the next one minted is offered again",
    }
}

/// What permaura.com may hold now, newest first; see [`HeldConsoleSessions`].
fn held_by_permaura_com(current: Option<&str>, links: &HashMap<String, LinkState>) -> Vec<String> {
    let open: Vec<&LinkState> = links.values().filter(|l| !l.closed).collect();
    let mut held: Vec<String> = Vec::new();
    if let Some(current) = current {
        if open.iter().any(|l| l.refused.as_deref() != Some(current)) {
            held.push(current.to_string());
        }
    }
    let mut sealed: Vec<(&str, Option<Instant>)> =
        open.iter().filter_map(|l| Some((l.sealed.as_deref()?, l.sealed_at))).collect();
    sealed.sort_by_key(|(_, at)| std::cmp::Reverse(*at));
    for (token, _) in sealed {
        if !held.iter().any(|h| h == token) {
            held.push(token.to_string());
        }
    }
    held
}

/// Re-seal every link whenever the console bearer changes, until the gateway stops.
pub(crate) async fn run(sources: Sources, transport: Arc<dyn Transport>, timing: Timing) {
    let mut links: HashMap<String, LinkState> = HashMap::new();
    let mut said_no_install = false;
    // The pairing count `operator.token` was last rotated for; `None` until the first poll with a link, which rotates whatever a previous run left in the file.
    let mut rotated_for: Option<u64> = None;
    loop {
        match (sources.linked)() {
            None => {
                links.clear();
                sources.held.set(Vec::new());
            }
            Some(linked) => {
                links.retain(|id, _| linked.gateway_ids.contains(id));
                let asked = sources.asked.take();
                // Read before the token, so a pairing that lands between the two is still rotated for at the next poll.
                let pairings = sources.pairings.count();
                // Read at the moment of sending: permaura.com keeps whatever arrives last, so a retry must never carry a bearer older than the current one.
                let token = (sources.token)();
                // Before the offers, which permaura.com can hold open for a whole request timeout per link; it still has the grace to take the console session before the token it may hold dies. Due on this gateway's clock whatever permaura.com answers, once per pairing however many links it named.
                if token.is_some() && rotated_for != Some(pairings) {
                    if let Some(rotation) = &sources.rotation {
                        rotation.rotate();
                    }
                    rotated_for = Some(pairings);
                }
                for gateway_id in &linked.gateway_ids {
                    let state = links.entry(gateway_id.clone()).or_default();
                    if let Some(fingerprint) = linked.fingerprints.get(gateway_id) {
                        if state.fingerprint.as_ref().is_some_and(|kept| kept != fingerprint) {
                            tracing::info!(link = %gateway_id, "this link was paired again, so the current console session is offered to it afresh");
                            *state = LinkState::default();
                        }
                        state.fingerprint = Some(fingerprint.clone());
                    }
                    if asked.contains(gateway_id) {
                        reopen(gateway_id, state, &timing);
                    }
                }
                // Before anything is sent, so `/health` already proves a session by the time permaura.com can hand it to a browser.
                sources.held.set(held_by_permaura_com(token.as_deref(), &links));
                for gateway_id in &linked.gateway_ids {
                    let Some(state) = links.get_mut(gateway_id) else { continue };
                    let Some(token) = token.clone() else { continue };
                    reseal(&sources, transport.as_ref(), &timing, &linked.base, gateway_id, token, state, &mut said_no_install).await;
                }
                sources.held.set(held_by_permaura_com(token.as_deref(), &links));
            }
        }
        tokio::time::sleep(timing.poll).await;
    }
}

/// Forget what this link was last told and why it was left alone, so the current console session is offered to it again: permaura.com said it holds none. At most once per [`Timing::reopen_every`].
fn reopen(gateway_id: &str, state: &mut LinkState, timing: &Timing) {
    if state.reopened_at.is_some_and(|at| at.elapsed() < timing.reopen_every) {
        return;
    }
    tracing::info!(link = %gateway_id, "permaura.com holds no console bearer for this link, so the current one is sealed again");
    *state = LinkState { reopened_at: Some(Instant::now()), fingerprint: state.fingerprint.take(), ..LinkState::default() };
}

/// Offer `token` to one link.
#[allow(clippy::too_many_arguments)]
async fn reseal(
    sources: &Sources,
    transport: &dyn Transport,
    timing: &Timing,
    base: &str,
    gateway_id: &str,
    token: String,
    state: &mut LinkState,
    said_no_install: &mut bool,
) {
    if state.closed || state.not_before.is_some_and(|at| Instant::now() < at) {
        return;
    }
    if state.sealed.as_deref() == Some(token.as_str()) || state.refused.as_deref() == Some(token.as_str()) {
        return;
    }
    let url = match endpoint(base, gateway_id) {
        Ok(url) => url,
        Err(why) => {
            tracing::error!(link = %gateway_id, "console bearer not re-sealed: {why}");
            state.closed = true;
            return;
        }
    };
    let Some(install) = (sources.install)() else {
        if !*said_no_install {
            tracing::warn!("this gateway is linked to permaura.com but has no install identity, so permaura.com's console bearer for it cannot be kept current; pair again");
            *said_no_install = true;
        }
        state.refused = Some(token);
        return;
    };
    let sent = tokio::time::timeout(timing.request_timeout, transport.send(&url, &body(&install, &token))).await;
    let asked_again = matches!(&sent, Ok(Ok(reply)) if reply.needs_reseal);
    let verdict = judge(sent);
    // A seal that landed is the answer to the request, so only an answer that did not take this bearer can ask again.
    if asked_again && !matches!(verdict, Verdict::Landed) {
        sources.asked.ask(gateway_id);
    }
    match verdict {
        Verdict::Landed => {
            tracing::info!(link = %gateway_id, attempt = state.failures + 1, "permaura.com now holds this gateway's current console bearer");
            *state = LinkState {
                sealed: Some(token),
                sealed_at: Some(Instant::now()),
                reopened_at: state.reopened_at,
                fingerprint: state.fingerprint.take(),
                ..LinkState::default()
            };
        }
        Verdict::Retry(asked, why) => {
            let step = timing.backoff.get(state.failures).or(timing.backoff.last()).copied().unwrap_or(timing.poll);
            let wait = asked.map_or(step, |asked| asked.max(step));
            state.failures += 1;
            state.not_before = Some(Instant::now() + wait);
            tracing::warn!(link = %gateway_id, attempt = state.failures, retry_in = ?wait, "could not hand permaura.com this gateway's current console bearer ({why}); retrying");
        }
        Verdict::RefuseToken(status) => {
            tracing::warn!(link = %gateway_id, status, "{}", refusal(status));
            state.refused = Some(token);
            state.failures = 0;
            state.not_before = None;
        }
        Verdict::CloseLink(status) => {
            tracing::warn!(link = %gateway_id, status, "{}", refusal(status));
            state.closed = true;
        }
    }
}

/// Keep permaura.com's sealed console bearer current for a self-run gateway: its links are the ones it announces to, and its install identity is the one in `$PERMAURA_HOME`. `held` is where it says which sessions permaura.com may hold, for `/health` to prove. `published` is the operator token this gateway published, which is rotated at the first poll with a link and after every pairing on this machine.
///
/// `config_path` is where an owner re-pin a check-in brings is written, so it survives a restart; the environment keeps the pin only when the app that supervises this gateway set `PERMAURA_OWNER_SUB`.
pub fn spawn(
    service: Arc<crate::service::EnforcementService>,
    held: Arc<HeldConsoleSessions>,
    published: Arc<crate::PublishedToken>,
    config_path: Option<std::path::PathBuf>,
) {
    let timing = Timing::default();
    let transport = match Https::new(timing.request_timeout) {
        Ok(transport) => Arc::new(transport),
        Err(e) => {
            tracing::warn!("could not build the client that keeps permaura.com's console bearer current ({e})");
            return;
        }
    };
    let rotation = crate::OperatorTokenRotation::for_this_install(service.store().clone(), published);
    let owner = OwnerPin::new(
        crate::config::pinned_by_environment("PERMAURA_OWNER_SUB"),
        crate::config::supervised_by_app(),
        config_path,
        crate::config::environment_owner_sub(),
    );
    start_with(service, held, Box::new(permaura_core::install::load), transport, timing, rotation, owner);
}

/// Where an owner named at a check-in may go: nowhere when the app that supervises this gateway set `PERMAURA_OWNER_SUB` (the desktop re-binds on its own), otherwise the resource server and, when there is one, the config file, with the environment's own value recorded as the one it replaces.
pub(crate) struct OwnerPin {
    pub(crate) settable: bool,
    pub(crate) config_path: Option<std::path::PathBuf>,
    pub(crate) replaces_env: Option<String>,
}

impl OwnerPin {
    /// A VPS's `gateway.env` pins `PERMAURA_OWNER_SUB` too, and nothing there re-binds it, so only an environment pin under `PERMAURA_SUPERVISED_BY_APP` is a supervisor's.
    pub(crate) fn new(env_pinned: bool, supervised: bool, config_path: Option<std::path::PathBuf>, environment_owner: Option<String>) -> Self {
        OwnerPin { settable: !(env_pinned && supervised), config_path, replaces_env: environment_owner }
    }

    /// In memory only, as a test wants it.
    #[cfg(test)]
    pub(crate) fn in_memory() -> Self {
        OwnerPin::new(false, false, None, None)
    }

    fn repin(self, service: Arc<crate::service::EnforcementService>) -> OwnerRepin {
        Arc::new(move |sub: &str| {
            if let Err(e) = service.repin_owner(sub, self.settable, self.config_path.as_deref(), self.replaces_env.as_deref()) {
                tracing::warn!(error = %e, "permaura.com named a new owner for this gateway at a check-in, but the binding could not be moved");
            }
        })
    }
}

/// What a link's check-in told this gateway.
#[derive(Debug, PartialEq, Eq)]
enum CheckIn {
    /// permaura.com answered; `true` when it holds no bearer for the link and wants one.
    Answered(bool),
    /// 404: permaura.com has no live row this link's announce credential names (the row was removed, a re-pair replaced it, or its secret was rotated and the new one never reached this machine), or it has no check-in route yet.
    NoSuchRow,
    /// 401 or 403: the link's announce credential is not the one permaura.com holds.
    Refused(u16),
    /// 409: a hosted row or one with a public URL, which holds no sealed bearer, so nothing is re-sealed.
    NoBearerHeld,
    /// Anything else, a transport error or no answer in time.
    Failed(String),
}

fn judge_check_in(sent: Result<Result<Reply, String>, tokio::time::error::Elapsed>) -> CheckIn {
    match sent {
        Err(_) => CheckIn::Failed("no answer in time".into()),
        Ok(Err(e)) => CheckIn::Failed(e),
        Ok(Ok(Reply { status, needs_reseal, .. })) => match status {
            200..=299 => CheckIn::Answered(needs_reseal),
            404 => CheckIn::NoSuchRow,
            401 | 403 => CheckIn::Refused(status),
            409 => CheckIn::NoBearerHeld,
            _ => CheckIn::Failed(format!("permaura.com answered {status}")),
        },
    }
}

/// Whether two public addresses are one origin, compared as permaura.com compares them (`canonicalOrigin`): scheme and host without case, a default port, and any path, trailing slash or trailing dot ignored. Anything but an http(s) URL matches nothing.
fn same_address(a: &str, b: &str) -> bool {
    fn origin(raw: &str) -> Option<(String, String, Option<u16>)> {
        let url = reqwest::Url::parse(raw.trim()).ok()?;
        if !matches!(url.scheme(), "https" | "http") {
            return None;
        }
        let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
        (!host.is_empty()).then(|| (url.scheme().to_string(), host, url.port_or_known_default()))
    }
    matches!((origin(a), origin(b)), (Some(a), Some(b)) if a == b)
}

/// Why a check-in that may hold the public URL gave no owner, for the log.
fn unanswered(sent: &Result<Result<Reply, String>, tokio::time::error::Elapsed>) -> String {
    match sent {
        Err(_) => "no answer in time".into(),
        Ok(Err(e)) => e.clone(),
        Ok(Ok(reply)) => format!("permaura.com answered {}", reply.status),
    }
}

/// What a check-in does with the owner permaura.com names: see [`crate::service::EnforcementService::repin_owner`].
pub(crate) type OwnerRepin = Arc<dyn Fn(&str) + Send + Sync>;

/// Every [`Timing::check_in`], ask permaura.com, for each link, whether it still holds the link's console bearer, and record a link it says does not in `asked` for the re-seal task. The first check-in is one interval after boot, which seals at once anyway.
///
/// The check-in for the link whose row holds this gateway's public URL (the 409 answer that says `publicUrl: true` with a `publicUrlValue` that is this gateway's public URL or one of its aliases, `own_addresses`, or with no `publicUrlValue` at all from a permaura.com older than that field) also names that organization's owner now; it goes to `repin`, which is how a headless gateway pinned to a previous owner follows an ownership change without anyone re-running `permaura remote enable`. The check-in carries the link's announce credential, so permaura.com answers only for a row that credential names; the answer itself is trusted on HTTPS to the linked control plane, so whoever controls permaura.com decides which owner this gateway accepts tokens for. Every other link's owner is ignored: a machine paired into a second organization is answered with that organization's owner too, and following it would hand the gateway to whoever paired it last, then back, on every round.
///
/// The binding moves only on a round where every link that may hold the public URL answered and they all named the same owner. A link may hold it when its last answer said so, and when it has not answered since boot; a link whose last answer was a 2xx, a 409 without `publicUrl: true`, a 409 whose `publicUrlValue` is another address or `null`, or a 404 does not. A 404 is permaura.com saying no live row answers to the link's credential, which a removed row's link, or the one a re-pair leaves behind (pairing adds a link and never drops the old one), answers every round; counted as silence it froze the pin for good. permaura.com gives that one 404 for every credential it cannot match, so a link to this gateway's own row whose secret was rotated without reaching this machine is set aside the same way. The log warns of a link's 404, naming both causes and what to do, when the link starts answering 404, and again only after it has had a 2xx, 401, 403 or 409 (no answer, a 5xx or a 429 says nothing of the row) or has left this gateway's links. The rule below does not hold for such a link: another row holding this gateway's address, which permaura.com allows only for the same machine, or one from a permaura.com too old to send `publicUrlValue`, then decides alone. Nor does a row that names an address other than this gateway's: a second organization's row holding an address of its own answers `publicUrl: true` too, and without the address the two rows could only disagree for good. A `publicUrlValue: null` is permaura.com saying the row's stored public URL is not an origin, so that row holds no address of this gateway's and is set aside the same way; only an answer with no `publicUrlValue` at all, from a permaura.com older than the field, is taken at its word. So two rows that disagree keep the pin until they agree, and a round in which one of them fails (no answer, a 5xx, a 429 a neighbor's traffic can cause, a refused credential, or no owner named) is not taken as the other's word: one transient failure would otherwise hand the gateway to the other organization's owner and lock out the one who set remote access up.
///
/// On a gateway with a public URL, a round in which at most one owner was named and a link that may hold the public URL named none is held back, and the log names each such link with why (the status permaura.com answered, a transport error, no answer in time, or a row holding the public URL that named no owner). That is logged when the links or any reason differ from the round before, and when the round before was not held back: it settled, with a repin or with no owner to repin to, or its rows named different owners. The same links for the same reasons round after round are logged once.
pub(crate) async fn check_ins(
    links: Box<dyn Fn() -> Vec<crate::announce::Config> + Send + Sync>,
    asked: Arc<crate::announce::ResealRequests>,
    transport: Arc<dyn Transport>,
    timing: Timing,
    repin: OwnerRepin,
    own_addresses: Vec<String>,
) {
    let mut said_refused = std::collections::HashSet::<String>::new();
    let mut said_no_row = std::collections::HashSet::<String>::new();
    let mut said_elsewhere = std::collections::HashSet::<String>::new();
    let mut said_no_address = std::collections::HashSet::<String>::new();
    let mut said_disagree = false;
    // The links the last round was held back on, with why, as logged; empty after a round that was not.
    let mut said_waiting_on = Vec::<(String, String)>::new();
    // Whether each link's last answer said its row holds the public URL; a link missing here has not answered since boot.
    let mut holds_public_url = HashMap::<String, bool>::new();
    let mut wait = timing.first_check_in;
    loop {
        tokio::time::sleep(wait).await;
        wait = timing.check_in;
        let mut owners = std::collections::BTreeSet::<String>::new();
        // The links that may hold the public URL and gave no owner this round, each with why.
        let mut waiting_on = Vec::<(String, String)>::new();
        let links = links();
        holds_public_url.retain(|id, _| links.iter().any(|link| link.gateway_id() == id));
        said_no_row.retain(|id| links.iter().any(|link| link.gateway_id() == id));
        for link in links {
            let gateway_id = link.gateway_id().to_string();
            let Ok(url) = checkin_endpoint(link.base_url(), &gateway_id) else { continue };
            let body = crate::announce::checkin_payload(&link);
            let sent = tokio::time::timeout(timing.request_timeout, transport.check_in(&url, &body)).await;
            match &sent {
                Ok(Ok(Reply { status: 409, public_url: true, row_public_url: RowAddress::Address(theirs), .. }))
                    if !own_addresses.iter().any(|own| same_address(own, theirs)) =>
                {
                    holds_public_url.insert(gateway_id.clone(), false);
                    if said_elsewhere.insert(gateway_id.clone()) {
                        tracing::info!(link = %gateway_id, address = %theirs, "this link's row holds a public URL that is not this gateway's, so it plays no part in the owner binding");
                    }
                }
                Ok(Ok(Reply { status: 409, public_url: true, row_public_url: RowAddress::NoAddress, .. })) => {
                    holds_public_url.insert(gateway_id.clone(), false);
                    if said_no_address.insert(gateway_id.clone()) {
                        tracing::info!(link = %gateway_id, "permaura.com says this link's row holds a public URL but names no address for it (the one it stores is not an origin), so the row holds none of this gateway's and plays no part in the owner binding");
                    }
                }
                Ok(Ok(Reply { status: 409, public_url: true, owner_sub, .. })) => {
                    holds_public_url.insert(gateway_id.clone(), true);
                    match owner_sub {
                        Some(owner) => {
                            owners.insert(owner.clone());
                        }
                        None => waiting_on.push((gateway_id.clone(), "its row holds the public URL and named no owner".into())),
                    }
                }
                Ok(Ok(Reply { status: 200..=299 | 404 | 409, .. })) => {
                    holds_public_url.insert(gateway_id.clone(), false);
                }
                _ if holds_public_url.get(&gateway_id) == Some(&false) => {}
                _ => waiting_on.push((gateway_id.clone(), unanswered(&sent))),
            }
            let verdict = judge_check_in(sent);
            // No answer, a 5xx or a 429 says nothing of the row, so only another answer ends a run of 404s.
            if !matches!(verdict, CheckIn::NoSuchRow | CheckIn::Failed(_)) {
                said_no_row.remove(&gateway_id);
            }
            match verdict {
                CheckIn::Answered(true) => asked.ask(&gateway_id),
                CheckIn::Answered(false) | CheckIn::NoBearerHeld => {}
                CheckIn::NoSuchRow => {
                    if said_no_row.insert(gateway_id.clone()) {
                        tracing::warn!(link = %gateway_id, "permaura.com answered this link's check-in 404: no live row answers to its announce credential. Either the row was removed or a later pairing replaced it, or the link's announce secret was rotated on permaura.com and the new one never reached this machine. Until that changes the link holds no public URL and plays no part in the owner binding. If the row is still this gateway's, run `permaura announce rotate --gateway {gateway_id}` on this machine to save a new announce secret (where the announce credentials come from the environment or the hosting, change them there). If the row is gone, the link is dead: drop it with DELETE /v1/announce naming gateway_id {gateway_id}, and this line stops");
                    }
                }
                CheckIn::Refused(status) => {
                    if said_refused.insert(gateway_id.clone()) {
                        tracing::warn!(link = %gateway_id, status, "permaura.com refused this link's check-in: its announce credential is not the one permaura.com holds, so a console bearer it has lost is not noticed until the gateway restarts; pair again");
                    }
                }
                CheckIn::Failed(why) => tracing::debug!(link = %gateway_id, "check-in with permaura.com did not complete ({why})"),
            }
        }
        waiting_on.sort();
        let mut owners = owners.into_iter();
        let held_back = match (owners.next(), owners.next()) {
            (Some(owner), None) if waiting_on.is_empty() => {
                said_disagree = false;
                repin(&owner);
                false
            }
            // A loopback-only gateway has no binding to hold.
            (_, None) if !waiting_on.is_empty() && !own_addresses.is_empty() => {
                if waiting_on != said_waiting_on {
                    let why = waiting_on.iter().map(|(id, why)| format!("{id}: {why}")).collect::<Vec<_>>().join("; ");
                    tracing::info!(waiting_on = %why, "a link that may hold this gateway's public URL did not name its owner at this check-in, so the owner binding stays where it is until every such link answers");
                }
                true
            }
            (Some(_), Some(_)) => {
                if !said_disagree {
                    said_disagree = true;
                    tracing::warn!("more than one of this gateway's links says it holds the public URL, and they name different owners, so the owner binding stays where it is; set PERMAURA_OWNER_SUB, or owner_sub in the config file when nothing sets it, to the owner you mean");
                }
                false
            }
            _ => false,
        };
        said_waiting_on = if held_back { waiting_on } else { Vec::new() };
    }
}

/// [`start_with`], keeping an owner re-pin in memory.
#[cfg(test)]
pub(crate) fn start(
    service: Arc<crate::service::EnforcementService>,
    held: Arc<HeldConsoleSessions>,
    install: Box<dyn Fn() -> Option<Install> + Send + Sync>,
    transport: Arc<dyn Transport>,
    timing: Timing,
    rotation: Option<crate::OperatorTokenRotation>,
) -> bool {
    start_with(service, held, install, transport, timing, rotation, OwnerPin::in_memory())
}

/// Start the check-ins, and the re-seal task unless this gateway has a public URL; say whether the re-seal task started. A public URL is the one predicate: with it nothing is sealed or reopened, whatever permaura.com asks. The check-ins run either way, since a gateway with a public URL is the one an owner re-pin is for.
pub(crate) fn start_with(
    service: Arc<crate::service::EnforcementService>,
    held: Arc<HeldConsoleSessions>,
    install: Box<dyn Fn() -> Option<Install> + Send + Sync>,
    transport: Arc<dyn Transport>,
    timing: Timing,
    rotation: Option<crate::OperatorTokenRotation>,
    owner: OwnerPin,
) -> bool {
    let asked = service.reseal_requests();
    let announcing = service.clone();
    let public = service.oauth().is_some();
    let check_in_timing = if public { timing.clone().for_public_url() } else { timing.clone() };
    tokio::spawn(check_ins(
        Box::new(move || announcing.announce_links()),
        asked.clone(),
        transport.clone(),
        check_in_timing,
        owner.repin(service.clone()),
        service.oauth().map(|oauth| std::iter::once(&oauth.config().public_url).chain(&oauth.config().public_url_aliases).cloned().collect::<Vec<_>>()).unwrap_or_default(),
    ));
    if public {
        held.set(Vec::new());
        let revoked = crate::revoke_console_sessions(service.store().as_ref());
        tracing::info!(revoked, "this gateway has a public URL, so permaura.com reaches it with the owner's own short-lived token and holds no sealed bearer for it");
        return false;
    }
    let console = ConsoleSession::new(service.store().clone());
    let pairings = service.pairings();
    let sources = Sources {
        token: Box::new(move || console.current()),
        linked: Box::new(move || Linked::from_announce(&service.announce_links())),
        install,
        asked,
        pairings,
        rotation,
        held,
    };
    tokio::spawn(run(sources, transport, timing));
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PublishedToken;
    use std::sync::Mutex;
    use std::time::Instant;

    const INSTALL_ID: &str = "gwi_AbCdEfGhIjKlMnOpQrStUvWxYz012345";
    const INSTALL_SECRET: &str = "s3cr3t-install-value-never-logged";
    const T1: &str = "pgc_firsttokenvalue0001";
    const T2: &str = "pgc_secondtokenvalue0002";

    fn fast() -> Timing {
        Timing {
            poll: Duration::from_millis(10),
            backoff: vec![Duration::from_millis(60), Duration::from_millis(120)],
            request_timeout: Duration::from_secs(2),
            // Never within a test unless it asks for check-ins with `checking_in`.
            check_in: Duration::from_secs(3600),
            first_check_in: Duration::from_secs(3600),
            reopen_every: Duration::from_millis(50),
        }
    }

    /// [`fast`], checking in every 30 ms.
    fn checking_in() -> Timing {
        Timing { check_in: Duration::from_millis(30), first_check_in: Duration::from_millis(30), ..fast() }
    }

    /// A gateway with a public URL checks in soon after boot, so a restart after a hand-over is re-pinned at once; a loopback-only gateway keeps its first check-in one interval out, and a test's faster cadence is never slowed.
    #[test]
    fn a_public_gateway_checks_in_soon_after_boot() {
        let production = Timing::default().for_public_url();
        assert_eq!(production.first_check_in, PUBLIC_FIRST_CHECK_IN);
        assert_eq!(production.check_in, Duration::from_secs(15 * 60), "the cadence is unchanged");
        assert_eq!(Timing::default().first_check_in, Timing::default().check_in, "loopback-only: one interval out");
        assert_eq!(checking_in().for_public_url().first_check_in, Duration::from_millis(30));
    }

    fn install() -> Option<Install> {
        Some(Install { install_id: INSTALL_ID.into(), secret: INSTALL_SECRET.into() })
    }

    /// A control plane under a name that never resolves: the re-seal transport here carries its requests to a loopback server, and anything else these links announce goes nowhere.
    const CONTROL_PLANE_HOST: &str = "permaura.invalid";

    fn link(gateway_id: &str) -> crate::announce::Config {
        crate::announce::Config::at(&format!("https://{CONTROL_PLANE_HOST}"), gateway_id, "gwa_0123456789abcdefghijklmnopqrstuv")
    }

    /// Links a request makes in this test (`PUT /v1/announce`) name [`CONTROL_PLANE_HOST`] too. The runtime is this test's own thread.
    fn links_name_the_test_control_plane() {
        crate::announce::TEST_CONTROL_PLANE.with(|named| *named.borrow_mut() = Some(format!("https://{CONTROL_PLANE_HOST}")));
    }

    /// A gateway as `permaura start` wires one: the console bearer it holds sealed now, and the announce links a pairing sets through `PUT /v1/announce`.
    struct Gateway {
        console: Arc<PublishedToken>,
        announcer: Arc<crate::announce::Announcer>,
        held: Arc<HeldConsoleSessions>,
    }

    impl Gateway {
        fn new(token: Option<&str>) -> Self {
            let console = Arc::new(PublishedToken::default());
            console.set(token.map(String::from));
            Gateway {
                console,
                announcer: Arc::new(crate::announce::Announcer::with(Vec::new())),
                held: Arc::new(HeldConsoleSessions::default()),
            }
        }

        /// What the last step of `permaura pair`, `start --pair` and the desktop's pairing does.
        fn enrol(&self, gateway_ids: &[&str]) {
            self.announcer.set(gateway_ids.iter().map(|id| link(id)).collect());
            self.announcer.pairings().note();
        }

        fn sources(&self, install: Option<Install>) -> Sources {
            let announcer = self.announcer.clone();
            let console = self.console.clone();
            Sources {
                token: Box::new(move || console.get()),
                linked: Box::new(move || Linked::from_announce(&announcer.links())),
                install: Box::new(move || install.clone()),
                asked: self.announcer.reseal_requests(),
                pairings: self.announcer.pairings(),
                rotation: None,
                held: self.held.clone(),
            }
        }
    }

    #[derive(Clone, Debug)]
    struct Seen {
        method: String,
        path: String,
        body: serde_json::Value,
        at: Instant,
    }

    impl Seen {
        fn token(&self) -> &str {
            self.body["token"].as_str().unwrap_or_default()
        }
    }

    /// Hold the first request until the test lets it go.
    #[derive(Clone, Default)]
    struct Gate {
        arrived: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }

    /// Status, and an optional `Location` or `Retry-After` value, for the nth request and its body.
    type Answer = Arc<dyn Fn(usize, &Seen) -> (u16, Option<(&'static str, String)>) + Send + Sync>;

    /// The body to answer a request with, when it is not the re-seal's own.
    type Said = Arc<dyn Fn(&Seen) -> Option<serde_json::Value> + Send + Sync>;

    struct Fake {
        addr: std::net::SocketAddr,
        seen: Arc<Mutex<Vec<Seen>>>,
    }

    impl Fake {
        fn seen(&self) -> Vec<Seen> {
            self.seen.lock().unwrap().clone()
        }
        fn count(&self) -> usize {
            self.seen.lock().unwrap().len()
        }
        fn to(&self, gateway_id: &str) -> Vec<Seen> {
            let path = format!("/api/gateways/{gateway_id}/operator-token");
            self.seen().into_iter().filter(|s| s.path == path).collect()
        }
    }

    /// A stand-in for permaura.com on a loopback port, recording every request it is sent.
    async fn fake(answer: Answer, gate: Option<Gate>) -> Fake {
        links_name_the_test_control_plane();
        fake_saying(answer, gate, Arc::new(|_| None)).await
    }

    /// [`fake`], answering with `said`'s body wherever it gives one.
    async fn fake_saying(answer: Answer, gate: Option<Gate>, said: Said) -> Fake {
        let seen = Arc::new(Mutex::new(Vec::<Seen>::new()));
        let record = seen.clone();
        let app = axum::Router::new().fallback(move |req: axum::extract::Request| {
            let (record, answer, gate, said) = (record.clone(), answer.clone(), gate.clone(), said.clone());
            async move {
                let (parts, body) = req.into_parts();
                let bytes = axum::body::to_bytes(body, 1 << 16).await.unwrap_or_default();
                let seen = Seen {
                    method: parts.method.to_string(),
                    path: parts.uri.path().to_string(),
                    body: serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
                    at: Instant::now(),
                };
                let n = {
                    let mut all = record.lock().unwrap();
                    all.push(seen.clone());
                    all.len() - 1
                };
                if n == 0 {
                    if let Some(gate) = &gate {
                        gate.arrived.notify_one();
                        gate.release.notified().await;
                    }
                }
                let (status, header) = answer(n, &seen);
                let ok = said(&seen)
                    .unwrap_or_else(|| serde_json::json!({ "id": "gw", "sealedAt": "2026-10-14T00:00:00.000Z", "last4": "0001" }));
                let mut resp = axum::response::Response::new(axum::body::Body::from(ok.to_string()));
                *resp.status_mut() = axum::http::StatusCode::from_u16(status).unwrap();
                if let Some((name, value)) = header {
                    resp.headers_mut().insert(name, value.parse().unwrap());
                }
                resp
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Fake { addr, seen }
    }

    fn answer(f: impl Fn(usize, &Seen) -> (u16, Option<(&'static str, String)>) + Send + Sync + 'static) -> Answer {
        Arc::new(f)
    }

    fn always(status: u16) -> Answer {
        answer(move |_, _| (status, None))
    }

    /// The task only ever hands a transport a vetted https URL on permaura.com, so the test transport checks that and then delivers the same request to the fake over loopback, through the client settings and request builder the real one uses.
    struct Loopback {
        client: reqwest::Client,
        origin: String,
    }

    impl Loopback {
        fn to(addr: std::net::SocketAddr) -> Arc<dyn Transport> {
            Arc::new(Loopback { client: client(false, Duration::from_secs(2)).unwrap(), origin: format!("http://{addr}") })
        }
    }

    #[async_trait::async_trait]
    impl Transport for Loopback {
        async fn send(&self, url: &reqwest::Url, body: &serde_json::Value) -> Result<Reply, String> {
            assert_eq!(url.scheme(), "https");
            assert_eq!(url.host_str(), Some(CONTROL_PLANE_HOST));
            let target = reqwest::Url::parse(&format!("{}{}", self.origin, url.path())).unwrap();
            patch(&self.client, target, body).await
        }

        async fn check_in(&self, url: &reqwest::Url, body: &serde_json::Value) -> Result<Reply, String> {
            assert_eq!(url.scheme(), "https");
            assert_eq!(url.host_str(), Some(CONTROL_PLANE_HOST));
            let target = reqwest::Url::parse(&format!("{}{}", self.origin, url.path())).unwrap();
            post(&self.client, target, body).await
        }
    }

    /// Records that a send was attempted at all.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

    #[async_trait::async_trait]
    impl Transport for Recorder {
        async fn send(&self, url: &reqwest::Url, _: &serde_json::Value) -> Result<Reply, String> {
            self.0.lock().unwrap().push(url.to_string());
            Ok(Reply { status: 200, retry_after: None, needs_reseal: false, owner_sub: None, public_url: false, row_public_url: RowAddress::Unsent })
        }

        async fn check_in(&self, url: &reqwest::Url, _: &serde_json::Value) -> Result<Reply, String> {
            self.0.lock().unwrap().push(url.to_string());
            Ok(Reply { status: 200, retry_after: None, needs_reseal: false, owner_sub: None, public_url: false, row_public_url: RowAddress::Unsent })
        }
    }

    #[derive(Clone, Default)]
    struct Logs(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Logs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Logs {
        /// Capture on this thread at the filter `permaura start` runs with. Every test here is a current-thread runtime, so the task, the client and the fake all log through it.
        fn capture(&self) -> (tracing::subscriber::DefaultGuard, tracing::Dispatch) {
            let subscriber = |writer: Logs| {
                tracing_subscriber::fmt()
                    .with_env_filter(tracing_subscriber::EnvFilter::new("info,permaura_gateway=debug"))
                    .with_writer(move || writer.clone())
                    .with_ansi(false)
                    .finish()
            };
            // With one dispatcher alive tracing-core caches a callsite's interest from whichever thread hits it first, so a test that logs nothing would mute this capture's callsites; a second one keeps every thread's interest counted.
            let second = tracing::Dispatch::new(subscriber(Logs::default()));
            (tracing::subscriber::set_default(subscriber(self.clone())), second)
        }

        fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }

        fn assert_no_credentials(&self) {
            let text = self.text();
            for secret in [T1, T2, INSTALL_SECRET, "firsttoken", "secondtoken", "never-logged"] {
                assert!(!text.contains(secret), "a credential reached the log:\n{text}");
            }
        }
    }

    async fn until(what: &str, done: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done() {
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Long enough for thirty polls and both backoff steps.
    async fn settle() {
        tokio::time::sleep(Duration::from_millis(400)).await;
    }

    #[test]
    fn the_endpoint_is_an_https_remote_origin_and_nothing_else() {
        assert_eq!(
            endpoint("https://permaura.com", "gw_one").unwrap().as_str(),
            "https://permaura.com/api/gateways/gw_one/operator-token"
        );
        assert_eq!(
            endpoint("https://dev.permaura.example/", "gw-1_A").unwrap().as_str(),
            "https://dev.permaura.example/api/gateways/gw-1_A/operator-token"
        );
        for base in [
            "http://permaura.com",
            "http://127.0.0.1:7376",
            "https://127.0.0.1",
            "https://127.1",
            "https://localhost:3000",
            "https://LOCALHOST.",
            "https://console.localhost",
            "https://[::1]:443",
            "https://[::ffff:127.0.0.1]",
            "https://0.0.0.0",
            "https://[::]",
            "https://user:pw@permaura.com",
            "https://permaura.com/api",
            "https://permaura.com/?x=1",
            "ftp://permaura.com",
            "not a url",
            "",
        ] {
            assert!(endpoint(base, "gw_one").is_err(), "{base} must be refused");
            assert!(checkin_endpoint(base, "gw_one").is_err(), "{base} must be refused a check-in too");
        }
        assert_eq!(
            checkin_endpoint("https://permaura.com", "gw_one").unwrap().as_str(),
            "https://permaura.com/api/gateways/gw_one/checkin"
        );
        let long = "g".repeat(65);
        for id in ["", "gw/../../api/admin", "gw one", "gw%2Fone", long.as_str()] {
            assert!(endpoint("https://permaura.com", id).is_err(), "{id} must be refused");
        }
    }

    #[tokio::test]
    async fn enrolment_reseals_the_published_token_once_and_a_refresh_reseals_the_new_one() {
        let logs = Logs::default();
        let _log = logs.capture();
        let permaura_com = fake(always(200), None).await;
        let gateway = Gateway::new(Some(T1));
        tokio::spawn(run(gateway.sources(install()), Loopback::to(permaura_com.addr), fast()));

        settle().await;
        assert_eq!(permaura_com.count(), 0, "not linked yet, so nothing to re-seal");

        gateway.enrol(&["gw_one"]);
        until("the re-seal after enrolment", || permaura_com.count() == 1).await;
        settle().await;
        let seen = permaura_com.seen();
        assert_eq!(seen.len(), 1, "one re-seal per published token: {seen:?}");
        assert_eq!(seen[0].method, "PATCH");
        assert_eq!(seen[0].path, "/api/gateways/gw_one/operator-token");
        assert_eq!(
            seen[0].body,
            serde_json::json!({ "installId": INSTALL_ID, "installSecret": INSTALL_SECRET, "token": T1 })
        );

        // What the refresher does when it replaces the token for local readers.
        gateway.console.set(Some(T2.into()));
        until("the re-seal after a refresh", || permaura_com.count() == 2).await;
        settle().await;
        let seen = permaura_com.seen();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert_eq!(seen[1].token(), T2);
        assert!(logs.text().contains("permaura.com now holds this gateway's current console bearer"), "{}", logs.text());
        logs.assert_no_credentials();
    }

    #[tokio::test]
    async fn every_link_holds_its_own_copy_and_a_second_pairing_is_resealed_too() {
        let permaura_com = fake(always(200), None).await;
        let gateway = Gateway::new(Some(T1));
        tokio::spawn(run(gateway.sources(install()), Loopback::to(permaura_com.addr), fast()));

        gateway.enrol(&["gw_one"]);
        until("the first link", || permaura_com.count() == 1).await;
        gateway.enrol(&["gw_one", "gw_two"]);
        until("the second link", || permaura_com.to("gw_two").len() == 1).await;
        settle().await;
        assert_eq!(permaura_com.to("gw_one").len(), 1, "the first link already holds this token");

        gateway.console.set(Some(T2.into()));
        until("both links", || permaura_com.count() == 4).await;
        settle().await;
        assert_eq!(permaura_com.count(), 4);
        assert_eq!(permaura_com.to("gw_one")[1].token(), T2);
        assert_eq!(permaura_com.to("gw_two")[1].token(), T2);
    }

    #[tokio::test]
    async fn a_failing_permaura_com_is_retried_with_backoff_and_never_holds_up_a_local_reader() {
        let logs = Logs::default();
        let _log = logs.capture();
        let gate = Gate::default();
        let answer = answer(|n, _| (if n < 2 { [500, 503][n] } else { 200 }, None));
        let permaura_com = fake(answer, Some(gate.clone())).await;
        let gateway = Gateway::new(Some(T1));
        tokio::spawn(run(gateway.sources(install()), Loopback::to(permaura_com.addr), fast()));
        gateway.enrol(&["gw_one"]);

        tokio::time::timeout(Duration::from_secs(5), gate.arrived.notified()).await.expect("the first re-seal");
        // permaura.com is sitting on the request. Local readers carry on as if it did not exist.
        let started = Instant::now();
        assert_eq!(gateway.console.get().as_deref(), Some(T1));
        gateway.console.set(Some(T1.into()));
        assert_eq!(gateway.console.get().as_deref(), Some(T1));
        assert!(started.elapsed() < Duration::from_secs(1), "a reader waited on permaura.com");
        gate.release.notify_one();

        until("two retries", || permaura_com.count() == 3).await;
        settle().await;
        let seen = permaura_com.seen();
        assert_eq!(seen.len(), 3, "landed on the third attempt and stopped: {seen:?}");
        assert!(seen.iter().all(|s| s.token() == T1), "{seen:?}");
        assert!(seen[1].at - seen[0].at >= Duration::from_millis(60), "first backoff skipped");
        assert!(seen[2].at - seen[1].at >= Duration::from_millis(120), "backoff did not grow");
        let text = logs.text();
        assert_eq!(text.matches("retrying").count(), 2, "{text}");
        assert!(text.contains("permaura.com now holds this gateway's current console bearer"), "{text}");
        logs.assert_no_credentials();
    }

    #[tokio::test]
    async fn a_rate_limited_reseal_waits_as_long_as_permaura_com_asks() {
        let answer = answer(|n, _| match n {
            0 => (429, Some(("retry-after", "1".to_string()))),
            _ => (200, None),
        });
        let permaura_com = fake(answer, None).await;
        let gateway = Gateway::new(Some(T1));
        tokio::spawn(run(gateway.sources(install()), Loopback::to(permaura_com.addr), fast()));
        gateway.enrol(&["gw_one"]);

        until("the retry", || permaura_com.count() == 2).await;
        let seen = permaura_com.seen();
        assert!(seen[1].at - seen[0].at >= Duration::from_secs(1), "Retry-After was not honoured: {seen:?}");
    }

    #[tokio::test]
    async fn a_retry_carries_the_token_published_now_never_an_older_one() {
        let answer = answer(|_, seen| (if seen.token() == T2 { 200 } else { 500 }, None));
        let permaura_com = fake(answer, None).await;
        let gateway = Gateway::new(Some(T1));
        tokio::spawn(run(gateway.sources(install()), Loopback::to(permaura_com.addr), fast()));
        gateway.enrol(&["gw_one"]);
        until("a retry of the first token", || permaura_com.count() >= 2).await;

        gateway.console.set(Some(T2.into()));
        until("the newer token", || permaura_com.seen().iter().any(|s| s.token() == T2)).await;
        settle().await;
        let seen = permaura_com.seen();
        let first_t2 = seen.iter().position(|s| s.token() == T2).unwrap();
        assert_eq!(first_t2, seen.len() - 1, "landed, then nothing more, and never the older token again: {seen:?}");
    }

    /// permaura.com answers 409 for a hosted row and for a row with a public URL (`{"publicUrl": true}`), which it reaches with the owner's own token; either stops re-sealing that link until the gateway restarts, whatever the body says.
    #[tokio::test]
    async fn a_link_permaura_com_refuses_or_holds_as_hosted_is_left_alone_and_the_others_carry_on() {
        let logs = Logs::default();
        let _log = logs.capture();
        let answer = answer(|_, seen| match seen.path.as_str() {
            "/api/gateways/gw_other/operator-token" => (403, None),
            "/api/gateways/gw_hosted/operator-token" => (409, None),
            "/api/gateways/gw_public/operator-token" => (409, None),
            "/api/gateways/gw_retired/operator-token" => (410, None),
            _ => (200, None),
        });
        let permaura_com = fake(answer, None).await;
        let gateway = Gateway::new(Some(T1));
        tokio::spawn(run(gateway.sources(install()), Loopback::to(permaura_com.addr), fast()));
        gateway.enrol(&["gw_mine", "gw_other", "gw_hosted", "gw_public", "gw_retired"]);

        until("every link once", || permaura_com.count() == 5).await;
        settle().await;
        assert_eq!(permaura_com.count(), 5, "a 403, 409 or 410 is not retried: {:?}", permaura_com.seen());

        // Not for this token only: those links are not this machine's to re-seal, so a refresh skips them.
        gateway.console.set(Some(T2.into()));
        until("the link that took it", || permaura_com.to("gw_mine").len() == 2).await;
        settle().await;
        for refused in ["gw_other", "gw_hosted", "gw_public", "gw_retired"] {
            assert_eq!(permaura_com.to(refused).len(), 1, "{refused}");
        }
        let text = logs.text();
        assert!(text.contains("status=403"), "{text}");
        assert!(text.contains("not this machine's link"), "{text}");
        assert!(text.contains("status=409"), "{text}");
        assert!(text.contains("hosted"), "{text}");
        assert!(text.contains("status=410"), "{text}");
        assert_eq!(text.matches("retrying").count(), 0, "{text}");
        logs.assert_no_credentials();
    }

    /// A 404 is what a permaura.com that does not have the re-seal route yet answers, so it is waited out like an outage rather than closing the link until the gateway restarts.
    #[tokio::test]
    async fn a_404_is_retried_and_the_reseal_lands_once_the_route_answers() {
        let logs = Logs::default();
        let _log = logs.capture();
        let answer = answer(|n, _| (if n < 2 { 404 } else { 200 }, None));
        let permaura_com = fake(answer, None).await;
        let gateway = Gateway::new(Some(T1));
        tokio::spawn(run(gateway.sources(install()), Loopback::to(permaura_com.addr), fast()));
        gateway.enrol(&["gw_one"]);

        until("the retries", || permaura_com.count() == 3).await;
        settle().await;
        let seen = permaura_com.seen();
        assert_eq!(seen.len(), 3, "landed on the third attempt and stopped: {seen:?}");
        assert!(seen.iter().all(|s| s.token() == T1), "{seen:?}");
        assert!(seen[1].at - seen[0].at >= Duration::from_millis(60), "backed off like any other outage");
        let text = logs.text();
        assert_eq!(text.matches("retrying").count(), 2, "{text}");
        assert!(text.contains("permaura.com now holds this gateway's current console bearer"), "{text}");
        logs.assert_no_credentials();
    }

    #[tokio::test]
    async fn a_gateway_that_is_not_linked_posts_nothing() {
        let logs = Logs::default();
        let _log = logs.capture();
        let permaura_com = fake(always(200), None).await;

        // Never paired.
        let unpaired = Gateway::new(Some(T1));
        tokio::spawn(run(unpaired.sources(install()), Loopback::to(permaura_com.addr), fast()));

        // Paired, but no install identity to prove a re-seal with.
        let anonymous = Gateway::new(Some(T1));
        anonymous.enrol(&["gw_one"]);
        tokio::spawn(run(anonymous.sources(None), Loopback::to(permaura_com.addr), fast()));

        // Linked but publishing nothing: a store outside the home, or a hosted worker's env links.
        let hosted = Gateway::new(None);
        hosted.enrol(&["gw_one"]);
        tokio::spawn(run(hosted.sources(install()), Loopback::to(permaura_com.addr), fast()));

        settle().await;
        assert_eq!(permaura_com.count(), 0, "{:?}", permaura_com.seen());
        anonymous.console.set(Some(T2.into()));
        settle().await;
        assert_eq!(permaura_com.count(), 0, "{:?}", permaura_com.seen());
        assert_eq!(logs.text().matches("no install identity").count(), 1, "said once: {}", logs.text());

        // Unlinking stops it too.
        let unlinked = Gateway::new(Some(T1));
        unlinked.enrol(&["gw_one"]);
        tokio::spawn(run(unlinked.sources(install()), Loopback::to(permaura_com.addr), fast()));
        until("the linked re-seal", || permaura_com.count() == 1).await;
        unlinked.announcer.set(Vec::new());
        unlinked.console.set(Some(T2.into()));
        settle().await;
        assert_eq!(permaura_com.count(), 1, "{:?}", permaura_com.seen());
    }

    #[tokio::test]
    async fn the_token_never_goes_to_a_plain_http_or_loopback_control_plane() {
        let logs = Logs::default();
        let _log = logs.capture();
        let listener = fake(always(200), None).await;
        let port = listener.addr.port();
        let published = Arc::new(PublishedToken::default());
        published.set(Some(T1.into()));
        let sources = |base: String| Sources {
            token: Box::new({
                let published = published.clone();
                move || published.get()
            }),
            linked: Box::new(move || Some(Linked { base: base.clone(), gateway_ids: vec!["gw_one".into()], fingerprints: HashMap::new() })),
            install: Box::new(install),
            asked: Default::default(),
            pairings: Default::default(),
            rotation: None,
            held: Arc::new(HeldConsoleSessions::default()),
        };

        // The real transport, aimed at a real listener over plain http: nothing may arrive.
        let real: Arc<dyn Transport> = Arc::new(Https::new(Duration::from_secs(2)).unwrap());
        tokio::spawn(run(sources(format!("http://127.0.0.1:{port}")), real.clone(), fast()));

        // Every loopback spelling, against a transport that records any attempt at all.
        let recorder = Arc::new(Recorder::default());
        for base in [
            format!("http://localhost:{port}"),
            format!("https://127.0.0.1:{port}"),
            format!("https://localhost:{port}"),
            format!("https://[::1]:{port}"),
            format!("https://gateway.localhost:{port}"),
        ] {
            tokio::spawn(run(sources(base), recorder.clone(), fast()));
        }
        settle().await;
        published.set(Some(T2.into()));
        settle().await;
        assert_eq!(listener.count(), 0, "{:?}", listener.seen());
        assert!(recorder.0.lock().unwrap().is_empty(), "{:?}", recorder.0.lock().unwrap());
        assert_eq!(logs.text().matches("not re-sealed").count(), 6, "once per link: {}", logs.text());

        // The real client refuses plain http by itself as well, so the URL check is not the only guard.
        let url = reqwest::Url::parse(&format!("http://127.0.0.1:{port}/api/gateways/gw_one/operator-token")).unwrap();
        let install = install().unwrap();
        assert!(real.send(&url, &body(&install, T1)).await.is_err());
        assert_eq!(listener.count(), 0);
        logs.assert_no_credentials();
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let logs = Logs::default();
        let _log = logs.capture();
        let sink = fake(always(200), None).await;
        let elsewhere = format!("http://{}/steal", sink.addr);
        let answer = answer(move |_, _| (307, Some(("location", elsewhere.clone()))));
        let permaura_com = fake(answer, None).await;
        let gateway = Gateway::new(Some(T1));
        tokio::spawn(run(gateway.sources(install()), Loopback::to(permaura_com.addr), fast()));
        gateway.enrol(&["gw_one"]);

        until("the re-seal", || permaura_com.count() == 1).await;
        settle().await;
        assert_eq!(permaura_com.count(), 1, "a redirect is an answer, not a reason to retry");
        assert_eq!(sink.count(), 0, "the body followed a redirect: {:?}", sink.seen());
        assert!(logs.text().contains("status=307"), "{}", logs.text());
        logs.assert_no_credentials();
    }

    // ── What permaura.com is handed, and when ─────────────────────────────────────────────────────

    const VAULT_EXPORT: &str = "/v1/vault/export";

    fn loopback_only() -> crate::AppState {
        links_name_the_test_control_plane();
        crate::AppState::in_memory_seeded_with_http(Arc::new(crate::connectors::MockHttpClient::new()))
    }

    /// The same store behind a gateway that has a public URL, which is what makes it an OAuth resource server.
    fn with_public_url(store: Arc<dyn Store>) -> Arc<crate::service::EnforcementService> {
        with_public_url_and_aliases(store, Vec::new())
    }

    fn with_public_url_and_aliases(store: Arc<dyn Store>, public_url_aliases: Vec<String>) -> Arc<crate::service::EnforcementService> {
        let oauth = Arc::new(crate::oauth::OAuthRs::new(crate::oauth::RsConfig {
            public_url: "https://g-reseal.permaura.test".into(),
            mcp_resource: "https://g-reseal.permaura.test/mcp".into(),
            public_url_aliases,
            issuer: "https://permaura.test/api/auth".into(),
            jwks_uri: "https://permaura.test/api/auth/jwks".into(),
            owner_sub: Some("user_owner".into()),
        }));
        Arc::new(services_from(store, Some(oauth)))
    }

    fn services_from(
        store: Arc<dyn Store>,
        oauth: Option<Arc<crate::oauth::OAuthRs>>,
    ) -> crate::service::EnforcementService {
        let backend = crate::backend::build_backend(store.clone());
        crate::service::EnforcementService::from_components(
            store,
            Arc::new(crate::connectors::MockHttpClient::new()),
            Arc::new(crate::connectors::MockCommandRunner::new()),
            backend,
            oauth,
        )
    }

    fn console_sessions(store: &dyn Store) -> Vec<crate::store::Session> {
        store.list_sessions().unwrap().into_iter().filter(|s| crate::is_console_token(&s.token)).collect()
    }

    /// One request through the real router, no peer address (loopback), no `Origin`, no forwarder header: what a request delivered over a `tcp://` tunnel ingress looks like.
    async fn on_loopback(state: &crate::AppState, bearer: &str, uri: &str, body: serde_json::Value) -> u16 {
        sent(state, "POST", bearer, uri, body, None).await
    }

    /// One request through the real router with `method`, and the `Origin` a web page would send, if any.
    async fn sent(state: &crate::AppState, method: &str, bearer: &str, uri: &str, body: serde_json::Value, origin: Option<&str>) -> u16 {
        use tower::ServiceExt as _;
        let app = crate::build_router(state.clone(), "127.0.0.1:7376".parse().unwrap());
        let mut req = axum::http::Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {bearer}"));
        if let Some(origin) = origin {
            req = req.header("origin", origin);
        }
        app.oneshot(req.body(axum::body::Body::from(body.to_string())).unwrap()).await.unwrap().status().as_u16()
    }

    /// The last step of `permaura pair` on this machine: `PUT /v1/announce` with the operator token and the link permaura.com sent back.
    async fn paired_on_this_machine(state: &crate::AppState, operator: &str, gateway_id: &str, secret: &str) {
        let body = serde_json::json!({ "gateway_id": gateway_id, "announce_secret": secret });
        assert_eq!(sent(state, "PUT", operator, "/v1/announce", body, None).await, 200);
    }

    const SECOND_SECRET: &str = "gwa_9876543210zyxwvutsrqponmlkjihgfedcbaZYXW";

    /// The bearer the re-seal hands permaura.com, presented on loopback with no `Origin` and no forwarder, is not the local operator. The operator token the CLI and the desktop supervisor read stays local.
    #[tokio::test]
    async fn the_bearer_permaura_com_is_handed_is_never_the_local_operator() {
        let permaura_com = fake(always(200), None).await;
        let state = loopback_only();
        let store = state.service.store().clone();
        let operator_token = crate::mint_operator_session(store.as_ref()).unwrap();
        state.published_token.set(Some(operator_token.clone()));
        state.service.set_announce(vec![link("gw_one")]);

        assert!(start(state.service.clone(), state.held_console_sessions.clone(), Box::new(install), Loopback::to(permaura_com.addr), fast(), None));
        until("the re-seal at boot", || permaura_com.count() == 1).await;
        let sealed = permaura_com.seen()[0].token().to_string();
        assert_ne!(sealed, operator_token, "operator.token never leaves this machine");
        assert!(sealed.starts_with(crate::CONSOLE_TOKEN_PREFIX), "{sealed}");
        assert!(state.service.authenticate(&sealed).is_ok(), "it is a live operator session the console can use");

        assert!(!state.service.any_device_trusted());
        let export = serde_json::json!({ "passphrase": "correct horse battery staple" });
        assert_eq!(on_loopback(&state, &sealed, VAULT_EXPORT, export.clone()).await, 403, "remote on loopback, so an unpaired gateway refuses it the vault");
        assert_eq!(on_loopback(&state, &operator_token, VAULT_EXPORT, export).await, 200, "operator.token on loopback is still the owner at the host");
    }

    /// A public URL means permaura.com reaches the gateway with the owner's own short-lived token: nothing is sealed at boot or ever after, and a console session left by a loopback-only boot stops working.
    #[tokio::test]
    async fn a_gateway_with_a_public_url_never_hands_permaura_com_a_bearer() {
        let permaura_com = fake(always(200), None).await;
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        let left_over = crate::mint_console_session(store.as_ref()).unwrap();

        let service = with_public_url(store.clone());
        service.set_announce(vec![link("gw_one")]);
        let held = Arc::new(HeldConsoleSessions::default());
        held.set(vec![left_over.clone()]);
        assert!(!start(service.clone(), held.clone(), Box::new(install), Loopback::to(permaura_com.addr), fast(), None));
        assert!(service.authenticate(&left_over).is_err(), "the console session a loopback-only boot sealed is revoked");
        assert!(held.get().is_empty(), "/health proves no console session on a gateway with a public URL");

        settle().await;
        // Anything that would have made a running task re-seal: a second link, and no fresh console session left.
        service.set_announce(vec![link("gw_one"), link("gw_two")]);
        crate::revoke_console_sessions(store.as_ref());
        settle().await;
        assert_eq!(permaura_com.count(), 0, "{:?}", permaura_com.seen());
        assert!(console_sessions(store.as_ref()).iter().all(|s| s.revoked), "none minted");
    }

    /// Moving back to loopback-only is a restart without `PERMAURA_PUBLIC_URL`, and that boot seals a fresh console session at once.
    #[tokio::test]
    async fn removing_the_public_url_reseals_at_boot() {
        let permaura_com = fake(always(200), None).await;
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        let public = with_public_url(store.clone());
        public.set_announce(vec![link("gw_one")]);
        assert!(!start(public, Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), fast(), None));

        let loopback = Arc::new(services_from(store.clone(), None));
        loopback.set_announce(vec![link("gw_one")]);
        assert!(start(loopback.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), fast(), None));
        until("the re-seal at boot", || permaura_com.count() == 1).await;
        let sealed = permaura_com.seen()[0].token().to_string();
        assert!(crate::is_console_token(&sealed), "{sealed}");
        assert!(loopback.authenticate(&sealed).is_ok());
    }

    /// The console session is replaced before it runs out, and the replacement is what permaura.com is handed next.
    #[tokio::test]
    async fn a_console_session_near_its_expiry_is_replaced_and_resealed() {
        let permaura_com = fake(always(200), None).await;
        let state = loopback_only();
        let store = state.service.store().clone();
        state.service.set_announce(vec![link("gw_one")]);
        assert!(start(state.service.clone(), state.held_console_sessions.clone(), Box::new(install), Loopback::to(permaura_com.addr), fast(), None));
        until("the re-seal at boot", || permaura_com.count() == 1).await;
        let first = permaura_com.seen()[0].token().to_string();

        let mut row = console_sessions(store.as_ref()).into_iter().find(|s| s.token == first).unwrap();
        row.expires_at = Some(crate::service::now_ms() + 60_000);
        store.put_session(row).unwrap();
        until("the replacement", || permaura_com.count() == 2).await;
        let second = permaura_com.seen()[1].token().to_string();
        assert_ne!(second, first);
        assert!(crate::is_console_token(&second));
        settle().await;
        assert_eq!(permaura_com.count(), 2, "one re-seal per console session: {:?}", permaura_com.seen());
    }

    /// SQLite keeps a bearer's digest, never its `pgc_`, so the console session a loopback-only boot left is found by the class recorded when it was minted, and a public-URL boot revokes it there as it does in memory. The operator token beside it is untouched.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn a_public_url_boot_revokes_a_leftover_console_session_on_sqlite() {
        let store: Arc<dyn Store> = Arc::new(crate::store::sqlite::SqliteStore::open_in_memory().unwrap());
        let left_over = crate::mint_console_session(store.as_ref()).unwrap();
        let operator = crate::mint_operator_session(store.as_ref()).unwrap();
        let rows = store.list_sessions().unwrap();
        assert!(rows.iter().all(|s| !crate::is_console_token(&s.token)), "at rest a bearer is a digest");
        assert_eq!(rows.iter().filter(|s| s.class == crate::store::SessionClass::Console).count(), 1);

        let service = with_public_url(store.clone());
        assert!(service.authenticate(&left_over).is_ok());
        assert!(!start(service.clone(), Arc::default(), Box::new(install), Arc::new(Recorder::default()), fast(), None));
        assert!(service.authenticate(&left_over).is_err(), "revoked on SQLite");
        assert!(service.authenticate(&operator).is_ok(), "only the console session");
    }

    /// A scratch `operator.token` for one test, in the test's own temporary directory, never `$PERMAURA_HOME`'s.
    struct TokenFile(std::path::PathBuf);

    impl TokenFile {
        fn holding(token: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("rotation-{}-{}", std::process::id(), crate::service::short_id()));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("operator.token");
            std::fs::write(&path, token).unwrap();
            TokenFile(path)
        }

        fn read(&self) -> String {
            std::fs::read_to_string(&self.0).unwrap().trim().to_string()
        }
    }

    impl Drop for TokenFile {
        fn drop(&mut self) {
            if let Some(dir) = self.0.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    fn rotation(state: &crate::AppState, file: &TokenFile, grace: Duration) -> crate::OperatorTokenRotation {
        crate::OperatorTokenRotation {
            store: state.service.store().clone(),
            path: file.0.clone(),
            published: state.published_token.clone(),
            grace,
        }
    }

    /// The operator token permaura.com was handed at redeem (or kept by an earlier build) exported an unpaired gateway's vault over loopback and applied a loosening edit unheld on a paired one, after the console session had replaced it. Now the file is rotated at the first poll that has a link and a console session to offer, the handed-over token is refused after the grace, and the token read fresh from the file works. One rotation, and no further seal.
    #[tokio::test]
    async fn the_operator_token_permaura_com_was_handed_stops_once_the_console_session_lands() {
        let permaura_com = fake(always(200), None).await;
        let state = loopback_only();
        let store = state.service.store().clone();
        let handed_over = crate::mint_operator_session(store.as_ref()).unwrap();
        let file = TokenFile::holding(&handed_over);
        state.published_token.set(Some(handed_over.clone()));
        state.service.set_announce(vec![link("gw_one")]);
        let grace = Duration::from_millis(300);
        assert!(start(state.service.clone(), state.held_console_sessions.clone(), Box::new(install), Loopback::to(permaura_com.addr), fast(), Some(rotation(&state, &file, grace))));

        until("the re-seal", || permaura_com.count() == 1).await;
        until("the rotation", || file.read() != handed_over).await;
        let fresh = file.read();
        assert!(fresh.starts_with("pgt_") && fresh != permaura_com.seen()[0].token(), "a fresh operator token, not the console session");
        assert_eq!(state.published_token.get().as_deref(), Some(fresh.as_str()), "/health proves the new one");
        assert!(state.service.authenticate(&handed_over).is_ok(), "a local reader that read the file just before still gets through inside the grace");

        until("the grace to pass", || state.service.authenticate(&handed_over).is_err()).await;
        let export = serde_json::json!({ "passphrase": "correct horse battery staple" });
        assert_eq!(on_loopback(&state, &handed_over, VAULT_EXPORT, export.clone()).await, 401, "the handed-over token exports nothing");
        assert_eq!(on_loopback(&state, &fresh, VAULT_EXPORT, export).await, 200, "the file's token is still the owner at the host");
        let sk = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
        use base64::Engine as _;
        assert!(state.service.trust_approver_key("device:owner", &base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes())));
        let loosening = |id: &str| serde_json::json!({ "id": id, "connection_id": "generic_http", "name": id, "allow": ["request"] });
        assert_eq!(on_loopback(&state, &handed_over, "/v1/policies", loosening("p_rotation_old")).await, 401);
        assert_eq!(on_loopback(&state, &fresh, "/v1/policies", loosening("p_rotation_fresh")).await, 201);

        settle().await;
        assert_eq!(permaura_com.count(), 1, "rotating operator.token seals nothing: {:?}", permaura_com.seen());
        assert_eq!(file.read(), fresh, "one rotation per pairing");
    }

    /// A permaura.com that never acknowledges the seal (a 503 on every attempt) used to keep the handed-over `pgt_` alive, since the rotation ran only on a 2xx. The rotation now runs on the gateway's clock whatever the answer, so the owner's later restart into a public URL (remote access) finds the token dead: it neither authenticates nor exports the vault over a loopback ingress permaura.com's Cloudflare account could push to the connector, or private-network traffic it could route through it.
    #[tokio::test]
    async fn a_permaura_com_that_never_acknowledges_the_seal_still_loses_the_handed_over_token() {
        let permaura_com = fake(always(503), None).await;
        let state = loopback_only();
        let store = state.service.store().clone();
        let handed_over = crate::mint_operator_session(store.as_ref()).unwrap();
        let file = TokenFile::holding(&handed_over);
        state.published_token.set(Some(handed_over.clone()));
        state.service.set_announce(vec![link("gw_one")]);
        assert!(start(
            state.service.clone(),
            state.held_console_sessions.clone(),
            Box::new(install),
            Loopback::to(permaura_com.addr),
            fast(),
            Some(rotation(&state, &file, Duration::from_millis(50))),
        ));
        until("the re-seal attempt", || permaura_com.count() >= 1).await;
        until("the rotation", || file.read() != handed_over).await;
        until("the grace to pass", || state.service.authenticate(&handed_over).is_err()).await;
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(permaura_com.count() >= 2, "the seal keeps being retried: {:?}", permaura_com.seen());
        let fresh = file.read();
        assert!(fresh.starts_with("pgt_") && fresh != handed_over);
        assert!(state.service.authenticate(&fresh).is_ok(), "the file's token is the live one");
        let live: Vec<_> = store
            .list_sessions()
            .unwrap()
            .into_iter()
            .filter(|s| s.class == crate::store::SessionClass::OperatorToken && !s.revoked && !s.is_expired(crate::service::now_ms()))
            .collect();
        assert_eq!(live.len(), 1, "one rotation however many attempts: {live:?}");

        let restarted = with_public_url(store.clone());
        assert!(!start(restarted.clone(), Arc::default(), Box::new(install), Arc::new(Recorder::default()), fast(), None));
        let export = serde_json::json!({ "passphrase": "chosen by permaura.com" });
        assert!(restarted.authenticate(&handed_over).is_err(), "the handed-over token is dead after the restart");
        let public = crate::AppState { service: restarted.clone(), ..state.clone() };
        assert_eq!(on_loopback(&public, &handed_over, VAULT_EXPORT, export).await, 401, "and exports nothing over loopback");
    }

    /// Every answer short of a 2xx, retried or not, leaves the handed-over token dead after a restart into a public URL.
    #[tokio::test]
    async fn every_unacknowledged_answer_leaves_the_handed_over_token_dead_after_a_public_url_restart() {
        let mut failures = Vec::new();
        for status in [503u16, 429, 418, 409] {
            let permaura_com = fake(always(status), None).await;
            let state = loopback_only();
            let store = state.service.store().clone();
            let handed_over = crate::mint_operator_session(store.as_ref()).unwrap();
            let file = TokenFile::holding(&handed_over);
            state.published_token.set(Some(handed_over.clone()));
            state.service.set_announce(vec![link("gw_one")]);
            assert!(start(
                state.service.clone(),
                state.held_console_sessions.clone(),
                Box::new(install),
                Loopback::to(permaura_com.addr),
                fast(),
                Some(rotation(&state, &file, Duration::from_millis(50))),
            ));
            until("the re-seal attempt", || permaura_com.count() >= 1).await;
            until("the rotation", || file.read() != handed_over).await;
            until("the grace to pass", || state.service.authenticate(&handed_over).is_err()).await;

            let restarted = with_public_url(store.clone());
            assert!(!start(restarted.clone(), Arc::default(), Box::new(install), Arc::new(Recorder::default()), fast(), None));
            let public = crate::AppState { service: restarted.clone(), ..state.clone() };
            let auth = restarted.authenticate(&handed_over).is_ok();
            let export = serde_json::json!({ "passphrase": "chosen by permaura.com" });
            let code = on_loopback(&public, &handed_over, VAULT_EXPORT, export).await;
            if auth || code == 200 {
                failures.push((status, auth, code));
            }
        }
        assert!(failures.is_empty(), "the handed-over pgt_ must be refused and export nothing; (status, authenticates, export code): {failures:?}");
    }

    /// The paired half of that case: with a device trusted, the handed-over token used to apply a loosening policy edit with no device signature; now it is refused outright.
    #[tokio::test]
    async fn on_a_paired_gateway_the_unacknowledged_handed_over_token_loosens_nothing() {
        let permaura_com = fake(always(503), None).await;
        let state = loopback_only();
        let store = state.service.store().clone();
        let handed_over = crate::mint_operator_session(store.as_ref()).unwrap();
        let file = TokenFile::holding(&handed_over);
        state.published_token.set(Some(handed_over.clone()));
        state.service.set_announce(vec![link("gw_one")]);
        assert!(start(state.service.clone(), state.held_console_sessions.clone(), Box::new(install), Loopback::to(permaura_com.addr), fast(), Some(rotation(&state, &file, Duration::from_millis(50)))));
        until("the re-seal attempt", || permaura_com.count() >= 1).await;
        until("the rotation", || file.read() != handed_over).await;
        until("the grace to pass", || state.service.authenticate(&handed_over).is_err()).await;

        let restarted = with_public_url(store.clone());
        assert!(!start(restarted.clone(), Arc::default(), Box::new(install), Arc::new(Recorder::default()), fast(), None));
        let public = crate::AppState { service: restarted.clone(), ..state.clone() };
        let sk = ed25519_dalek::SigningKey::from_bytes(&[73; 32]);
        use base64::Engine as _;
        assert!(public.service.trust_approver_key("device:owner", &base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes())));

        let export = serde_json::json!({ "passphrase": "chosen by permaura.com" });
        assert_eq!(on_loopback(&public, &handed_over, VAULT_EXPORT, export).await, 401);
        let loosening = serde_json::json!({ "id": "p_handover", "connection_id": "generic_http", "name": "p_handover", "allow": ["request"] });
        assert_eq!(on_loopback(&public, &handed_over, "/v1/policies", loosening).await, 401);
        assert!(!public.service.store().list_policies().unwrap().iter().any(|p| p.id == "p_handover"), "nothing applied");
    }

    /// A gateway with a public URL, pinned to the owner who set remote access up. The organization is handed over; permaura.com answers the next check-in (the 409 such a gateway is given, since it holds no bearer for it) naming the new owner. The gateway re-pins, audits the move, writes it to the config file, and the new owner's tokens verify while the old owner's stop.
    #[tokio::test]
    async fn a_check_in_naming_a_new_owner_repins_a_public_gateway_and_records_it() {
        let permaura_com = fake_saying(
            always(409),
            None,
            Arc::new(|seen| seen.path.ends_with("/checkin").then(|| serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_new" }))),
        )
        .await;
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        let service = with_public_url(store.clone());
        service.set_announce(vec![link("gw_one")]);
        let config = TokenFile::holding("");
        let config_path = config.0.parent().unwrap().join("config.toml");
        std::fs::write(&config_path, "public_url = \"https://g-reseal.permaura.test\"\nowner_sub = \"user_owner\"\n").unwrap();
        let oauth = service.oauth().cloned().expect("a resource server");
        assert_eq!(oauth.owner_sub().as_deref(), Some("user_owner"));
        assert!(!start_with(
            service.clone(),
            Arc::default(),
            Box::new(install),
            Loopback::to(permaura_com.addr),
            checking_in(),
            None,
            OwnerPin::new(false, false, Some(config_path.clone()), None),
        ));
        until("the re-pin", || oauth.owner_sub().as_deref() == Some("user_new")).await;
        until("a second check-in", || permaura_com.count() >= 2).await;
        let moves: Vec<serde_json::Value> = store
            .audit_events(None)
            .unwrap()
            .into_iter()
            .filter(|e| e.payload.action == crate::service::OWNER_REPIN_ACTION)
            .map(|e| e.payload.summary)
            .collect();
        assert_eq!(moves.len(), 1, "one move, audited once however many check-ins repeat it: {moves:?}");
        assert_eq!(moves[0]["from"], "user_owner");
        assert_eq!(moves[0]["to"], "user_new");
        assert_eq!(moves[0]["source"], "checkin");
        let written = crate::config::GatewayConfig::load_from(&config_path).unwrap().unwrap();
        assert_eq!(written.owner_sub.as_deref(), Some("user_new"), "the move survives a restart");
        assert_eq!(written.public_url.as_deref(), Some("https://g-reseal.permaura.test"), "and touches nothing else");
        assert!(permaura_com.seen().iter().all(|s| s.path.ends_with("/checkin")), "a public gateway seals nothing: {:?}", permaura_com.seen());
    }

    /// The pin stays put when a check-in names the owner already bound, names no owner, names something that is not an account id, or when the app that supervises the gateway set `PERMAURA_OWNER_SUB` (it moves the binding itself); none of those is audited.
    #[tokio::test]
    async fn a_check_in_that_names_no_new_owner_or_cannot_move_the_pin_changes_nothing() {
        for (what, said, supervised) in [
            ("the same owner", serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_owner" }), false),
            ("no owner", serde_json::json!({ "publicUrl": true, "needs_reseal": false }), false),
            ("a malformed owner", serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user new\n[section]" }), false),
            ("a number where the owner goes", serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": 7 }), false),
            ("an owner the supervising app pinned", serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_new" }), true),
            ("a hosted row's answer", serde_json::json!({ "hosted": true, "needs_reseal": false, "owner_sub": "user_new" }), false),
        ] {
            let permaura_com = fake_saying(always(409), None, Arc::new(move |seen| seen.path.ends_with("/checkin").then(|| said.clone()))).await;
            let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
            let service = with_public_url(store.clone());
            service.set_announce(vec![link("gw_one")]);
            let oauth = service.oauth().cloned().unwrap();
            let owner = OwnerPin::new(supervised, supervised, None, supervised.then(|| "user_owner".to_string()));
            assert!(!start_with(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None, owner));
            until("two check-ins", || permaura_com.count() >= 2).await;
            assert_eq!(oauth.owner_sub().as_deref(), Some("user_owner"), "{what}");
            assert!(!store.audit_events(None).unwrap().iter().any(|e| e.payload.action == crate::service::OWNER_REPIN_ACTION), "{what}: nothing audited");
        }
    }

    /// The documented VPS setup pins `PERMAURA_OWNER_SUB` in `/etc/permaura/gateway.env` with no app supervising the gateway. A hand-over moves its binding in memory and in the config file, which records the environment value it replaced so the new owner outranks it at the next boot. The same pin under the desktop (`PERMAURA_SUPERVISED_BY_APP`) is the app's to move: nothing moves, nothing is audited, and the file is untouched.
    #[tokio::test]
    async fn a_vps_pinned_by_its_environment_follows_a_hand_over_and_a_supervised_gateway_leaves_it_to_the_app() {
        for supervised in [false, true] {
            let permaura_com = fake_saying(
                always(409),
                None,
                Arc::new(|seen| seen.path.ends_with("/checkin").then(|| serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_new" }))),
            )
            .await;
            let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
            let service = with_public_url(store.clone());
            service.set_announce(vec![link("gw_one")]);
            let dir = TokenFile::holding("");
            let config_path = dir.0.parent().unwrap().join("config.toml");
            let before = "public_url = \"https://gw.acme.example\"\n";
            std::fs::write(&config_path, before).unwrap();
            let oauth = service.oauth().cloned().unwrap();
            let owner = OwnerPin::new(true, supervised, Some(config_path.clone()), Some("user_owner".into()));
            assert!(!start_with(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None, owner));
            if supervised {
                until("two check-ins", || permaura_com.count() >= 2).await;
                assert_eq!(oauth.owner_sub().as_deref(), Some("user_owner"), "the app moves a pin it set");
                assert!(owner_moves(&store).is_empty());
                assert_eq!(std::fs::read_to_string(&config_path).unwrap(), before);
                continue;
            }
            until("the re-pin", || oauth.owner_sub().as_deref() == Some("user_new")).await;
            let moves = owner_moves(&store);
            assert_eq!(moves.len(), 1, "{moves:?}");
            assert_eq!((moves[0]["from"].as_str(), moves[0]["to"].as_str()), (Some("user_owner"), Some("user_new")));
            let written = crate::config::GatewayConfig::load_from(&config_path).unwrap().unwrap();
            assert_eq!(written.owner_sub.as_deref(), Some("user_new"));
            assert_eq!(written.owner_sub_replaces_env.as_deref(), Some("user_owner"));
            assert_eq!(written.public_url.as_deref(), Some("https://gw.acme.example"), "the operator's own domain stays");
            assert!(written.owner_outranks_environment(Some("user_owner"), false), "the next boot comes up bound to the new owner");
            assert!(!written.owner_outranks_environment(Some("user_owner"), true), "never over a supervising app's pin");
            assert!(!written.owner_outranks_environment(Some("user_chosen"), false), "nor over an environment line the operator has changed since");
        }
    }

    /// A gateway whose remote access belongs to one organization is also paired into a second, and permaura.com names each organization's owner at that link's check-in. Following every answer re-pinned to one and then the other on every round, so the steady state was whichever answered last and every token of the owner who set remote access up was refused. Only the row holding the public URL (the 409 that says `publicUrl: true`) decides the binding: the gateway moves to that organization's new owner once and never to the second's.
    #[tokio::test]
    async fn only_the_link_holding_the_public_url_moves_the_owner() {
        let permaura_com = fake_saying(
            answer(|_, seen| (if seen.path.contains("/gw_public/") { 409 } else { 200 }, None)),
            None,
            Arc::new(|seen| {
                if !seen.path.ends_with("/checkin") {
                    return None;
                }
                Some(if seen.path.contains("/gw_public/") {
                    serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_new" })
                } else {
                    serde_json::json!({ "needs_reseal": false, "owner_sub": "user_bob" })
                })
            }),
        )
        .await;
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        let service = with_public_url(store.clone());
        service.set_announce(vec![link("gw_public"), link("gw_other")]);
        let oauth = service.oauth().cloned().unwrap();
        assert!(!start_with(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None, OwnerPin::in_memory()));
        until("four rounds of check-ins", || permaura_com.count() >= 8).await;
        assert_eq!(oauth.owner_sub().as_deref(), Some("user_new"), "the owner of the organization remote access belongs to");
        let moves: Vec<serde_json::Value> = store
            .audit_events(None)
            .unwrap()
            .into_iter()
            .filter(|e| e.payload.action == crate::service::OWNER_REPIN_ACTION)
            .map(|e| e.payload.summary)
            .collect();
        assert_eq!(moves.len(), 1, "one move and no flip back and forth: {moves:?}");
        assert_eq!(moves[0]["to"], "user_new");
    }

    /// Two rows that both say they hold the public URL and name different owners leave the binding where it is, audited nowhere, until they agree.
    #[tokio::test]
    async fn rows_that_disagree_on_the_owner_move_nothing() {
        let permaura_com = fake_saying(
            always(409),
            None,
            Arc::new(|seen| {
                let owner = if seen.path.contains("/gw_one/") { "user_a" } else { "user_b" };
                seen.path.ends_with("/checkin").then(|| serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": owner }))
            }),
        )
        .await;
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        let service = with_public_url(store.clone());
        service.set_announce(vec![link("gw_one"), link("gw_two")]);
        let oauth = service.oauth().cloned().unwrap();
        assert!(!start_with(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None, OwnerPin::in_memory()));
        until("three rounds of check-ins", || permaura_com.count() >= 6).await;
        assert_eq!(oauth.owner_sub().as_deref(), Some("user_owner"));
        assert!(!store.audit_events(None).unwrap().iter().any(|e| e.payload.action == crate::service::OWNER_REPIN_ACTION));
    }

    /// A second organization's row holding a public URL of its own answers `409 publicUrl: true` too. A round in which this gateway's own row does not answer is not that row's word.
    #[tokio::test]
    async fn a_round_where_only_another_rows_public_url_answers_does_not_move_the_owner() {
        let permaura_com = fake_saying(
            answer(|n, seen| (if n == 0 && seen.path.contains("/gw_mine/") { 503 } else { 409 }, None)),
            None,
            Arc::new(|seen| {
                if !seen.path.ends_with("/checkin") {
                    return None;
                }
                let owner = if seen.path.contains("/gw_mine/") { "user_owner" } else { "user_other_org" };
                Some(serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": owner }))
            }),
        )
        .await;
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        let service = with_public_url(store.clone());
        service.set_announce(vec![link("gw_mine"), link("gw_other")]);
        let oauth = service.oauth().cloned().unwrap();
        assert!(!start_with(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None, OwnerPin::in_memory()));
        until("three rounds of check-ins", || permaura_com.count() >= 6).await;
        assert_eq!(
            oauth.owner_sub().as_deref(),
            Some("user_owner"),
            "another organization's row, whose public URL is not this gateway's, decided the binding"
        );
    }

    /// Two rows both answer `409 publicUrl: true` with different owners, which froze the pin for good while nothing said which address each row holds. permaura.com now names it, so only the row whose address is this gateway's decides, compared the way permaura.com compares addresses; a row whose answer has no `publicUrlValue` (a permaura.com before the field) is still taken at its word, and one whose `publicUrlValue` is `null` (a stored address that is no origin) is set aside like the other row, so nothing decides.
    #[tokio::test]
    async fn only_the_row_holding_this_gateways_own_address_decides_the_owner() {
        let other = serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_other_org", "publicUrlValue": "https://acme-other.permaura.test" });
        for (what, mine, moves_to) in [
            (
                "its own address, spelled differently",
                serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_new", "publicUrlValue": "HTTPS://G-RESEAL.permaura.test.:443/" }),
                Some("user_new"),
            ),
            ("no publicUrlValue sent", serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_new" }), Some("user_new")),
            ("a null address", serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_new", "publicUrlValue": null }), None),
        ] {
            let logs = Logs::default();
            let _log = logs.capture();
            let (mine, other) = (mine.clone(), other.clone());
            let permaura_com = fake_saying(
                always(409),
                None,
                Arc::new(move |seen| {
                    seen.path.ends_with("/checkin").then(|| if seen.path.contains("/gw_mine/") { mine.clone() } else { other.clone() })
                }),
            )
            .await;
            let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
            let service = with_public_url(store.clone());
            service.set_announce(vec![link("gw_mine"), link("gw_other")]);
            let oauth = service.oauth().cloned().unwrap();
            assert!(!start_with(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None, OwnerPin::in_memory()));
            until("four rounds of check-ins", || checkins(&permaura_com).len() >= 8).await;
            let moves = owner_moves(&store);
            let text = logs.text();
            match moves_to {
                Some(owner) => {
                    assert_eq!(oauth.owner_sub().as_deref(), Some(owner), "{what}");
                    assert_eq!(moves.len(), 1, "{what}: one move, never toward the other row: {moves:?}");
                    assert_eq!(moves[0]["to"], owner, "{what}");
                    assert!(!text.contains("names no address"), "{what}: {text}");
                }
                None => {
                    assert_eq!(oauth.owner_sub().as_deref(), Some("user_owner"), "{what}: a row naming no address is not taken at its word");
                    assert!(moves.is_empty(), "{what}: {moves:?}");
                    assert_eq!(text.matches("names no address").count(), 1, "{what}: said once:\n{text}");
                    assert!(text.contains("link=gw_mine"), "{what}: {text}");
                }
            }
            assert_eq!(text.matches("holds a public URL that is not this gateway's").count(), 1, "{what}: said once:\n{text}");
            assert!(text.contains("link=gw_other"), "{what}: {text}");
        }
    }

    /// The contract with permaura.com's check-in route: a row whose stored public URL is no origin answers `publicUrlValue: null`. Read as an absent field it was taken at its word as this gateway's own, so it disagreed with the row that does hold this gateway's address and the pin froze; it names no address, so the row holding this gateway's own decides alone.
    #[tokio::test]
    async fn a_row_naming_a_null_address_never_holds_back_the_row_holding_this_gateways_own() {
        for (what, other, moves_to) in [
            ("a null address", serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_other_org", "publicUrlValue": null }), "user_new"),
            ("no publicUrlValue sent", serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_other_org" }), "user_owner"),
        ] {
            let other = other.clone();
            let permaura_com = fake_saying(
                always(409),
                None,
                Arc::new(move |seen| {
                    seen.path.ends_with("/checkin").then(|| {
                        if seen.path.contains("/gw_mine/") {
                            serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_new", "publicUrlValue": "https://g-reseal.permaura.test" })
                        } else {
                            other.clone()
                        }
                    })
                }),
            )
            .await;
            let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
            let service = with_public_url(store.clone());
            service.set_announce(vec![link("gw_mine"), link("gw_other")]);
            let oauth = service.oauth().cloned().unwrap();
            assert!(!start_with(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None, OwnerPin::in_memory()));
            until("four rounds of check-ins", || checkins(&permaura_com).len() >= 8).await;
            assert_eq!(oauth.owner_sub().as_deref(), Some(moves_to), "{what}");
            assert_eq!(owner_moves(&store).len(), usize::from(moves_to == "user_new"), "{what}");
        }
    }

    /// The other row's own address never decides, even while this gateway's own row is silent or gone: nothing moves, and nothing is audited.
    #[tokio::test]
    async fn a_row_holding_another_address_never_decides_alone() {
        for (what, status) in [("this gateway's own row failing", 503), ("this gateway's own row gone", 404)] {
            let permaura_com = fake_saying(
                answer(move |_, seen| (if seen.path.contains("/gw_mine/") { status } else { 409 }, None)),
                None,
                Arc::new(|seen| {
                    seen.path.ends_with("/checkin").then(|| {
                        serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_other_org", "publicUrlValue": "https://acme-other.permaura.test" })
                    })
                }),
            )
            .await;
            let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
            let service = with_public_url(store.clone());
            service.set_announce(vec![link("gw_mine"), link("gw_other")]);
            let oauth = service.oauth().cloned().unwrap();
            assert!(!start_with(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None, OwnerPin::in_memory()));
            until("four rounds of check-ins", || checkins(&permaura_com).len() >= 8).await;
            assert_eq!(oauth.owner_sub().as_deref(), Some("user_owner"), "{what}");
            assert!(owner_moves(&store).is_empty(), "{what}");
        }
    }

    /// A gateway moved to a new name with the old one kept as an alias (PERMAURA_PUBLIC_URL_ALIASES) still serves its row's old address, so a row holding that alias is its own and decides; without the alias it is set aside and nothing decides.
    #[tokio::test]
    async fn a_row_holding_an_alias_of_this_gateways_address_decides_the_owner() {
        for (what, aliases, moves_to) in [
            ("the old name kept as an alias", vec!["https://g-old.permaura.test".to_string()], "user_new"),
            ("no alias", Vec::new(), "user_owner"),
        ] {
            let permaura_com = fake_saying(
                always(409),
                None,
                Arc::new(|seen| {
                    seen.path.ends_with("/checkin").then(|| {
                        if seen.path.contains("/gw_mine/") {
                            serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_new", "publicUrlValue": "https://g-old.permaura.test" })
                        } else {
                            serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_other_org", "publicUrlValue": "https://acme-other.permaura.test" })
                        }
                    })
                }),
            )
            .await;
            let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
            let service = with_public_url_and_aliases(store.clone(), aliases);
            service.set_announce(vec![link("gw_mine"), link("gw_other")]);
            let oauth = service.oauth().cloned().unwrap();
            assert!(!start_with(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None, OwnerPin::in_memory()));
            until("four rounds of check-ins", || checkins(&permaura_com).len() >= 8).await;
            assert_eq!(oauth.owner_sub().as_deref(), Some(moves_to), "{what}");
        }
    }

    #[test]
    fn addresses_compare_as_permaura_com_compares_them() {
        for (a, b) in [
            ("https://g-reseal.permaura.test", "https://g-reseal.permaura.test/"),
            ("https://g-reseal.permaura.test", "HTTPS://G-RESEAL.PERMAURA.TEST"),
            ("https://g-reseal.permaura.test", "https://g-reseal.permaura.test.:443/mcp"),
            ("http://gw.acme.example:8080", "http://gw.acme.example:8080/"),
        ] {
            assert!(same_address(a, b), "{a} and {b}");
        }
        for (a, b) in [
            ("https://g-reseal.permaura.test", "https://acme-other.permaura.test"),
            ("https://g-reseal.permaura.test", "http://g-reseal.permaura.test"),
            ("https://g-reseal.permaura.test", "https://g-reseal.permaura.test:8443"),
            ("https://g-reseal.permaura.test", "g-reseal.permaura.test"),
            ("https://g-reseal.permaura.test", ""),
            ("ftp://g-reseal.permaura.test", "ftp://g-reseal.permaura.test"),
        ] {
            assert!(!same_address(a, b), "{a} and {b}");
        }
    }

    /// The owner re-pins a check-in has made on `store`, oldest first.
    fn owner_moves(store: &Arc<dyn Store>) -> Vec<serde_json::Value> {
        store
            .audit_events(None)
            .unwrap()
            .into_iter()
            .filter(|e| e.payload.action == crate::service::OWNER_REPIN_ACTION)
            .map(|e| e.payload.summary)
            .collect()
    }

    /// A partial round: two rows both hold the public URL and name different owners, so the pin stays. Then the second row's check-in fails for a round (a 5xx, a 429 a neighbour's traffic can cause, a refused credential, or a 409 that names no owner) while the first keeps naming its owner. That round is not agreement: a row that last said it holds the public URL has not answered, so the pin stays where `remote enable` put it, unaudited, for as long as the row stays silent.
    #[tokio::test]
    async fn a_round_missing_a_row_that_holds_the_public_url_moves_nothing() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        for (what, status, silent) in [
            ("a 5xx", 503, serde_json::json!({})),
            ("a 429", 429, serde_json::json!({})),
            ("a refused credential", 401, serde_json::json!({})),
            ("a forbidden credential", 403, serde_json::json!({})),
            ("a public row that names no owner", 409, serde_json::json!({ "publicUrl": true, "needs_reseal": false })),
        ] {
            let second = Arc::new(AtomicUsize::new(0));
            let counted = second.clone();
            let answering = second.clone();
            let permaura_com = fake_saying(
                answer(move |_, seen| {
                    if seen.path.contains("/gw_two/") && counted.fetch_add(1, SeqCst) > 0 {
                        return (status, None);
                    }
                    (409, None)
                }),
                None,
                Arc::new(move |seen| {
                    if !seen.path.ends_with("/checkin") {
                        return None;
                    }
                    Some(if seen.path.contains("/gw_one/") {
                        serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_a" })
                    } else if answering.load(SeqCst) <= 1 {
                        serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_b" })
                    } else {
                        silent.clone()
                    })
                }),
            )
            .await;
            let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
            let service = with_public_url(store.clone());
            service.set_announce(vec![link("gw_one"), link("gw_two")]);
            let oauth = service.oauth().cloned().unwrap();
            assert!(!start_with(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None, OwnerPin::in_memory()));
            until("five rounds of check-ins", || checkins(&permaura_com).len() >= 10).await;
            assert!(second.load(SeqCst) >= 4, "{what}: the second row went silent after its first answer");
            assert_eq!(oauth.owner_sub().as_deref(), Some("user_owner"), "{what}");
            assert!(owner_moves(&store).is_empty(), "{what}: nothing audited");
        }
    }

    /// The other half: a row not heard from since boot is not taken as agreeing either, so the pin waits while it fails. Once every row has answered, and the one that was silent turns out to be a loopback-only row (a 200), the row holding the public URL decides, and the move is audited once.
    #[tokio::test]
    async fn the_pin_moves_once_every_row_has_answered_and_the_public_ones_agree() {
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        let answers = Arc::new(AtomicBool::new(false));
        let answering = answers.clone();
        let permaura_com = fake_saying(
            answer(move |_, seen| {
                if seen.path.contains("/gw_public/") {
                    (409, None)
                } else if answering.load(SeqCst) {
                    (200, None)
                } else {
                    (503, None)
                }
            }),
            None,
            Arc::new(|seen| {
                if !seen.path.ends_with("/checkin") {
                    return None;
                }
                Some(if seen.path.contains("/gw_public/") {
                    serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_new" })
                } else {
                    serde_json::json!({ "needs_reseal": false })
                })
            }),
        )
        .await;
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        let service = with_public_url(store.clone());
        service.set_announce(vec![link("gw_public"), link("gw_other")]);
        let oauth = service.oauth().cloned().unwrap();
        assert!(!start_with(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None, OwnerPin::in_memory()));
        until("four rounds with the other row failing", || checkins(&permaura_com).len() >= 8).await;
        assert_eq!(oauth.owner_sub().as_deref(), Some("user_owner"), "a row never heard from may hold the public URL too");
        assert!(owner_moves(&store).is_empty());

        answers.store(true, SeqCst);
        until("the re-pin", || oauth.owner_sub().as_deref() == Some("user_new")).await;
        let seen = checkins(&permaura_com).len();
        until("two more rounds", || checkins(&permaura_com).len() >= seen + 4).await;
        let moves = owner_moves(&store);
        assert_eq!(moves.len(), 1, "{moves:?}");
        assert_eq!(moves[0]["to"], "user_new");
    }

    /// A link whose row permaura.com no longer has (removed in the console, or the one a re-pair leaves behind, since pairing adds a link and never drops the old one) answers 404 at every check-in. It can hold no public URL, so the row that does decides, and a hand-over moves the owner.
    #[tokio::test]
    async fn a_dead_link_does_not_freeze_the_owner_pin() {
        let permaura_com = fake_saying(
            answer(|_, seen| if seen.path.contains("/gw_public/") { (409, None) } else { (404, None) }),
            None,
            Arc::new(|seen| {
                if !seen.path.ends_with("/checkin") {
                    return None;
                }
                Some(if seen.path.contains("/gw_public/") {
                    serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_new" })
                } else {
                    serde_json::json!({ "error": "gateway not found" })
                })
            }),
        )
        .await;
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        let service = with_public_url(store.clone());
        service.set_announce(vec![link("gw_public"), link("gw_removed")]);
        let oauth = service.oauth().cloned().unwrap();
        assert!(!start_with(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None, OwnerPin::in_memory()));
        until("four rounds of check-ins", || checkins(&permaura_com).len() >= 8).await;
        assert_eq!(
            oauth.owner_sub().as_deref(),
            Some("user_new"),
            "the only row holding the public URL named the new owner every round; a link whose row is gone froze the pin"
        );
    }

    /// The log says which link kept a round from settling and why, once while that stays the same, and says once that a link answering 404 holds no public URL.
    #[tokio::test]
    async fn the_log_names_the_link_that_keeps_a_round_unsettled() {
        let logs = Logs::default();
        let _log = logs.capture();
        let permaura_com = fake_saying(
            answer(|_, seen| {
                if seen.path.contains("/gw_public/") {
                    (409, None)
                } else if seen.path.contains("/gw_flaky/") {
                    (503, None)
                } else {
                    (404, None)
                }
            }),
            None,
            Arc::new(|seen| {
                if !seen.path.ends_with("/checkin") {
                    return None;
                }
                Some(if seen.path.contains("/gw_public/") {
                    serde_json::json!({ "publicUrl": true, "needs_reseal": false, "owner_sub": "user_new" })
                } else {
                    serde_json::json!({ "error": "gateway not found" })
                })
            }),
        )
        .await;
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        let service = with_public_url(store.clone());
        service.set_announce(vec![link("gw_public"), link("gw_flaky"), link("gw_removed")]);
        let oauth = service.oauth().cloned().unwrap();
        assert!(!start_with(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None, OwnerPin::in_memory()));
        until("four rounds of check-ins", || checkins(&permaura_com).len() >= 12).await;
        assert_eq!(oauth.owner_sub().as_deref(), Some("user_owner"), "a row never heard from may hold the public URL");
        let text = logs.text();
        assert_eq!(text.matches("gw_flaky: permaura.com answered 503").count(), 1, "named once while it stays the same:\n{text}");
        assert!(!text.contains("gw_removed:"), "a 404 does not keep a round unsettled:\n{text}");
        assert_eq!(text.matches("answered this link's check-in 404").count(), 1, "{text}");
        assert!(text.contains("link=gw_removed"), "{text}");
        logs.assert_no_credentials();
    }

    /// The log, second pass: a round in which no link named an owner still names the links that kept it unsettled, and the same links in another order are no change.
    #[tokio::test]
    async fn a_round_naming_no_owner_is_logged_once_whatever_the_order_of_the_links() {
        let logs = Logs::default();
        let _log = logs.capture();
        let permaura_com = fake(always(503), None).await;
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        let service = with_public_url(store.clone());
        service.set_announce(vec![link("gw_a"), link("gw_b")]);
        assert!(!start_with(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None, OwnerPin::in_memory()));
        until("a round of check-ins", || checkins(&permaura_com).len() >= 2).await;
        service.set_announce(vec![link("gw_b"), link("gw_a")]);
        until("three more rounds", || checkins(&permaura_com).len() >= 8).await;
        let text = logs.text();
        assert_eq!(text.matches("did not name its owner at this check-in").count(), 1, "said once:\n{text}");
        assert!(text.contains("gw_a: permaura.com answered 503; gw_b: permaura.com answered 503"), "{text}");
    }

    /// A permaura.com scripted check-in by check-in: the nth one's reply, or `None` for one that is never answered.
    struct Scripted {
        calls: std::sync::atomic::AtomicUsize,
        script: Box<dyn Fn(usize) -> Option<Reply> + Send + Sync>,
    }

    impl Scripted {
        fn new(script: impl Fn(usize) -> Option<Reply> + Send + Sync + 'static) -> Arc<Self> {
            Arc::new(Scripted { calls: Default::default(), script: Box::new(script) })
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl Transport for Scripted {
        async fn send(&self, _: &reqwest::Url, _: &serde_json::Value) -> Result<Reply, String> {
            Err("no re-seal here".into())
        }

        async fn check_in(&self, _: &reqwest::Url, _: &serde_json::Value) -> Result<Reply, String> {
            match (self.script)(self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst)) {
                Some(reply) => Ok(reply),
                None => std::future::pending().await,
            }
        }
    }

    fn reply(status: u16, public_url: bool) -> Option<Reply> {
        Some(Reply { status, retry_after: None, needs_reseal: false, owner_sub: None, public_url, row_public_url: RowAddress::Unsent })
    }

    /// Check in for the one link `gw_x` of a gateway with a public URL, through `transport`, giving up on a check-in after 40 ms; the owners it re-pins to are recorded in the returned list.
    fn check_in_gw_x(transport: Arc<Scripted>) -> Arc<Mutex<Vec<String>>> {
        let repinned = Arc::new(Mutex::new(Vec::new()));
        let recorded = repinned.clone();
        tokio::spawn(check_ins(
            Box::new(|| vec![link("gw_x")]),
            Arc::default(),
            transport,
            Timing { request_timeout: Duration::from_millis(40), ..checking_in() },
            Arc::new(move |owner: &str| recorded.lock().unwrap().push(owner.to_string())),
            vec!["https://g-reseal.permaura.test".into()],
        ));
        repinned
    }

    /// The log, third pass: the same link held back for another reason is a change. A 503 that becomes no answer in time, and then a 503 again, is three lines, not one.
    #[tokio::test]
    async fn the_unsettled_log_is_said_again_when_a_links_reason_changes() {
        let logs = Logs::default();
        let _log = logs.capture();
        let permaura_com = Scripted::new(|n| if matches!(n, 2 | 3) { None } else { reply(503, false) });
        let repinned = check_in_gw_x(permaura_com.clone());
        until("six rounds of check-ins", || permaura_com.calls() >= 7).await;
        let text = logs.text();
        assert_eq!(text.matches("did not name its owner at this check-in").count(), 3, "503, no answer in time, 503:\n{text}");
        assert_eq!(text.matches("gw_x: permaura.com answered 503").count(), 2, "{text}");
        assert_eq!(text.matches("gw_x: no answer in time").count(), 1, "{text}");
        assert!(repinned.lock().unwrap().is_empty());
    }

    /// The log, third pass: a round that settled with no owner to repin to (the link answered 200, so no row holds the public URL) ends the run, and the same link held back for the same reason afterwards is said again.
    #[tokio::test]
    async fn the_unsettled_log_is_said_again_after_a_round_that_settled_without_a_repin() {
        let logs = Logs::default();
        let _log = logs.capture();
        let permaura_com = Scripted::new(|n| if n == 2 { reply(200, false) } else { reply(409, true) });
        let repinned = check_in_gw_x(permaura_com.clone());
        until("five rounds of check-ins", || permaura_com.calls() >= 6).await;
        let text = logs.text();
        assert_eq!(
            text.matches("gw_x: its row holds the public URL and named no owner").count(),
            2,
            "before and after the round that settled, once each:\n{text}"
        );
        assert!(repinned.lock().unwrap().is_empty(), "no owner was named, so nothing was repinned");
    }

    /// A link's check-in 404 is warned of with both causes, a removed or replaced row and a rotated announce secret that never reached this machine, and what to do. Once per change: no answer in time between two 404s is no change, a 200 is.
    #[tokio::test]
    async fn a_404_at_check_in_is_warned_once_per_change_and_says_what_to_do() {
        let logs = Logs::default();
        let _log = logs.capture();
        let permaura_com = Scripted::new(|n| match n {
            2 => None,
            4 => reply(200, false),
            _ => reply(404, false),
        });
        check_in_gw_x(permaura_com.clone());
        until("seven rounds of check-ins", || permaura_com.calls() >= 8).await;
        let text = logs.text();
        let warned: Vec<&str> = text.lines().filter(|line| line.contains("answered this link's check-in 404")).collect();
        assert_eq!(warned.len(), 2, "404, 404, no answer, 404 is one run; a 200 ends it:\n{text}");
        for line in warned {
            assert!(line.contains(" WARN "), "{line}");
            assert!(line.contains("link=gw_x"), "{line}");
            assert!(line.contains("announce secret was rotated on permaura.com and the new one never reached this machine"), "{line}");
            assert!(line.contains("run `permaura announce rotate --gateway gw_x` on this machine"), "{line}");
            assert!(line.contains("drop it with DELETE /v1/announce naming gateway_id gw_x"), "{line}");
            assert!(!line.contains("pair the gateway again"), "a re-pair adds a link and leaves the dead one: {line}");
        }
    }

    /// A loopback-only gateway has no resource server and so no pin; an owner named at its check-in is nothing to act on, and the check-in's other work is unaffected.
    #[tokio::test]
    async fn an_owner_named_to_a_loopback_only_gateway_is_nothing_to_act_on() {
        let permaura_com = fake_saying(always(200), None, Arc::new(|seen| seen.path.ends_with("/checkin").then(|| serde_json::json!({ "needs_reseal": false, "owner_sub": "user_new" })))).await;
        let state = loopback_only();
        state.service.set_announce(vec![link("gw_one")]);
        assert!(start(state.service.clone(), state.held_console_sessions.clone(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None));
        until("a check-in", || permaura_com.seen().iter().any(|s| s.path.ends_with("/checkin"))).await;
        assert!(state.service.oauth().is_none());
        assert!(!state.service.store().audit_events(None).unwrap().iter().any(|e| e.payload.action == crate::service::OWNER_REPIN_ACTION));
    }

    /// A reopening (permaura.com says it lost the bearer) and a retry re-send the same console session; neither is a pairing, so neither rotates the file again: a permaura.com that could make the gateway rotate on demand would churn a local file at will.
    #[tokio::test]
    async fn a_reopened_link_offered_the_same_session_does_not_rotate_again() {
        let permaura_com = fake_saying(always(200), None, Arc::new(|seen| seen.path.ends_with("/checkin").then(|| serde_json::json!({ "needs_reseal": true })))).await;
        let state = loopback_only();
        let store = state.service.store().clone();
        let handed_over = crate::mint_operator_session(store.as_ref()).unwrap();
        let file = TokenFile::holding(&handed_over);
        state.published_token.set(Some(handed_over.clone()));
        state.service.set_announce(vec![link("gw_one")]);
        assert!(start(state.service.clone(), state.held_console_sessions.clone(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), Some(rotation(&state, &file, Duration::from_millis(10)))));
        until("the first seal", || permaura_com.to("gw_one").len() == 1).await;
        until("the rotation", || file.read() != handed_over).await;
        let rotated_once = file.read();
        until("a reopening seals again", || permaura_com.to("gw_one").len() >= 2).await;
        settle().await;
        assert_eq!(file.read(), rotated_once, "the same session offered again is not a pairing");
        let tokens: std::collections::BTreeSet<String> = permaura_com.to("gw_one").iter().map(|s| s.token().to_string()).collect();
        assert_eq!(tokens.len(), 1, "one console session, sealed more than once: {:?}", permaura_com.seen());
    }

    /// A rotation only ever replaces the token this gateway published: a file another process wrote (a `--demo` gateway beside a real install) is left alone, and so is the token it names.
    #[tokio::test]
    async fn a_file_another_gateway_published_is_not_rotated() {
        let permaura_com = fake(always(200), None).await;
        let state = loopback_only();
        let store = state.service.store().clone();
        let ours = crate::mint_operator_session(store.as_ref()).unwrap();
        let theirs = crate::mint_operator_session(store.as_ref()).unwrap();
        let file = TokenFile::holding(&theirs);
        state.published_token.set(Some(ours.clone()));
        state.service.set_announce(vec![link("gw_one")]);
        assert!(start(state.service.clone(), state.held_console_sessions.clone(), Box::new(install), Loopback::to(permaura_com.addr), fast(), Some(rotation(&state, &file, Duration::from_millis(10)))));
        until("the re-seal", || permaura_com.count() == 1).await;
        settle().await;
        assert_eq!(file.read(), theirs);
        assert_eq!(state.published_token.get().as_deref(), Some(ours.as_str()));
        assert!(state.service.authenticate(&theirs).is_ok() && state.service.authenticate(&ours).is_ok());
    }

    /// The console session permaura.com holds is an operator bearer, and revoking it through `POST /v1/sessions/<id>/revoke` makes the next poll mint and offer a new one, which used to be a first offer and so a rotation every poll. A new console session is not a pairing: the file is rotated once at boot and never again however often it is done, and no operator token is minted for it.
    #[tokio::test]
    async fn a_console_session_permaura_com_revokes_is_replaced_without_rotating_the_file() {
        let permaura_com = fake(always(200), None).await;
        let state = loopback_only();
        let store = state.service.store().clone();
        let handed_over = crate::mint_operator_session(store.as_ref()).unwrap();
        let file = TokenFile::holding(&handed_over);
        state.published_token.set(Some(handed_over.clone()));
        state.service.set_announce(vec![link("gw_one")]);
        assert!(start(state.service.clone(), state.held_console_sessions.clone(), Box::new(install), Loopback::to(permaura_com.addr), fast(), Some(rotation(&state, &file, Duration::from_millis(10)))));
        until("the first seal", || permaura_com.count() == 1).await;
        until("the boot rotation", || file.read() != handed_over).await;
        let rotated = file.read();
        let operator_rows = |store: &dyn Store| {
            store.list_sessions().unwrap().into_iter().filter(|s| s.class == crate::store::SessionClass::OperatorToken).count()
        };
        let minted = operator_rows(store.as_ref());
        for round in 1..=3 {
            let sealed = permaura_com.seen().last().unwrap().token().to_string();
            let id = store.session_by_token(&sealed).unwrap().expect("the sealed console session").id;
            assert_eq!(on_loopback(&state, &sealed, &format!("/v1/sessions/{id}/revoke"), serde_json::json!({})).await, 200);
            until("a new console session sealed", || permaura_com.count() == round + 1).await;
        }
        settle().await;
        let sealed: std::collections::BTreeSet<String> = permaura_com.seen().iter().map(|s| s.token().to_string()).collect();
        assert_eq!(sealed.len(), 4, "a new console session each time: {:?}", permaura_com.seen());
        assert_eq!(file.read(), rotated, "a new console session is not a pairing, so the file is not rotated again");
        assert_eq!(operator_rows(store.as_ref()), minted, "and no operator token is minted for it");
        assert!(state.service.authenticate(&rotated).is_ok());
    }

    /// Permaura.com answers a later pairing with a link id this gateway already holds, so `PUT /v1/announce` replaces that link in place. The link state was kept by id and the console session it had sealed looked handled, so the token handed over at that pairing was never retired. Every pairing on this machine now rotates the file within a poll, and a link paired again in place is offered the console session afresh. The console's own `PUT /v1/announce`, a remote caller, hands nothing over and rotates nothing.
    #[tokio::test]
    async fn a_pairing_that_reuses_a_link_id_still_retires_the_token_it_handed_over() {
        let permaura_com = fake(always(200), None).await;
        let state = loopback_only();
        let store = state.service.store().clone();
        let first = crate::mint_operator_session(store.as_ref()).unwrap();
        let file = TokenFile::holding(&first);
        state.published_token.set(Some(first.clone()));
        state.service.set_announce(vec![link("gw_one")]);
        assert!(start(state.service.clone(), state.held_console_sessions.clone(), Box::new(install), Loopback::to(permaura_com.addr), fast(), Some(rotation(&state, &file, Duration::from_millis(10)))));
        until("the first seal", || permaura_com.to("gw_one").len() == 1).await;
        until("the boot rotation", || file.read() != first).await;

        // `permaura pair` again: the enrol body carries the token the file names now, and permaura.com sends back gw_one.
        let handed_over = file.read();
        paired_on_this_machine(&state, &handed_over, "gw_one", SECOND_SECRET).await;
        until("the rotation for that pairing", || file.read() != handed_over).await;
        until("the grace to pass", || state.service.authenticate(&handed_over).is_err()).await;
        until("gw_one offered the console session again", || permaura_com.to("gw_one").len() == 2).await;
        let export = serde_json::json!({ "passphrase": "chosen by permaura.com" });
        assert_eq!(on_loopback(&state, &handed_over, VAULT_EXPORT, export).await, 401);

        let rotated = file.read();
        let console = permaura_com.to("gw_one").last().unwrap().token().to_string();
        assert!(crate::is_console_token(&console));
        let set = serde_json::json!({ "gateway_id": "gw_two", "announce_secret": SECOND_SECRET });
        assert_eq!(sent(&state, "PUT", &console, "/v1/announce", set, None).await, 200, "the console may set a link");
        until("the console's link sealed", || permaura_com.to("gw_two").len() == 1).await;
        settle().await;
        assert_eq!(file.read(), rotated, "a remote caller hands nothing over, so it rotates nothing");
        assert!(state.service.authenticate(&rotated).is_ok());
    }

    /// The re-seal task never rotated when permaura.com answered the enrolment with no link (no `announceSecret`, so nothing is announced and the task has nothing to offer), nor when `permaura pair && permaura remote enable --yes && systemctl restart permaura` finished inside one poll. The token handed over was still live when the gateway came back with a public URL, the boot remote access is meant to reach. That boot now publishes a fresh token and ends every earlier one, and what they opened, once it holds its address and before it serves: the handed-over token neither authenticates nor exports over loopback, and on a paired gateway loosens nothing.
    #[tokio::test]
    async fn a_boot_with_a_public_url_ends_a_handed_over_token_the_reseal_task_never_saw() {
        for (schedule, linked) in [("A, no link", false), ("B, restarted inside one poll", true)] {
            let state = loopback_only();
            let store = state.service.store().clone();
            let handed_over = crate::mint_operator_session(store.as_ref()).unwrap();
            let file = TokenFile::holding(&handed_over);
            state.published_token.set(Some(handed_over.clone()));
            let opened = open_session(&state, &handed_over).await;
            if linked {
                paired_on_this_machine(&state, &handed_over, "gw_one", SECOND_SECRET).await;
            }

            let fresh = crate::republish_operator_token_for_a_public_url(store.as_ref(), &file.0).expect("a fresh operator token");
            assert_eq!(file.read(), fresh, "{schedule}");
            let restarted = with_public_url(store.clone());
            assert!(!start(restarted.clone(), Arc::default(), Box::new(install), Arc::new(Recorder::default()), fast(), None));
            let public = crate::AppState { service: restarted.clone(), ..state.clone() };
            assert!(restarted.authenticate(&handed_over).is_err(), "{schedule}: the handed-over token is dead at boot, with no grace");
            assert!(restarted.authenticate(&opened).is_err(), "{schedule}: so is what it opened");
            assert!(restarted.authenticate(&fresh).is_ok(), "{schedule}: the file's token works");
            let export = serde_json::json!({ "passphrase": "chosen by permaura.com" });
            assert_eq!(on_loopback(&public, &handed_over, VAULT_EXPORT, export).await, 401, "{schedule}");
            let sk = ed25519_dalek::SigningKey::from_bytes(&[74; 32]);
            use base64::Engine as _;
            assert!(public.service.trust_approver_key("device:owner", &base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes())));
            let loosening = serde_json::json!({ "id": "p_handover_boot", "connection_id": "generic_http", "name": "p_handover_boot", "allow": ["request"] });
            assert_eq!(on_loopback(&public, &handed_over, "/v1/policies", loosening).await, 401, "{schedule}");
            assert!(!public.service.store().list_policies().unwrap().iter().any(|p| p.id == "p_handover_boot"), "{schedule}: nothing applied");
        }
    }

    /// A permaura.com that holds the re-seal open cannot hold the rotation back with it. The file is replaced before the offer goes out, so the handed-over token is on its grace while the offer is still unanswered.
    #[tokio::test]
    async fn a_reseal_held_open_does_not_hold_back_the_rotation() {
        let gate = Gate::default();
        let permaura_com = fake(always(200), Some(gate.clone())).await;
        let state = loopback_only();
        let store = state.service.store().clone();
        let handed_over = crate::mint_operator_session(store.as_ref()).unwrap();
        let file = TokenFile::holding(&handed_over);
        state.published_token.set(Some(handed_over.clone()));
        state.service.set_announce(vec![link("gw_one")]);
        let rotation = rotation(&state, &file, Duration::from_millis(300));
        assert!(start(state.service.clone(), state.held_console_sessions.clone(), Box::new(install), Loopback::to(permaura_com.addr), fast(), Some(rotation)));

        tokio::time::timeout(Duration::from_secs(5), gate.arrived.notified()).await.expect("the re-seal arrives and is held");
        let arrived = Instant::now();
        until("the rotation", || file.read() != handed_over).await;
        assert!(arrived.elapsed() < Duration::from_secs(1), "the rotation waited on the held offer");
        until("the grace to pass", || state.service.authenticate(&handed_over).is_err()).await;
        assert_eq!(permaura_com.count(), 1, "the offer is still unanswered");
        gate.release.notify_one();
    }

    /// Several links taking the console session in one poll rotate the file once, and a link paired later on this machine, carrying the token the file named then, rotates it again.
    #[tokio::test]
    async fn links_sealed_together_rotate_once_and_a_later_pairing_rotates_again() {
        let permaura_com = fake(always(200), None).await;
        let state = loopback_only();
        let store = state.service.store().clone();
        let first = crate::mint_operator_session(store.as_ref()).unwrap();
        let file = TokenFile::holding(&first);
        state.published_token.set(Some(first.clone()));
        state.service.set_announce(vec![link("gw_one"), link("gw_two")]);
        assert!(start(state.service.clone(), state.held_console_sessions.clone(), Box::new(install), Loopback::to(permaura_com.addr), fast(), Some(rotation(&state, &file, Duration::from_millis(10)))));
        until("both links sealed", || permaura_com.count() == 2).await;
        settle().await;
        let second = file.read();
        assert_ne!(second, first);
        let now = crate::service::now_ms();
        let live: Vec<_> = store
            .list_sessions()
            .unwrap()
            .into_iter()
            .filter(|s| s.class == crate::store::SessionClass::OperatorToken && !s.revoked && !s.is_expired(now))
            .collect();
        assert_eq!(live.len(), 1, "one rotation: only the file's token is live: {live:?}");

        paired_on_this_machine(&state, &second, "gw_three", "gwa_0123456789abcdefghijklmnopqrstuv").await;
        until("the new link sealed", || permaura_com.to("gw_three").len() == 1).await;
        until("the rotation for the new pairing", || file.read() != second).await;
        settle().await;
        assert_ne!(file.read(), second, "the token handed over at the new pairing is replaced too");
        assert!(state.service.authenticate(&second).is_err());
        assert_eq!(permaura_com.count(), 3, "{:?}", permaura_com.seen());
    }

    /// Two rotations inside one grace (a second workspace paired within two minutes, `start --pair` on a gateway already linked, a seal retried after a 5xx) end the two tokens they replaced and never the one the file names, which a sweep by class at the end of the first grace used to revoke.
    #[tokio::test]
    async fn a_second_rotation_inside_the_grace_never_ends_the_token_the_file_names() {
        let state = loopback_only();
        let store = state.service.store().clone();
        let handed_over = crate::mint_operator_session(store.as_ref()).unwrap();
        let file = TokenFile::holding(&handed_over);
        state.published_token.set(Some(handed_over.clone()));
        let rotation = rotation(&state, &file, Duration::from_millis(400));

        let first = rotation.rotate().expect("the first rotation");
        let second = rotation.rotate().expect("the second, inside the first one's grace");
        assert_eq!(file.read(), second);
        for token in [&handed_over, &first, &second] {
            assert!(state.service.authenticate(token).is_ok(), "inside the grace every one still works");
        }
        until("the grace to pass", || state.service.authenticate(&first).is_err()).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(state.service.authenticate(&handed_over).is_err(), "the handed-over token is ended");
        assert!(state.service.authenticate(&first).is_err(), "so is the one the first rotation published");
        assert!(state.service.authenticate(&second).is_ok(), "the token the file names keeps working");
        assert_eq!(state.published_token.get().as_deref(), Some(second.as_str()));
    }

    /// The end of the grace is in the store, so a restart inside it, even into a public URL (which never rotates and only revokes console sessions), still ends the token permaura.com was handed at pairing once the grace has passed, rather than leaving it live for its twelve hours.
    #[cfg(feature = "sqlite")]
    #[tokio::test]
    async fn a_restart_into_a_public_url_inside_the_grace_still_ends_the_handed_over_token() {
        let dir = std::env::temp_dir().join(format!("grace-{}-{}", std::process::id(), crate::service::short_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("gateway.db").to_string_lossy().into_owned();
        let grace = Duration::from_millis(800);
        // The first process: paired, then rotated once permaura.com acknowledged the console session. Its runtime is dropped with it, as an exit drops anything it had scheduled.
        let first_boot = db.clone();
        let (handed_over, fresh) = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
            runtime.block_on(async move {
                let store: Arc<dyn Store> = Arc::new(crate::store::sqlite::SqliteStore::open(&first_boot).unwrap());
                let handed_over = crate::mint_operator_session(store.as_ref()).unwrap();
                let file = TokenFile::holding(&handed_over);
                let published = Arc::new(PublishedToken::default());
                published.set(Some(handed_over.clone()));
                let rotation = crate::OperatorTokenRotation { store, path: file.0.clone(), published, grace };
                let fresh = rotation.rotate().expect("the rotation once permaura.com acknowledged the console session");
                (handed_over, fresh)
            })
        })
        .join()
        .unwrap();

        let store: Arc<dyn Store> = Arc::new(crate::store::sqlite::SqliteStore::open(&db).unwrap());
        let restarted = with_public_url(store);
        assert!(!start(restarted.clone(), Arc::default(), Box::new(install), Arc::new(Recorder::default()), fast(), None));
        assert!(restarted.authenticate(&handed_over).is_ok(), "still inside the grace after the restart");
        until("the grace to pass", || restarted.authenticate(&handed_over).is_err()).await;
        assert!(restarted.authenticate(&fresh).is_ok(), "the file's token is untouched");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `expire_session_by` behaves the same on every store: it brings an expiry forward and never pushes one back, leaves a revoked row alone, and is what authentication then honors.
    #[test]
    fn expire_session_by_only_ever_brings_an_expiry_forward_on_every_store() {
        let stores: Vec<Arc<dyn Store>> = vec![
            Arc::new(crate::store::memory::MemoryStore::new()),
            #[cfg(feature = "sqlite")]
            Arc::new(crate::store::sqlite::SqliteStore::open_in_memory().unwrap()),
        ];
        for store in stores {
            let kind = store.kind();
            let token = crate::mint_operator_session(store.as_ref()).unwrap();
            let id = store.session_by_token(&token).unwrap().unwrap().id;
            let minted = store.get_session(&id).unwrap().unwrap().expires_at.unwrap();
            let now = crate::service::now_ms();
            assert!(store.expire_session_by(&id, now + 60_000).unwrap(), "{kind}");
            assert_eq!(store.get_session(&id).unwrap().unwrap().expires_at, Some(now + 60_000), "{kind}");
            assert!(store.expire_session_by(&id, minted + 1).unwrap(), "{kind}");
            assert_eq!(store.get_session(&id).unwrap().unwrap().expires_at, Some(now + 60_000), "{kind}: never later");
            assert!(store.expire_session_by(&id, now - 1).unwrap(), "{kind}");
            let service = crate::service::EnforcementService::new(store.clone(), Arc::new(crate::connectors::MockHttpClient::new()));
            assert!(service.authenticate(&token).is_err(), "{kind}: an expiry in the past is honored");

            let revoked = crate::mint_operator_session(store.as_ref()).unwrap();
            let revoked_id = store.session_by_token(&revoked).unwrap().unwrap().id;
            store.revoke_session(&revoked_id).unwrap();
            assert!(!store.expire_session_by(&revoked_id, now).unwrap(), "{kind}");
            assert!(store.get_session(&revoked_id).unwrap().unwrap().revoked, "{kind}");
            assert!(!store.expire_session_by("sess_missing", now).unwrap(), "{kind}");
        }
    }

    /// `POST /v1/sessions` over loopback with `bearer`, returning the token it opened.
    async fn open_session(state: &crate::AppState, bearer: &str) -> String {
        use tower::ServiceExt as _;
        let req = axum::http::Request::builder()
            .method("POST")
            .uri("/v1/sessions")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {bearer}"))
            .body(axum::body::Body::from(serde_json::json!({ "agent_id": "codex-cli" }).to_string()))
            .unwrap();
        let resp = crate::build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::CREATED);
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["token"].as_str().unwrap().to_string()
    }

    /// A session opened from the handed-over token through `POST /v1/sessions` before the rotation, and one opened from that, end with it once the grace has passed rather than living out their own twelve hours; one opened from it during the grace never outlives it; one opened from the file's fresh token keeps working.
    #[tokio::test]
    async fn sessions_opened_from_a_retired_token_end_with_it() {
        let state = loopback_only();
        let store = state.service.store().clone();
        let handed_over = crate::mint_operator_session(store.as_ref()).unwrap();
        let file = TokenFile::holding(&handed_over);
        state.published_token.set(Some(handed_over.clone()));
        let child = open_session(&state, &handed_over).await;
        let grandchild = open_session(&state, &child).await;

        let fresh = rotation(&state, &file, Duration::from_millis(400)).rotate().expect("the rotation");
        let during = open_session(&state, &handed_over).await;
        let from_fresh = open_session(&state, &fresh).await;
        for token in [&handed_over, &child, &grandchild, &during, &from_fresh] {
            assert!(state.service.authenticate(token).is_ok(), "inside the grace every one still works");
        }
        until("the grace to pass", || state.service.authenticate(&handed_over).is_err()).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        for (what, token) in [("the opened one", &child), ("what it opened", &grandchild), ("one opened during the grace", &during)] {
            assert!(state.service.authenticate(token).is_err(), "{what} ends with the handed-over token");
        }
        assert!(state.service.authenticate(&fresh).is_ok() && state.service.authenticate(&from_fresh).is_ok());
    }

    /// Who opened a session survives the store it is written to, on every store.
    #[test]
    fn the_opener_is_kept_on_every_store() {
        let stores: Vec<Arc<dyn Store>> = vec![
            Arc::new(crate::store::memory::MemoryStore::new()),
            #[cfg(feature = "sqlite")]
            Arc::new(crate::store::sqlite::SqliteStore::open_in_memory().unwrap()),
        ];
        for store in stores {
            let parent = crate::mint_operator_session(store.as_ref()).unwrap();
            let parent_id = store.session_by_token(&parent).unwrap().unwrap().id;
            let mut row = store.session_by_token(&parent).unwrap().unwrap();
            row.id = "sess_opened".into();
            row.token = "tok_opened_child".into();
            row.class = Default::default();
            row.opened_by = Some(parent_id.clone());
            store.put_session(row).unwrap();
            let read = store.list_sessions().unwrap().into_iter().find(|s| s.id == "sess_opened").unwrap();
            assert_eq!(read.opened_by.as_deref(), Some(parent_id.as_str()), "{}", store.kind());
        }
    }

    // ── Permaura.com asks for a link's bearer again ──────────────────────────────────────────────────

    const ANNOUNCE_SECRET: &str = "gwa_0123456789abcdefghijklmnopqrstuv";

    fn checkins(permaura_com: &Fake) -> Vec<Seen> {
        permaura_com.seen().into_iter().filter(|s| s.path.ends_with("/checkin")).collect()
    }

    /// Run the re-seal task and its check-ins for `gateway`, as `start` does.
    fn run_with_check_ins(gateway: &Gateway, permaura_com: &Fake, timing: Timing) {
        let announcer = gateway.announcer.clone();
        tokio::spawn(check_ins(
            Box::new(move || announcer.links()),
            gateway.announcer.reseal_requests(),
            Loopback::to(permaura_com.addr),
            timing.clone(),
            Arc::new(|_| {}),
            Vec::new(),
        ));
        tokio::spawn(run(gateway.sources(install()), Loopback::to(permaura_com.addr), timing));
    }

    /// The row had a public URL, so the re-seal was refused with a 409 and the link closed; then the URL was cleared and permaura.com held no bearer, and the gateway would not send one until it restarted. Now the check-in says so, the link reopens, and the current console session is sealed once.
    #[tokio::test]
    async fn a_link_permaura_com_cleared_is_resealed_when_a_check_in_asks() {
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        let logs = Logs::default();
        let _log = logs.capture();
        let (cleared, sealed) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let (c, s) = (cleared.clone(), sealed.clone());
        let reseal = answer(move |_, seen| match (seen.path.ends_with("/operator-token"), c.load(SeqCst)) {
            (true, false) => (409, None),
            (true, true) => {
                s.store(true, SeqCst);
                (200, None)
            }
            (false, _) => (200, None),
        });
        let (c, s) = (cleared.clone(), sealed.clone());
        let said: Said = Arc::new(move |seen| {
            seen.path.ends_with("/checkin").then(|| serde_json::json!({ "needs_reseal": c.load(SeqCst) && !s.load(SeqCst), "unknown": [1, 2] }))
        });
        let permaura_com = fake_saying(reseal, None, said).await;
        let gateway = Gateway::new(Some(T1));
        gateway.enrol(&["gw_one"]);
        // A check-in answered just before the seal landed may still have asked; the reopen window is what keeps that to one seal.
        run_with_check_ins(&gateway, &permaura_com, Timing { reopen_every: Duration::from_secs(3600), ..checking_in() });

        until("the refused re-seal", || permaura_com.to("gw_one").len() == 1).await;
        until("three check-ins", || checkins(&permaura_com).len() >= 3).await;
        assert_eq!(permaura_com.to("gw_one").len(), 1, "a 409 closes the link, and a check-in that asks for nothing leaves it closed");

        cleared.store(true, SeqCst);
        until("the re-seal the check-in asked for", || permaura_com.to("gw_one").len() == 2).await;
        assert_eq!(permaura_com.to("gw_one")[1].token(), T1, "the current console session");
        let after = checkins(&permaura_com).len();
        until("three more check-ins", || checkins(&permaura_com).len() >= after + 3).await;
        assert_eq!(permaura_com.to("gw_one").len(), 2, "sealed once; permaura.com stops asking: {:?}", permaura_com.seen());

        for check_in in checkins(&permaura_com) {
            assert_eq!((check_in.method.as_str(), check_in.path.as_str()), ("POST", "/api/gateways/gw_one/checkin"));
            assert_eq!(check_in.body, serde_json::json!({ "gatewayId": "gw_one", "announceSecret": ANNOUNCE_SECRET }), "never the bearer");
        }
        logs.assert_no_credentials();
        assert!(!logs.text().contains(ANNOUNCE_SECRET), "{}", logs.text());
    }

    /// The control: an answer without `needs_reseal`, with it false, or with anything but a boolean there asks for nothing, so a sealed link is not offered its bearer again.
    #[tokio::test]
    async fn a_check_in_that_does_not_ask_changes_nothing() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let n = Arc::new(AtomicUsize::new(0));
        let said: Said = Arc::new(move |seen| {
            seen.path.ends_with("/checkin").then(|| match n.fetch_add(1, SeqCst) % 3 {
                0 => serde_json::json!({}),
                1 => serde_json::json!({ "needs_reseal": false, "lastSeenAt": "2026-10-14T00:00:00.000Z" }),
                _ => serde_json::json!({ "needs_reseal": "true" }),
            })
        });
        let permaura_com = fake_saying(always(200), None, said).await;
        let gateway = Gateway::new(Some(T1));
        gateway.enrol(&["gw_one"]);
        run_with_check_ins(&gateway, &permaura_com, checking_in());

        until("the re-seal at enrolment", || permaura_com.to("gw_one").len() == 1).await;
        until("six check-ins", || checkins(&permaura_com).len() >= 6).await;
        settle().await;
        assert_eq!(permaura_com.to("gw_one").len(), 1, "{:?}", permaura_com.seen());
    }

    /// A 404 (no live row answers to the link's credential) and a 401 or 403 are each said once; a 409 is a row that holds no sealed bearer and is never re-sealed, whatever its body says.
    #[tokio::test]
    async fn a_check_in_that_is_not_answered_reopens_nothing() {
        let logs = Logs::default();
        let _log = logs.capture();
        let reseal = answer(|_, seen| match seen.path.as_str() {
            "/api/gateways/gw_missing/checkin" => (404, None),
            "/api/gateways/gw_public/checkin" => (409, None),
            "/api/gateways/gw_other/checkin" => (403, None),
            _ => (200, None),
        });
        let said: Said = Arc::new(|seen| seen.path.ends_with("/checkin").then(|| serde_json::json!({ "needs_reseal": true })));
        let permaura_com = fake_saying(reseal, None, said).await;
        let gateway = Gateway::new(Some(T1));
        gateway.enrol(&["gw_missing", "gw_public", "gw_other"]);
        run_with_check_ins(&gateway, &permaura_com, checking_in());

        until("every link sealed once", || permaura_com.seen().iter().filter(|s| s.path.ends_with("/operator-token")).count() == 3).await;
        until("three rounds of check-ins", || checkins(&permaura_com).len() >= 9).await;
        settle().await;
        for link in ["gw_missing", "gw_public", "gw_other"] {
            assert_eq!(permaura_com.to(link).len(), 1, "{link}: {:?}", permaura_com.seen());
        }
        let text = logs.text();
        assert_eq!(text.matches("refused this link's check-in").count(), 1, "said once: {text}");
        assert!(text.contains("status=403"), "{text}");
        assert_eq!(text.lines().filter(|l| l.contains("gw_missing") && l.contains("check-in")).count(), 1, "a 404 is said once: {text}");
        assert!(text.contains("answered this link's check-in 404"), "{text}");
        logs.assert_no_credentials();
    }

    /// A re-seal refused with `needs_reseal: true` reopens the link and seals again; a re-seal that landed is the answer, so its `needs_reseal` is not acted on.
    #[tokio::test]
    async fn a_reseal_answer_that_asks_again_is_heard_unless_it_landed() {
        let said: Said = Arc::new(|seen| seen.path.ends_with("/operator-token").then(|| serde_json::json!({ "needs_reseal": true })));
        let permaura_com = fake_saying(answer(|n, _| (if n == 0 { 409 } else { 200 }, None)), None, said).await;
        let gateway = Gateway::new(Some(T1));
        gateway.enrol(&["gw_one"]);
        run_with_check_ins(&gateway, &permaura_com, fast());

        until("the second re-seal", || permaura_com.to("gw_one").len() == 2).await;
        settle().await;
        assert_eq!(permaura_com.to("gw_one").len(), 2, "{:?}", permaura_com.seen());
        assert!(checkins(&permaura_com).is_empty());
    }

    /// The predicate is the public URL, as for the re-seal itself: such a gateway checks in (that is how an owner re-pin reaches it) but never seals a bearer and never reopens a link, whatever an answer asks for.
    #[tokio::test]
    async fn a_gateway_with_a_public_url_checks_in_but_never_seals_or_reopens_a_link() {
        let said: Said = Arc::new(|seen| seen.path.ends_with("/checkin").then(|| serde_json::json!({ "needs_reseal": true })));
        let permaura_com = fake_saying(always(200), None, said).await;
        let store: Arc<dyn Store> = Arc::new(crate::store::memory::MemoryStore::new());
        let service = with_public_url(store);
        service.set_announce(vec![link("gw_one")]);
        assert!(!start(service.clone(), Arc::default(), Box::new(install), Loopback::to(permaura_com.addr), checking_in(), None));
        service.reseal_requests().ask("gw_one");
        until("check-ins", || checkins(&permaura_com).len() >= 3).await;
        settle().await;
        assert!(permaura_com.to("gw_one").is_empty(), "nothing sealed however often it is asked: {:?}", permaura_com.seen());
        assert!(permaura_com.seen().iter().all(|s| s.path.ends_with("/checkin")), "{:?}", permaura_com.seen());
    }

    /// `start` wires the check-ins to the links the gateway announces to and to the re-seal task, so an answer asking for a bearer is acted on in a running gateway too.
    #[tokio::test]
    async fn a_started_gateway_checks_in_and_reseals_when_asked() {
        let said: Said = Arc::new(|seen| seen.path.ends_with("/checkin").then(|| serde_json::json!({ "needs_reseal": true })));
        let permaura_com = fake_saying(always(200), None, said).await;
        let state = loopback_only();
        state.service.set_announce(vec![link("gw_one")]);
        let timing = Timing { reopen_every: Duration::from_secs(3600), ..checking_in() };
        assert!(start(state.service.clone(), state.held_console_sessions.clone(), Box::new(install), Loopback::to(permaura_com.addr), timing, None));
        until("the re-seal at boot", || permaura_com.to("gw_one").len() == 1).await;
        until("the re-seal a check-in asked for", || permaura_com.to("gw_one").len() == 2).await;
        until("more check-ins", || checkins(&permaura_com).len() >= 5).await;
        assert_eq!(permaura_com.to("gw_one").len(), 2, "at most one reopening per reopen window: {:?}", permaura_com.seen());
        assert_eq!(permaura_com.to("gw_one")[1].token(), permaura_com.to("gw_one")[0].token(), "the same live console session");
    }

    // ── What `/health` proves for the browser-direct console ──────────────────────────────────────

    /// A minted session is proved from before it is sent, beside the one permaura.com acknowledged last, newest first, and alone once permaura.com acknowledges it; nothing is proved once the gateway is unlinked.
    #[tokio::test]
    async fn the_sessions_permaura_com_may_hold_follow_the_mint_and_the_ack() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let accept_second = Arc::new(AtomicBool::new(false));
        let accepting = accept_second.clone();
        let permaura_com = fake(
            answer(move |_, seen| {
                if seen.token() == T2 && !accepting.load(Ordering::SeqCst) {
                    (503, None)
                } else {
                    (200, None)
                }
            }),
            None,
        )
        .await;
        let gateway = Gateway::new(Some(T1));
        tokio::spawn(run(gateway.sources(install()), Loopback::to(permaura_com.addr), fast()));
        settle().await;
        assert!(gateway.held.get().is_empty(), "nothing is linked, so permaura.com holds nothing");

        gateway.enrol(&["gw_one"]);
        until("the re-seal after enrolment", || permaura_com.count() == 1).await;
        settle().await;
        assert_eq!(gateway.held.get(), [T1]);

        gateway.console.set(Some(T2.into()));
        until("the refused first try", || permaura_com.seen().iter().any(|s| s.token() == T2)).await;
        settle().await;
        assert_eq!(gateway.held.get(), [T2, T1], "on its way, beside the one permaura.com acknowledged, newest first");

        accept_second.store(true, Ordering::SeqCst);
        until("the acknowledgement of the new one", || gateway.held.get() == [T2]).await;

        gateway.announcer.set(Vec::new());
        until("the unlink", || gateway.held.get().is_empty()).await;
    }

    /// A link permaura.com closes holds nothing to prove, while another link's session still is; with no install identity nothing is ever sent, so nothing is proved.
    #[tokio::test]
    async fn a_closed_link_or_an_unsent_session_leaves_nothing_to_prove() {
        let permaura_com =
            fake(answer(|_, seen| if seen.path.contains("gw_two") { (410, None) } else { (200, None) }), None).await;
        let gateway = Gateway::new(Some(T1));
        tokio::spawn(run(gateway.sources(install()), Loopback::to(permaura_com.addr), fast()));
        gateway.enrol(&["gw_two"]);
        until("the closing answer", || permaura_com.count() == 1).await;
        settle().await;
        assert!(gateway.held.get().is_empty(), "{:?}", gateway.held.get());
        gateway.enrol(&["gw_one", "gw_two"]);
        until("the open link", || permaura_com.to("gw_one").len() == 1).await;
        settle().await;
        assert_eq!(gateway.held.get(), [T1]);

        let anonymous = Gateway::new(Some(T1));
        tokio::spawn(run(anonymous.sources(None), Loopback::to(permaura_com.addr), fast()));
        anonymous.enrol(&["gw_three"]);
        settle().await;
        assert!(anonymous.held.get().is_empty(), "{:?}", anonymous.held.get());
    }

    /// End to end: the session the boot re-seal hands permaura.com is what `/health` proves in the console header, keyed exactly as the operator proof is, which still proves the operator token.
    #[tokio::test]
    async fn health_proves_the_console_session_permaura_com_was_handed() {
        use permaura_core::health_proof::{new_challenge, verify, CHALLENGE_HEADER, CONSOLE_PROOF_HEADER, PROOF_HEADER};
        use tower::ServiceExt as _;
        let permaura_com = fake(always(200), None).await;
        let state = loopback_only();
        state.service.set_announce(vec![link("gw_one")]);
        assert!(start(state.service.clone(), state.held_console_sessions.clone(), Box::new(install), Loopback::to(permaura_com.addr), fast(), None));
        until("the re-seal at boot", || permaura_com.count() == 1).await;
        let sealed = permaura_com.seen()[0].token().to_string();
        until("the acknowledgement", || state.held_console_sessions.get() == [sealed.clone()]).await;

        let challenge = new_challenge();
        let req = axum::http::Request::builder()
            .uri("/health")
            .header(CHALLENGE_HEADER, &challenge)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = crate::build_router(state.clone(), "127.0.0.1:7376".parse().unwrap()).oneshot(req).await.unwrap();
        let header = |name: &str| resp.headers().get(name).and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        let console = header(CONSOLE_PROOF_HEADER);
        assert!(verify(&sealed, 7376, &challenge, &console), "{console}");
        let operator = header(PROOF_HEADER);
        assert!(verify(crate::seed::DEMO_TOKEN, 7376, &challenge, &operator), "the operator proof is unchanged");
        assert!(!verify(&sealed, 7376, &challenge, &operator), "and is not keyed on the console session");
    }
}
