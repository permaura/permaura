//! The tunnel connector this process runs: the local configuration that pins it, the guard that keeps it pinned, and what `/health` says about it.
//!
//! The managed tunnel is locally managed. `permaura remote enable` stores the tunnel's credentials ([`CREDENTIALS_FILE`]), and `permaura start` writes [`CONFIG_FILE`] with one destination, the loopback address and port the gateway holds ([`origin_for`]), for the gateway's public hostname and a 404 for anything else, then runs `cloudflared tunnel --config <file> --management-diagnostics=false --no-autoupdate --label permaura run <tunnel id>` with no `TUNNEL_*` variables in its environment. A local file alone does not pin the connector: cloudflared applies any configuration Cloudflare pushes to it with a version above the -1 a local file runs at, and nothing on the connector withdraws that. Nor does it stop cloudflared carrying Cloudflare private-network (WARP) traffic, which it dials to whatever address the edge names. So the process that started it also reads, every half second, the configuration the connector reports it is running and its private-network counters, and stops the connector the moment either is not what this machine set up ([`config_violation`], [`private_network_traffic`], [`Watch`]).
//!
//! The bound: Permaura (permaura.com and its Cloudflare account) and Cloudflare can still see or redirect traffic for the gateway's permaura.app hostname, and run a second connector for the tunnel, because Permaura created it and Cloudflare terminates TLS. They cannot point this connector anywhere else on the machine without the gateway stopping it: its one destination, written here, is the loopback address and port the gateway holds, for that hostname. A pushed configuration, or private-network traffic Permaura's account routed to the tunnel, is stopped within about a second and reported in the log and `/health`; requests or connections in that second get through. A configuration put to the tunnel through Cloudflare's API does reach it: on 15 Oct 2026 the API accepted one for a locally managed tunnel, turned the tunnel remotely managed, and the connector applied it the next time it connected (`tests/cloudflared_live_capture.rs`). Delivery of private-network traffic is untested. The connector's logs and this machine's network address are visible to Permaura's Cloudflare account.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The tunnel's credentials under the Permaura home, in the shape cloudflared reads from a credentials file.
pub const CREDENTIALS_FILE: &str = "tunnel-credentials.json";

/// The connector's local configuration under the Permaura home, rewritten every time a connector starts.
pub const CONFIG_FILE: &str = "cloudflared.yml";

/// A remotely managed tunnel's run token, which older versions stored. Removed wherever the files above are written or remote access is turned off.
pub const LEGACY_TOKEN_FILE: &str = "tunnel.token";

/// A guard stop that evidences a push or private-network traffic ([`Stop::Evidence`]), recorded under the Permaura home so that a restart does not start the connector again without the operator: owner-only, holding the reason. `permaura remote enable` and `permaura remote disable` remove it.
pub const STOP_MARKER_FILE: &str = "tunnel.stopped";

/// The value `/health` reports while a connector this process started runs with the local pin.
pub const LOCAL: &str = "local";

/// The value `/health` reports once the guard has stopped the connector.
pub const STOPPED: &str = "stopped";

/// How often the guard reads the connector's running configuration.
pub const GUARD_INTERVAL: Duration = Duration::from_millis(500);

/// How long one of the guard's reads may take, so a poll and the wait for the next stay under a second.
pub const GUARD_REQUEST_TIMEOUT: Duration = Duration::from_millis(400);

/// How long the connector's metrics server may go unanswered before the guard stops the connector, provided [`UNANSWERED_POLLS`] polls in a row went unanswered too.
pub const UNANSWERED_LIMIT: Duration = Duration::from_secs(30);

/// Unanswered polls in a row needed beside [`UNANSWERED_LIMIT`], so the clock jumping while a laptop sleeps is not read as a dead connector.
pub const UNANSWERED_POLLS: u32 = 20;

/// The most a `/config` answer may be. The file this machine writes reports as about 2 KB, so a larger answer did not come from it, and reading all of it inside [`GUARD_REQUEST_TIMEOUT`] could fail and leave the push running unseen.
pub const MAX_CONFIG_BYTES: usize = 64 << 10;

/// The configuration version cloudflared reports while it runs its local file: anything pushed to it is applied with a higher one.
const LOCAL_VERSION: i64 = -1;

const CATCH_ALL: &str = "http_status:404";

/// The credentials file cloudflared reads (`connection.Credentials`, whose keys carry no JSON tags). `TunnelSecret` is a bearer for the tunnel, so this type has no `Debug` and nothing prints it.
#[derive(Clone, Deserialize, Serialize)]
pub struct Credentials {
    /// The Cloudflare account the tunnel belongs to.
    #[serde(rename = "AccountTag")]
    pub account_tag: String,
    /// Base64 of at least 32 bytes.
    #[serde(rename = "TunnelSecret")]
    pub tunnel_secret: String,
    /// The tunnel's UUID, which is also the argument to `run`.
    #[serde(rename = "TunnelID")]
    pub tunnel_id: String,
    /// The region the connector should use, empty for Cloudflare's default.
    #[serde(rename = "Endpoint", default, deserialize_with = "null_as_empty")]
    pub endpoint: String,
}

fn null_as_empty<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

impl Credentials {
    /// Read and check credentials, from permaura.com's answer or from the file. The error never quotes a value.
    pub fn from_value(value: Value) -> Result<Self, String> {
        let credentials: Self = serde_json::from_value(value)
            .map_err(|e| format!("they are not tunnel credentials ({e})"))?;
        credentials.check()?;
        Ok(credentials)
    }

    /// [`Credentials::from_value`] over a file's bytes.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, String> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|e| format!("they are not JSON ({e})"))?;
        Self::from_value(value)
    }

    fn check(&self) -> Result<(), String> {
        if self.account_tag.trim().is_empty() {
            return Err("the account tag is empty".into());
        }
        if !is_uuid(&self.tunnel_id) {
            return Err("the tunnel id is not a UUID".into());
        }
        // Standard alphabet with padding, which is how Go encodes the `[]byte` cloudflared reads it into.
        match STANDARD.decode(&self.tunnel_secret) {
            Ok(secret) if secret.len() >= 32 => Ok(()),
            Ok(_) => Err("the tunnel secret is shorter than 32 bytes".into()),
            Err(_) => Err("the tunnel secret is not base64".into()),
        }
    }

    /// The file's bytes. `Endpoint` is always present, empty when permaura.com named none.
    pub fn to_file_bytes(&self) -> Vec<u8> {
        serde_json::to_vec_pretty(self).expect("four strings always serialise")
    }
}

fn is_uuid(s: &str) -> bool {
    s.len() == 36
        && s.char_indices().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => c == '-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// What the connector is pinned to: the public host it answers for, the gateway origin it sends that host to, and the loopback port its metrics server (and so its running configuration) is read on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    /// The public hostname, from [`tunnel_hostname`].
    pub host: String,
    /// The connector's one destination, from [`origin_for`].
    pub origin: String,
    /// A free loopback port chosen when the connector starts.
    pub metrics_port: u16,
}

impl Pin {
    /// The connector's one destination, as cloudflared reports it back.
    pub fn service(&self) -> String {
        self.origin.clone()
    }
}

/// The origin the connector sends the public hostname to, for a gateway listening on `addr` (never port 0): the bound loopback address itself, `127.0.0.1` for `0.0.0.0` and `[::1]` for `[::]`, always a literal and never `localhost`, which macOS resolves to ::1 first. Any other bind is refused: the connector would dial a loopback port the gateway does not hold, which any local process could take while the configuration still read as written.
pub fn origin_for(addr: std::net::SocketAddr) -> Result<String, String> {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    if addr.port() == 0 {
        return Err(format!(
            "this gateway's address {addr} names no port, so Permaura did not start the tunnel connector: port 0 is whichever port the system picks, not one the connector can be pinned to"
        ));
    }
    let ip = match addr.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip if ip.is_loopback() => ip,
        _ => {
            return Err(format!(
                "this gateway listens on {addr}, which is not a loopback address, so Permaura did not start the tunnel connector: it would send the public hostname to a loopback port the gateway does not hold"
            ))
        }
    };
    Ok(format!(
        "http://{}",
        std::net::SocketAddr::new(ip, addr.port())
    ))
}

/// The hostname the connector answers for, from `public_url`'s host: lowercased, and only a plain DNS name of `[a-z0-9-]` labels. cloudflared reads a `*` in a hostname rule as a wildcard, and an IP literal is not a tunnel hostname, so either is refused rather than written.
pub fn tunnel_hostname(host: &str) -> Result<String, String> {
    let host = host.to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    let plain = !host.is_empty()
        && host.len() <= 253
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && l.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    let numeric = labels.iter().all(|l| l.bytes().all(|b| b.is_ascii_digit()));
    if plain && !numeric {
        Ok(host)
    } else {
        Err(format!(
            "{} is not a plain DNS hostname (letters, digits, hyphens and dots; no wildcard, no IP address), so Permaura did not start the tunnel connector for it",
            shown(&host)
        ))
    }
}

/// [`CONFIG_FILE`]'s contents. Every scalar is a JSON string, which YAML reads as the same string, so a path with spaces or backslashes needs no further quoting.
pub fn render_config(tunnel_id: &str, credentials_file: &str, pin: &Pin) -> String {
    let q = |s: &str| serde_json::to_string(s).expect("a string always serialises");
    format!(
        "tunnel: {}\ncredentials-file: {}\nmetrics: {}\ningress:\n  - hostname: {}\n    service: {}\n  - service: {}\n",
        q(tunnel_id),
        q(credentials_file),
        q(&format!("127.0.0.1:{}", pin.metrics_port)),
        q(&pin.host),
        q(&pin.service()),
        q(CATCH_ALL),
    )
}

/// Why the configuration the connector reports (`GET /config` on its metrics server: `{"version": N, "config": {"ingress": [{"hostname", "service", ...}], ...}}`) is not the one [`render_config`] wrote for `pin`, or `None` when it is.
pub fn config_violation(running: &Value, pin: &Pin) -> Option<String> {
    let rules = running.pointer("/config/ingress").and_then(Value::as_array);
    match running.get("version").and_then(Value::as_i64) {
        Some(LOCAL_VERSION) => rule_mismatch(rules, pin).map(|why| {
            format!("the tunnel connector is not running the configuration this machine wrote, so Permaura stopped it: {why}")
        }),
        version => {
            let version = version.map_or_else(|| "no version".to_string(), |v| format!("version {v}"));
            Some(format!(
                "Cloudflare pushed a different configuration to this tunnel, so Permaura stopped it: the connector reported {version} where the local file runs as {LOCAL_VERSION}, routing {}",
                describe(rules)
            ))
        }
    }
}

fn rule_mismatch(rules: Option<&Vec<Value>>, pin: &Pin) -> Option<String> {
    let Some(rules) = rules else {
        return Some("it reported no ingress rules".into());
    };
    if rules.len() != 2 {
        return Some(format!(
            "it has {} ingress rules, not 2, routing {}",
            rules.len(),
            describe(Some(rules))
        ));
    }
    let field = |rule: &Value, key: &str| {
        rule.get(key)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    };
    let (host, service, fallback) = (
        field(&rules[0], "hostname"),
        field(&rules[0], "service"),
        field(&rules[1], "service"),
    );
    if host != pin.host {
        return Some(format!(
            "its first rule answers for {}, not {}",
            shown(&host),
            pin.host
        ));
    }
    if service != pin.service() {
        return Some(format!(
            "it sends {} to {}, not {}",
            pin.host,
            shown(&service),
            pin.service()
        ));
    }
    if fallback != CATCH_ALL {
        return Some(format!(
            "it sends every other hostname to {}, not {CATCH_ALL}",
            shown(&fallback)
        ));
    }
    None
}

/// The rules as `host to service`, bounded: the text comes from whoever pushed the configuration.
fn describe(rules: Option<&Vec<Value>>) -> String {
    let Some(rules) = rules else {
        return "nothing".into();
    };
    let text = rules
        .iter()
        .map(|rule| {
            let host = rule
                .get("hostname")
                .and_then(Value::as_str)
                .filter(|h| !h.is_empty())
                .unwrap_or("every other hostname");
            let service = rule
                .get("service")
                .map(|s| s.as_str().map_or_else(|| s.to_string(), str::to_string))
                .unwrap_or_default();
            format!("{host} to {service}")
        })
        .collect::<Vec<_>>()
        .join(", ");
    shown(&text)
}

/// Pushed text as it goes into the log and `/health`: control, bidi and zero-width characters dropped, so it cannot forge log lines, terminal escapes or text that reads other than it is, and cut short.
fn shown(s: &str) -> String {
    const MAX: usize = 300;
    let hidden = |c: char| matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}');
    let s: String = s
        .chars()
        .filter(|&c| !c.is_control() && !hidden(c))
        .collect();
    if s.is_empty() {
        return "nothing".into();
    }
    match s.char_indices().nth(MAX) {
        Some((cut, _)) => format!("{}...", &s[..cut]),
        None => s,
    }
}

/// The counters cloudflared moves when it carries Cloudflare private-network (WARP) traffic, which it dials to whatever address the edge names, whatever the local ingress says. A tunnel that only carries HTTP to its one origin never moves them.
pub const PRIVATE_NETWORK_COUNTERS: [&str; 4] = [
    "cloudflared_tcp_total_sessions",
    "cloudflared_udp_total_sessions",
    "cloudflared_udp_total_flows",
    "cloudflared_icmp_total_requests",
];

/// What the connector's `GET /metrics` says about private-network traffic.
#[derive(Debug, PartialEq)]
pub enum PrivateNetwork {
    /// Every counter that appears is at zero.
    Quiet,
    /// At least one counter moved; the reason to stop the connector.
    Carried(String),
    /// None of [`PRIVATE_NETWORK_COUNTERS`] appears, which the guard counts as no answer.
    Unreported,
}

/// [`PrivateNetwork`] for a Prometheus text exposition: `name value` and `name{labels} value` lines, comments skipped, every label set of a name summed.
pub fn private_network_traffic(metrics: &str) -> PrivateNetwork {
    let mut totals = [None::<f64>; 4];
    for line in metrics.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, value)) = sample(line) else {
            continue;
        };
        if let Some(i) = PRIVATE_NETWORK_COUNTERS.iter().position(|c| *c == name) {
            *totals[i].get_or_insert(0.0) += value;
        }
    }
    if totals.iter().all(Option::is_none) {
        return PrivateNetwork::Unreported;
    }
    let moved: Vec<String> = PRIVATE_NETWORK_COUNTERS
        .iter()
        .zip(totals)
        .filter_map(|(name, total)| {
            total
                .filter(|v| v.is_nan() || *v > 0.0)
                .map(|v| format!("{name} {v}"))
        })
        .collect();
    if moved.is_empty() {
        PrivateNetwork::Quiet
    } else {
        PrivateNetwork::Carried(format!(
            "Cloudflare sent private-network traffic through this tunnel, which Permaura's tunnel never carries, so Permaura stopped it: {}",
            moved.join(", ")
        ))
    }
}

/// One sample line's metric name and value. Label values may hold spaces, braces and escaped quotes, so the label set is skipped by walking it.
fn sample(line: &str) -> Option<(&str, f64)> {
    let name_end = line.find(|c: char| c == '{' || c.is_whitespace())?;
    let name = &line[..name_end];
    let mut rest = &line[name_end..];
    if rest.starts_with('{') {
        let (mut quoted, mut escaped) = (false, false);
        let close = rest.char_indices().skip(1).find_map(|(i, c)| {
            match (quoted, escaped, c) {
                (true, true, _) => escaped = false,
                (true, false, '\\') => escaped = true,
                (true, false, '"') => quoted = false,
                (false, _, '"') => quoted = true,
                (false, _, '}') => return Some(i),
                _ => {}
            }
            None
        })?;
        rest = &rest[close + 1..];
    }
    let value = rest.split_whitespace().next()?;
    Some((name, value.parse().ok()?))
}

/// Why the guard stopped the connector.
#[derive(Debug, PartialEq)]
pub enum Stop {
    /// The connector ran something this machine did not set up: a pushed configuration, rules other than the ones written, or private-network traffic. Recorded in [`STOP_MARKER_FILE`], so a restart does not start it again.
    Evidence(String),
    /// Its metrics server stopped answering, which proves nothing was pushed. Reported in the log and `/health` only; the next start tries again.
    Unconfirmed(String),
}

impl Stop {
    /// The reason, for the log and `/health`.
    pub fn reason(&self) -> &str {
        match self {
            Stop::Evidence(why) | Stop::Unconfirmed(why) => why,
        }
    }
}

/// One tick's reads of the connector's metrics server, each `None` when it did not answer with a success (and, for `/config`, with JSON).
pub struct Reading {
    /// `GET /config`.
    pub config: Option<Value>,
    /// `GET /metrics`.
    pub metrics: Option<String>,
}

/// The guard's decision over successive reads, kept free of I/O and of the clock so it is tested without a cloudflared.
pub struct Watch {
    pin: Pin,
    config_unanswered: Option<(Instant, u32)>,
    metrics_unanswered: Option<(Instant, u32)>,
}

impl Watch {
    /// A watch over a connector just started for `pin`.
    pub fn new(pin: Pin) -> Self {
        Self {
            pin,
            config_unanswered: None,
            metrics_unanswered: None,
        }
    }

    /// Why to stop the connector after this tick's reads, or `None` to keep watching. Only called while the connector is alive.
    pub fn observe(&mut self, now: Instant, reading: Reading) -> Option<Stop> {
        let config_answered = match &reading.config {
            Some(running) => {
                if let Some(why) = config_violation(running, &self.pin) {
                    return Some(Stop::Evidence(why));
                }
                true
            }
            None => false,
        };
        let metrics_answered = match reading.metrics.as_deref().map(private_network_traffic) {
            Some(PrivateNetwork::Carried(why)) => return Some(Stop::Evidence(why)),
            Some(PrivateNetwork::Quiet) => true,
            Some(PrivateNetwork::Unreported) | None => false,
        };
        let metrics_port = self.pin.metrics_port;
        let overdue = |unanswered: &mut Option<(Instant, u32)>, answered: bool, what: &str| {
            if answered {
                *unanswered = None;
                return None;
            }
            let (first, polls) = unanswered.get_or_insert((now, 0));
            *polls += 1;
            (now.saturating_duration_since(*first) >= UNANSWERED_LIMIT && *polls >= UNANSWERED_POLLS).then(|| {
                Stop::Unconfirmed(format!(
                    "Permaura could not confirm the connector's configuration, so it stopped the tunnel: its metrics server on 127.0.0.1:{metrics_port} has not {what} for {} seconds and {} polls in a row",
                    UNANSWERED_LIMIT.as_secs(),
                    *polls
                ))
            })
        };
        overdue(
            &mut self.config_unanswered,
            config_answered,
            "answered /config",
        )
        .or_else(|| {
            overdue(
                &mut self.metrics_unanswered,
                metrics_answered,
                "reported cloudflared's private-network counters",
            )
        })
    }
}

enum State {
    Idle,
    Local,
    Stopped(String),
}

/// What this process knows about the connector it runs: one per process, read by the health document.
pub struct Connector(Mutex<State>);

impl Connector {
    /// No connector yet.
    pub const fn new() -> Self {
        Self(Mutex::new(State::Idle))
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> T) -> T {
        f(&mut self.0.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// A connector started with the local pin.
    pub fn note_local(&self) {
        self.with(|s| *s = State::Local);
    }

    /// The guard stopped the connector, for `reason`.
    pub fn note_stopped(&self, reason: &str) {
        self.with(|s| *s = State::Stopped(reason.to_string()));
    }

    /// The connector exited by itself. A stop the guard recorded stays recorded.
    pub fn note_gone(&self) {
        self.with(|s| {
            if matches!(s, State::Local) {
                *s = State::Idle;
            }
        });
    }

    /// [`LOCAL`] while a connector this process started runs with the local pin, [`STOPPED`] once the guard stopped it, `None` otherwise (no remote access, a bring-your-own tunnel, a hosted worker, a connector another process runs, or one that exited by itself).
    pub fn ingress(&self) -> Option<&'static str> {
        self.with(|s| match s {
            State::Idle => None,
            State::Local => Some(LOCAL),
            State::Stopped(_) => Some(STOPPED),
        })
    }

    /// Why the guard stopped the connector, once it has.
    pub fn stop_reason(&self) -> Option<String> {
        self.with(|s| match s {
            State::Stopped(reason) => Some(reason.clone()),
            _ => None,
        })
    }
}

impl Default for Connector {
    fn default() -> Self {
        Self::new()
    }
}

static CONNECTOR: Connector = Connector::new();

/// This process's connector.
pub fn connector() -> &'static Connector {
    &CONNECTOR
}

/// Write `reason` to `marker`, owner-only.
pub fn record_stop(marker: &std::path::Path, reason: &str) -> std::io::Result<()> {
    permaura_core::replace_secret_file(marker, reason.as_bytes())?;
    permaura_credential_store::restrict_to_owner(marker)
}

/// Why no connector may start while a stop is recorded at `marker`, or `None` when none is. A marker that exists but cannot be read still refuses.
pub fn recorded_stop(marker: &std::path::Path) -> Option<String> {
    if !marker.exists() {
        return None;
    }
    let reason = std::fs::read_to_string(marker)
        .map(|r| shown(r.trim()))
        .unwrap_or_else(|e| format!("a stop was recorded but cannot be read ({e})"));
    Some(format!(
        "{reason}. Permaura recorded this stop in {} and starts no tunnel connector until `permaura remote enable` or `permaura remote disable` clears it",
        marker.display()
    ))
}

/// Where the guard writes what it decides, and reads what the connector said.
pub struct Records {
    /// [`STOP_MARKER_FILE`] under the Permaura home.
    pub stop_marker: std::path::PathBuf,
    /// `cloudflared.log`, and its length when this connector was spawned, so only what this connector wrote is read.
    pub log: Option<(std::path::PathBuf, u64)>,
}

/// The line cloudflared logs when it applies a configuration pushed to it.
const APPLIED_PUSH: &str = "Updated to new configuration";

/// Why a connector that exited by itself is a stop rather than an exit: what it logged since it started shows it applied a pushed configuration first. The version is taken from the last such line.
pub fn pushed_before_exit(log_since_spawn: &str) -> Option<String> {
    let line = log_since_spawn
        .lines()
        .rev()
        .find(|l| l.contains(APPLIED_PUSH))?;
    let version = line
        .split_once("version=")
        .map(|(_, rest)| {
            rest.chars()
                .take_while(|c| c.is_ascii_digit() || *c == '-')
                .collect::<String>()
        })
        .filter(|v| !v.is_empty())
        .map(|v| format!(" (version {v})"))
        .unwrap_or_default();
    Some(format!(
        "Cloudflare pushed a different configuration to this tunnel, so Permaura stopped it: the connector exited after cloudflared.log recorded \"{APPLIED_PUSH}\"{version}"
    ))
}

/// What `path` gained after `start` bytes, at most the last mebibyte of it.
fn log_since(path: &std::path::Path, start: u64) -> Option<String> {
    use std::io::{Read as _, Seek as _};
    const TAIL: u64 = 1 << 20;
    let mut file = std::fs::File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    file.seek(std::io::SeekFrom::Start(
        start.max(len.saturating_sub(TAIL)).min(len),
    ))
    .ok()?;
    let mut bytes = Vec::new();
    file.take(TAIL).read_to_end(&mut bytes).ok()?;
    Some(String::from_utf8_lossy(&bytes).into_owned())
}

/// The child slot `permaura start` keeps its connector in, shared with the shutdown path that stops it with the gateway.
pub type ConnectorSlot = std::sync::Arc<Mutex<Option<std::process::Child>>>;

/// Keep the connector in `slot` on what was written for `pin`, or stop it.
///
/// Every [`GUARD_INTERVAL`] it reads `/config` and `/metrics` from the connector's metrics server with `client`, which must be loopback-only (no proxy, no redirects), and hands both to [`Watch`]. A stop kills the child, logs the reason and records it for `/health`; nothing here starts it again. The task ends when the gateway takes the child to stop it, when the connector exits by itself, or at a stop.
pub async fn guard(slot: ConnectorSlot, pin: Pin, client: reqwest::Client, records: Records) {
    let config_url = format!("http://127.0.0.1:{}/config", pin.metrics_port);
    let metrics_url = format!("http://127.0.0.1:{}/metrics", pin.metrics_port);
    let mut watch = Watch::new(pin);
    let mut tick = tokio::time::interval(GUARD_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        {
            let mut held = slot.lock().unwrap_or_else(|p| p.into_inner());
            let Some(child) = held.as_mut() else {
                return;
            };
            if let Ok(Some(status)) = child.try_wait() {
                held.take();
                drop(held);
                let pushed = records
                    .log
                    .as_ref()
                    .and_then(|(log, start)| log_since(log, *start))
                    .and_then(|text| pushed_before_exit(&text));
                if let Some(reason) = pushed {
                    record(&Stop::Evidence(reason), &records.stop_marker);
                    return;
                }
                connector().note_gone();
                tracing::warn!(
                    "remote access: the tunnel connector exited by itself ({status}); see cloudflared.log. Remote access is down until the gateway restarts"
                );
                return;
            }
        }
        let (config, metrics) = tokio::join!(
            fetch_capped(&client, &config_url, MAX_CONFIG_BYTES),
            async {
                match client.get(&metrics_url).send().await {
                    Ok(resp) if resp.status().is_success() => resp.text().await.ok(),
                    _ => None,
                }
            },
        );
        let config = match config {
            Fetched::Body(body) => serde_json::from_slice::<Value>(&body).ok(),
            Fetched::TooLarge => {
                stop_connector(&slot, &Stop::Evidence(oversize_config()), &records.stop_marker);
                return;
            }
            Fetched::Nothing => None,
        };
        if let Some(stop) = watch.observe(Instant::now(), Reading { config, metrics }) {
            stop_connector(&slot, &stop, &records.stop_marker);
            return;
        }
    }
}

/// What one capped read of the connector's metrics server came to.
#[derive(Debug, PartialEq, Eq)]
enum Fetched {
    /// A success, and its whole body.
    Body(Vec<u8>),
    /// A success whose body runs past the limit, declared or read.
    TooLarge,
    /// Anything else, including no answer in time.
    Nothing,
}

/// `GET url`, reading at most `limit` bytes of a successful body and stopping as soon as it is past them.
async fn fetch_capped(client: &reqwest::Client, url: &str, limit: usize) -> Fetched {
    let mut resp = match client.get(url).send().await {
        Ok(resp) if resp.status().is_success() => resp,
        _ => return Fetched::Nothing,
    };
    if resp.content_length().is_some_and(|len| len > limit as u64) {
        return Fetched::TooLarge;
    }
    let mut body = Vec::new();
    loop {
        match resp.chunk().await {
            Ok(Some(chunk)) => {
                body.extend_from_slice(&chunk);
                if body.len() > limit {
                    return Fetched::TooLarge;
                }
            }
            Ok(None) => return Fetched::Body(body),
            Err(_) => return Fetched::Nothing,
        }
    }
}

fn oversize_config() -> String {
    format!(
        "Cloudflare pushed a different configuration to this tunnel, so Permaura stopped it: the connector reported a configuration of more than {} KiB, where the file this machine wrote is about 2 KB",
        MAX_CONFIG_BYTES >> 10
    )
}

/// Kill the connector in `slot` and say why, recording a [`Stop::Evidence`] at `stop_marker` so a restart keeps it stopped. Run even over a poisoned lock: a connector left running is the outcome this exists to prevent.
pub fn stop_connector(
    slot: &Mutex<Option<std::process::Child>>,
    stop: &Stop,
    stop_marker: &std::path::Path,
) {
    let child = slot.lock().unwrap_or_else(|p| p.into_inner()).take();
    let Some(mut child) = child else {
        return;
    };
    let _ = child.kill();
    let _ = child.wait();
    record(stop, stop_marker);
}

/// Why `/health` reports a connector stopped by `permaura remote disable`.
pub const TURNED_OFF: &str = "remote access was turned off on this machine (`permaura remote disable`)";

/// How long [`turn_off`] waits for a killed connector to exit before reporting it still running.
pub const TURN_OFF_WITHIN: Duration = Duration::from_secs(5);

/// What [`turn_off`] found and did.
#[derive(Debug, PartialEq, Eq)]
pub enum TurnedOff {
    /// This process runs no connector.
    Nothing,
    /// The connector with this pid was killed and has exited.
    Stopped(u32),
    /// The connector with this pid is still running, for the reason given.
    StillRunning(u32, String),
    /// The stop did not finish, so whether the connector runs is not known; reported as still running.
    Unknown(String),
}

/// Kill the connector in `slot` for `permaura remote disable` and confirm it exited, reporting it stopped in `/health`. One that will not go stays in the slot, so the guard and the gateway's own stop still hold it. Blocks for up to `within`: run it off the async runtime.
pub fn turn_off(slot: &Mutex<Option<std::process::Child>>, within: Duration) -> TurnedOff {
    turn_off_with(slot, within, |child| child.kill())
}

fn turn_off_with(
    slot: &Mutex<Option<std::process::Child>>,
    within: Duration,
    kill: impl FnOnce(&mut std::process::Child) -> std::io::Result<()>,
) -> TurnedOff {
    let mut held = slot.lock().unwrap_or_else(|p| p.into_inner());
    let Some(child) = held.as_mut() else {
        return TurnedOff::Nothing;
    };
    let pid = child.id();
    let signalled = match child.try_wait() {
        Ok(Some(_)) => Ok(()),
        _ => kill(child),
    };
    let deadline = Instant::now() + within;
    let exited = loop {
        if matches!(child.try_wait(), Ok(Some(_))) {
            break true;
        }
        if signalled.is_err() || Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    if exited {
        held.take();
        connector().note_stopped(TURNED_OFF);
        tracing::warn!("remote access: {TURNED_OFF}; the tunnel connector (pid {pid}) has exited");
        return TurnedOff::Stopped(pid);
    }
    let why = match signalled {
        Err(e) => format!("it could not be signalled ({e})"),
        Ok(()) => format!("it had not exited {} seconds after SIGKILL", within.as_secs()),
    };
    tracing::error!("remote access: the tunnel connector (pid {pid}) was asked to stop for `permaura remote disable`, but {why}");
    TurnedOff::StillRunning(pid, why)
}

/// Report a stop in `/health` and the log, and an [`Stop::Evidence`] one in the marker too.
fn record(stop: &Stop, stop_marker: &std::path::Path) {
    let reason = stop.reason();
    connector().note_stopped(reason);
    let Stop::Evidence(_) = stop else {
        tracing::error!(
            "remote access: {reason}. Remote access stays off until the gateway restarts."
        );
        return;
    };
    if let Err(e) = record_stop(stop_marker, reason) {
        tracing::error!(
            "remote access: could not record the stop in {}: {e}",
            stop_marker.display()
        );
    }
    tracing::error!("remote access: {reason}. Remote access stays off, across restarts, until `permaura remote enable` or `permaura remote disable`.");
}

/// The log line printed beside the connector's start, so the bound is in the gateway log as well as in `/health`.
pub const STARTED_NOTE: &str = "remote access: the tunnel connector is pinned on this machine to one destination, the loopback address and port this gateway holds, for the public hostname alone. Permaura and Cloudflare can still see or redirect traffic for that hostname and can run a second connector for the tunnel; if a configuration is pushed to this connector or private-network traffic is routed through it, the gateway stops it within about a second and says so here and in /health, and what arrives in that second gets through. A configuration put to the tunnel through Cloudflare's API reaches the connector the next time it connects. The connector's logs and this machine's network address are visible to Permaura's Cloudflare account";

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    const TUNNEL_ID: &str = "6ff42ae2-765d-4adf-8112-31c55c1551ef";

    fn pin() -> Pin {
        Pin {
            host: "studio-mini.permaura.app".into(),
            origin: "http://127.0.0.1:7376".into(),
            metrics_port: 49152,
        }
    }

    fn secret(len: usize) -> String {
        STANDARD.encode(vec![7u8; len])
    }

    /// What cloudflared's `GET /config` (`GetVersionedConfigJSON`) returns for the file [`render_config`] writes: each rule is `{hostname, path, service, originRequest}`, an HTTP service marshals as its URL string and the catch-all as `http_status:404`.
    const PINNED: &str = r#"{"version":-1,"config":{"ingress":[
        {"hostname":"studio-mini.permaura.app","path":null,"service":"http://127.0.0.1:7376","originRequest":{"connectTimeout":30,"noTLSVerify":false,"proxyAddress":"127.0.0.1","proxyPort":0,"proxyType":"","ipRules":null,"http2Origin":false}},
        {"hostname":"","path":null,"service":"http_status:404","originRequest":{"connectTimeout":30,"noTLSVerify":false,"proxyAddress":"127.0.0.1","proxyPort":0,"proxyType":"","ipRules":null,"http2Origin":false}}],
        "warp-routing":{"connectTimeout":5,"tcpKeepAlive":30},"originRequest":{"connectTimeout":30}}}"#;

    fn pinned() -> Value {
        serde_json::from_str(PINNED).unwrap()
    }

    fn with(edit: impl FnOnce(&mut Value)) -> Value {
        let mut running = pinned();
        edit(&mut running);
        running
    }

    #[test]
    fn the_local_file_running_as_written_passes() {
        assert_eq!(config_violation(&pinned(), &pin()), None);
    }

    #[test]
    fn any_pushed_version_is_a_violation_even_with_the_same_rules() {
        for version in [0, 1, 7] {
            let why = config_violation(&with(|r| r["version"] = json!(version)), &pin())
                .expect("a pushed version is stopped");
            assert!(why.starts_with("Cloudflare pushed a different configuration to this tunnel, so Permaura stopped it"), "{why}");
            assert!(
                why.contains(&format!("version {version}"))
                    && why.contains("studio-mini.permaura.app to http://127.0.0.1:7376"),
                "{why}"
            );
        }
        let unversioned = with(|r| {
            r.as_object_mut().unwrap().remove("version");
        });
        let why = config_violation(&unversioned, &pin()).unwrap();
        assert!(why.contains("no version"), "{why}");
    }

    #[test]
    fn a_pushed_destination_is_named_in_the_reason() {
        let running = with(|r| {
            r["version"] = json!(3);
            r["config"]["ingress"][0]["service"] = json!("tcp://127.0.0.1:22");
        });
        let why = config_violation(&running, &pin()).unwrap();
        assert!(
            why.contains("version 3")
                && why.contains("studio-mini.permaura.app to tcp://127.0.0.1:22"),
            "{why}"
        );
    }

    #[test]
    fn every_other_destination_fails_even_at_the_local_version() {
        for service in [
            "http://127.0.0.1:22",
            "tcp://127.0.0.1:7376",
            "http://192.168.1.20:7376",
            "http://localhost:7376",
            "https://127.0.0.1:7376",
            "ssh://127.0.0.1:22",
        ] {
            let why = config_violation(
                &with(|r| r["config"]["ingress"][0]["service"] = json!(service)),
                &pin(),
            )
            .unwrap_or_else(|| panic!("{service} must fail"));
            assert!(
                why.contains(service) && why.contains("not http://127.0.0.1:7376"),
                "{why}"
            );
        }
    }

    #[test]
    fn the_wrong_hostname_fails() {
        let why = config_violation(
            &with(|r| r["config"]["ingress"][0]["hostname"] = json!("other.permaura.app")),
            &pin(),
        )
        .unwrap();
        assert!(why.contains("answers for other.permaura.app"), "{why}");
        let why = config_violation(
            &with(|r| r["config"]["ingress"][0]["hostname"] = json!("")),
            &pin(),
        )
        .unwrap();
        assert!(
            why.contains("answers for nothing"),
            "a catch-all first rule is not ours: {why}"
        );
    }

    #[test]
    fn an_extra_rule_fails() {
        let running = with(|r| {
            let rules = r["config"]["ingress"].as_array_mut().unwrap();
            rules.insert(1, json!({"hostname":"ssh.permaura.app","path":null,"service":"ssh://127.0.0.1:22","originRequest":{}}));
        });
        let why = config_violation(&running, &pin()).unwrap();
        assert!(
            why.contains("3 ingress rules")
                && why.contains("ssh.permaura.app to ssh://127.0.0.1:22"),
            "{why}"
        );
    }

    #[test]
    fn a_missing_or_wrong_catch_all_fails() {
        let one_rule = with(|r| {
            r["config"]["ingress"].as_array_mut().unwrap().pop();
        });
        assert!(config_violation(&one_rule, &pin())
            .unwrap()
            .contains("1 ingress rules"));
        let open = with(|r| r["config"]["ingress"][1]["service"] = json!("http://127.0.0.1:7376"));
        let why = config_violation(&open, &pin()).unwrap();
        assert!(
            why.contains("every other hostname to http://127.0.0.1:7376"),
            "{why}"
        );
        let no_ingress = with(|r| r["config"] = json!({}));
        assert!(config_violation(&no_ingress, &pin())
            .unwrap()
            .contains("no ingress rules"));
    }

    #[test]
    fn a_huge_pushed_value_is_cut_short_in_the_reason() {
        let long = format!("http://{}.example:1", "a".repeat(5000));
        let why = config_violation(
            &with(|r| r["config"]["ingress"][0]["service"] = json!(long)),
            &pin(),
        )
        .unwrap();
        assert!(why.len() < 1000, "{}", why.len());
    }

    /// A metrics answer shaped like cloudflared's `/metrics`: the four counters at zero, one of them with a label set per connection, beside counters an HTTP-only tunnel does move.
    const QUIET_METRICS: &str = "\
# HELP cloudflared_tcp_total_sessions Total number of TCP sessions that have been proxied to any origin
# TYPE cloudflared_tcp_total_sessions counter
cloudflared_tcp_total_sessions 0
# HELP cloudflared_tcp_active_sessions Concurrent count of TCP sessions that are being proxied to any origin
# TYPE cloudflared_tcp_active_sessions gauge
cloudflared_tcp_active_sessions 0
# HELP cloudflared_udp_total_sessions Total count of UDP sessions that have been proxied to any origin
# TYPE cloudflared_udp_total_sessions counter
cloudflared_udp_total_sessions 0
# HELP cloudflared_udp_total_flows Total count of flows that have been proxied to any origin
# TYPE cloudflared_udp_total_flows counter
cloudflared_udp_total_flows{conn_index=\"0\"} 0
cloudflared_udp_total_flows{conn_index=\"1\"} 0
# HELP cloudflared_icmp_total_requests Total count of ICMP requests that have been proxied to any origin
# TYPE cloudflared_icmp_total_requests counter
cloudflared_icmp_total_requests 0
# HELP cloudflared_tunnel_total_requests Amount of requests proxied through all the tunnels
# TYPE cloudflared_tunnel_total_requests counter
cloudflared_tunnel_total_requests 4182
cloudflared_tunnel_response_by_code{status_code=\"200\"} 4180
";

    fn quiet() -> Reading {
        Reading {
            config: Some(pinned()),
            metrics: Some(QUIET_METRICS.to_string()),
        }
    }

    #[test]
    fn all_four_counters_at_zero_pass_whatever_http_traffic_the_tunnel_carried() {
        assert_eq!(
            private_network_traffic(QUIET_METRICS),
            PrivateNetwork::Quiet
        );
    }

    #[test]
    fn each_counter_above_zero_stops_the_connector() {
        for (zero, moved) in [
            (
                "cloudflared_tcp_total_sessions 0",
                "cloudflared_tcp_total_sessions 1",
            ),
            (
                "cloudflared_udp_total_sessions 0",
                "cloudflared_udp_total_sessions 1",
            ),
            (
                "cloudflared_udp_total_flows{conn_index=\"1\"} 0",
                "cloudflared_udp_total_flows{conn_index=\"1\"} 1",
            ),
            (
                "cloudflared_icmp_total_requests 0",
                "cloudflared_icmp_total_requests 1",
            ),
        ] {
            let metrics = QUIET_METRICS.replace(zero, moved);
            assert_ne!(metrics, QUIET_METRICS, "{moved}");
            let PrivateNetwork::Carried(why) = private_network_traffic(&metrics) else {
                panic!("{moved} must stop the connector");
            };
            let name = moved.split(['{', ' ']).next().unwrap();
            assert!(why.starts_with("Cloudflare sent private-network traffic through this tunnel, which Permaura's tunnel never carries, so Permaura stopped it: "), "{why}");
            assert!(why.ends_with(&format!("{name} 1")), "{why}");
        }
    }

    #[test]
    fn labeled_series_are_summed_and_label_values_cannot_hide_a_sample() {
        let metrics = "cloudflared_udp_total_flows{conn_index=\"0\"} 2\ncloudflared_udp_total_flows{conn_index=\"1\",note=\"a } b \\\"c\\\" 9\"} 3 1700000000000\n";
        let PrivateNetwork::Carried(why) = private_network_traffic(metrics) else {
            panic!("a moved flow counter stops the connector");
        };
        assert!(why.ends_with("cloudflared_udp_total_flows 5"), "{why}");
        assert!(
            matches!(
                private_network_traffic("cloudflared_tcp_total_sessions NaN\n"),
                PrivateNetwork::Carried(_)
            ),
            "a NaN is not a zero"
        );
    }

    #[test]
    fn an_answer_naming_none_of_the_four_is_unreported() {
        assert_eq!(private_network_traffic(""), PrivateNetwork::Unreported);
        let renamed = QUIET_METRICS
            .lines()
            .filter(|l| l.starts_with('#') || l.starts_with("cloudflared_tunnel"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            renamed.contains("cloudflared_tcp_total_sessions"),
            "the names still appear in comments"
        );
        assert_eq!(
            private_network_traffic(&renamed),
            PrivateNetwork::Unreported
        );
        assert_eq!(
            private_network_traffic("cloudflared_tcp_total_sessions_created 1\n"),
            PrivateNetwork::Unreported
        );
    }

    /// Feed `watch` one reading per [`GUARD_INTERVAL`] from `start`, and say at which poll (counting from 1) it stopped the connector, with the reason.
    fn polls(
        watch: &mut Watch,
        start: Instant,
        count: u32,
        reading: impl Fn() -> Reading,
    ) -> Option<(u32, String)> {
        (1..=count).find_map(|n| {
            watch
                .observe(start + GUARD_INTERVAL * (n - 1), reading())
                .map(|stop| {
                    assert!(
                        matches!(stop, Stop::Unconfirmed(_)),
                        "an unanswered metrics server is no evidence: {stop:?}"
                    );
                    (n, stop.reason().to_string())
                })
        })
    }

    fn no_config() -> Reading {
        Reading {
            config: None,
            metrics: Some(QUIET_METRICS.to_string()),
        }
    }

    #[test]
    fn thirty_seconds_of_unanswered_polls_stops_and_an_answer_resets_the_count() {
        let t0 = Instant::now();
        let mut watch = Watch::new(pin());
        assert_eq!(
            polls(&mut watch, t0, 60, no_config),
            None,
            "60 polls span 29.5 s"
        );
        assert_eq!(
            watch.observe(t0 + Duration::from_millis(30_000), quiet()),
            None,
            "an answer resets"
        );
        let (n, why) = polls(
            &mut watch,
            t0 + Duration::from_millis(30_500),
            100,
            no_config,
        )
        .expect("30 s unanswered stops the connector");
        assert_eq!(
            n, 61,
            "the 61st unanswered poll is the first 30 s after the first"
        );
        assert!(
            why.contains("could not confirm the connector's configuration")
                && why.contains("127.0.0.1:49152")
                && why.contains("/config"),
            "{why}"
        );
    }

    /// A laptop that sleeps between two polls wakes to a clock 30 s or more ahead: that alone is not a dead connector, only 20 polls in a row without an answer are.
    #[test]
    fn a_jump_in_the_clock_needs_twenty_polls_in_a_row_as_well() {
        let t0 = Instant::now();
        let mut watch = Watch::new(pin());
        assert_eq!(watch.observe(t0, no_config()), None);
        let woke = t0 + Duration::from_secs(3600);
        let (n, _) = polls(&mut watch, woke, 40, no_config)
            .expect("a connector that stays silent is still stopped");
        assert_eq!(
            n,
            UNANSWERED_POLLS - 1,
            "the 20th unanswered poll in a row, counting the one before the sleep"
        );

        let mut watch = Watch::new(pin());
        assert_eq!(watch.observe(t0, no_config()), None);
        assert_eq!(watch.observe(woke, no_config()), None);
        assert_eq!(
            watch.observe(woke + GUARD_INTERVAL, quiet()),
            None,
            "an answer after waking keeps it"
        );
        assert_eq!(
            polls(&mut watch, woke + GUARD_INTERVAL * 2, 59, no_config),
            None
        );
    }

    #[test]
    fn thirty_seconds_without_the_counters_stops_even_while_the_configuration_answers() {
        let t0 = Instant::now();
        let renamed = || Reading {
            config: Some(pinned()),
            metrics: Some("cloudflared_tunnel_total_requests 3\n".into()),
        };
        let silent = || Reading {
            config: Some(pinned()),
            metrics: None,
        };
        let mut watch = Watch::new(pin());
        assert_eq!(polls(&mut watch, t0, 30, renamed), None);
        let (n, why) = polls(&mut watch, t0 + GUARD_INTERVAL * 30, 40, silent)
            .expect("30 s without the counters stops the connector");
        assert_eq!(n, 31);
        assert!(
            why.contains("could not confirm the connector's configuration")
                && why.contains("private-network counters"),
            "{why}"
        );
    }

    #[test]
    fn the_watch_stops_on_the_first_pushed_answer_or_the_first_private_network_flow() {
        let t0 = Instant::now();
        let mut watch = Watch::new(pin());
        assert_eq!(watch.observe(t0, quiet()), None);
        let pushed = Reading {
            config: Some(with(|r| r["version"] = json!(0))),
            metrics: Some(QUIET_METRICS.into()),
        };
        let stop = watch.observe(t0 + GUARD_INTERVAL, pushed).unwrap();
        assert!(
            matches!(&stop, Stop::Evidence(why) if why.starts_with("Cloudflare pushed")),
            "{stop:?}"
        );

        let mut watch = Watch::new(pin());
        let routed = Reading {
            config: Some(pinned()),
            metrics: Some(QUIET_METRICS.replace(
                "cloudflared_tcp_total_sessions 0",
                "cloudflared_tcp_total_sessions 1",
            )),
        };
        let stop = watch.observe(t0, routed).unwrap();
        assert!(
            matches!(&stop, Stop::Evidence(why) if why.starts_with("Cloudflare sent private-network traffic")),
            "{stop:?}"
        );
    }

    #[test]
    fn the_config_file_is_exactly_the_contract() {
        let yaml = render_config(
            TUNNEL_ID,
            "/home/op/.permaura/tunnel-credentials.json",
            &pin(),
        );
        assert_eq!(
            yaml,
            "tunnel: \"6ff42ae2-765d-4adf-8112-31c55c1551ef\"\n\
             credentials-file: \"/home/op/.permaura/tunnel-credentials.json\"\n\
             metrics: \"127.0.0.1:49152\"\n\
             ingress:\n  \
             - hostname: \"studio-mini.permaura.app\"\n    \
             service: \"http://127.0.0.1:7376\"\n  \
             - service: \"http_status:404\"\n"
        );
    }

    #[test]
    fn a_windows_path_with_spaces_and_backslashes_reads_back_unchanged() {
        let path = r"C:\Users\Ada Lovelace\.permaura\tunnel-credentials.json";
        let yaml = render_config(TUNNEL_ID, path, &pin());
        let parsed: serde_yaml::Value = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed["credentials-file"].as_str(), Some(path));
        assert_eq!(parsed["tunnel"].as_str(), Some(TUNNEL_ID));
        assert_eq!(
            parsed["ingress"][0]["service"].as_str(),
            Some("http://127.0.0.1:7376")
        );
        assert_eq!(
            parsed["ingress"][1]["service"].as_str(),
            Some("http_status:404")
        );
        assert!(parsed["ingress"][1].get("hostname").is_none());
    }

    #[test]
    fn credentials_are_checked_and_written_in_cloudflareds_shape() {
        let good = json!({"AccountTag": "acct", "TunnelSecret": secret(32), "TunnelID": TUNNEL_ID});
        let c = Credentials::from_value(good.clone()).unwrap();
        let file: Value = serde_json::from_slice(&c.to_file_bytes()).unwrap();
        assert_eq!(
            file,
            json!({"AccountTag": "acct", "TunnelSecret": secret(32), "TunnelID": TUNNEL_ID, "Endpoint": ""})
        );
        let with_endpoint = json!({"AccountTag": "acct", "TunnelSecret": secret(32), "TunnelID": TUNNEL_ID, "Endpoint": "fed"});
        assert_eq!(
            Credentials::from_value(with_endpoint).unwrap().endpoint,
            "fed"
        );
        let null_endpoint = json!({"AccountTag": "acct", "TunnelSecret": secret(32), "TunnelID": TUNNEL_ID, "Endpoint": null});
        assert_eq!(Credentials::from_value(null_endpoint).unwrap().endpoint, "");
        assert!(
            Credentials::from_slice(&c.to_file_bytes()).is_ok(),
            "the file reads back"
        );
    }

    #[test]
    fn malformed_credentials_are_refused_without_quoting_them() {
        let refused = |v: Value| Credentials::from_value(v).err().expect("refused");
        let short = secret(31);
        let why =
            refused(json!({"AccountTag": "acct", "TunnelSecret": short, "TunnelID": TUNNEL_ID}));
        assert!(
            why.contains("shorter than 32 bytes") && !why.contains(&short),
            "{why}"
        );
        let url_safe = STANDARD
            .encode([0xfbu8; 33])
            .replace('+', "-")
            .replace('/', "_");
        assert!(refused(
            json!({"AccountTag": "acct", "TunnelSecret": url_safe, "TunnelID": TUNNEL_ID})
        )
        .contains("not base64"));
        assert!(refused(
            json!({"AccountTag": "acct", "TunnelSecret": "not base64!", "TunnelID": TUNNEL_ID})
        )
        .contains("not base64"));
        assert!(refused(
            json!({"AccountTag": " ", "TunnelSecret": secret(32), "TunnelID": TUNNEL_ID})
        )
        .contains("account tag"));
        for id in [
            "",
            "6ff42ae2765d4adf811231c55c1551ef",
            "6ff42ae2-765d-4adf-8112-31c55c1551eg",
            "../../etc/passwd",
        ] {
            assert!(
                refused(json!({"AccountTag": "acct", "TunnelSecret": secret(32), "TunnelID": id}))
                    .contains("not a UUID"),
                "{id}"
            );
        }
        assert!(
            refused(json!({"TunnelSecret": secret(32), "TunnelID": TUNNEL_ID}))
                .contains("not tunnel credentials")
        );
        assert!(Credentials::from_slice(b"eyJhIjoi")
            .err()
            .unwrap()
            .contains("not JSON"));
    }

    #[test]
    fn the_health_state_is_local_then_stopped_with_its_reason_and_a_stop_outlives_the_exit() {
        let c = Connector::new();
        assert_eq!((c.ingress(), c.stop_reason()), (None, None));
        c.note_local();
        assert_eq!((c.ingress(), c.stop_reason()), (Some("local"), None));
        c.note_gone();
        assert_eq!(
            c.ingress(),
            None,
            "a connector that exited by itself no longer runs"
        );
        c.note_local();
        c.note_stopped(
            "Cloudflare pushed a different configuration to this tunnel, so Permaura stopped it: x",
        );
        assert_eq!(c.ingress(), Some(STOPPED));
        c.note_gone();
        assert_eq!(c.ingress(), Some("stopped"));
        assert!(c.stop_reason().unwrap().starts_with("Cloudflare pushed"));
    }

    /// The origin is the address the gateway holds, so no other local process can take the port the connector dials.
    #[test]
    fn the_origin_is_the_bound_loopback_address_and_any_other_bind_is_refused() {
        let origin = |a: &str| origin_for(a.parse().unwrap());
        assert_eq!(
            origin("127.0.0.1:7376").as_deref(),
            Ok("http://127.0.0.1:7376")
        );
        assert_eq!(
            origin("127.0.0.2:7377").as_deref(),
            Ok("http://127.0.0.2:7377")
        );
        assert_eq!(
            origin("0.0.0.0:7376").as_deref(),
            Ok("http://127.0.0.1:7376")
        );
        assert_eq!(origin("[::1]:7376").as_deref(), Ok("http://[::1]:7376"));
        assert_eq!(origin("[::]:7376").as_deref(), Ok("http://[::1]:7376"));
        for refused in [
            "192.168.1.20:7376",
            "100.101.102.103:7376",
            "[fd7a:115c:a1e0::1]:7376",
            "[::ffff:127.0.0.1]:7376",
        ] {
            let why = origin(refused).expect_err(refused);
            assert!(
                why.contains("not a loopback address") && why.contains(refused),
                "{why}"
            );
        }
        for no_port in ["127.0.0.1:0", "0.0.0.0:0", "[::1]:0", "[::]:0"] {
            let why = origin(no_port).expect_err(no_port);
            assert!(
                why.contains("names no port") && why.contains(no_port),
                "{why}"
            );
        }

        let v6 = Pin {
            origin: origin("[::1]:7376").unwrap(),
            ..pin()
        };
        assert!(render_config(TUNNEL_ID, "/c.json", &v6).contains("service: \"http://[::1]:7376\""));
        let running = with(|r| r["config"]["ingress"][0]["service"] = json!("http://[::1]:7376"));
        assert_eq!(
            config_violation(&running, &v6),
            None,
            "the guard compares against the same string"
        );
        let why = config_violation(&pinned(), &v6)
            .expect("127.0.0.1 is not the origin this gateway holds");
        assert!(why.contains("not http://[::1]:7376"), "{why}");
    }

    /// The host is lowercased, and a wildcard, an IP literal or anything else that is not a plain DNS name is refused.
    #[test]
    fn only_a_plain_dns_hostname_is_written_into_the_config() {
        assert_eq!(
            tunnel_hostname("Studio-Mini.Permaura.App").as_deref(),
            Ok("studio-mini.permaura.app")
        );
        assert_eq!(
            tunnel_hostname("a-1.permaura.app").as_deref(),
            Ok("a-1.permaura.app")
        );
        for refused in [
            "*.permaura.app",
            "*",
            "[::1]",
            "::1",
            "127.0.0.1",
            "10.0.0.7",
            "",
            "a..permaura.app",
            "a.permaura.app.",
            "studio_mini.permaura.app",
            "st\u{fc}dio.permaura.app",
            "a b.permaura.app",
        ] {
            let why = tunnel_hostname(refused).expect_err(refused);
            assert!(why.contains("not a plain DNS hostname"), "{why}");
        }
        assert!(
            tunnel_hostname(&format!("{}.app", "a".repeat(64))).is_err(),
            "a label is at most 63 characters"
        );
        assert!(
            tunnel_hostname(&format!("{}.app", "a.".repeat(126))).is_err(),
            "a name is at most 253 characters"
        );
    }

    /// A pushed value cannot carry a newline, an escape sequence or any other control character into the log or `/health`.
    #[test]
    fn control_characters_in_pushed_values_never_reach_the_reason() {
        let forged = "http://127.0.0.1:22\n2026-10-15T00:00:00Z INF all clear\u{1b}[2J\r\u{7}";
        for running in [
            with(|r| r["config"]["ingress"][0]["service"] = json!(forged)),
            with(|r| {
                r["version"] = json!(2);
                r["config"]["ingress"][0]["hostname"] = json!(forged);
            }),
        ] {
            let why = config_violation(&running, &pin()).unwrap();
            assert!(!why.chars().any(char::is_control), "{why:?}");
            assert!(
                why.contains("http://127.0.0.1:222026-10-15T00:00:00Z INF all clear[2J"),
                "{why:?}"
            );
        }
    }

    /// Bidi overrides, isolates and zero-width characters in a pushed value are dropped like control characters.
    #[test]
    fn bidi_and_zero_width_characters_in_pushed_values_never_reach_the_reason() {
        let hidden =
            "http://127.0.0.1:2\u{200B}2\u{200F}\u{202E}evil\u{202C}\u{2066}x\u{2069}\u{FEFF}";
        let why = config_violation(
            &with(|r| r["config"]["ingress"][0]["service"] = json!(hidden)),
            &pin(),
        )
        .unwrap();
        assert!(why.contains("http://127.0.0.1:22evilx"), "{why:?}");
        for c in [
            '\u{200B}', '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202E}',
            '\u{2066}', '\u{2069}', '\u{FEFF}',
        ] {
            assert!(!why.contains(c), "{c:?} in {why:?}");
        }
    }

    /// Only a stop that evidences a push or private-network traffic is recorded; a metrics server that went quiet is reported and the next start tries again.
    #[cfg(unix)]
    #[tokio::test]
    async fn only_a_stop_with_evidence_is_recorded_across_restarts() {
        let _turn = STOPPING.lock().await;
        let home = scratch_home("evidence");
        let marker = home.join(STOP_MARKER_FILE);
        let child = || {
            std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap()
        };

        let quiet = Mutex::new(Some(child()));
        stop_connector(&quiet, &Stop::Unconfirmed("Permaura could not confirm the connector's configuration, so it stopped the tunnel: x".into()), &marker);
        assert!(
            quiet.lock().unwrap().is_none(),
            "the connector is stopped either way"
        );
        assert_eq!(connector().ingress(), Some("stopped"));
        assert!(connector()
            .stop_reason()
            .unwrap()
            .contains("could not confirm"));
        assert!(
            !marker.exists(),
            "no evidence, no marker: the next start tries again"
        );

        let pushed = Mutex::new(Some(child()));
        stop_connector(&pushed, &Stop::Evidence("Cloudflare pushed a different configuration to this tunnel, so Permaura stopped it: y".into()), &marker);
        assert_eq!(
            std::fs::read_to_string(&marker).unwrap(),
            "Cloudflare pushed a different configuration to this tunnel, so Permaura stopped it: y"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    /// A read that times out and the wait for the next poll together stay under a second, which is what the notes promise.
    #[test]
    fn one_poll_and_its_timeout_fit_in_the_second_the_notes_promise() {
        assert!(GUARD_INTERVAL + GUARD_REQUEST_TIMEOUT < Duration::from_secs(1));
        assert!(
            STARTED_NOTE.contains("within about a second")
                && !STARTED_NOTE.contains("half a second")
        );
    }

    #[test]
    fn the_notes_carry_no_em_dash() {
        assert!(!STARTED_NOTE.contains('\u{2014}'));
        assert!(
            !config_violation(&with(|r| r["version"] = json!(1)), &pin())
                .unwrap()
                .contains('\u{2014}')
        );
    }

    /// The tests that stop a connector read this process's one `/health` state, so they take turns, the remote disable route's included.
    pub(crate) static STOPPING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// A stand-in for the connector's metrics server: `GET /config` and `GET /metrics` answer whatever the test last put in `current`.
    async fn metrics_server(current: std::sync::Arc<Mutex<(Value, String)>>) -> u16 {
        let metrics = current.clone();
        let app = axum::Router::new()
            .route(
                "/config",
                axum::routing::get(move || {
                    let current = current.clone();
                    async move { axum::Json(current.lock().unwrap().0.clone()) }
                }),
            )
            .route(
                "/metrics",
                axum::routing::get(move || {
                    let metrics = metrics.clone();
                    async move { metrics.lock().unwrap().1.clone() }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        port
    }

    /// A fresh directory for one test's files, never the Permaura home.
    fn scratch_home(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("permaura-tunnel-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn records(home: &std::path::Path) -> Records {
        Records {
            stop_marker: home.join(STOP_MARKER_FILE),
            log: None,
        }
    }

    fn client() -> reqwest::Client {
        reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(GUARD_REQUEST_TIMEOUT)
            .build()
            .unwrap()
    }

    fn running(version: i64, service: &str) -> Value {
        json!({"version": version, "config": {"ingress": [
            {"hostname": "studio-mini.permaura.app", "path": null, "service": service, "originRequest": {}},
            {"hostname": "", "path": null, "service": "http_status:404", "originRequest": {}}
        ], "warp-routing": {}, "originRequest": {}}})
    }

    /// The guard's real loop over a real child process: the pinned configuration keeps it, and the first pushed one kills it within a poll and leaves `/health` saying why. The guard waits on the child it kills, so returning inside the timeout shows `sleep 30` was killed. Unix only, for `sleep`.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_guard_kills_the_connector_at_the_first_pushed_configuration() {
        let _turn = STOPPING.lock().await;
        let home = scratch_home("pushed");
        let current = std::sync::Arc::new(Mutex::new((
            running(-1, "http://127.0.0.1:7376"),
            QUIET_METRICS.to_string(),
        )));
        let port = metrics_server(current.clone()).await;
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let slot: ConnectorSlot = std::sync::Arc::new(Mutex::new(Some(child)));
        let pin = Pin {
            host: "studio-mini.permaura.app".into(),
            origin: "http://127.0.0.1:7376".into(),
            metrics_port: port,
        };
        let guard = tokio::spawn(super::guard(slot.clone(), pin, client(), records(&home)));

        tokio::time::sleep(Duration::from_millis(1600)).await;
        assert!(
            slot.lock().unwrap().is_some() && !guard.is_finished(),
            "the pinned configuration keeps the connector"
        );

        current.lock().unwrap().0 = running(4, "tcp://127.0.0.1:22");
        let pushed = Instant::now();
        tokio::time::timeout(Duration::from_secs(3), guard)
            .await
            .expect("the guard stops the connector")
            .unwrap();
        assert!(
            pushed.elapsed() < Duration::from_millis(1500),
            "{:?}",
            pushed.elapsed()
        );
        assert!(
            slot.lock().unwrap().is_none(),
            "the connector left the slot"
        );
        assert_eq!(connector().ingress(), Some("stopped"));
        let why = connector().stop_reason().unwrap();
        assert!(why.starts_with("Cloudflare pushed a different configuration to this tunnel, so Permaura stopped it") && why.contains("tcp://127.0.0.1:22"), "{why}");
        assert_eq!(
            std::fs::read_to_string(home.join(STOP_MARKER_FILE)).unwrap(),
            why,
            "the stop outlives the process"
        );
        let refusal =
            recorded_stop(&home.join(STOP_MARKER_FILE)).expect("a restart starts no connector");
        assert!(
            refusal.starts_with(&why) && refusal.contains("permaura remote enable"),
            "{refusal}"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    /// A `/config` answer too large to read inside the request timeout is evidence of a push, not silence. The stand-in streams a configuration far past the cap, slowly enough that reading all of it times out every poll, and the guard still stops the connector within a poll and records why.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_guard_kills_the_connector_at_an_oversize_configuration() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _turn = STOPPING.lock().await;
        let home = scratch_home("oversize");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else { return };
                tokio::spawn(async move {
                    let mut req = [0u8; 1024];
                    let n = sock.read(&mut req).await.unwrap_or(0);
                    if String::from_utf8_lossy(&req[..n]).starts_with("GET /metrics") {
                        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", QUIET_METRICS.len());
                        let _ = sock.write_all(head.as_bytes()).await;
                        let _ = sock.write_all(QUIET_METRICS.as_bytes()).await;
                        return;
                    }
                    let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"version\":-1,\"pad\":\"";
                    if sock.write_all(head.as_bytes()).await.is_err() {
                        return;
                    }
                    let chunk = vec![b'a'; 16 << 10];
                    for _ in 0..400 {
                        if sock.write_all(&chunk).await.is_err() {
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(40)).await;
                    }
                });
            }
        });
        let child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let slot: ConnectorSlot = std::sync::Arc::new(Mutex::new(Some(child)));
        let pin = Pin { host: "studio-mini.permaura.app".into(), origin: "http://127.0.0.1:7376".into(), metrics_port: port };
        let started = Instant::now();
        let guard = tokio::spawn(super::guard(slot.clone(), pin, client(), records(&home)));
        tokio::time::timeout(Duration::from_secs(5), guard)
            .await
            .expect("the guard stops the connector rather than waiting out a silence")
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
        assert!(slot.lock().unwrap().is_none(), "the connector left the slot");
        let why = connector().stop_reason().unwrap();
        assert!(why.starts_with("Cloudflare pushed a different configuration to this tunnel") && why.contains("more than 64 KiB"), "{why}");
        assert_eq!(std::fs::read_to_string(home.join(STOP_MARKER_FILE)).unwrap(), why, "the stop is recorded across restarts");
        std::fs::remove_dir_all(&home).ok();
    }

    /// The configuration still reads as written, but a private-network counter moves: the guard kills the connector within a poll.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_guard_kills_the_connector_at_the_first_private_network_session() {
        let _turn = STOPPING.lock().await;
        let home = scratch_home("routed");
        let current = std::sync::Arc::new(Mutex::new((
            running(-1, "http://127.0.0.1:7376"),
            QUIET_METRICS.to_string(),
        )));
        let port = metrics_server(current.clone()).await;
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let slot: ConnectorSlot = std::sync::Arc::new(Mutex::new(Some(child)));
        let pin = Pin {
            host: "studio-mini.permaura.app".into(),
            origin: "http://127.0.0.1:7376".into(),
            metrics_port: port,
        };
        let guard = tokio::spawn(super::guard(slot.clone(), pin, client(), records(&home)));

        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert!(
            slot.lock().unwrap().is_some() && !guard.is_finished(),
            "all four counters at zero keep the connector"
        );

        current.lock().unwrap().1 = QUIET_METRICS.replace(
            "cloudflared_tcp_total_sessions 0",
            "cloudflared_tcp_total_sessions 1",
        );
        let routed = Instant::now();
        tokio::time::timeout(Duration::from_secs(3), guard)
            .await
            .expect("the guard stops the connector")
            .unwrap();
        assert!(
            routed.elapsed() < Duration::from_millis(1500),
            "{:?}",
            routed.elapsed()
        );
        assert!(
            slot.lock().unwrap().is_none(),
            "the connector left the slot"
        );
        assert_eq!(connector().ingress(), Some("stopped"));
        let why = connector().stop_reason().unwrap();
        assert!(why.starts_with("Cloudflare sent private-network traffic through this tunnel, which Permaura's tunnel never carries, so Permaura stopped it") && why.contains("cloudflared_tcp_total_sessions 1"), "{why}");
        assert_eq!(
            std::fs::read_to_string(home.join(STOP_MARKER_FILE)).unwrap(),
            why
        );
        std::fs::remove_dir_all(&home).ok();
    }

    /// A connector that exits by itself ends the guard, which starts nothing in its place.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_guard_ends_quietly_when_the_connector_exits_by_itself() {
        let home = scratch_home("exited");
        let current = std::sync::Arc::new(Mutex::new((
            running(-1, "http://127.0.0.1:7376"),
            QUIET_METRICS.to_string(),
        )));
        let port = metrics_server(current).await;
        let child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let mut child = child;
        child.kill().unwrap();
        let slot: ConnectorSlot = std::sync::Arc::new(Mutex::new(Some(child)));
        let pin = Pin {
            host: "studio-mini.permaura.app".into(),
            origin: "http://127.0.0.1:7376".into(),
            metrics_port: port,
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            super::guard(slot.clone(), pin, client(), records(&home)),
        )
        .await
        .expect("the guard ends");
        assert!(slot.lock().unwrap().is_none());
        assert!(
            !home.join(STOP_MARKER_FILE).exists(),
            "an exit is not a stop"
        );
        std::fs::remove_dir_all(&home).ok();
    }

    /// A connector that exits after applying a pushed configuration is a stop, read from what it logged since this spawn; a line from an earlier connector is not.
    #[cfg(unix)]
    #[tokio::test]
    async fn an_exit_after_a_pushed_configuration_is_recorded_as_a_stop() {
        let _turn = STOPPING.lock().await;
        let home = scratch_home("pushed-exit");
        let log = home.join("cloudflared.log");
        let earlier =
            "2026-10-14T23:00:00Z INF Updated to new configuration config=\"{}\" version=1\n";
        std::fs::write(&log, earlier).unwrap();
        let start = std::fs::metadata(&log).unwrap().len();
        let port = metrics_server(std::sync::Arc::new(Mutex::new((
            running(-1, "http://127.0.0.1:7376"),
            QUIET_METRICS.to_string(),
        ))))
        .await;
        let pin = || Pin {
            host: "studio-mini.permaura.app".into(),
            origin: "http://127.0.0.1:7376".into(),
            metrics_port: port,
        };
        let exited = || {
            let mut child = std::process::Command::new("sleep")
                .arg("30")
                .spawn()
                .unwrap();
            child.kill().unwrap();
            std::sync::Arc::new(Mutex::new(Some(child)))
        };

        let quiet = Records {
            stop_marker: home.join(STOP_MARKER_FILE),
            log: Some((log.clone(), start)),
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            super::guard(exited(), pin(), client(), quiet),
        )
        .await
        .unwrap();
        assert!(
            !home.join(STOP_MARKER_FILE).exists(),
            "the line an earlier connector wrote is not this one's"
        );

        let mut appended = std::fs::OpenOptions::new().append(true).open(&log).unwrap();
        std::io::Write::write_all(&mut appended, b"2026-10-15T01:02:03Z INF Updated to new configuration config=\"{}\" version=4\n2026-10-15T01:02:04Z INF Initiating graceful shutdown\n").unwrap();
        let watched = Records {
            stop_marker: home.join(STOP_MARKER_FILE),
            log: Some((log.clone(), start)),
        };
        tokio::time::timeout(
            Duration::from_secs(5),
            super::guard(exited(), pin(), client(), watched),
        )
        .await
        .unwrap();
        let why = std::fs::read_to_string(home.join(STOP_MARKER_FILE))
            .expect("the exit is recorded as a stop");
        assert!(why.starts_with("Cloudflare pushed a different configuration to this tunnel, so Permaura stopped it") && why.ends_with("\"Updated to new configuration\" (version 4)"), "{why}");
        assert_eq!(connector().ingress(), Some("stopped"));
        assert_eq!(connector().stop_reason().as_deref(), Some(why.as_str()));
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn the_pushed_line_is_found_in_the_log_and_its_version_read() {
        assert_eq!(
            pushed_before_exit("2026-10-15T01:02:03Z INF Starting tunnel\n"),
            None
        );
        let why = pushed_before_exit(
            "a\n2026-10-15T01:02:03Z INF Updated to new configuration config=\"{}\" version=2\nb\n",
        )
        .unwrap();
        assert!(why.ends_with("(version 2)"), "{why}");
        let why = pushed_before_exit(
            "{\"level\":\"info\",\"message\":\"Updated to new configuration\"}\n",
        )
        .unwrap();
        assert!(
            why.ends_with("\"Updated to new configuration\""),
            "a line without a version still counts: {why}"
        );
    }

    /// The marker is owner-only and holds the reason; a restart refuses while it exists, even when it cannot be read, and starts once it is gone.
    #[test]
    fn a_recorded_stop_is_owner_only_and_refuses_a_restart_until_it_is_removed() {
        let home = scratch_home("marker");
        let marker = home.join(STOP_MARKER_FILE);
        assert_eq!(recorded_stop(&marker), None);
        record_stop(
            &marker,
            "Cloudflare pushed a different configuration to this tunnel, so Permaura stopped it: x",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&marker).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let refusal = recorded_stop(&marker).unwrap();
        assert!(refusal.starts_with("Cloudflare pushed a different configuration to this tunnel, so Permaura stopped it: x. Permaura recorded this stop in "), "{refusal}");
        std::fs::remove_file(&marker).unwrap();
        std::fs::create_dir(&marker).unwrap();
        assert!(
            recorded_stop(&marker).unwrap().contains("cannot be read"),
            "an unreadable marker still refuses"
        );
        std::fs::remove_dir(&marker).unwrap();
        assert_eq!(recorded_stop(&marker), None);
        std::fs::remove_dir_all(&home).ok();
    }

    fn exists(pid: u32) -> bool {
        std::process::Command::new("kill").args(["-0", &pid.to_string()]).stderr(std::process::Stdio::null()).status().is_ok_and(|s| s.success())
    }

    /// `permaura remote disable` kills the running connector, waits for it to exit, and `/health` says why it stopped.
    #[cfg(unix)]
    #[tokio::test]
    async fn turning_remote_access_off_kills_the_connector_and_reports_it_stopped() {
        let _turn = STOPPING.lock().await;
        let child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id();
        let slot: ConnectorSlot = std::sync::Arc::new(Mutex::new(Some(child)));
        connector().note_local();
        assert_eq!(turn_off(&slot, TURN_OFF_WITHIN), TurnedOff::Stopped(pid));
        assert!(slot.lock().unwrap().is_none(), "the connector left the slot");
        assert!(!exists(pid), "the connector has exited and been reaped");
        assert_eq!(connector().ingress(), Some(STOPPED));
        assert_eq!(connector().stop_reason().as_deref(), Some(TURNED_OFF));
        assert_eq!(turn_off(&slot, TURN_OFF_WITHIN), TurnedOff::Nothing, "a second disable finds nothing to stop");
    }

    /// A connector that cannot be signalled, or has not exited in time, is reported still running and stays in the slot for the guard and the gateway's own stop.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_connector_that_does_not_stop_is_reported_running_and_kept() {
        let _turn = STOPPING.lock().await;
        for (kill, within, said) in [
            (Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)), TURN_OFF_WITHIN, "could not be signalled"),
            (Ok(()), Duration::from_millis(200), "had not exited 0 seconds after SIGKILL"),
        ] {
            let child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
            let pid = child.id();
            let slot: ConnectorSlot = std::sync::Arc::new(Mutex::new(Some(child)));
            connector().note_local();
            let started = Instant::now();
            match turn_off_with(&slot, within, move |_| kill) {
                TurnedOff::StillRunning(still, why) => {
                    assert_eq!(still, pid);
                    assert!(why.contains(said), "{why}");
                }
                other => panic!("reported {other:?}"),
            }
            assert!(started.elapsed() < within + Duration::from_secs(1), "{:?}", started.elapsed());
            assert_ne!(connector().ingress(), Some(STOPPED), "nothing reports it stopped");
            let mut held = slot.lock().unwrap().take().expect("the connector stays in the slot");
            assert!(held.try_wait().unwrap().is_none(), "it is still running");
            let _ = held.kill();
            let _ = held.wait();
        }
    }
}
