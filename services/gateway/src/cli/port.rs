//! Who holds the gateway's port, and what to say and do about it.
//!
//! `permaura start` used to die with the bare `Address already in use (os error 48)`, and
//! `permaura stop` with `the gateway refused to stop (401)`, when the thing on the port was one of our
//! own gateways: one a shell left behind under `nohup`, or one still running on a binary and a store
//! that an uninstall had since deleted. Both messages were true and neither said what to do. A
//! Permaura gateway holding the port is something Permaura can name, diagnose and remove, and this is
//! where it does all three.
//!
//! The OS answers "which process" (`listeners`, the same crate the desktop app uses for the same
//! question), and the gateway's own unauthenticated `/health` answers "is it one of ours". Whether it is serving THIS home is a challenge it has to answer ([`permaura_core::health_proof`]): `/health` is asked with a fresh random challenge and no bearer, and only a listener whose proof matches this home's operator token (or a `--token`) is [`Health::Ours`]. Anything else answering as a Permaura gateway is [`Health::Unconfirmed`]; nothing here infers ownership from a body.
//!
//! The rule: this home's operator token is sent only to a loopback listener that has just proved it already holds it ([`bearer_for`], [`graceful_shutdown`]). Holding the address proves nothing, and neither does running as this OS user: a sandboxed app that cannot read `~/.permaura` can still bind the port while the gateway is down, and a squatter handed the token keeps a live bearer for the real gateway. [`listener_is_this_users`] (the desktop's same-user listener check) is still required before the token is sent and before anything is stopped, but it no longer licenses either on its own.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context as _};

/// Where the port-conflict caveats are written down.
///
/// Only ever shown for a holder that is NOT one of ours: a Permaura gateway on the port is something
/// this module can name and remove in a sentence, and sending someone to a web page for that would be
/// worse than the sentence. Someone else's program is the case with real caveats behind it (a listener
/// on the wildcard does not take the address off us, so the port can be shared and still broken), and
/// those do not fit in an error. The anchor deliberately carries no port number so it survives the
/// gateway moving again.
pub const PORT_HELP_URL: &str = "https://docs.permaura.com/help/troubleshooting#port-conflicts";

/// The process listening on a port, as far as the OS will say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Holder {
    pub pid: u32,
    pub name: String,
    /// The executable, when the OS reports one.
    pub exe: Option<PathBuf>,
    /// Whether `exe` is still on disk. `false` means the file was deleted or replaced under the running
    /// process: an uninstall, an upgrade, or a rebuild.
    pub exe_on_disk: bool,
}

impl Holder {
    /// `pid N, /path/to/exe, no longer on disk`, with whatever parts the OS gave us.
    pub fn describe(&self) -> String {
        let mut s = format!("pid {}", self.pid);
        match &self.exe {
            Some(exe) => {
                s.push_str(&format!(", {}", exe.display()));
                if !self.exe_on_disk {
                    s.push_str(", no longer on disk");
                }
            }
            None if !self.name.is_empty() => s.push_str(&format!(", {}", self.name)),
            None => {}
        }
        s
    }
}

/// What `GET /health` on the address said, asked with a fresh challenge and no bearer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Health {
    /// Answered as a Permaura gateway and proved it holds a token it was asked about: this home's
    /// operator token, or one named with `--token`.
    Ours,
    /// Answered as a Permaura gateway, and did not prove it holds any token it was asked about.
    Unconfirmed(Unproven),
    /// Answered HTTP, but not as a Permaura gateway.
    NotPermaura,
    /// Did not answer HTTP at all.
    Unreachable,
}

/// Why a listener answering as a Permaura gateway is not confirmed as this home's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unproven {
    /// There was no token to check an answer against: this home has no operator token and none was
    /// named.
    NoToken,
    /// It sent no proof at all: a gateway older than 1.3.41, or a program imitating one.
    NoProof,
    /// It sent a proof for some other token: a gateway serving another home, or one left running on
    /// a store that has since been recreated.
    WrongProof,
}

impl Health {
    pub fn is_permaura(&self) -> bool {
        matches!(self, Health::Ours | Health::Unconfirmed(_))
    }
}

/// The process listening on `port`, or `None` when nothing is or the OS will not say.
pub fn holder_of(port: u16) -> Option<Holder> {
    let p = listeners::get_process_by_port(port, listeners::Protocol::TCP).ok()?;
    // Linux reports a deleted executable as `/path (deleted)`; the suffix is the OS's note, not part of
    // the path, and the on-disk check below says the same thing without it.
    let raw = p.path.trim().trim_end_matches(" (deleted)").to_string();
    // macOS's proc_pidpath answers nothing at all for an executable that has been unlinked, which is
    // the very case worth naming; sysinfo then reads the exec path the kernel kept in the process's
    // argument block instead.
    let exe = (!raw.is_empty())
        .then(|| PathBuf::from(&raw))
        .or_else(|| sysinfo_exe(p.pid));
    let exe_on_disk = exe.as_deref().is_some_and(Path::is_file);
    Some(Holder {
        pid: p.pid,
        name: p.name,
        exe,
        exe_on_disk,
    })
}

fn sysinfo_exe(pid: u32) -> Option<PathBuf> {
    let pid = sysinfo::Pid::from_u32(pid);
    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&[pid]),
        false,
        sysinfo::ProcessRefreshKind::nothing().with_exe(sysinfo::UpdateKind::Always),
    );
    sys.processes().get(&pid)?.exe().map(Path::to_path_buf)
}

/// Ask `/health` on `addr` what is there, with a fresh challenge and no bearer, and check the answer
/// against `keys` (this home's operator token, and any token named with `--token`). Nothing in `keys`
/// is sent.
pub async fn probe_health(addr: SocketAddr, keys: &[&str]) -> Health {
    let Ok(client) = probe_client(Duration::from_secs(2)) else {
        return Health::Unreachable;
    };
    let challenge = permaura_core::health_proof::new_challenge();
    let Ok(resp) = client
        .get(format!("http://{addr}/health"))
        .header(permaura_core::health_proof::CHALLENGE_HEADER, &challenge)
        .send()
        .await
    else {
        return Health::Unreachable;
    };
    let proof = resp
        .headers()
        .get(permaura_core::health_proof::PROOF_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    classify_health(&body, addr.port(), keys, &challenge, proof.as_deref())
}

/// A client for a loopback listener that has not proved itself: no redirects, or a listener could send the challenge on to a real gateway elsewhere and pass off its answer, and no proxy.
fn probe_client(timeout: Duration) -> reqwest::Result<reqwest::Client> {
    local_client(Some(timeout)).build()
}

/// A client for a listener on this machine: the probe's rules, for everything sent after the proof as well as the proof itself.
///
/// `HTTP_PROXY` and `ALL_PROXY` apply to 127.0.0.1 unless `NO_PROXY` names that exact address, so a default client sends the bearer, and a `vault add` secret, to whoever runs the proxy, on a connection other than the one that answered the challenge.
pub fn local_client(timeout: Option<Duration>) -> reqwest::ClientBuilder {
    let builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).no_proxy();
    match timeout {
        Some(t) => builder.timeout(t),
        None => builder,
    }
}

/// The client for a request to `url`: [`local_client`] when `url` names this machine, sent to the address [`local_addr_of`] gave the proof, and [`remote_client`], proxy and all, when it does not.
pub fn client_for(url: &str, timeout: Option<Duration>) -> reqwest::Result<reqwest::Client> {
    if let Some(addr) = local_addr_of(url) {
        // The proof was asked of `addr`, so `localhost` goes there too: it resolves to ::1 first on macOS, where any process may listen on the port while the gateway holds only 127.0.0.1.
        return local_client(timeout).resolve("localhost", addr).build();
    }
    remote_client(timeout, true)
}

/// `resp`, or a refusal naming where a redirect pointed: no client here follows one, because a 307 or 308 would resend a bearer or a secret wherever it points.
pub fn refuse_redirect(resp: reqwest::Response) -> anyhow::Result<reqwest::Response> {
    if resp.status().is_redirection() {
        let to = resp.headers().get(reqwest::header::LOCATION).and_then(|v| v.to_str().ok()).unwrap_or("no location");
        anyhow::bail!(
            "{} answered {} pointing at {to}; a redirect is not followed with a token or a secret, so nothing was sent there",
            resp.url(),
            resp.status().as_u16()
        );
    }
    Ok(resp)
}

/// The client for a gateway that is not on this machine: no redirect is followed, since [`remote_bearer`] checks only the URL the operator typed and a 307 or 308 resends the bearer and the body, and with `https_only` no request, first or later, goes out over plain http.
fn remote_client(timeout: Option<Duration>, https_only: bool) -> reqwest::Result<reqwest::Client> {
    let builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).https_only(https_only);
    match timeout {
        Some(t) => builder.timeout(t),
        None => builder,
    }
    .build()
}

/// The pure half of [`probe_health`]: what a `/health` reply means, given the challenge that was sent,
/// the port it was sent to, and the proof that came back.
pub fn classify_health(
    body: &serde_json::Value,
    port: u16,
    keys: &[&str],
    challenge: &str,
    proof: Option<&str>,
) -> Health {
    if body.get("service").and_then(|v| v.as_str()) != Some("permaura-gateway") {
        return Health::NotPermaura;
    }
    let keys: Vec<&str> = keys.iter().copied().filter(|k| !k.is_empty()).collect();
    if keys.is_empty() {
        return Health::Unconfirmed(Unproven::NoToken);
    }
    let Some(proof) = proof else {
        return Health::Unconfirmed(Unproven::NoProof);
    };
    if keys
        .iter()
        .any(|k| permaura_core::health_proof::verify(k, port, challenge, proof))
    {
        Health::Ours
    } else {
        Health::Unconfirmed(Unproven::WrongProof)
    }
}

/// This home's operator token, if the file is there and non-empty.
pub fn operator_token() -> Option<String> {
    super::enroll::operator_token().ok()
}

/// Where this home keeps its operator token, for messages.
pub fn operator_token_path() -> PathBuf {
    permaura_core::permaura_path("operator.token")
        .unwrap_or_else(|| PathBuf::from("~/.permaura/operator.token"))
}

/// Everything `start` needs to say why it could not bind `addr`.
///
/// Sends a challenge and no token, whoever holds the port: `start` reaches this precisely when
/// something it did not start has the address, which is the moment a squatter is listening for the
/// bearer.
pub async fn diagnose_addr_in_use(addr: SocketAddr) -> String {
    let holder = holder_of(addr.port());
    let token = operator_token();
    let keys: Vec<&str> = token.as_deref().into_iter().collect();
    let health = probe_health(addr, &keys).await;
    explain_addr_in_use(addr, holder.as_ref(), &health, &operator_token_path())
}

/// The text `start` prints when the bind fails, from the facts alone.
pub fn explain_addr_in_use(
    addr: SocketAddr,
    holder: Option<&Holder>,
    health: &Health,
    token_path: &Path,
) -> String {
    let who = holder
        .map(Holder::describe)
        .unwrap_or_else(|| "pid unknown".to_string());
    let kill = holder
        .map(|h| format!(" (or `kill {}`)", h.pid))
        .unwrap_or_default();
    let alt = SocketAddr::new(addr.ip(), addr.port().wrapping_add(1));
    let head = format!("{addr} is already in use: ");
    match health {
        Health::Ours => format!(
            "{head}a Permaura gateway is already serving this home on {addr} ({who}): it proved it holds {token}.\n  \
             There is nothing to start. `permaura status` shows it; `permaura stop` stops it.",
            token = token_path.display()
        ),
        Health::Unconfirmed(why) => format!(
            "{head}something answering like a Permaura gateway holds {addr} ({who}), but it did not prove it is this home's: {reason}.\n  \
             It was not sent this home's operator token, and nothing here will stop it. If it is yours, stop it with `permaura stop --force`{kill}, then run `permaura start` again; \
             otherwise start this gateway on another port: PERMAURA_ADDR={alt} permaura start",
            reason = unproven_reason(*why, token_path)
        ),
        Health::NotPermaura | Health::Unreachable => {
            let name = holder
                .map(|h| format!("pid {}, {}", h.pid, if h.name.is_empty() { "unknown program" } else { h.name.as_str() }))
                .unwrap_or_else(|| "pid unknown".to_string());
            let how = if *health == Health::Unreachable { " and does not answer HTTP" } else { "" };
            format!(
                "{head}something that is not a Permaura gateway holds {addr} ({name}){how}.\n  \
                 Stop that program, or start Permaura on another port: PERMAURA_ADDR={alt} permaura start\n  \
                 More on sharing a port with another program: {PORT_HELP_URL}"
            )
        }
    }
}

/// Why a listener did not prove it is this home's, as a clause.
pub fn unproven_reason(why: Unproven, token_path: &Path) -> String {
    match why {
        Unproven::NoToken => format!("this home has no {} for it to prove it holds", token_path.display()),
        Unproven::NoProof => "it sent no proof at all, so it is a gateway older than 1.3.41 or a program imitating one".to_string(),
        Unproven::WrongProof => "it holds a different operator token, so it was started under a different PERMAURA_HOME, or before this home's store was recreated (an uninstall or reinstall)".to_string(),
    }
}

/// Why a `POST /v1/shutdown` came back 401, and what to do about it. Shared by `stop` and `uninstall`.
pub fn explain_rejected_shutdown(
    addr: SocketAddr,
    holder: Option<&Holder>,
    force_hint: bool,
) -> String {
    let who = holder
        .map(Holder::describe)
        .unwrap_or_else(|| "pid unknown".to_string());
    let mut s = format!(
        "the gateway on {addr} rejected this home's operator token, so it is not serving this home's store: \
         it was started under a different PERMAURA_HOME, or before this home's store was recreated (an uninstall or reinstall).\n  \
         It is {who}."
    );
    if force_hint {
        let kill = holder
            .map(|h| format!(" (or `kill {}`)", h.pid))
            .unwrap_or_default();
        s.push_str(&format!(
            "\n  Re-run with `permaura stop --force` to end it anyway{kill}."
        ));
    }
    s
}

/// What the graceful path said.
#[derive(Debug)]
pub enum Graceful {
    /// `202`: it is draining and will exit.
    Accepted,
    /// `401`: the token this home holds is not the token it wants.
    Unauthorized,
    /// Any other answer.
    Refused {
        status: reqwest::StatusCode,
        detail: String,
    },
    /// Nothing answered.
    Unreachable,
    /// The holder could not be confirmed as this user's, so the token was not sent at all.
    NotOffered,
    /// The holder answered as a Permaura gateway but did not prove it holds the token, so the token
    /// was not sent at all.
    NotProven(Unproven),
}

/// `POST /v1/shutdown` with `token`, reading the outcome without judging it. The token goes only to a
/// listener running as this user that has just proved it already holds it.
pub async fn graceful_shutdown(addr: SocketAddr, token: &str) -> Graceful {
    if !listener_is_this_users(addr) {
        return Graceful::NotOffered;
    }
    match probe_health(addr, &[token]).await {
        Health::Ours => {}
        Health::Unconfirmed(why) => return Graceful::NotProven(why),
        Health::NotPermaura | Health::Unreachable => return Graceful::Unreachable,
    }
    let Ok(client) = probe_client(Duration::from_secs(5)) else {
        return Graceful::Unreachable;
    };
    let Ok(resp) = client
        .post(format!("http://{addr}/v1/shutdown"))
        .bearer_auth(token)
        .send()
        .await
    else {
        return Graceful::Unreachable;
    };
    let status = resp.status();
    if status == reqwest::StatusCode::ACCEPTED {
        return Graceful::Accepted;
    }
    if status == reqwest::StatusCode::UNAUTHORIZED {
        return Graceful::Unauthorized;
    }
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    let detail = body
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Graceful::Refused { status, detail }
}

/// Whether process `pid` is still running. A zombie, which has exited and only waits for its parent to
/// reap it, has let go of everything it held, so it counts as gone.
pub fn process_alive(pid: u32) -> bool {
    let pid = sysinfo::Pid::from_u32(pid);
    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&[pid]),
        true,
        sysinfo::ProcessRefreshKind::nothing(),
    );
    sys.process(pid).is_some_and(|p| p.status() != sysinfo::ProcessStatus::Zombie)
}

/// Whether process `pid` is running a Permaura binary, by the file name of its executable: the check
/// before signalling a pid read from the store lock, whose file still carries an earlier holder's pid when the
/// current holder could not write its own, and whose pid may since have been reused.
pub fn runs_permaura(pid: u32) -> bool {
    sysinfo_exe(pid)
        .and_then(|exe| exe.file_name().map(|n| n.to_string_lossy().to_lowercase()))
        .is_some_and(|name| name.starts_with("permaura"))
}

/// How long a stopping gateway can take to exit after it accepted the request: its drain window and
/// last carry, then the tunnel and relay teardown. The same bound the desktop supervisor waits.
pub const STOP_EXIT_WINDOW: Duration = Duration::from_secs(15);

/// Whether `addr` can be bound right now.
pub fn is_free(addr: SocketAddr) -> bool {
    std::net::TcpListener::bind(addr).is_ok()
}

/// Poll until `addr` can be bound, or `limit` runs out.
pub async fn wait_until_free(addr: SocketAddr, limit: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if is_free(addr) {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// End the Permaura gateway holding `addr` without its cooperation, and wait for the port to free.
///
/// Refuses anything that does not answer `/health` as a Permaura gateway: the port lookup names a pid,
/// and a pid is only ours to signal once it has said it is one of ours. `Ok(None)` means nothing was
/// listening to begin with.
///
/// A Permaura gateway that has not proved it is this home's is still ended, because this is the explicit `--force` (or an uninstall) and such a gateway is what it exists for; it is never sent the token.
pub async fn force_stop(addr: SocketAddr) -> anyhow::Result<Option<Holder>> {
    let Some(holder) = holder_of(addr.port()) else {
        if is_free(addr) {
            return Ok(None);
        }
        return Err(anyhow!(
            "{addr} is held, but the OS would not say by which process; find it with `lsof -i :{}` and stop it yourself",
            addr.port()
        ));
    };
    // `is_permaura` needs no token, and none is offered.
    let health = probe_health(addr, &[]).await;
    if !health.is_permaura() {
        return Err(anyhow!(
            "refusing to stop {} on {addr}: it does not answer /health as a Permaura gateway, so it is not ours to kill",
            holder.describe()
        ));
    }
    terminate(holder.pid).with_context(|| format!("stopping {}", holder.describe()))?;
    if !wait_until_free(addr, Duration::from_secs(5)).await {
        return Err(anyhow!(
            "{} was signalled but {addr} is still held after 5s; try `kill -9 {}`",
            holder.describe(),
            holder.pid
        ));
    }
    Ok(Some(holder))
}

/// TERM where the platform has one, the platform's hard kill where it does not.
pub(super) fn terminate(pid: u32) -> anyhow::Result<()> {
    let pid = sysinfo::Pid::from_u32(pid);
    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&[pid]),
        false,
        sysinfo::ProcessRefreshKind::nothing(),
    );
    let proc_ = sys
        .processes()
        .get(&pid)
        .ok_or_else(|| anyhow!("pid {pid} vanished before it could be stopped"))?;
    let killed = proc_
        .kill_with(sysinfo::Signal::Term)
        .unwrap_or_else(|| proc_.kill());
    anyhow::ensure!(
        killed,
        "the OS refused to signal pid {pid}; it may belong to another user"
    );
    Ok(())
}

/// Whether the process LISTENing on `addr` runs as the same OS user as this one.
///
/// The desktop supervisor's same-user listener check, ported. False whenever that cannot be shown: nothing
/// listening, a lookup the OS refuses (on macOS and Linux another user's sockets are not visible to us
/// at all), or a process whose user it will not name. The residual race is the port changing hands
/// between this check and the request that follows it, a window only the gateway's own exit opens.
pub fn listener_is_this_users(addr: SocketAddr) -> bool {
    matches!(listening_pids(addr), Some(pids) if !pids.is_empty() && pids.iter().all(|&pid| runs_as_this_user(pid)))
}

/// The processes holding a TCP socket in LISTEN that accepts connections to `addr`, or `None` when
/// the OS would not list them.
///
/// Only LISTEN rows. `listeners::get_process_by_port` returns the first socket of any state with that
/// local port, and on Windows the table is unsorted and a closed connection leaves a TIME_WAIT row
/// owned by pid 0, so after one connection the gateway closed first the lookup could name the System
/// Idle Process instead of the gateway, and its own user's gateway read as another user's.
fn listening_pids(addr: SocketAddr) -> Option<Vec<u32>> {
    let all = listeners::get_all().ok()?;
    let mut pids: Vec<u32> = all
        .iter()
        .filter(|l| {
            l.protocol == listeners::Protocol::TCP
                && l.state == listeners::SocketState::Listen
                && l.socket.port() == addr.port()
                && (l.socket.ip() == addr.ip() || l.socket.ip().is_unspecified())
        })
        .map(|l| l.process.pid)
        .collect();
    pids.sort_unstable();
    pids.dedup();
    Some(pids)
}

/// Whether `pid` is this process or runs as the same OS user. A user the OS will not name is not
/// this user.
fn runs_as_this_user(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    let Ok(me) = sysinfo::get_current_pid() else { return false };
    let them = sysinfo::Pid::from_u32(pid);
    let mut sys = sysinfo::System::new();
    sys.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&[them, me]),
        false,
        sysinfo::ProcessRefreshKind::nothing().with_user(sysinfo::UpdateKind::Always),
    );
    same_user(
        sys.process(them).and_then(sysinfo::Process::user_id),
        sys.process(me).and_then(sysinfo::Process::user_id),
    )
}

fn same_user(listener: Option<&sysinfo::Uid>, me: Option<&sysinfo::Uid>) -> bool {
    matches!((listener, me), (Some(a), Some(b)) if a == b)
}

/// Who is on a loopback address, for deciding what may be sent there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Listener {
    /// A Permaura gateway that has just proved it holds the token about to be sent, running as this
    /// OS user.
    Ours,
    /// Nothing: a connection is refused outright.
    Nobody,
    /// Something answering as a Permaura gateway that did not prove it holds the token.
    Unproven(Unproven),
    /// A gateway that proved it holds the token, but cannot be shown to run as this user.
    NotThisUser,
    /// Something accepts connections and does not answer as a Permaura gateway.
    Foreign,
}

/// Who is listening on `addr`, checked against `keys` (the tokens the caller might send). Asks with a
/// challenge, never a token.
pub async fn listener_at(addr: SocketAddr, keys: &[&str]) -> Listener {
    match probe_health(addr, keys).await {
        Health::Ours if listener_is_this_users(addr) => Listener::Ours,
        Health::Ours => Listener::NotThisUser,
        Health::Unconfirmed(why) => Listener::Unproven(why),
        Health::Unreachable if nobody_listens(addr, listening_pids(addr).as_deref()) => Listener::Nobody,
        Health::NotPermaura | Health::Unreachable => Listener::Foreign,
    }
}

/// Whether nothing at all listens on `addr`, which is never inferred from silence.
///
/// Windows retries a connection that a closed loopback port refuses for about two seconds before it
/// reports the refusal, so a short connect probe there read every free port as taken. Its TCP table
/// lists every listening socket whoever owns it, so an empty `listed` is the answer there. On macOS
/// and Linux another user's socket is not in any table this process can read, and a refused
/// connection, which arrives at once there, is the only proof the port is free.
fn nobody_listens(addr: SocketAddr, listed: Option<&[u32]>) -> bool {
    #[cfg(windows)]
    {
        let _ = addr;
        listed.is_some_and(<[u32]>::is_empty)
    }
    #[cfg(not(windows))]
    {
        let _ = listed;
        matches!(
            std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(500)),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused
        )
    }
}

/// A request the CLI would not send, and why. Its own type so a caller can tell it from the network
/// failing.
#[derive(Debug)]
pub struct Refused(pub String);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refused {}

/// The bearer to present to `url`, decided before anything is sent, or a refusal to send at all.
///
/// `explicit` is a `--token` / `PERMAURA_TOKEN` the caller named; `home` reads this home's operator
/// token. The home token belongs to the gateway on this machine, so it is offered only to a loopback
/// URL, and there only to a listener that has just proved it holds a token this CLI holds (see the
/// module docs) and runs as this user: the body can carry a secret (`vault add`) as well as the header
/// carrying the bearer, so a listener that has not proved itself is sent nothing at all, token or not.
/// Nothing listening sends nothing worth refusing, so that request goes out bare and fails to connect
/// as before. A gateway elsewhere gets only an explicit token, and only over https.
pub async fn bearer_for(
    url: &str,
    explicit: Option<&str>,
    home: impl FnOnce() -> Option<String>,
) -> Result<Option<String>, Refused> {
    let Some(addr) = local_addr_of(url) else {
        return remote_bearer(url, explicit);
    };
    let home = home().filter(|t| !t.is_empty());
    let keys: Vec<&str> = explicit.into_iter().chain(home.as_deref()).collect();
    let listener = listener_at(addr, &keys).await;
    local_bearer(addr, explicit, home, listener, &operator_token_path())
}

/// [`bearer_for`] for a URL that is not on this machine.
fn remote_bearer(url: &str, explicit: Option<&str>) -> Result<Option<String>, Refused> {
    match reqwest::Url::parse(url) {
        Ok(u) if u.scheme() == "https" => Ok(explicit.map(str::to_string)),
        Ok(_) => Err(Refused(format!(
            "refusing to talk to {url}: it is not on this machine and not https, so a token or a secret sent there would cross the network in the clear. \
             Use the gateway's https address"
        ))),
        Err(e) => Err(Refused(format!("{url} is not a gateway URL: {e}"))),
    }
}

/// The pure half of [`bearer_for`] for a loopback address: what may be sent, given who answered.
pub fn local_bearer(
    addr: SocketAddr,
    explicit: Option<&str>,
    home: Option<String>,
    listener: Listener,
    token_path: &Path,
) -> Result<Option<String>, Refused> {
    match listener {
        Listener::Ours => Ok(explicit.map(str::to_string).or(home)),
        Listener::Nobody => Ok(None),
        Listener::Unproven(Unproven::NoToken) => Err(Refused(format!(
            "refusing to talk to {addr}: something answering like a Permaura gateway is there, but there is no operator token ({path}, or --token) \
             for it to prove it holds, so it was not sent anything. Run this as the account whose gateway it is, or name its token with --token",
            path = token_path.display()
        ))),
        Listener::Unproven(Unproven::NoProof) => Err(Refused(format!(
            "refusing to talk to {addr}: it answers like a Permaura gateway but sent no proof that it holds this home's operator token, \
             so it was not sent the token or anything else. A gateway older than 1.3.41 cannot prove it: if this one is yours, \
             restart it on the current version (`permaura stop --force`, then `permaura start`)"
        ))),
        Listener::Unproven(Unproven::WrongProof) => Err(Refused(format!(
            "refusing to talk to {addr}: the Permaura gateway there holds a different operator token, so it is not serving this home ({path}) \
             and was not sent its token or anything else. It was started under a different PERMAURA_HOME, or before this home's store was recreated; \
             stop it with `permaura stop --force`, or name its own token with --token",
            path = token_path.display()
        ))),
        Listener::NotThisUser => Err(Refused(format!(
            "refusing to talk to {addr}: the process listening there is not running as you (or the OS would not say who it runs as), \
             so it was not sent this home's operator token or anything else. If it is your gateway, run this command as the account that started it \
             (for a service install, `sudo -u permaura permaura ...`); otherwise stop it, or start the gateway on another port with PERMAURA_ADDR"
        ))),
        Listener::Foreign => Err(Refused(format!(
            "refusing to talk to {addr}: what is listening there does not answer as a Permaura gateway, so it was not sent this home's operator token \
             or anything else. Stop that program, or start the gateway on another port with PERMAURA_ADDR. \
             More on sharing a port with another program: {PORT_HELP_URL}"
        ))),
    }
}

/// The socket a gateway URL names, when it names one on this machine: a loopback name or address, or one of this machine's own addresses (traffic to which never leaves it). Every bearer this CLI sends there goes only after the listener proves it holds it.
///
/// The port lookup and the kill are local acts, so they only make sense for a URL that is local too. A wildcard address names no one socket; [`reachable_url`] turns it into loopback first.
pub fn local_addr_of(url: &str) -> Option<SocketAddr> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?;
    let port = parsed.port_or_known_default()?;
    let ip: std::net::IpAddr = match host {
        "localhost" => std::net::Ipv4Addr::LOCALHOST.into(),
        h => h.trim_matches(|c| c == '[' || c == ']').parse().ok()?,
    };
    (ip.is_loopback() || this_machine_has(ip, &interface_addresses())).then(|| SocketAddr::new(ip, port))
}

/// Whether `ip` is one of `interfaces`, this machine's own addresses. Read from the interface list rather than from whether a socket binds it: with `ip_nonlocal_bind` set, as on keepalived and HAProxy hosts, any address binds.
fn this_machine_has(ip: std::net::IpAddr, interfaces: &[std::net::IpAddr]) -> bool {
    !ip.is_unspecified() && !ip.is_multicast() && interfaces.contains(&ip)
}

/// This machine's interface addresses, from `getifaddrs`; none where it fails.
#[cfg(unix)]
fn interface_addresses() -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs hands back a list freed by freeifaddrs on the one path out; each address is read unaligned by its family's own struct, so nothing assumes the buffer's alignment.
    unsafe {
        if libc::getifaddrs(&mut head) != 0 {
            return out;
        }
        let mut cur = head;
        while !cur.is_null() {
            let addr = (*cur).ifa_addr;
            if !addr.is_null() {
                match i32::from((*addr).sa_family) {
                    libc::AF_INET => {
                        let sin = std::ptr::read_unaligned(addr.cast::<libc::sockaddr_in>());
                        out.push(std::net::Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)).into());
                    }
                    libc::AF_INET6 => {
                        let sin6 = std::ptr::read_unaligned(addr.cast::<libc::sockaddr_in6>());
                        out.push(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr).into());
                    }
                    _ => {}
                }
            }
            cur = (*cur).ifa_next;
        }
        libc::freeifaddrs(head);
    }
    out
}

/// This machine's interface addresses: none on Windows, where an address other than loopback is then treated as another machine's and refused over plain http.
#[cfg(not(unix))]
fn interface_addresses() -> Vec<std::net::IpAddr> {
    Vec::new()
}

/// `url` with a wildcard host (`0.0.0.0`, `[::]`), which a gateway is bound to but no client can dial, replaced by that family's loopback address, where such a gateway answers this machine; any other URL as given.
pub fn reachable_url(url: &str) -> String {
    let Ok(mut parsed) = reqwest::Url::parse(url.trim()) else { return url.to_string() };
    let host = parsed.host_str().unwrap_or_default().trim_matches(|c| c == '[' || c == ']');
    let loopback = match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) if ip.is_unspecified() => "127.0.0.1",
        Ok(std::net::IpAddr::V6(ip)) if ip.is_unspecified() => "[::1]",
        _ => return url.to_string(),
    };
    if parsed.set_host(Some(loopback)).is_err() {
        return url.to_string();
    }
    let rebuilt = parsed.to_string();
    if url.trim().ends_with('/') { rebuilt } else { rebuilt.trim_end_matches('/').to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A gateway off this machine gets a client that follows no redirect, so a 307 in front of it cannot carry a `vault add` value and the bearer to another place, and (in production) refuses plain http on every hop.
    #[tokio::test]
    async fn the_remote_client_follows_no_redirect_and_leaves_no_https() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        async fn server(reply: String) -> (String, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let record = seen.clone();
            tokio::spawn(async move {
                while let Ok((mut sock, _)) = listener.accept().await {
                    let mut buf = [0u8; 8192];
                    if let Ok(n) = sock.read(&mut buf).await {
                        record.lock().unwrap().extend_from_slice(&buf[..n]);
                    }
                    let _ = sock.write_all(reply.as_bytes()).await;
                    let _ = sock.shutdown().await;
                }
            });
            (format!("http://{addr}"), seen)
        }
        let (elsewhere, landed) = server("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}".into()).await;
        let (front, _) = server(format!(
            "HTTP/1.1 307 Temporary Redirect\r\nlocation: {elsewhere}/v1/secrets\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        ))
        .await;
        // https_only is lifted only so a loopback listener can stand in for the redirecting front.
        let client = remote_client(Some(Duration::from_secs(5)), false).unwrap();
        let resp = client
            .post(format!("{front}/v1/secrets"))
            .bearer_auth("pgt_synthetic_operator")
            .json(&serde_json::json!({ "id": "stripe-key", "value": "sk_synthetic_value" }))
            .send()
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        let got = String::from_utf8_lossy(&landed.lock().unwrap()).to_string();
        assert!(!got.contains("sk_synthetic_value") && !got.contains("pgt_synthetic_operator"), "the redirect was followed: {got}");
        assert!(refuse_redirect(resp).is_err(), "a redirect is a refusal");

        let strict = remote_client(Some(Duration::from_secs(5)), true).unwrap();
        let (plain, reached) = server("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}".into()).await;
        assert!(strict.get(format!("{plain}/health")).send().await.is_err(), "plain http is refused");
        assert!(reached.lock().unwrap().is_empty(), "before anything is sent");
    }

    fn addr() -> SocketAddr {
        "127.0.0.1:7376".parse().unwrap()
    }

    fn deleted_gateway() -> Holder {
        Holder {
            pid: 4242,
            name: "permaura".into(),
            exe: Some(PathBuf::from("/Users/x/.permaura/bin/permaura")),
            exe_on_disk: false,
        }
    }

    const CHALLENGE: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn gateway_body() -> serde_json::Value {
        json!({"status":"ok","service":"permaura-gateway"})
    }

    #[test]
    fn only_a_proof_from_a_token_this_cli_holds_makes_a_gateway_ours() {
        let right = permaura_core::health_proof::proof("pgt_home", 7376, CHALLENGE).unwrap();
        let classify = |keys: &[&str], proof: Option<&str>| classify_health(&gateway_body(), 7376, keys, CHALLENGE, proof);
        assert_eq!(classify(&["pgt_home"], Some(&right)), Health::Ours);
        assert_eq!(classify(&["pgt_named", "pgt_home"], Some(&right)), Health::Ours, "either key it was asked about");
        assert_eq!(classify(&["pgt_home"], None), Health::Unconfirmed(Unproven::NoProof));
        assert_eq!(classify(&["pgt_other"], Some(&right)), Health::Unconfirmed(Unproven::WrongProof));
        assert_eq!(classify(&["pgt_home"], Some("deadbeef")), Health::Unconfirmed(Unproven::WrongProof));
        assert_eq!(classify(&[], Some(&right)), Health::Unconfirmed(Unproven::NoToken));
        assert_eq!(classify(&[""], Some(&right)), Health::Unconfirmed(Unproven::NoToken), "an empty token is no token");
        // The answer a gateway on another port gives, relayed back by whatever holds this one.
        let relayed = permaura_core::health_proof::proof("pgt_home", 7399, CHALLENGE).unwrap();
        assert_eq!(classify(&["pgt_home"], Some(&relayed)), Health::Unconfirmed(Unproven::WrongProof));
        // A version in the body is the old "this is yours" signal, and it no longer is one.
        let versioned = json!({"status":"ok","service":"permaura-gateway","version":"1.3.40"});
        assert_eq!(
            classify_health(&versioned, 7376, &["pgt_home"], CHALLENGE, None),
            Health::Unconfirmed(Unproven::NoProof)
        );
    }

    #[test]
    fn anything_else_answering_is_not_permaura() {
        let right = permaura_core::health_proof::proof("pgt_home", 7376, CHALLENGE).unwrap();
        assert_eq!(
            classify_health(&json!({"ok":true}), 7376, &["pgt_home"], CHALLENGE, Some(&right)),
            Health::NotPermaura
        );
        assert_eq!(
            classify_health(&serde_json::Value::Null, 7376, &["pgt_home"], CHALLENGE, None),
            Health::NotPermaura
        );
    }

    /// The incident: a gateway left by `nohup` on a deleted binary and a deleted store, holding the
    /// token its own boot published rather than the one a reinstall wrote. The message has to name
    /// the pid, say the binary is gone, say why it is not this home's, and give the ways out.
    #[test]
    fn a_stale_gateway_is_named_with_its_deleted_binary_and_the_force_fix() {
        let text = explain_addr_in_use(
            addr(),
            Some(&deleted_gateway()),
            &Health::Unconfirmed(Unproven::WrongProof),
            Path::new("/Users/x/.permaura/operator.token"),
        );
        assert!(text.starts_with("127.0.0.1:7376 is already in use: something answering like a Permaura gateway holds 127.0.0.1:7376 (pid 4242, /Users/x/.permaura/bin/permaura, no longer on disk), but it did not prove it is this home's: it holds a different operator token"), "{text}");
        assert!(text.contains("It was not sent this home's operator token, and nothing here will stop it."), "{text}");
        assert!(text.contains("permaura stop --force"), "{text}");
        assert!(text.contains("`kill 4242`"), "{text}");
        assert!(text.contains("PERMAURA_ADDR=127.0.0.1:7377 permaura start"), "{text}");
        assert!(!text.contains('\u{2014}'), "no em-dashes: {text}");
    }

    #[test]
    fn a_gateway_too_old_to_prove_itself_is_named_as_such_and_not_trusted() {
        let text = explain_addr_in_use(
            addr(),
            Some(&deleted_gateway()),
            &Health::Unconfirmed(Unproven::NoProof),
            Path::new("t"),
        );
        assert!(text.contains("did not prove it is this home's: it sent no proof at all, so it is a gateway older than 1.3.41 or a program imitating one"), "{text}");
        assert!(text.contains("nothing here will stop it"), "{text}");
        let none = explain_addr_in_use(addr(), None, &Health::Unconfirmed(Unproven::NoToken), Path::new("/h/operator.token"));
        assert!(none.contains("this home has no /h/operator.token for it to prove it holds"), "{none}");
    }

    #[test]
    fn a_gateway_serving_this_home_means_there_is_nothing_to_start() {
        let mut h = deleted_gateway();
        h.exe_on_disk = true;
        let text = explain_addr_in_use(addr(), Some(&h), &Health::Ours, Path::new("/Users/x/.permaura/operator.token"));
        assert!(text.contains("a Permaura gateway is already serving this home on 127.0.0.1:7376 (pid 4242, /Users/x/.permaura/bin/permaura): it proved it holds /Users/x/.permaura/operator.token"), "{text}");
        assert!(!text.contains("no longer on disk"), "{text}");
        assert!(text.contains("`permaura status`"), "{text}");
        assert!(!text.contains("--force"), "{text}");
    }

    #[test]
    fn a_foreign_listener_is_named_and_another_port_is_offered() {
        let h = Holder {
            pid: 77,
            name: "node".into(),
            exe: Some("/usr/local/bin/node".into()),
            exe_on_disk: true,
        };
        let text = explain_addr_in_use(addr(), Some(&h), &Health::NotPermaura, Path::new("t"));
        assert!(
            text.contains(
                "something that is not a Permaura gateway holds 127.0.0.1:7376 (pid 77, node)"
            ),
            "{text}"
        );
        assert!(
            text.contains("PERMAURA_ADDR=127.0.0.1:7377 permaura start"),
            "{text}"
        );
        assert!(!text.contains("--force"), "{text}");
        assert!(text.contains(PORT_HELP_URL), "the caveats are linked: {text}");
        let silent = explain_addr_in_use(addr(), Some(&h), &Health::Unreachable, Path::new("t"));
        assert!(silent.contains("does not answer HTTP"), "{silent}");
        assert!(silent.contains(PORT_HELP_URL), "{silent}");
    }

    /// A gateway of ours on the port is diagnosed in full here, so it must NOT be sent to a web page.
    #[test]
    fn our_own_gateway_on_the_port_is_answered_in_place_not_linked_away() {
        for health in [
            Health::Ours,
            Health::Unconfirmed(Unproven::NoToken),
            Health::Unconfirmed(Unproven::NoProof),
            Health::Unconfirmed(Unproven::WrongProof),
        ] {
            let text = explain_addr_in_use(addr(), Some(&deleted_gateway()), &health, Path::new("t"));
            assert!(!text.contains(PORT_HELP_URL), "{health:?} should not need the docs: {text}");
            assert!(!text.contains('\u{2014}'), "{text}");
        }
    }

    #[test]
    fn an_unnamed_holder_still_gets_a_diagnosis_without_a_kill_hint() {
        let text = explain_addr_in_use(addr(), None, &Health::Unconfirmed(Unproven::WrongProof), Path::new("t"));
        assert!(text.contains("(pid unknown)"), "{text}");
        assert!(text.contains("permaura stop --force"), "{text}");
        assert!(!text.contains("`kill "), "{text}");
    }

    #[test]
    fn a_rejected_shutdown_is_explained_and_force_is_offered_only_when_asked() {
        let with = explain_rejected_shutdown(addr(), Some(&deleted_gateway()), true);
        assert!(
            with.contains("rejected this home's operator token"),
            "{with}"
        );
        assert!(
            with.contains("pid 4242, /Users/x/.permaura/bin/permaura, no longer on disk"),
            "{with}"
        );
        assert!(with.contains("permaura stop --force"), "{with}");
        let without = explain_rejected_shutdown(addr(), Some(&deleted_gateway()), false);
        assert!(!without.contains("--force"), "{without}");
    }

    /// How a test listener answers `/health`.
    #[derive(Clone)]
    enum Answer {
        /// The body and nothing else: a gateway older than 1.3.41, or a squatter imitating one.
        NoProof,
        /// The body and a proof keyed on some other token.
        WrongProof,
        /// The body and the proof the given token gives.
        ProofFor(String),
    }

    /// A loopback listener that answers `/health` as a Permaura gateway (with whatever proof `answer`
    /// says) and every other path with `{}`, and keeps every request it got, lowercased.
    fn recording_gateway(answer: Answer) -> (SocketAddr, std::sync::Arc<std::sync::Mutex<Vec<String>>>, std::net::TcpListener) {
        recording_gateway_on(std::net::Ipv4Addr::LOCALHOST.into(), answer)
    }

    /// [`recording_gateway`] listening on `ip` instead of loopback.
    fn recording_gateway_on(
        ip: std::net::IpAddr,
        answer: Answer,
    ) -> (SocketAddr, std::sync::Arc<std::sync::Mutex<Vec<String>>>, std::net::TcpListener) {
        use std::io::{Read as _, Write as _};
        // macOS lets this bind share a port with another process's wildcard listener, and these tests ask who listens on the port, so take one no other process listens on.
        let listener = (0..50)
            .map(|_| std::net::TcpListener::bind(SocketAddr::new(ip, 0)).expect("bind a listener"))
            .find(|l| listening_pids(l.local_addr().unwrap()).is_none_or(|pids| pids == [std::process::id()]))
            .expect("a port no other process listens on");
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let (accepting, log) = (listener.try_clone().unwrap(), seen.clone());
        std::thread::spawn(move || {
            for stream in accepting.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                // Headers, then as much body as they announce, so a POST's JSON is captured too.
                loop {
                    let n = stream.read(&mut buf).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&raw).to_ascii_lowercase();
                    if let Some(end) = text.find("\r\n\r\n") {
                        let want = text[..end]
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if raw.len() >= end + 4 + want {
                            break;
                        }
                    }
                }
                let request = String::from_utf8_lossy(&raw).to_string();
                log.lock().unwrap().push(request.to_ascii_lowercase());
                let challenge = request
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case(permaura_core::health_proof::CHALLENGE_HEADER).then(|| value.trim().to_string())
                    })
                    .unwrap_or_default();
                let health = request.starts_with("GET /health ");
                let proof = match (&answer, health) {
                    (Answer::ProofFor(token), true) => permaura_core::health_proof::proof(token, addr.port(), &challenge),
                    (Answer::WrongProof, true) => permaura_core::health_proof::proof("pgt_not_this_homes", addr.port(), &challenge),
                    _ => None,
                };
                // The only write these tests send is the `vault add` of `sec_proof`, answered as a gateway answers a stored secret.
                let body = if health {
                    r#"{"status":"ok","service":"permaura-gateway"}"#
                } else {
                    r#"{"secret_id":"sec_proof","value":"[REDACTED]"}"#
                };
                let proof = proof
                    .map(|p| format!("{}: {p}\r\n", permaura_core::health_proof::PROOF_HEADER))
                    .unwrap_or_default();
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n{proof}connection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        (addr, seen, listener)
    }

    fn block_on<T>(f: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Runtime::new().unwrap().block_on(f)
    }

    fn scratch_home(tag: &str, token: &str) -> PathBuf {
        let home = std::env::temp_dir().join(format!("pm-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("operator.token"), token).unwrap();
        home
    }

    fn assert_nothing_presented(requests: &[String], token: &str) {
        assert!(!requests.is_empty(), "it did ask /health");
        for r in requests {
            assert!(!r.contains(&token.to_ascii_lowercase()), "the token went to the holder: {r}");
            assert!(!r.contains("authorization:"), "no bearer of any kind: {r}");
            assert!(r.starts_with("get /health "), "nothing but the challenge was sent: {r}");
        }
    }

    /// The original flaw: a listener that answers like a Permaura gateway, running as this user,
    /// was handed this home's operator token. Without the proof it must be sent nothing, by every
    /// path that has the token to send: `start`'s diagnosis, every CLI request, and `stop`'s
    /// graceful path, for a listener that sends no proof and for one that sends the wrong one.
    #[test]
    fn a_permaura_shaped_listener_that_cannot_prove_it_holds_the_token_is_sent_nothing() {
        let token = "pgt_proofsquattertoken";
        let home = scratch_home("proof-unproven", token);
        for (answer, why) in [(Answer::NoProof, Unproven::NoProof), (Answer::WrongProof, Unproven::WrongProof)] {
            let (addr, seen, _held) = recording_gateway(answer);
            assert!(listener_is_this_users(addr), "the old gate passes, which is the point");
            let url = format!("http://{addr}");
            let (health, text, bearer, sent, graceful) = crate::cli::with_permaura_home(&home, || {
                block_on(async {
                    let ctx = super::super::commands::Ctx::new(url.clone(), None);
                    (
                        probe_health(addr, &[token]).await,
                        diagnose_addr_in_use(addr).await,
                        ctx.bearer().await,
                        bearer_for(&url, None, operator_token).await,
                        graceful_shutdown(addr, token).await,
                    )
                })
            });
            assert_eq!(health, Health::Unconfirmed(why));
            assert!(text.contains("something answering like a Permaura gateway holds"), "{text}");
            assert!(text.contains("did not prove it is this home's"), "{text}");
            let refused = bearer.unwrap_err();
            assert!(refused.0.contains("was not sent"), "{refused}");
            assert!(!refused.0.contains('\u{2014}'), "{refused}");
            assert!(sent.is_err());
            assert!(matches!(graceful, Graceful::NotProven(w) if w == why), "{graceful:?}");
            assert_nothing_presented(&seen.lock().unwrap(), token);
        }
        let _ = std::fs::remove_dir_all(&home);
    }

    /// `start --pair` on a wildcard bind hands the link to `http://0.0.0.0:<port>`: the operator bearer goes there only after the listener on this machine's loopback, where a gateway bound to every interface answers, proves it holds the token, and a listener that does not is sent nothing.
    #[test]
    fn a_wildcard_address_gets_the_operator_bearer_only_after_the_proof() {
        let token = "pgt_proofwildcardtoken";
        let (addr, seen, _held) = recording_gateway(Answer::ProofFor(token.into()));
        let applied = block_on(super::super::announce::apply(&format!("http://0.0.0.0:{}", addr.port()), token, "gw_wildcard", "gwa_wildcard"));
        assert!(matches!(applied, super::super::announce::Applied::Live { .. }), "the proven gateway takes the link");
        let requests = seen.lock().unwrap().clone();
        assert!(requests.first().is_some_and(|r| r.starts_with("get /health ") && r.contains(permaura_core::health_proof::CHALLENGE_HEADER)), "{requests:?}");
        assert!(requests.iter().any(|r| r.starts_with("put /v1/announce ") && r.contains(&format!("authorization: bearer {token}"))), "{requests:?}");

        let (addr, seen, _held) = recording_gateway(Answer::NoProof);
        let applied = block_on(super::super::announce::apply(&format!("http://0.0.0.0:{}", addr.port()), token, "gw_wildcard", "gwa_wildcard"));
        assert!(matches!(applied, super::super::announce::Applied::Refused(_)));
        assert_nothing_presented(&seen.lock().unwrap(), token);
    }

    /// An http gateway that is not on this machine is refused before anything is sent: no proof run over the network makes a bearer in clear safe.
    #[test]
    fn an_http_gateway_elsewhere_is_refused_before_anything_is_sent() {
        let started = std::time::Instant::now();
        let applied = block_on(super::super::announce::apply("http://192.0.2.10:7376", "pgt_proofelsewhere", "gw_elsewhere", "gwa_elsewhere"));
        let super::super::announce::Applied::Refused(why) = applied else { panic!("sent to a gateway elsewhere over http") };
        assert!(why.contains("not on this machine"), "{why}");
        assert!(started.elapsed() < Duration::from_secs(1), "refused without dialing");
    }

    /// The address the default route leaves from, which is one of this machine's own, or `None` on a host with no network.
    fn route_address() -> Option<std::net::IpAddr> {
        std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| s.connect("192.0.2.1:9").map(|()| s))
            .and_then(|s| s.local_addr())
            .ok()
            .map(|a| a.ip())
            .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
    }

    /// Whether an address is this machine's is read from its interface list, not from whether a socket binds it: with `ip_nonlocal_bind` set, as on keepalived and HAProxy hosts, any address binds, and a URL naming a remote one would be sent the operator token in clear after a relayed proof.
    #[test]
    fn this_machines_own_address_is_read_from_its_interfaces_not_a_bind() {
        let Some(ip) = route_address() else {
            eprintln!("no non-loopback address on this machine; skipped");
            return;
        };
        assert!(!this_machine_has(ip, &[]), "an address no interface carries is not this machine's, whatever a bind says");
        assert!(this_machine_has(ip, &[ip]));
        assert!(interface_addresses().contains(&ip), "the interface list names the route's own address");
    }

    /// Whether a request sent to `addr` is answered within the probe's own two seconds.
    ///
    /// A connect alone proves nothing: the macOS Application Firewall completes the handshake for a binary it has not been told to allow and then holds the flow, so the listener never sees the request.
    fn answers_there(addr: SocketAddr) -> bool {
        use std::io::{Read as _, Write as _};
        let Ok(mut stream) = std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2)) else { return false };
        let mut first = [0u8; 1];
        stream.set_read_timeout(Some(Duration::from_secs(2))).is_ok()
            && stream.write_all(b"GET /reachable HTTP/1.1\r\nhost: reachable\r\n\r\n").is_ok()
            && matches!(stream.read(&mut first), Ok(1))
    }

    /// The check that gates the proof half takes an answer, not a handshake: a listener that answers is reachable, and one whose handshake completes but which never reads, as a held flow looks from the client, is not.
    #[test]
    fn reachability_takes_an_answer_not_a_handshake() {
        let (addr, _seen, _held) = recording_gateway(Answer::NoProof);
        assert!(answers_there(addr), "a listener that answers is reachable");
        let silent = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        assert!(!answers_there(silent.local_addr().unwrap()), "a completed handshake alone is not reachability");
    }

    /// Whether the own-address test may skip its proof half on `os` (`std::env::consts::OS`) when this machine's own address cannot be reached: only on macOS, whose Application Firewall holds a freshly built test binary's inbound connections until someone answers its prompt. Anywhere else, CI's Linux lane included, an unreachable own address fails the test.
    fn own_address_may_skip_on(os: &str) -> bool {
        os == "macos"
    }

    /// The proof half cannot be skipped on Linux or Windows: only macOS has the firewall hold the skip exists for.
    #[test]
    fn only_macos_may_skip_the_own_address_proof() {
        assert!(!own_address_may_skip_on("linux"));
        assert!(!own_address_may_skip_on("windows"));
        assert!(!own_address_may_skip_on("freebsd"));
        assert!(own_address_may_skip_on("macos"));
    }

    /// A gateway bound to one of this machine's own non-loopback addresses is local too: it is asked for the proof there and, once it gives it, sent the bearer there.
    #[test]
    fn a_gateway_on_this_machines_own_address_is_proved_there() {
        let Some(ip) = std::net::UdpSocket::bind("0.0.0.0:0")
            .and_then(|s| s.connect("192.0.2.1:9").map(|()| s))
            .and_then(|s| s.local_addr())
            .ok()
            .map(|a| a.ip())
            .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        else {
            assert!(own_address_may_skip_on(std::env::consts::OS), "no non-loopback address on this machine, so the own-address proof did not run");
            eprintln!("no non-loopback address on this machine; skipped");
            return;
        };
        let token = "pgt_proofownaddrtoken";
        let home = scratch_home("proof-ownaddr", token);
        let (addr, seen, _held) = recording_gateway_on(ip, Answer::ProofFor(token.into()));
        assert_eq!(local_addr_of(&format!("http://{addr}")), Some(addr));
        if !answers_there(addr) {
            let _ = std::fs::remove_dir_all(&home);
            assert!(own_address_may_skip_on(std::env::consts::OS), "a request to {addr}, this machine's own address, was never answered, so the own-address proof did not run");
            eprintln!("a request to {addr} never reached its listener: the macOS Application Firewall holds a new test binary's inbound connections until its prompt is answered; the proof half skipped");
            return;
        }
        let sent = crate::cli::with_permaura_home(&home, || block_on(bearer_for(&format!("http://{addr}"), None, operator_token)));
        let _ = std::fs::remove_dir_all(&home);
        assert_eq!(sent.as_ref().ok().and_then(|s| s.as_deref()), Some(token), "answer: {sent:?}; requests: {:?}", seen.lock().unwrap());
    }

    /// A refused request carries nothing at all, body included: `vault add` puts a secret there.
    #[test]
    fn a_refused_request_sends_no_body_either() {
        let token = "pgt_proofbodytoken";
        let home = scratch_home("proof-body", token);
        let (addr, seen, _held) = recording_gateway(Answer::NoProof);
        let ctx = super::super::commands::Ctx::new(format!("http://{addr}"), None);
        let var = format!("PM_PROOF_REFUSED_SECRET_{}", std::process::id());
        std::env::set_var(&var, "secret-value-xyz");
        let result = crate::cli::with_permaura_home(&home, || {
            block_on(super::super::commands::vault_add(&ctx, "sec_proof", Some(var.clone())))
        });
        let _ = std::fs::remove_dir_all(&home);
        assert!(result.is_err(), "refused");
        let requests = seen.lock().unwrap().clone();
        assert_nothing_presented(&requests, token);
        assert!(requests.iter().all(|r| !r.contains("secret-value-xyz")), "{requests:?}");
    }

    /// The same listener with the right proof is this home's gateway, and only then gets the token.
    #[test]
    fn a_listener_that_proves_it_holds_the_token_is_ours_and_gets_it() {
        let token = "pgt_proofrealgateway";
        let home = scratch_home("proof-proven", token);
        let (addr, seen, _held) = recording_gateway(Answer::ProofFor(token.into()));
        let url = format!("http://{addr}");
        let (health, text, bearer) = crate::cli::with_permaura_home(&home, || {
            block_on(async {
                let ctx = super::super::commands::Ctx::new(url.clone(), None);
                (probe_health(addr, &[token]).await, diagnose_addr_in_use(addr).await, ctx.bearer().await)
            })
        });
        let _ = std::fs::remove_dir_all(&home);
        assert_eq!(health, Health::Ours);
        assert!(text.contains("a Permaura gateway is already serving this home"), "{text}");
        assert_eq!(bearer.unwrap().as_deref(), Some(token));
        // Proving it took challenges only: the diagnosis and the probes sent no bearer either.
        assert_nothing_presented(&seen.lock().unwrap(), token);
    }

    /// The real request path end to end: once proven, the request itself carries the token.
    #[test]
    fn a_proven_gateway_is_sent_the_token_on_the_request_that_follows() {
        let token = "pgt_prooffollowup";
        let home = scratch_home("proof-followup", token);
        let (addr, seen, _held) = recording_gateway(Answer::ProofFor(token.into()));
        let ctx = super::super::commands::Ctx::new(format!("http://{addr}"), None);
        let var = format!("PM_PROOF_PROVEN_SECRET_{}", std::process::id());
        std::env::set_var(&var, "secret-value-xyz");
        let result = crate::cli::with_permaura_home(&home, || {
            block_on(super::super::commands::vault_add(&ctx, "sec_proof", Some(var.clone())))
        });
        let _ = std::fs::remove_dir_all(&home);
        assert!(result.is_ok(), "{result:?}");
        let requests = seen.lock().unwrap().clone();
        let posted: Vec<&String> = requests.iter().filter(|r| r.starts_with("post ")).collect();
        assert_eq!(posted.len(), 1, "{requests:?}");
        assert!(posted[0].contains(&format!("authorization: bearer {token}")), "{}", posted[0]);
        let probes = requests.iter().filter(|r| r.starts_with("get /health ")).count();
        assert_eq!(probes + 1, requests.len(), "the challenge is the only other request: {requests:?}");
    }

    /// A token named with `--token` is proved and sent the same way; this home's file is not read
    /// into the request.
    #[test]
    fn a_named_token_is_presented_once_the_listener_proves_it_holds_it() {
        let home = scratch_home("proof-named", "pgt_thishome");
        let (addr, seen, _held) = recording_gateway(Answer::ProofFor("pgt_explicit".into()));
        let ctx = super::super::commands::Ctx::new(format!("http://{addr}"), Some("pgt_explicit".into()));
        let bearer = crate::cli::with_permaura_home(&home, || block_on(ctx.bearer()));
        let _ = std::fs::remove_dir_all(&home);
        assert_eq!(bearer.unwrap().as_deref(), Some("pgt_explicit"));
        assert_nothing_presented(&seen.lock().unwrap(), "pgt_explicit");
    }

    #[test]
    fn a_listener_this_process_opened_is_this_users_and_a_closed_port_is_nobodys() {
        let (addr, _seen, held) = recording_gateway(Answer::NoProof);
        assert!(listener_is_this_users(addr));
        drop(held);
        // The accept thread holds a clone of the socket, so a fresh port is the clean "nothing here".
        let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        assert!(!listener_is_this_users(free));
        assert_eq!(block_on(listener_at(free, &["pgt_x"])), Listener::Nobody);
    }

    /// The Windows flake: every connection the gateway closes first leaves a TIME_WAIT row on its port,
    /// owned by pid 0, and a lookup that took the first row with that port could name that instead of
    /// the listener. Many such rows, then the check, so a lookup that reads them cannot pass.
    #[test]
    fn closed_connections_on_the_port_do_not_hide_this_users_listener() {
        use std::io::Read as _;
        let (addr, _seen, _held) = recording_gateway(Answer::NoProof);
        for _ in 0..24 {
            let mut c = std::net::TcpStream::connect(addr).unwrap();
            std::io::Write::write_all(&mut c, b"GET /health HTTP/1.1\r\nhost: x\r\n\r\n").unwrap();
            let _ = c.read_to_end(&mut Vec::new());
        }
        for _ in 0..8 {
            assert!(listener_is_this_users(addr));
        }
        // Not an exact match: another process here may hold a wildcard listener on the same ephemeral port, which accepts connections to `addr` too.
        let pids = listening_pids(addr).expect("the OS lists its listeners");
        assert!(pids.contains(&std::process::id()), "{pids:?}");
        assert!(!pids.contains(&0), "a TIME_WAIT row's pid 0 is not a listener: {pids:?}");
    }

    #[test]
    fn a_loopback_listener_is_sent_a_token_only_once_it_has_proved_it() {
        let path = Path::new("/h/operator.token");
        let home = || Some("pgt_x".to_string());
        let decide = |explicit: Option<&str>, home: Option<String>, l: Listener| local_bearer(addr(), explicit, home, l, path);
        assert_eq!(decide(None, home(), Listener::Ours).unwrap().as_deref(), Some("pgt_x"));
        assert_eq!(decide(Some("pgt_named"), home(), Listener::Ours).unwrap().as_deref(), Some("pgt_named"));
        assert_eq!(decide(None, home(), Listener::Nobody).unwrap(), None);
        for listener in [
            Listener::Unproven(Unproven::NoToken),
            Listener::Unproven(Unproven::NoProof),
            Listener::Unproven(Unproven::WrongProof),
            Listener::NotThisUser,
            Listener::Foreign,
        ] {
            for explicit in [None, Some("pgt_named")] {
                let refused = decide(explicit, home(), listener).unwrap_err();
                assert!(refused.0.starts_with("refusing to talk to 127.0.0.1:7376"), "{listener:?}: {refused}");
                assert!(!refused.0.contains("pgt_"), "{refused}");
                assert!(!refused.0.contains('\u{2014}'), "{refused}");
            }
            // No token to lose, but `vault add` carries a secret in the body: still nothing is sent.
            assert!(decide(None, None, listener).is_err());
        }
        assert!(decide(None, home(), Listener::Unproven(Unproven::NoProof)).unwrap_err().0.contains("older than 1.3.41"));
        assert!(decide(None, home(), Listener::NotThisUser).unwrap_err().0.contains("not running as you"));
    }

    /// This machine's operator token belongs to the gateway on this machine. A `--url` elsewhere gets
    /// only a token named for it, and never over plain http, which would carry it (and any secret in a
    /// body) across the network in the clear.
    #[test]
    fn a_remote_url_never_gets_this_homes_token_and_plain_http_gets_nothing() {
        let home = scratch_home("remote", "pgt_thismachinesonly");
        let bearer = |url: &str, explicit: Option<&str>| {
            block_on(super::super::commands::Ctx::new(url.into(), explicit.map(str::to_string)).bearer())
        };
        crate::cli::with_permaura_home(&home, || {
            assert_eq!(bearer("https://my-vps.permaura.app", None).unwrap(), None, "not the local token");
            assert_eq!(
                bearer("https://my-vps.permaura.app", Some("pgt_named")).unwrap().as_deref(),
                Some("pgt_named"),
                "an explicit token over https still works"
            );
            for url in ["http://my-vps.permaura.app:7376", "http://10.0.0.5:7376"] {
                for explicit in [None, Some("pgt_named")] {
                    let refused = bearer(url, explicit).unwrap_err();
                    assert!(refused.0.contains("https"), "{url} {explicit:?}: {refused}");
                    assert!(!refused.0.contains('\u{2014}'), "{refused}");
                }
            }
        });
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn only_loopback_urls_name_a_local_socket() {
        assert_eq!(local_addr_of("http://127.0.0.1:7376"), Some(addr()));
        assert_eq!(local_addr_of("http://localhost:7376/"), Some(addr()));
        assert_eq!(
            local_addr_of("http://[::1]:7376"),
            Some("[::1]:7376".parse().unwrap())
        );
        assert_eq!(local_addr_of("https://my-vps.permaura.app"), None);
        assert_eq!(local_addr_of("http://10.0.0.5:7376"), None);
    }

    /// The address split: a `localhost` URL was proved at 127.0.0.1 and then sent wherever `localhost` resolved, which on macOS is ::1 first.
    #[test]
    fn a_localhost_url_is_sent_to_the_address_that_was_proved() {
        use std::io::{Read, Write};
        let v4 = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = v4.local_addr().unwrap().port();
        let Ok(v6) = std::net::TcpListener::bind(("::1", port)) else {
            eprintln!("no IPv6 loopback on this host, nothing to split");
            return;
        };
        for (listener, name) in [(v4, "127.0.0.1"), (v6, "::1")] {
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { continue };
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf);
                    let reply = format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{name}", name.len());
                    let _ = stream.write_all(reply.as_bytes());
                }
            });
        }
        let url = format!("http://localhost:{port}");
        let answered = block_on(async {
            let client = client_for(&url, Some(Duration::from_secs(5))).unwrap();
            client.get(format!("{url}/health")).send().await.unwrap().text().await.unwrap()
        });
        assert_eq!(answered, "127.0.0.1", "proved at {:?}", local_addr_of(&url));
    }
}
