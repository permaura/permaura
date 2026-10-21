//! `permaura uninstall`: the CLI counterpart of the desktop app's removal, for a `curl | sh` install.
//!
//! Uninstalling means UNLINKING. The account links are revoked first, while the install identity that
//! authorises revoking them still exists; then the gateway is stopped (by force if it is not this
//! home's), the boot service the installer registered is removed, the PATH link goes, and the binary
//! goes last. Data stays unless `--purge-data`, so a reinstall resumes; with it, the vault key is
//! forgotten before the files are deleted, while the binary that owns the Keychain entry still exists.
//!
//! The order is a pure plan over a handful of facts, so the sequence can be asserted without a machine
//! to take apart.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{anyhow, Context as _};

use super::commands::{self, Ctx};
use super::port;

/// The systemd unit name the installer writes, and the launchd label.
const SERVICE_NAME: &str = "permaura";
const LAUNCHD_LABEL: &str = "com.permaura.gateway";

/// Files in the Permaura home that hold the gateway's own state. Everything else (config.toml,
/// account.json, gateway.id) is the operator's or is handled elsewhere. `gateway.db.lock` is left on
/// purpose: a gateway still waiting on a deleted lock file would lock its unlinked inode while the next
/// one locked a new file at the path, and both would write the store.
const DATA_FILES: &[&str] = &[
    "gateway.db",
    "gateway.db.auditkey",
    "gateway.env",
    "operator.token",
    "cache",
    "vault-kek",
    "vault-kek.in-os-store",
    commands::SEALED_VAULT_KEK,
    "vault-kek.in-systemd-credential",
    "remote.json",
    "tunnel-credentials.json",
    "cloudflared.yml",
    "tunnel.stopped",
    "tunnel.token",
    "install.json",
    permaura_gateway::archive::LOCAL_DIR,
];

/// Where a `--service-user` install puts its home, and the root-owned directory beside it that holds
/// its settings and its TPM-sealed vault key.
const SERVICE_HOME: &str = "/var/lib/permaura";
const SERVICE_ETC: &str = "/etc/permaura";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    SystemUnit,
    UserUnit,
    LaunchAgent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceFile {
    pub kind: ServiceKind,
    pub path: PathBuf,
}

/// What the planner needs to know about this machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    pub addr: SocketAddr,
    pub has_install_identity: bool,
    pub purge_data: bool,
    pub services: Vec<ServiceFile>,
    pub binaries: Vec<PathBuf>,
    pub data: Vec<PathBuf>,
    /// Sealed copies of the vault key outside the home, removed when the key is forgotten.
    pub sealed_keys: Vec<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    RevokeLinks,
    StopGateway(SocketAddr),
    RemoveBootPersistence(Vec<ServiceFile>),
    Unlink,
    ForgetVaultKey(Vec<PathBuf>),
    PurgeData(Vec<PathBuf>),
    RemoveBinary(PathBuf),
}

impl Step {
    fn describe(&self) -> String {
        match self {
            Step::RevokeLinks => {
                "revoke this machine's links from every permaura.com workspace".into()
            }
            Step::StopGateway(addr) => {
                format!("stop the gateway on {addr} (by force if it is not this home's)")
            }
            Step::RemoveBootPersistence(files) => format!(
                "remove the boot service: {}",
                files
                    .iter()
                    .map(|f| f.path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Step::Unlink => "remove the `permaura` link from PATH".into(),
            Step::ForgetVaultKey(sealed) if sealed.is_empty() => {
                "forget the vault key (every sealed secret becomes unreadable)".into()
            }
            Step::ForgetVaultKey(sealed) => format!(
                "forget the vault key, including its TPM-sealed copy at {} (every sealed secret becomes unreadable)",
                sealed
                    .iter()
                    .map(|f| f.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Step::PurgeData(files) => format!(
                "delete {}",
                files
                    .iter()
                    .map(|f| f.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            Step::RemoveBinary(p) => format!("delete {}", p.display()),
        }
    }
}

/// The steps, in order, for these facts.
pub fn plan(f: &Facts) -> Vec<Step> {
    let mut steps = Vec::new();
    if f.has_install_identity {
        steps.push(Step::RevokeLinks);
    }
    steps.push(Step::StopGateway(f.addr));
    if !f.services.is_empty() {
        steps.push(Step::RemoveBootPersistence(f.services.clone()));
    }
    steps.push(Step::Unlink);
    if f.purge_data {
        steps.push(Step::ForgetVaultKey(f.sealed_keys.clone()));
        if !f.data.is_empty() {
            steps.push(Step::PurgeData(f.data.clone()));
        }
    }
    for b in &f.binaries {
        steps.push(Step::RemoveBinary(b.clone()));
    }
    steps
}

/// Which of a home's entries a purge deletes. The schema backups and any archive a reinstall moved aside
/// are matched rather than listed, since the set is whatever this install has been through.
pub fn purge_targets(entries: &[String]) -> Vec<String> {
    let mut out: Vec<String> = entries
        .iter()
        .filter(|e| {
            DATA_FILES.contains(&e.as_str())
                || e.starts_with("gateway.db.backup-v")
                || e.starts_with(&format!("{}.foreign-", permaura_gateway::archive::LOCAL_DIR))
        })
        .cloned()
        .collect();
    out.sort();
    out
}

pub async fn run(ctx: &Ctx, purge_data: bool, yes: bool) -> anyhow::Result<()> {
    let home = permaura_core::permaura_home()
        .context("could not resolve ~/.permaura: set PERMAURA_HOME or HOME")?;
    let facts = gather(ctx, &home, purge_data)?;
    let steps = plan(&facts);

    commands::heading("Uninstall Permaura");
    println!("Home: {}", home.display());
    for (i, step) in steps.iter().enumerate() {
        println!("  {}. {}", i + 1, step.describe());
    }
    if !purge_data {
        println!(
            "  (data under {} stays; a reinstall resumes with it. Add --purge-data to delete it.)",
            home.display()
        );
    }
    println!();
    if !yes {
        if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            return Err(anyhow!(
                "stdin is not a terminal, so nothing can be confirmed: re-run with --yes"
            ));
        }
        if !commands::confirm("Proceed?")? {
            println!("Nothing was changed.");
            return Ok(());
        }
    }

    let store_db = permaura_gateway::store_path_from_env()
        .filter(|db| db != ":memory:")
        .unwrap_or_else(|| home.join("gateway.db").to_string_lossy().into_owned());
    let mut summary: Vec<String> = Vec::new();
    for step in &steps {
        match step {
            Step::RevokeLinks => match revoke_links().await {
                Ok(lines) => summary.extend(lines),
                Err(e) if purge_data => {
                    commands::deny(&format!("could not revoke this machine's links: {e:#}"));
                    return Err(anyhow!(
                        "aborting before anything is removed: --purge-data would delete install.json, after which these links could never be revoked. Retry when permaura.com is reachable, or run without --purge-data"
                    ));
                }
                Err(e) => {
                    let line = format!("links NOT revoked ({e:#}); remove this gateway from each workspace in the console");
                    commands::deny(&line);
                    summary.push(line);
                }
            },
            Step::StopGateway(addr) => summary.push(stop_gateway(*addr, &store_db).await?),
            Step::RemoveBootPersistence(files) => {
                for f in files {
                    summary.push(remove_service(f));
                }
                // A supervised gateway stopped a step ago may have been restarted by its service manager
                // before the service was removed, so the port is checked once more.
                if !port::is_free(facts.addr) {
                    summary.push(stop_gateway(facts.addr, &store_db).await?);
                }
            }
            Step::Unlink => {
                super::link::unlink()?;
                summary.push(
                    "removed the `permaura` link from PATH, where Permaura had put one".into(),
                );
            }
            Step::ForgetVaultKey(sealed) => {
                // Before the key and the files go: nothing may still hold the store they belong to.
                summary.extend(wait_store_released(&store_db, port::STOP_EXIT_WINDOW, STALE_HOLDER_GRACE).await?);
                match commands::forget_vault_kek() {
                    Ok(()) => summary.push("forgot the vault key".into()),
                    Err(e) => summary.push(format!("vault key NOT fully forgotten ({e:#})")),
                }
                for f in sealed.iter().filter(|f| f.exists()) {
                    summary.push(remove_path(f));
                }
            }
            Step::PurgeData(files) => {
                // Forgetting the vault key a step ago already took vault-kek, its sealed copy and
                // both markers.
                summary.extend(wait_store_released(&store_db, port::STOP_EXIT_WINDOW, STALE_HOLDER_GRACE).await?);
                for f in files.iter().filter(|f| f.exists()) {
                    summary.push(remove_path(f));
                }
            }
            Step::RemoveBinary(p) => summary.push(remove_binary(p)),
        }
    }

    println!();
    commands::heading("Uninstall summary");
    for line in &summary {
        println!("  - {line}");
    }
    if purge_data {
        println!("Permaura is gone from this machine.");
    } else {
        println!("Permaura is gone from this machine; its data stays under {}. Reinstall to resume, then pair again to reconnect.", home.display());
    }
    Ok(())
}

fn gather(ctx: &Ctx, home: &Path, purge_data: bool) -> anyhow::Result<Facts> {
    // The address `start` would bind for this home, which is what a running gateway of ours holds.
    let addr: SocketAddr = match std::env::var("PERMAURA_ADDR")
        .ok()
        .filter(|v| !v.is_empty())
    {
        Some(v) => v
            .parse()
            .map_err(|e| anyhow!("invalid PERMAURA_ADDR: {e}"))?,
        None => port::local_addr_of(&ctx.url).ok_or_else(|| {
            anyhow!(
                "uninstall acts on this machine, but --url names a gateway elsewhere ({})",
                ctx.url
            )
        })?,
    };
    let entries: Vec<String> = std::fs::read_dir(home)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    let data = purge_targets(&entries)
        .into_iter()
        .map(|n| home.join(n))
        .collect();

    let mut binaries = Vec::new();
    if let Ok(me) = std::env::current_exe() {
        binaries.push(me);
    }
    if let Some(installed) = permaura_core::permaura_path("bin").map(|p| p.join(exe_name())) {
        if installed.is_file() && !binaries.iter().any(|b| same_file(b, &installed)) {
            binaries.push(installed);
        }
    }

    let etc_env = std::fs::read_to_string(Path::new(SERVICE_ETC).join("gateway.env")).ok();
    let sealed_keys = sealed_key_outside_home(home, etc_env.as_deref())
        .into_iter()
        .filter(|p| p.exists())
        .collect();

    Ok(Facts {
        addr,
        has_install_identity: home.join("install.json").is_file(),
        purge_data,
        sealed_keys,
        services: service_files()
            .into_iter()
            .filter(|f| f.path.exists())
            .collect(),
        binaries,
        data,
    })
}

/// The sealed vault key a `--service-user` install keeps in `/etc/permaura`, when `home` is that
/// install's home. `etc_env` is its root-owned `gateway.env`, whose `PERMAURA_HOME` names the home it
/// belongs to; unreadable, the install's fixed home stands in. Tied to the home being purged and never to
/// the file merely existing, so purging another home on the machine cannot take this install's key.
fn sealed_key_outside_home(home: &Path, etc_env: Option<&str>) -> Option<PathBuf> {
    let ours = match etc_env.and_then(super::installer_home_from_env) {
        Some(owner) => Path::new(&owner) == home,
        None => home == Path::new(SERVICE_HOME),
    };
    ours.then(|| Path::new(SERVICE_ETC).join(commands::SEALED_VAULT_KEK))
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => a == b,
    }
}

#[cfg(windows)]
fn exe_name() -> &'static str {
    "permaura.exe"
}

#[cfg(not(windows))]
fn exe_name() -> &'static str {
    "permaura"
}

/// Where the installer's boot persistence lives, whether or not any of it is present.
fn service_files() -> Vec<ServiceFile> {
    let mut v = vec![ServiceFile {
        kind: ServiceKind::SystemUnit,
        path: PathBuf::from(format!("/etc/systemd/system/{SERVICE_NAME}.service")),
    }];
    if let Some(home) = std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
    {
        v.push(ServiceFile {
            kind: ServiceKind::UserUnit,
            path: home
                .join(".config/systemd/user")
                .join(format!("{SERVICE_NAME}.service")),
        });
        v.push(ServiceFile {
            kind: ServiceKind::LaunchAgent,
            path: home
                .join("Library/LaunchAgents")
                .join(format!("{LAUNCHD_LABEL}.plist")),
        });
    }
    v
}

/// List this machine's links and revoke each, reporting per workspace. `Err` only for a failure to
/// reach or be understood by the account API; a single link that will not revoke is reported inline.
async fn revoke_links() -> anyhow::Result<Vec<String>> {
    let install =
        permaura_core::install::load().ok_or_else(|| anyhow!("install.json is unreadable"))?;
    let api = super::enroll::api_base();
    let client = super::enroll::api_client(&api, Duration::from_secs(20))?;
    let creds =
        serde_json::json!({ "installId": install.install_id, "installSecret": install.secret });

    let resp = client
        .post(format!("{api}/api/gateways/links"))
        .json(&creds)
        .send()
        .await
        .context("reaching the account API")
        .and_then(super::port::refuse_redirect)?;
    let status = resp.status();
    if status == reqwest::StatusCode::FORBIDDEN {
        let line = "no permaura.com workspace links this machine".to_string();
        println!("\x1b[2m·\x1b[0m {line}");
        return Ok(vec![line]);
    }
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    anyhow::ensure!(
        status.is_success(),
        "{}",
        body.get("error")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| format!("the account API answered {status}"))
    );
    let links = body
        .get("links")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if links.is_empty() {
        let line = "no permaura.com workspace links this machine".to_string();
        println!("\x1b[2m·\x1b[0m {line}");
        return Ok(vec![line]);
    }

    let mut lines = Vec::new();
    let mut all_revoked = true;
    for link in &links {
        let gid = link.get("gatewayId").and_then(|v| v.as_str()).unwrap_or("");
        let ws = link
            .get("workspaceName")
            .and_then(|v| v.as_str())
            .unwrap_or("a workspace");
        let org = link.get("organizationName").and_then(|v| v.as_str());
        let place = match org {
            Some(o) => format!("{ws} ({o})"),
            None => ws.to_string(),
        };
        let mut req = creds.clone();
        req["gatewayId"] = serde_json::Value::String(gid.to_string());
        let outcome = client
            .post(format!("{api}/api/gateways/links/revoke"))
            .json(&req)
            .send()
            .await
            .map_err(anyhow::Error::from)
            .and_then(super::port::refuse_redirect);
        let line = match outcome {
            Ok(r) if r.status().is_success() => {
                let b: serde_json::Value = r.json().await.unwrap_or(serde_json::Value::Null);
                match b.get("warning").and_then(|v| v.as_str()) {
                    Some(w) => format!("unlinked from {place}; {w}"),
                    None => format!("unlinked from {place}"),
                }
            }
            Ok(r) => {
                all_revoked = false;
                let b: serde_json::Value = r.json().await.unwrap_or(serde_json::Value::Null);
                let why = b.get("error").and_then(|v| v.as_str()).unwrap_or("refused");
                format!("NOT unlinked from {place} ({why}); remove it in the console")
            }
            Err(e) => {
                all_revoked = false;
                format!("NOT unlinked from {place} ({e}); remove it in the console")
            }
        };
        if line.starts_with("NOT") {
            commands::deny(&line);
        } else {
            commands::ok(&line);
        }
        lines.push(line);
    }
    // gateway.id names a link that no longer exists; kept, it would send `permaura remote` asking
    // permaura.com about a gateway row that is gone.
    if all_revoked {
        if let Some(p) = permaura_core::permaura_path("gateway.id") {
            let _ = std::fs::remove_file(p);
        }
    }
    Ok(lines)
}

/// How long a holder of the store has to exit once it has been signalled, before a purge is refused.
const STALE_HOLDER_GRACE: Duration = Duration::from_secs(5);

/// Poll until nothing holds the store at `db`, or `limit` runs out. `Ok(true)` when it was let go.
async fn wait_lock_free(db: &str, limit: Duration) -> anyhow::Result<bool> {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if permaura_gateway::store::lock::holder(db)?.is_none() {
            return Ok(true);
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Wait until nothing holds the store at `db`; once `wait` has passed, signal a holder that runs a
/// Permaura binary (never this process) and wait `grace` more; refuse, naming the holder, if one still
/// holds it. Any gateway of this home counts, on any port and however far into its drain, so a purge
/// never removes a store from under a live process. Returns what it did, for the summary.
async fn wait_store_released(db: &str, wait: Duration, grace: Duration) -> anyhow::Result<Vec<String>> {
    if wait_lock_free(db, wait).await? {
        return Ok(Vec::new());
    }
    let mut done = Vec::new();
    if let Some(Some(pid)) = permaura_gateway::store::lock::holder(db)? {
        if pid != std::process::id() && port::runs_permaura(pid) {
            port::terminate(pid)?;
            done.push(format!("sent TERM to pid {pid}, which still held the gateway store"));
            if wait_lock_free(db, grace).await? {
                return Ok(done);
            }
        }
    }
    let holder = permaura_gateway::store::lock::holder(db)?;
    match holder {
        None => Ok(done),
        Some(pid) => Err(anyhow!(
            "{} still holds the gateway store ({db}), so nothing was removed from under it. Stop that process, then run the uninstall again",
            permaura_gateway::store::lock::describe(pid)
        )),
    }
}

/// Graceful first, force when the graceful path is refused or cannot be used, then wait for the store at `db` to be let go.
async fn stop_gateway(addr: SocketAddr, db: &str) -> anyhow::Result<String> {
    if port::is_free(addr) {
        let line = format!("no gateway was running on {addr}");
        println!("\x1b[2m·\x1b[0m {line}");
        return Ok(line);
    }
    let token = port::operator_token();
    let graceful = match &token {
        Some(t) => port::graceful_shutdown(addr, t).await,
        None => port::Graceful::Unauthorized,
    };
    match graceful {
        port::Graceful::Accepted => {
            // The store lock, not the port or a pid: a gateway gives its port up as its drain begins and
            // writes its store until it exits, and the port's holder can be another listener sharing it.
            if wait_lock_free(db, port::STOP_EXIT_WINDOW).await.unwrap_or(false) {
                let line = format!("stopped the gateway on {addr}");
                commands::ok(&line);
                return Ok(line);
            }
            println!(
                "the gateway on {addr} accepted the stop but still holds the store; forcing."
            );
        }
        port::Graceful::Unauthorized => {
            let holder = port::holder_of(addr.port());
            println!(
                "{}",
                port::explain_rejected_shutdown(addr, holder.as_ref(), false)
            );
            println!("Forcing: checking that it answers /health as a Permaura gateway before signalling it.");
        }
        port::Graceful::Refused { status, detail } => {
            println!(
                "the gateway on {addr} refused to stop ({status}{}{detail}); forcing.",
                if detail.is_empty() { "" } else { ": " }
            );
        }
        port::Graceful::Unreachable => {
            println!(
                "{addr} is held but nothing answers /v1/shutdown there; checking what holds it."
            );
        }
        port::Graceful::NotOffered => {
            println!(
                "{addr} is held by a process that is not running as you, so it was not sent this home's operator token; checking what holds it."
            );
        }
        port::Graceful::NotProven(why) => {
            println!(
                "{addr} answers like a Permaura gateway but did not prove it is this home's ({}), so it was not sent this home's operator token; checking what holds it.",
                port::unproven_reason(why, &port::operator_token_path())
            );
        }
    }
    let line = match port::force_stop(addr).await? {
        Some(h) => format!("sent TERM to {}; {addr} is free", h.describe()),
        None => format!("nothing is listening on {addr} any more"),
    };
    commands::ok(&line);
    Ok(line)
}

/// Unregister and delete one piece of boot persistence, the way the installer's `remove_service` does.
fn remove_service(f: &ServiceFile) -> String {
    let quiet = |program: &str, args: &[&str]| {
        std::process::Command::new(program)
            .args(args)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    let path = f.path.to_string_lossy().into_owned();
    match f.kind {
        ServiceKind::SystemUnit => {
            quiet("systemctl", &["disable", "--now", SERVICE_NAME]);
            let removed = std::fs::remove_file(&f.path);
            quiet("systemctl", &["daemon-reload"]);
            report_removed("the systemd system unit", &path, removed)
        }
        ServiceKind::UserUnit => {
            quiet("systemctl", &["--user", "disable", "--now", SERVICE_NAME]);
            let removed = std::fs::remove_file(&f.path);
            quiet("systemctl", &["--user", "daemon-reload"]);
            report_removed("the systemd user unit", &path, removed)
        }
        ServiceKind::LaunchAgent => {
            let uid = std::process::Command::new("id")
                .arg("-u")
                .output()
                .ok()
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            let booted_out = uid
                .map(|u| {
                    quiet(
                        "launchctl",
                        &["bootout", &format!("gui/{u}/{LAUNCHD_LABEL}")],
                    )
                })
                .unwrap_or(false);
            if !booted_out {
                quiet("launchctl", &["unload", "-w", &path]);
            }
            let removed = std::fs::remove_file(&f.path);
            report_removed("the launchd agent", &path, removed)
        }
    }
}

fn report_removed(what: &str, path: &str, removed: std::io::Result<()>) -> String {
    let line = match removed {
        Ok(()) => format!("removed {what} {path}"),
        Err(e) => format!("{what} {path} NOT removed ({e}); remove it yourself"),
    };
    if line.contains("NOT removed") {
        commands::deny(&line);
    } else {
        commands::ok(&line);
    }
    line
}

fn remove_path(p: &Path) -> String {
    let removed = if p.is_dir() {
        std::fs::remove_dir_all(p)
    } else {
        std::fs::remove_file(p)
    };
    let path = p.display().to_string();
    let line = match removed {
        Ok(()) => format!("deleted {path}"),
        Err(e) => format!("{path} NOT deleted ({e}); delete it yourself"),
    };
    if line.contains("NOT deleted") {
        commands::deny(&line);
    } else {
        commands::ok(&line);
    }
    line
}

/// The binary goes last, and on Unix it can go while it is the one running. Windows holds an open
/// executable, so there it is named for the user to delete.
fn remove_binary(p: &Path) -> String {
    #[cfg(windows)]
    {
        let line = format!("{} is this running program and Windows will not delete it while it runs; delete it yourself", p.display());
        commands::deny(&line);
        return line;
    }
    #[cfg(not(windows))]
    {
        let removed = std::fs::remove_file(p);
        let line = report_removed("the gateway binary", &p.display().to_string(), removed);
        if let Some(dir) = p.parent() {
            // An empty ~/.permaura/bin is nothing to keep; a non-empty one is somebody else's.
            let _ = std::fs::remove_dir(dir);
        }
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A purge waits on the store lock, not the port, and refuses while anything still holds
    /// the store, naming the holder; it never signals its own process.
    #[tokio::test]
    async fn a_purge_is_refused_while_the_store_is_still_held_and_never_signals_itself() {
        let dir = std::env::temp_dir().join(format!("permaura-uninstall-lock-{}-{}", std::process::id(), permaura_gateway::service::short_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("gateway.db").to_string_lossy().into_owned();

        assert!(wait_store_released(&db, Duration::from_millis(50), Duration::from_millis(50)).await.unwrap().is_empty(), "a store nothing ever locked is free");

        let held = permaura_gateway::store::lock::StoreLock::acquire(&db, Duration::ZERO).unwrap();
        let refused = wait_store_released(&db, Duration::from_millis(300), Duration::from_millis(300)).await.expect_err("refused while held").to_string();
        assert!(refused.contains(&format!("pid {}", std::process::id())), "{refused}");
        assert!(refused.contains("nothing was removed"), "{refused}");
        assert!(!refused.contains("sent TERM"), "{refused}");

        let release = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            drop(held);
        });
        let done = wait_store_released(&db, Duration::from_secs(5), Duration::from_millis(50)).await.expect("free once the holder lets go");
        assert!(done.is_empty(), "{done:?}");
        release.await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A purge leaves gateway.db.lock where it is, so a gateway that waited on the store through the purge holds the very lock file a later opener meets, and that opener is refused rather than locking a new file beside it.
    #[test]
    fn a_waiter_keeps_the_store_lock_across_a_purge_and_a_new_opener_is_still_refused() {
        use permaura_gateway::store::lock::StoreLock;
        let home = std::env::temp_dir().join(format!("permaura-uninstall-orphan-{}-{}", std::process::id(), permaura_gateway::service::short_id()));
        std::fs::create_dir_all(&home).unwrap();
        let db = home.join("gateway.db").to_string_lossy().into_owned();
        std::fs::write(&db, b"synthetic").unwrap();
        let holder = StoreLock::acquire(&db, Duration::ZERO).unwrap();
        let waiter = std::thread::spawn({
            let db = db.clone();
            move || StoreLock::acquire(&db, Duration::from_secs(20))
        });
        std::thread::sleep(Duration::from_millis(500));

        let entries: Vec<String> = std::fs::read_dir(&home).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        for name in purge_targets(&entries) {
            remove_path(&home.join(name));
        }
        assert!(!std::path::Path::new(&db).exists(), "the store itself was purged");
        drop(holder);

        let waited = waiter.join().unwrap().expect("the waiter takes the store once the holder lets go");
        let refused = StoreLock::acquire(&db, Duration::ZERO).expect_err("a later opener meets the waiter's lock");
        assert!(matches!(refused, permaura_gateway::error::GatewayError::StoreHeld(_)), "{refused}");
        drop(waited);
        let _ = std::fs::remove_dir_all(&home);
    }

    fn facts(purge: bool, identity: bool) -> Facts {
        Facts {
            addr: "127.0.0.1:7376".parse().unwrap(),
            has_install_identity: identity,
            purge_data: purge,
            services: vec![ServiceFile {
                kind: ServiceKind::LaunchAgent,
                path: PathBuf::from("/Users/x/Library/LaunchAgents/com.permaura.gateway.plist"),
            }],
            binaries: vec![PathBuf::from("/Users/x/.permaura/bin/permaura")],
            data: vec![
                PathBuf::from("/Users/x/.permaura/gateway.db"),
                PathBuf::from("/Users/x/.permaura/install.json"),
            ],
            sealed_keys: Vec::new(),
        }
    }

    fn kinds(steps: &[Step]) -> Vec<&'static str> {
        steps
            .iter()
            .map(|s| match s {
                Step::RevokeLinks => "revoke",
                Step::StopGateway(_) => "stop",
                Step::RemoveBootPersistence(_) => "service",
                Step::Unlink => "unlink",
                Step::ForgetVaultKey(_) => "forget-key",
                Step::PurgeData(_) => "purge",
                Step::RemoveBinary(_) => "binary",
            })
            .collect()
    }

    /// Links are revoked while install.json still exists, the vault key is forgotten before the files
    /// that hold it go, and the binary goes after everything that might need to run it.
    #[test]
    fn a_purge_revokes_first_forgets_the_key_before_the_files_and_deletes_the_binary_last() {
        let steps = plan(&facts(true, true));
        assert_eq!(
            kinds(&steps),
            [
                "revoke",
                "stop",
                "service",
                "unlink",
                "forget-key",
                "purge",
                "binary"
            ]
        );
    }

    #[test]
    fn without_purge_the_data_and_the_key_stay() {
        let steps = plan(&facts(false, true));
        assert_eq!(
            kinds(&steps),
            ["revoke", "stop", "service", "unlink", "binary"]
        );
    }

    #[test]
    fn a_machine_that_never_paired_has_nothing_to_revoke() {
        let steps = plan(&facts(false, false));
        assert_eq!(kinds(&steps), ["stop", "service", "unlink", "binary"]);
    }

    #[test]
    fn no_boot_service_means_no_step_for_it() {
        let mut f = facts(false, false);
        f.services.clear();
        assert_eq!(kinds(&plan(&f)), ["stop", "unlink", "binary"]);
    }

    #[test]
    fn purge_targets_take_the_gateways_state_and_every_schema_backup_and_nothing_else() {
        let entries: Vec<String> = [
            "gateway.db",
            "gateway.db.auditkey",
            "gateway.db.lock",
            "gateway.db.backup-v3",
            "gateway.db.backup-v11",
            "gateway.env",
            "operator.token",
            "cache",
            "vault-kek",
            "vault-kek.in-os-store",
            "remote.json",
            "tunnel-credentials.json",
            "cloudflared.yml",
            "tunnel.stopped",
            "tunnel.token",
            "install.json",
            "audit-archive",
            "audit-archive.foreign-1",
            "config.toml",
            "account.json",
            "gateway.id",
            "bin",
            "cloudflared.log",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let got = purge_targets(&entries);
        assert_eq!(
            got,
            [
                "audit-archive",
                "audit-archive.foreign-1",
                "cache",
                "cloudflared.yml",
                "gateway.db",
                "gateway.db.auditkey",
                "gateway.db.backup-v11",
                "gateway.db.backup-v3",
                "gateway.env",
                "install.json",
                "operator.token",
                "remote.json",
                "tunnel-credentials.json",
                "tunnel.stopped",
                "tunnel.token",
                "vault-kek",
                "vault-kek.in-os-store",
            ]
        );
    }

    /// A root install seals the vault key to the TPM beside its home, and the gateway records that it
    /// did. Left behind, the sealed key outlives a purge, and the claim makes a reinstall refuse to start.
    #[test]
    fn a_purge_takes_the_sealed_vault_key_and_its_claim_when_present() {
        let with = |extra: &[&str]| {
            let mut entries: Vec<String> = ["gateway.db", "vault-kek", "config.toml"].iter().map(|s| s.to_string()).collect();
            entries.extend(extra.iter().map(|s| s.to_string()));
            purge_targets(&entries)
        };
        assert_eq!(
            with(&["vault-kek.cred", "vault-kek.in-systemd-credential"]),
            ["gateway.db", "vault-kek", "vault-kek.cred", "vault-kek.in-systemd-credential"]
        );
        assert_eq!(with(&[]), ["gateway.db", "vault-kek"], "nothing is listed that is not there");
    }

    /// A `--service-user` install seals its key outside its home, where a purge of the home never
    /// reaches. Forgetting the key names that copy, in the step that already asks about the key.
    #[test]
    fn a_service_user_purge_names_the_sealed_key_in_etc() {
        let etc = PathBuf::from("/etc/permaura/vault-kek.cred");
        let svc = Path::new("/var/lib/permaura");
        let env = "# Permaura gateway settings\nPERMAURA_HOME=/var/lib/permaura\nPERMAURA_ADDR=127.0.0.1:7376\n";
        assert_eq!(sealed_key_outside_home(svc, Some(env)), Some(etc.clone()));
        assert_eq!(sealed_key_outside_home(svc, None), Some(etc.clone()), "an unreadable gateway.env falls back to the fixed home");
        let custom = "PERMAURA_HOME=\"/srv/permaura\"\n";
        assert_eq!(sealed_key_outside_home(Path::new("/srv/permaura"), Some(custom)), Some(etc.clone()));
        assert_eq!(sealed_key_outside_home(svc, Some(custom)), None, "the file belongs to the home its settings name");
        assert_eq!(sealed_key_outside_home(Path::new("/root/.permaura"), Some(env)), None, "another home's purge leaves it");
        assert_eq!(sealed_key_outside_home(Path::new("/home/x/.permaura"), None), None);

        let mut f = facts(true, true);
        f.sealed_keys = vec![etc.clone()];
        let steps = plan(&f);
        let forget = steps.iter().find(|s| matches!(s, Step::ForgetVaultKey(_))).expect("a purge forgets the key");
        assert_eq!(forget, &Step::ForgetVaultKey(vec![etc]));
        let said = forget.describe();
        assert!(said.starts_with("forget the vault key") && said.contains("/etc/permaura/vault-kek.cred"), "{said}");
        assert!(said.contains("every sealed secret becomes unreadable"), "{said}");

        f.purge_data = false;
        assert!(!plan(&f).iter().any(|s| matches!(s, Step::ForgetVaultKey(_))), "without a purge the key stays");
    }

    #[test]
    fn the_printed_plan_has_no_em_dashes() {
        for step in plan(&facts(true, true)) {
            assert!(!step.describe().contains('\u{2014}'), "{}", step.describe());
        }
    }
}
