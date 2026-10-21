//! `permaura remote`: turn a headless gateway into one the internet can reach.
//!
//! Everything here exists because the alternative was six manual steps across two machines: click
//! Enable in a console on your laptop, copy a run token, install cloudflared yourself, run it, then
//! hand-edit four undocumented variables into `gateway.env` and restart. Each of those is a place to
//! get it subtly wrong, and the two most common wrong answers (a tunnel with no
//! `PERMAURA_OWNER_SUB`, or a `public_url` that does not match the tunnel) both fail closed in ways
//! that look like "remote access is broken" rather than "you missed a step".
//!
//! The machine asks for its own tunnel using the install identity minted at pairing time, so no
//! human and no browser is in the loop after the first pairing. See
//! [`permaura_core::install`] for what that credential is and why it is allowed to do this.

use anyhow::{Context, Result};
use serde::Deserialize;

use permaura_gateway::config::GatewayConfig;
use permaura_gateway::tunnel::{self, Credentials};

/// What permaura.com returns when it has provisioned (or re-found) this gateway's tunnel.
///
/// camelCase, because that is what the route sends. The first release of this read `gateway_env`
/// and `public_url`, so every field that mattered deserialised to None: the server provisioned a
/// tunnel and claimed a name, and the machine then reported "the account API did not return the
/// gateway settings" and persisted nothing. The test below pins the real shape.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct TunnelResponse {
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    hostname: Option<String>,
    #[serde(default)]
    public_url: Option<String>,
    /// The tunnel's credentials, in the shape cloudflared reads from a credentials file (`AccountTag`, `TunnelSecret`, `TunnelID`, `Endpoint`). A bearer for the tunnel: written owner-only and never logged.
    #[serde(default)]
    credentials: Option<serde_json::Value>,
    /// A remotely managed tunnel's run token, which only an older permaura.com hands out. Read only so that it can be refused by name; never kept.
    #[serde(default)]
    token: Option<serde::de::IgnoredAny>,
    /// `PERMAURA_*` keys the gateway must come up with for the tunnel to mean anything.
    #[serde(default)]
    gateway_env: Option<std::collections::HashMap<String, String>>,
    /// Set when the refusal is a plan gate rather than a mistake.
    #[serde(default)]
    upgrade: Option<bool>,
    #[serde(default)]
    plan: Option<String>,
}

use super::commands::Ctx;
use super::enroll::api_base;

/// This gateway's id, as permaura.com knows it.
///
/// Recorded at pairing time next to the install identity. Without it there is nothing to ask about:
/// a machine that never paired has no gateway row to attach a tunnel to.
pub fn gateway_id() -> Result<String> {
    let path = permaura_core::paths::permaura_path("gateway.id")
        .context("could not resolve ~/.permaura: set PERMAURA_HOME or HOME")?;
    let id = std::fs::read_to_string(&path)
        .with_context(|| {
            format!(
                "this gateway is not paired with a Permaura account yet ({} is missing). Run the installer with --pair, or `permaura auth login`",
                path.display()
            )
        })?
        .trim()
        .to_string();
    anyhow::ensure!(!id.is_empty(), "{} is empty", path.display());
    Ok(id)
}

/// Ask permaura.com for this gateway's tunnel, as this gateway.
///
/// `label` names it; `None` lets the server generate one. The call is idempotent server-side (the
/// same label returns the same tunnel), so a re-run repairs a half-finished setup rather than
/// stacking a second one.
async fn request_tunnel(label: Option<&str>) -> Result<TunnelResponse> {
    let install =
        permaura_core::install::ensure().context("reading this machine's install identity")?;
    let id = gateway_id()?;
    let api = api_base();

    let client = super::enroll::api_client(&api, std::time::Duration::from_secs(45))?;

    let resp = client
        .post(format!("{api}/api/gateways/{id}/tunnel"))
        .json(&serde_json::json!({
            "subdomain": label,
            "installId": install.install_id,
            "installSecret": install.secret,
        }))
        .send()
        .await
        .context("reaching the account API")
        .and_then(super::port::refuse_redirect)?;

    let status = resp.status();
    let body: TunnelResponse = resp.json().await.unwrap_or(TunnelResponse {
        error: Some("the account API returned something this version cannot read".into()),
        hostname: None,
        public_url: None,
        credentials: None,
        token: None,
        gateway_env: None,
        upgrade: None,
        plan: None,
    });

    if !status.is_success() {
        // A plan gate is not a mistake the operator can fix at the terminal, so it gets its own
        // sentence rather than a raw feature slug.
        if body.upgrade == Some(true) {
            let plan = body.plan.as_deref().unwrap_or("Pro");
            anyhow::bail!(
                "remote access needs the {plan} plan. Upgrade at {api}/pricing, then run this again."
            );
        }
        anyhow::bail!(
            "{}",
            body.error
                .unwrap_or_else(|| format!("the account API refused this ({status})"))
        );
    }
    Ok(body)
}

/// The name this gateway currently answers on, if it has one.
pub fn current_hostname() -> Option<String> {
    let path = GatewayConfig::default_path()?;
    let cfg = GatewayConfig::load_from(&path).ok()??;
    host_of(&cfg.public_url?)
}

/// The host of an http(s) URL as the URL parser clients use reads it, an IPv6 literal bracketed; `None` for anything else, including a URL carrying userinfo or an authority two parsers could read apart.
pub(crate) fn host_of(url: &str) -> Option<String> {
    let (parsed, _) = permaura_gateway::connectors::egress::parse_checked(url.trim()).ok()?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    parsed.host_str().filter(|h| !h.is_empty()).map(str::to_string)
}

/// The four keys the account API hands back, written into `config.toml`.
///
/// `config.toml` rather than `gateway.env` on purpose. The env file belongs to the installer, which
/// rewrites it, and `--update` is entitled to touch it; this file belongs to the gateway. It also
/// loses to the environment by design, so an operator who sets one of these themselves still wins.
///
/// Only the keys named here are touched. The file is one the operator owns and has commented, so it
/// is edited in place rather than serialised back out from a struct.
fn write_config(env: &std::collections::HashMap<String, String>, api: &str) -> Result<std::path::PathBuf> {
    use toml_edit::{value, DocumentMut};

    refuse_a_foreign_issuer(env, api)?;
    let path = GatewayConfig::default_path()
        .context("could not resolve ~/.permaura: set PERMAURA_HOME or HOME")?;
    let existing = std::fs::read_to_string(&path).unwrap_or_default();
    let mut doc = existing
        .parse::<DocumentMut>()
        .map_err(|e| anyhow::anyhow!("{} is not valid config: {e}", path.display()))?;

    // env key -> config key. Anything the API sends that is not in this table is ignored rather than
    // written blind: `deny_unknown_fields` would turn an unrecognised key into a gateway that
    // refuses to boot, which is a worse outcome than not persisting it.
    for (env_key, cfg_key) in [
        ("PERMAURA_PUBLIC_URL", "public_url"),
        ("PERMAURA_OWNER_SUB", "owner_sub"),
        ("PERMAURA_AS_ISSUER", "as_issuer"),
        ("PERMAURA_AS_JWKS", "as_jwks"),
    ] {
        if let Some(v) = env.get(env_key) {
            doc[cfg_key] = value(v.as_str());
        }
    }
    // An owner chosen here was not written by a check-in re-pin, so it no longer outranks the environment.
    if env.contains_key("PERMAURA_OWNER_SUB") {
        doc.remove("owner_sub_replaces_env");
    }

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&path, doc.to_string())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Refuse an answer whose issuer or JWKS is not on the account API's own origin: the gateway accepts every token those name, so an answer from anywhere else would have it trust a signer of that party's choosing.
fn refuse_a_foreign_issuer(env: &std::collections::HashMap<String, String>, api: &str) -> Result<()> {
    let trusted = origin_of(api).with_context(|| format!("the account API address {api} is not an http(s) origin"))?;
    for key in ["PERMAURA_AS_ISSUER", "PERMAURA_AS_JWKS"] {
        let Some(v) = env.get(key) else { continue };
        if origin_of(v).as_deref() != Some(trusted.as_str()) {
            anyhow::bail!(
                "the account API answered with a {key} that is not on {trusted}, so nothing was written; this gateway accepts only tokens {trusted} signs"
            );
        }
    }
    Ok(())
}

/// `scheme://host[:port]` of an http(s) URL as the URL parser reads it, lowercased, with the scheme's default port dropped; `None` for anything else, including a URL carrying userinfo or an authority two parsers could read apart.
fn origin_of(url: &str) -> Option<String> {
    let (parsed, _) = permaura_gateway::connectors::egress::parse_checked(url.trim()).ok()?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

/// Remove the keys remote access owns, leaving the rest of the file alone, and say whether any was there.
fn clear_config() -> Result<bool> {
    use toml_edit::DocumentMut;
    let Some(path) = GatewayConfig::default_path() else {
        return Ok(false);
    };
    let Ok(existing) = std::fs::read_to_string(&path) else {
        return Ok(false);
    };
    let mut doc = existing
        .parse::<DocumentMut>()
        .map_err(|e| anyhow::anyhow!("{} is not valid config: {e}", path.display()))?;
    let mut removed = false;
    for k in ["public_url", "owner_sub", "owner_sub_replaces_env", "as_issuer", "as_jwks"] {
        removed |= doc.remove(k).is_some();
    }
    if !removed {
        return Ok(false);
    }
    std::fs::write(&path, doc.to_string())
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(true)
}

/// `permaura remote status`: what this machine's files say, and what the gateway running at `ctx` is actually doing, which can differ until it restarts.
pub async fn status(ctx: &Ctx) -> Result<()> {
    let home = permaura_core::permaura_home().context("could not resolve ~/.permaura: set PERMAURA_HOME or HOME")?;
    let stored = stored_tunnel();
    let configured = current_hostname();
    match &configured {
        Some(host) => {
            println!("Remote access is configured.");
            println!("  address   https://{host}");
            println!("  tunnel    {stored}");
            if let Some(why) = home_file(tunnel::STOP_MARKER_FILE).and_then(|m| tunnel::recorded_stop(&m)) {
                println!("  stopped   {why}");
            }
        }
        None => {
            println!("Remote access is off in the files in {}. Run `permaura remote enable [name]` to turn it on.", home.display());
            if !matches!(stored, Stored::Nothing) {
                println!("  Tunnel files are still stored on this machine: `permaura remote disable` removes them.");
            }
        }
    }
    let (url, running) = match running_health(ctx).await {
        Err(why) => match super::commands::this_homes_gateway_answering(ctx).await {
            Some(at) if at != ctx.url => {
                let health = running_health(&Ctx::new(at.clone(), None)).await;
                (at, health)
            }
            _ => (ctx.url.clone(), Err(why)),
        },
        answered => (ctx.url.clone(), answered),
    };
    match running {
        Ok(health) => {
            println!("  running   {}", describe_running(&url, &health));
            if configured.is_none() && still_serving(&health) {
                println!(
                    "  The running gateway is still serving remote access: `permaura remote disable` stops it now, or restart it ({}).",
                    restart_hint()
                );
            }
        }
        Err(why) => println!("  running   {}, so this reports the files in {} only", why.trim_end_matches('.'), home.display()),
    }
    if let Some(why) = service_install().and_then(|install| wrong_account(&install, &home, current_user().as_deref(), &this_command_line(std::env::args()), &this_binary())) {
        println!("  These may not be the running gateway's files: {why}.");
    }
    Ok(())
}

/// The gateway's authenticated health document, or why it could not be read.
async fn running_health(ctx: &Ctx) -> std::result::Result<serde_json::Value, String> {
    match ctx.get("/health").send().await {
        Ok(resp) if resp.status().is_success() => resp
            .json()
            .await
            .map_err(|e| format!("the gateway at {} sent a health document this version cannot read ({e})", ctx.url)),
        Ok(resp) => Err(format!("the gateway at {} answered {} for /health", ctx.url, resp.status().as_u16())),
        Err(e) if e.is::<super::port::Refused>() => Err(e.to_string()),
        Err(_) if super::port::local_addr_of(&ctx.url).is_some_and(super::port::is_free) => {
            Err(format!("no gateway is running at {}", ctx.url))
        }
        Err(e) => Err(format!("the gateway at {} could not be reached ({e})", ctx.url)),
    }
}

/// One line on the running gateway's remote access, from its health document.
fn describe_running(url: &str, health: &serde_json::Value) -> String {
    let connector = match health.get("tunnel_ingress").and_then(|v| v.as_str()) {
        Some(tunnel::LOCAL) => "tunnel connector running".to_string(),
        Some(tunnel::STOPPED) => format!(
            "tunnel connector stopped ({})",
            health.get("tunnel_stop_reason").and_then(|v| v.as_str()).unwrap_or("no reason given")
        ),
        _ => "no tunnel connector of its own".to_string(),
    };
    let tokens = match health.get("remote_tokens") {
        Some(serde_json::Value::String(s)) if s == "accepted" => "it accepts permaura.com tokens",
        Some(serde_json::Value::String(s)) if s == "refused" => "it refuses permaura.com tokens",
        Some(serde_json::Value::Null) => "it takes no permaura.com tokens",
        _ => "it does not say whether it accepts permaura.com tokens (a gateway older than this command)",
    };
    format!("the gateway at {url}: {connector}; {tokens}")
}

/// Whether a health document shows remote access still being served: a connector running, or permaura.com tokens accepted.
fn still_serving(health: &serde_json::Value) -> bool {
    health.get("tunnel_ingress").and_then(|v| v.as_str()) == Some(tunnel::LOCAL)
        || health.get("remote_tokens").and_then(|v| v.as_str()) == Some("accepted")
}

/// What this machine holds for its tunnel.
enum Stored {
    Credentials { tunnel_id: String },
    Unusable { path: std::path::PathBuf, why: String },
    LegacyToken,
    Nothing,
}

impl std::fmt::Display for Stored {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Stored::Credentials { tunnel_id } => write!(
                f,
                "credentials stored for tunnel {tunnel_id}; the connector runs with a configuration written on this machine"
            ),
            Stored::Unusable { path, why } => write!(
                f,
                "the credentials in {} cannot be used ({why}). Run `permaura remote enable` to replace them",
                path.display()
            ),
            Stored::LegacyToken => write!(
                f,
                "only a run token for a remotely managed tunnel is stored, which this version no longer runs. Run `permaura remote enable` to replace it"
            ),
            Stored::Nothing => write!(f, "no credentials stored. Run `permaura remote enable` to fetch them"),
        }
    }
}

fn stored_tunnel() -> Stored {
    if let Some(path) = home_file(tunnel::CREDENTIALS_FILE).filter(|p| p.exists()) {
        return match std::fs::read(&path).map_err(|e| e.to_string()).and_then(|b| Credentials::from_slice(&b)) {
            Ok(c) => Stored::Credentials { tunnel_id: c.tunnel_id },
            Err(why) => Stored::Unusable { path, why },
        };
    }
    if home_file(tunnel::LEGACY_TOKEN_FILE).is_some_and(|p| p.exists()) {
        return Stored::LegacyToken;
    }
    Stored::Nothing
}

/// A remote access file under the Permaura home: owner-only, the same names and shapes the desktop app uses.
fn home_file(name: &str) -> Option<std::path::PathBuf> {
    permaura_core::paths::permaura_path(name)
}

/// The credentials in permaura.com's answer, checked, or why there are none this version can run.
fn credentials_from(resp: &TunnelResponse) -> Result<Credentials> {
    match (&resp.credentials, &resp.token) {
        (Some(value), _) => Credentials::from_value(value.clone())
            .map_err(|why| anyhow::anyhow!("permaura.com returned tunnel credentials this version cannot use: {why}. Nothing was changed on this machine")),
        (None, Some(_)) => anyhow::bail!(
            "permaura.com handed out a remotely managed tunnel, which this version no longer runs: its destination would be chosen in permaura.com's Cloudflare account rather than on this machine. Nothing was changed on this machine; run this again once permaura.com has been updated"
        ),
        (None, None) => anyhow::bail!("the account API did not return the tunnel's credentials"),
    }
}

/// `permaura remote enable [name]`
pub async fn enable(name: Option<&str>, yes: bool) -> Result<()> {
    let home = permaura_core::permaura_home().context("could not resolve ~/.permaura: set PERMAURA_HOME or HOME")?;
    if let Some(why) = service_install().and_then(|install| wrong_account(&install, &home, current_user().as_deref(), &this_command_line(std::env::args()), &this_binary())) {
        anyhow::bail!("{why}. Nothing was asked of permaura.com and nothing was written");
    }
    // Moving a live address breaks every agent pointed at the old one, and the old name goes back
    // into circulation the moment the rename commits. That is worth stopping for; a first-time
    // enable breaks nothing and is not worth a prompt.
    if let (Some(requested), Some(current)) = (name, current_hostname()) {
        let moving = !current.starts_with(&format!("{requested}."));
        if moving && !yes {
            eprintln!("This gateway already answers on \x1b[36m{current}\x1b[0m.");
            eprintln!(
                "Renaming it to \x1b[36m{requested}\x1b[0m releases \x1b[36m{current}\x1b[0m back for anyone to claim,"
            );
            eprintln!("and agents connected to the old address will need reconnecting.");
            anyhow::bail!("re-run with --yes to go ahead");
        }
    }

    let resp = request_tunnel(name).await?;
    let credentials = credentials_from(&resp)?;
    let env = resp
        .gateway_env
        .context("the account API did not return the gateway settings")?;
    let public = resp
        .public_url
        .or_else(|| resp.hostname.map(|h| format!("https://{h}")))
        .context("the account API did not return an address")?;

    let path = write_config(&env, &api_base())?;
    let credentials_path = write_credentials(&credentials)?;

    // The connector, last: everything above is recoverable by re-running, whereas a tunnel process
    // started before its settings were written would front a gateway that has not adopted them yet.
    let bin = super::cloudflared::ensure().await?;
    let existing = super::cloudflared::find_existing();
    if existing.as_deref() == Some(bin.as_path()) {
        println!("  using cloudflared at {}", bin.display());
    }

    println!("\x1b[32m✓\x1b[0m Remote access is set up for \x1b[36m{public}\x1b[0m");
    println!("  settings written to {}", path.display());
    println!("  tunnel credentials written to {}", credentials_path.display());
    println!();
    println!("Restart the gateway to pick it up:");
    println!("  {}", restart_hint());
    Ok(())
}

/// How this machine restarts its gateway, as far as we can tell from how it was installed.
///
/// A systemd unit, a user unit, a launchd agent and a bare foreground process need different words, and telling someone to run
/// `systemctl` on a box with no unit is how a setup guide loses people at the last step.
fn restart_hint() -> String {
    let system_unit = UNIT_FILES.iter().any(|path| std::path::Path::new(path).exists());
    super::restart::restart_hint(&super::restart::detect(), system_unit)
}

/// The credentials are a bearer for this tunnel: written owner-only and never logged. A run token an older version stored goes with them, and so does a stop the guard recorded: enabling again is the operator's decision to run the connector.
fn write_credentials(credentials: &Credentials) -> Result<std::path::PathBuf> {
    let path = home_file(tunnel::CREDENTIALS_FILE)
        .context("could not resolve ~/.permaura: set PERMAURA_HOME or HOME")?;
    permaura_core::replace_secret_file(&path, &credentials.to_file_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    permaura_credential_store::restrict_to_owner(&path)
        .with_context(|| format!("restricting {} to its owner", path.display()))?;
    remove_home_file(tunnel::LEGACY_TOKEN_FILE)?;
    remove_home_file(tunnel::STOP_MARKER_FILE)?;
    Ok(path)
}

/// Remove one remote access file from the home, and say whether it was there.
fn remove_home_file(name: &str) -> Result<bool> {
    let Some(path) = home_file(name) else {
        return Ok(false);
    };
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(anyhow::anyhow!(e).context(format!("removing {}", path.display()))),
    }
}

/// `permaura remote disable`: stop serving the address, keep the name.
///
/// The deliberate counterpart to deleting it: the reservation is what makes turning this back on
/// return to the same hostname, so nothing here gives the name up.
///
/// Editing the files only changes the next start: a running gateway keeps its connector and the resource server it built at boot. So the gateway at `ctx` is asked to turn both off now (`POST /v1/remote/disable`), whatever the file edits came to, and its health document is read back to check it did. Anything short of that is reported as remote access still on, with a non-zero exit, except nothing listening at the address, which is reported as no gateway serving remote access from there; a restart is offered as the fix only when the running gateway proved it is this home's and something was removed from this home's files.
///
/// On a machine whose systemd unit runs the gateway as another account, or with another home, this home is not the one it reads, so the command refuses before touching anything and names the account to run it as.
pub async fn disable(ctx: &Ctx) -> Result<()> {
    let home = permaura_core::permaura_home().context("could not resolve ~/.permaura: set PERMAURA_HOME or HOME")?;
    let install = service_install();
    if let Some(why) = install.as_ref().and_then(|i| wrong_account(i, &home, current_user().as_deref(), &this_command_line(std::env::args()), &this_binary())) {
        anyhow::bail!("{why}. Nothing was changed");
    }
    let edited = remove_remote_access_files(home);
    if !edited.errors.is_empty() {
        eprintln!("\x1b[33m!\x1b[0m Could not remove everything remote access keeps in {}: {}.", edited.home.display(), edited.errors.join("; "));
    } else if edited.changed {
        println!(
            "Removed remote access from {}: the address, and the tunnel's credentials and configuration. The name stays reserved: `permaura remote enable` brings it back.",
            edited.home.display()
        );
    } else {
        println!("Nothing to remove in {}: its files name no public address and hold no tunnel files.", edited.home.display());
    }
    let (url, outcome) = match turn_off_running(ctx).await {
        RunningOff::NoGateway => match super::commands::this_homes_gateway_answering(ctx).await {
            Some(at) => {
                let outcome = turn_off_running(&Ctx::new(at.clone(), None)).await;
                (at, outcome)
            }
            None => (ctx.url.clone(), RunningOff::NoGateway),
        },
        outcome => (ctx.url.clone(), outcome),
    };
    let lines = report_disable(&url, &outcome, &edited, &public_url_set_outside_the_files());
    let still_on = matches!(outcome, RunningOff::StillOn { .. } | RunningOff::NotOff(_));
    for line in &lines {
        if still_on {
            eprintln!("\x1b[33m!\x1b[0m {line}");
        } else {
            println!("{line}");
        }
    }
    match disable_failed(&url, &outcome, &edited) {
        Some(why) => Err(anyhow::anyhow!(why)),
        None => Ok(()),
    }
}

/// Why `remote disable` exits non-zero, if it does: remote access still served, or a file it could not change, which the next start may read.
fn disable_failed(url: &str, outcome: &RunningOff, edited: &Edited) -> Option<String> {
    let home = edited.home.display();
    match outcome {
        RunningOff::StillOn { .. } | RunningOff::NotOff(_) => Some(format!("remote access is still served by the gateway at {url}")),
        _ if edited.errors.is_empty() => None,
        RunningOff::NoGateway => Some(format!("no gateway is running, and not every file in {home} could be changed, so the next start may serve remote access again")),
        RunningOff::Off(_) => Some(format!("remote access is off in the running gateway, but not every file in {home} could be changed, so the next start may serve it again")),
    }
}

/// What removing remote access from a home's files came to.
#[derive(Debug)]
struct Edited {
    home: std::path::PathBuf,
    /// Whether anything was there to remove.
    changed: bool,
    errors: Vec<String>,
}

/// Remove remote access from `home`'s files, each file on its own, so one that cannot be changed leaves the rest done.
fn remove_remote_access_files(home: std::path::PathBuf) -> Edited {
    let mut edited = Edited { home, changed: false, errors: Vec::new() };
    match clear_config() {
        Ok(changed) => edited.changed |= changed,
        Err(e) => edited.errors.push(format!("{e:#}")),
    }
    for name in [tunnel::CREDENTIALS_FILE, tunnel::CONFIG_FILE, tunnel::LEGACY_TOKEN_FILE, tunnel::STOP_MARKER_FILE] {
        match remove_home_file(name) {
            Ok(removed) => edited.changed |= removed,
            Err(e) => edited.errors.push(format!("{e:#}")),
        }
    }
    edited
}

/// What `POST /v1/remote/disable` answered with, when it answered 200.
#[derive(Debug, Deserialize)]
struct TurnedOffAnswer {
    connector: String,
    #[serde(default)]
    connector_pid: Option<u64>,
    remote_tokens: String,
    #[serde(default)]
    environment: Vec<String>,
    #[serde(default)]
    supervised_by_app: bool,
    /// What `/health` said of this process's own connector before the disable: `stopped` when its guard had already stopped it.
    #[serde(default)]
    tunnel_before: Option<String>,
    #[serde(default)]
    tunnel_after: Option<String>,
    #[serde(default)]
    tunnel_stop_reason: Option<String>,
    /// Absent from a gateway that predates the audit record, which counts as recorded: nothing to warn about there.
    #[serde(default = "recorded")]
    audited: bool,
    #[serde(default)]
    audit_error: Option<String>,
}

fn recorded() -> bool {
    true
}

/// What turning remote access off in the running gateway came to.
#[derive(Debug)]
enum RunningOff {
    /// Nothing listens at the address, so no gateway there serves remote access.
    NoGateway,
    /// The gateway turned it off, and its health document agrees.
    Off(TurnedOffAnswer),
    /// The gateway refuses permaura.com tokens now, but runs no tunnel of its own while something else may forward to it.
    NotOff(TurnedOffAnswer),
    /// The gateway may still serve remote access, for this reason. `ours` when it proved it holds this home's operator token, so a restart reads this home's files.
    StillOn { why: String, ours: bool },
}

async fn turn_off_running(ctx: &Ctx) -> RunningOff {
    let still_on = |why: String| async move { RunningOff::StillOn { why, ours: this_homes_gateway(ctx).await } };
    let resp = match ctx.post("/v1/remote/disable").send().await {
        Ok(resp) => resp,
        Err(e) if e.is::<super::port::Refused>() => return still_on(e.to_string()).await,
        Err(_) if super::port::local_addr_of(&ctx.url).is_some_and(super::port::is_free) => return RunningOff::NoGateway,
        Err(e) => return still_on(format!("the gateway at {} could not be reached ({e})", ctx.url)).await,
    };
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    let answer = match judge_disable(&ctx.url, status, &body) {
        Ok(answer) => answer,
        Err(why) => return still_on(why).await,
    };
    match running_health(ctx).await {
        Ok(health) if still_serving(&health) => still_on(format!(
            "the gateway at {} said it turned remote access off, but its health document still reads: {}",
            ctx.url,
            describe_running(&ctx.url, &health)
        ))
        .await,
        Ok(_) if forwarded_by_something_else(&answer) => RunningOff::NotOff(answer),
        Ok(_) => RunningOff::Off(answer),
        Err(why) => still_on(format!("the gateway answered, but whether it stopped could not be checked: {why}")).await,
    }
}

/// Whether the gateway at `ctx` proves it holds this home's own operator token, so the files this command edited are the ones its next start reads.
async fn this_homes_gateway(ctx: &Ctx) -> bool {
    let (Some(addr), Some(token)) = (super::port::local_addr_of(&ctx.url), super::port::operator_token()) else {
        return false;
    };
    matches!(super::port::listener_at(addr, &[token.as_str()]).await, super::port::Listener::Ours)
}

/// A gateway that ran no connector of its own but had remote access (permaura.com tokens, or a public URL from its environment, which is how the Permaura app's tunnel fronts it) is reached by whatever forwards to it, and turning off its tokens does not stop that. The app supervising a gateway is not remote access on its own: it supervises every gateway it starts.
fn forwarded_by_something_else(answer: &TurnedOffAnswer) -> bool {
    let its_own_stopped = answer.connector == "stopped" || (answer.tunnel_before.as_deref() == Some(tunnel::STOPPED) || answer.tunnel_after.as_deref() == Some(tunnel::STOPPED));
    let had_remote_access = answer.remote_tokens == "refused" || answer.environment.iter().any(|k| k == "PERMAURA_PUBLIC_URL");
    !its_own_stopped && had_remote_access
}

/// Read `POST /v1/remote/disable`'s answer: what it turned off, or why remote access may still be on.
fn judge_disable(url: &str, status: u16, body: &serde_json::Value) -> std::result::Result<TurnedOffAnswer, String> {
    match status {
        200 => serde_json::from_value(body.clone())
            .map_err(|e| format!("the gateway at {url} answered in a shape this version cannot read ({e})")),
        404 => Err(format!("the gateway at {url} is older than this command and cannot turn remote access off while it runs")),
        401 => Err(format!("the gateway at {url} refused this home's operator token, so it is not this home's gateway")),
        _ if body.get("connector").and_then(|v| v.as_str()) == Some("running") => Err(format!(
            "its tunnel connector{} did not stop: {}",
            body.get("connector_pid").and_then(|v| v.as_u64()).map(|p| format!(" (pid {p})")).unwrap_or_default(),
            body.get("detail").and_then(|v| v.as_str()).unwrap_or("no reason given")
        )),
        _ => Err(format!(
            "the gateway at {url} answered {status}: {}",
            body.get("error").and_then(|v| v.as_str()).unwrap_or("no reason given")
        )),
    }
}

/// Where this machine sets `PERMAURA_PUBLIC_URL` other than `config.toml`: this command's own environment, or an installer's env file. Either outranks the file at the gateway's next start, so `remote disable` cannot remove it. Read on every run, and reported only when the running gateway could not say for itself.
fn public_url_set_outside_the_files() -> Vec<String> {
    const KEY: &str = "PERMAURA_PUBLIC_URL";
    let mut found = Vec::new();
    if permaura_gateway::config::pinned_by_environment(KEY) {
        found.push("this shell's environment".to_string());
    }
    let files = [Some(std::path::PathBuf::from("/etc/permaura/gateway.env")), home_file("gateway.env")];
    for path in files.into_iter().flatten() {
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let sets_it = text.lines().map(str::trim).filter(|l| !l.starts_with('#')).any(|l| {
            l.strip_prefix(KEY)
                .and_then(|rest| rest.trim_start().strip_prefix('='))
                .is_some_and(|value| !value.trim().trim_matches('"').trim_matches('\'').is_empty())
        });
        if sets_it {
            found.push(path.display().to_string());
        }
    }
    found
}

/// The lines `remote disable` ends with. `edited` is what removing remote access from this home's files came to; `set_elsewhere` names where `PERMAURA_PUBLIC_URL` is set outside the files, for the outcomes where the gateway did not report its own environment.
fn report_disable(url: &str, outcome: &RunningOff, edited: &Edited, set_elsewhere: &[String]) -> Vec<String> {
    let elsewhere = (!set_elsewhere.is_empty()).then(|| {
        format!(
            "PERMAURA_PUBLIC_URL is set in {}, which outranks config.toml: the gateway's next start takes permaura.com tokens again unless it is removed there.",
            set_elsewhere.join(" and ")
        )
    });
    let home = edited.home.display();
    match outcome {
        RunningOff::NoGateway => [
            Some(format!("No gateway is running at {url}, nor at any other address this home's gateway is set to listen on, so none was serving remote access from there.")),
            Some("If this machine's gateway listens on another address, run this again with --url <its address>, or restart it: a running gateway keeps remote access until it is turned off or restarted.".to_string()),
            elsewhere,
        ]
        .into_iter()
        .flatten()
        .collect(),
        RunningOff::Off(answer) => {
            let connector = match (answer.connector.as_str(), answer.connector_pid) {
                ("stopped", Some(pid)) => format!("stopped its tunnel connector (pid {pid})"),
                ("stopped", None) => "stopped its tunnel connector".to_string(),
                _ if (answer.tunnel_before.as_deref() == Some(tunnel::STOPPED) || answer.tunnel_after.as_deref() == Some(tunnel::STOPPED)) => if answer.tunnel_stop_reason.as_deref() == Some(tunnel::TURNED_OFF) {
                    "runs no tunnel connector, an earlier permaura remote disable stopped it".to_string()
                } else { "runs no tunnel connector, it was stopped earlier".to_string() },
                _ => "runs no tunnel connector".to_string(),
            };
            let tokens = if answer.remote_tokens == "refused" {
                "refuses permaura.com tokens from now on"
            } else {
                "takes no permaura.com tokens"
            };
            let mut lines = vec![format!("Remote access is off: the running gateway at {url} {connector} and {tokens}.")];
            lines.extend(answer_notes(answer));
            lines
        }
        RunningOff::NotOff(answer) => {
            let mut lines = vec![format!(
                "Remote access is not off: the running gateway at {url} now refuses permaura.com-signed tokens, but it runs no tunnel of its own, so anything that forwards its public address still reaches it, and agents enrolled with a code (and anything holding its operator token) still connect through it."
            )];
            lines.push(if answer.supervised_by_app {
                "The Permaura app runs this gateway's tunnel: turn remote access off in the app, on its Remote access card, which stops that tunnel.".to_string()
            } else {
                "Stop the tunnel or reverse proxy that forwards to this gateway's address: this command cannot reach it.".to_string()
            });
            lines.extend(answer_notes(answer));
            lines
        }
        RunningOff::StillOn { why, ours } => {
            let account = install_hint();
            let next = match (edited.changed, *ours) {
                _ if !edited.errors.is_empty() => format!(
                    "Some of {home}'s files could not be changed ({}), so a restart may serve remote access again: fix them and run this again{account}.",
                    edited.errors.join("; ")
                ),
                (true, true) if elsewhere.is_some() => format!("Restart it now: {}", restart_hint()),
                (true, true) => format!("Its files are changed, so it starts again without remote access. Restart it now: {}", restart_hint()),
                (false, _) => format!("Nothing was removed from {home}, so a restart does not turn it off either: run this as the account whose gateway it is{account}."),
                (true, false) => format!(
                    "The files removed were {home}'s, which may not be the running gateway's: run this as the account whose gateway it is{account}, and restart that gateway only once its own files name no public address."
                ),
            };
            [Some(format!("Remote access stays on until the gateway restarts: {}.", why.trim_end_matches('.'))), Some(next), elsewhere]
                .into_iter()
                .flatten()
                .collect()
        }
    }
}

/// The lines about an answer that hold whether or not remote access is now off: the audit record, the app, and the environment.
fn answer_notes(answer: &TurnedOffAnswer) -> Vec<String> {
    let mut lines = Vec::new();
    if !answer.audited {
        lines.push(format!(
            "The gateway could not record this in its audit chain ({}), so the chain does not show remote access being turned off.",
            answer.audit_error.as_deref().unwrap_or("no reason given")
        ));
    }
    if answer.supervised_by_app && answer.connector == "stopped" {
        lines.push("The Permaura app runs this gateway: turn remote access off in the app as well, or it brings remote access back when it next starts the gateway.".to_string());
    }
    let pinned = answer.environment.join(", ");
    let (verb, pronoun) = if answer.environment.len() == 1 { ("is", "it is") } else { ("are", "they are") };
    if answer.environment.iter().any(|k| k == "PERMAURA_PUBLIC_URL") {
        lines.push(format!(
            "{pinned} {verb} set in the gateway's own environment (for a VPS, /etc/permaura/gateway.env), which outranks config.toml, so removing the file's copy does not remove {}: the next start takes permaura.com tokens again unless {pronoun} removed there.",
            if answer.environment.len() == 1 { "it" } else { "them" }
        ));
    } else if !answer.environment.is_empty() {
        lines.push(format!(
            "{pinned} {verb} set in the gateway's own environment, which outranks config.toml; without PERMAURA_PUBLIC_URL there, the next start still takes no permaura.com tokens."
        ));
    }
    lines
}

/// The gateway this machine's systemd unit runs, as far as the unit says: the account it runs as and the home its environment names.
#[derive(Debug, Default, PartialEq)]
struct ServiceInstall {
    user: Option<String>,
    home: Option<std::path::PathBuf>,
}

/// Where the installer writes the unit, the same two places [`restart_hint`] looks.
const UNIT_FILES: [&str; 2] = ["/etc/systemd/system/permaura.service", "/lib/systemd/system/permaura.service"];

fn service_install() -> Option<ServiceInstall> {
    let unit = UNIT_FILES.iter().find_map(|path| std::fs::read_to_string(path).ok())?;
    Some(parse_unit(&unit, |path| std::fs::read_to_string(path).ok()))
}

/// The unit's `User=`, and `PERMAURA_HOME` from its `Environment=` lines or the files its `EnvironmentFile=` lines name (read through `read`).
fn parse_unit(unit: &str, read: impl Fn(&str) -> Option<String>) -> ServiceInstall {
    let mut found = ServiceInstall::default();
    for line in unit.lines().map(str::trim) {
        if let Some(user) = line.strip_prefix("User=").map(str::trim).filter(|u| !u.is_empty()) {
            found.user = Some(user.to_string());
        } else if let Some(file) = line.strip_prefix("EnvironmentFile=") {
            if let Some(home) = read(file.trim().trim_start_matches('-')).and_then(|env| super::installer_home_from_env(&env)) {
                found.home = Some(home.into());
            }
        } else if let Some(assignments) = line.strip_prefix("Environment=") {
            for assignment in assignments.split_whitespace() {
                if let Some(home) = assignment.trim_matches('"').strip_prefix("PERMAURA_HOME=").filter(|h| !h.is_empty()) {
                    found.home = Some(home.into());
                }
            }
        }
    }
    found
}

/// Why `command` (its arguments, without the binary), run as `caller` with `home`, would act on files the service's gateway never reads, with the command that would not. `None` when this home is the service's, or nothing says otherwise.
fn wrong_account(install: &ServiceInstall, home: &std::path::Path, caller: Option<&str>, command: &str, bin: &str) -> Option<String> {
    let canonical = |p: &std::path::Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    match (&install.home, &install.user) {
        (Some(service_home), user) if canonical(service_home) != canonical(home) => {
            // The home is named outright, since the account's own login may not pick it up; `sudo` is asked for only to become an account the caller is not.
            let run_as = match user.as_deref() {
                Some(user) if caller != Some(user) => format!("sudo -u {user} "),
                None if caller != Some("root") => "sudo ".to_string(),
                _ => String::new(),
            };
            let runs = user.as_deref().map(|u| format!("runs as `{u}` with its files")).unwrap_or_else(|| "keeps its files".to_string());
            Some(format!(
                "this machine's gateway {runs} in {}, not in {} where this command would act, so the running gateway would never see the change: run `{run_as}env PERMAURA_HOME={} {bin} {command}`",
                service_home.display(),
                home.display(),
                service_home.display()
            ))
        }
        (None, Some(user)) if caller != Some(user.as_str()) => Some(format!(
            "this machine's gateway runs as `{user}` (permaura.service), so its files are that account's, not the ones in {}: run `sudo -u {user} {bin} {command}`",
            home.display()
        )),
        _ => None,
    }
}

/// ` (sudo -u <user> <bin> <this command>)` when the unit names an account other than this one, for a line that says to run this as the gateway's account.
fn install_hint() -> String {
    match service_install().and_then(|install| install.user) {
        Some(user) if current_user().as_deref() != Some(user.as_str()) => format!(" (`sudo -u {user} {} {}`)", this_binary(), this_command_line(std::env::args())),
        _ => String::new(),
    }
}

/// The arguments this command was run with, after the binary, ready to paste: what a refusal tells the operator to run again as another account, so a name or a flag they gave is not lost. A `--token` and its value are left out, since the line is printed.
fn this_command_line(args: impl IntoIterator<Item = String>) -> String {
    let mut out: Vec<String> = Vec::new();
    let mut args = args.into_iter().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--token" {
            args.next();
            continue;
        }
        if arg.starts_with("--token=") {
            continue;
        }
        let plain = !arg.is_empty() && arg.chars().all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c));
        out.push(if plain { arg } else { format!("'{}'", arg.replace('\'', "'\\''")) });
    }
    out.join(" ")
}

/// The account this command runs as.
fn current_user() -> Option<String> {
    #[cfg(unix)]
    // SAFETY: getpwuid returns a pointer into static storage or null, read here at once and copied before anything else in this process could call it again.
    unsafe {
        let entry = libc::getpwuid(libc::geteuid());
        if entry.is_null() || (*entry).pw_name.is_null() {
            return None;
        }
        std::ffi::CStr::from_ptr((*entry).pw_name).to_str().ok().map(str::to_string)
    }
    #[cfg(not(unix))]
    None
}

/// This binary's path, for a command line the operator can paste.
fn this_binary() -> String {
    std::env::current_exe().map(|p| p.display().to_string()).unwrap_or_else(|_| "permaura".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_is_taken_without_scheme_port_or_path() {
        assert_eq!(
            host_of("https://a.permaura.app").as_deref(),
            Some("a.permaura.app")
        );
        assert_eq!(
            host_of("https://a.permaura.app/health").as_deref(),
            Some("a.permaura.app")
        );
        assert_eq!(
            host_of("http://127.0.0.1:7376").as_deref(),
            Some("127.0.0.1")
        );
        assert_eq!(host_of("https://[::1]:7376/x").as_deref(), Some("[::1]"));
        assert_eq!(host_of(""), None);
    }

    /// The tunnel is configured for the host a client connects to, so the host is the URL parser's: a backslash ends the authority for it, and a URL a hand split would read as another host names none.
    #[test]
    fn the_host_is_the_one_the_url_parser_reads() {
        assert_eq!(host_of("https://a.permaura.app\\@evil.example/"), None);
        assert_eq!(host_of("https://user@a.permaura.app/"), None);
        assert_eq!(host_of("https://A.Permaura.App:8443/x").as_deref(), Some("a.permaura.app"));
    }

    /// The issuer check compares origins as the URL parser reads them, and refuses userinfo and an ambiguous authority outright.
    #[test]
    fn an_issuer_is_on_the_account_api_origin_only_as_the_parser_reads_it() {
        let trusted = origin_of("https://permaura.com").unwrap();
        assert_eq!(trusted, "https://permaura.com");
        for same in ["https://permaura.com/api/auth", "https://PERMAURA.com:443/api/auth/jwks"] {
            assert_eq!(origin_of(same).as_deref(), Some(trusted.as_str()), "{same}");
        }
        for other in ["https://permaura.com.evil.example/api/auth", "http://permaura.com/api/auth", "https://permaura.com:8443/api/auth"] {
            assert_ne!(origin_of(other).as_deref(), Some(trusted.as_str()), "{other}");
        }
        for refused in ["https://permaura.com@evil.example/", "https://permaura.com\\@evil.example/", "permaura.com/api/auth", "ftp://permaura.com/"] {
            assert_eq!(origin_of(refused), None, "{refused}");
        }
    }

    /// The exact body the tunnel route returns, so a rename on either side fails here rather than
    /// on a VPS after the server has already provisioned something.
    #[test]
    fn the_tunnel_response_is_read_from_the_routes_real_shape() {
        let body = r#"{"hostname":"vpstest.permaura.app","publicUrl":"https://vpstest.permaura.app",
            "credentials":{"AccountTag":"0123456789abcdef0123456789abcdef",
            "TunnelSecret":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
            "TunnelID":"6ff42ae2-765d-4adf-8112-31c55c1551ef"},
            "gatewayEnv":{"PERMAURA_PUBLIC_URL":"https://vpstest.permaura.app",
            "PERMAURA_OWNER_SUB":"user_1","PERMAURA_AS_ISSUER":"https://permaura.com/api/auth",
            "PERMAURA_AS_JWKS":"https://permaura.com/api/auth/jwks"}}"#;
        let r: TunnelResponse = serde_json::from_str(body).unwrap();
        assert_eq!(r.public_url.as_deref(), Some("https://vpstest.permaura.app"));
        assert!(r.token.is_none());
        let c = credentials_from(&r).expect("the credentials must deserialise and pass the checks");
        assert_eq!(c.tunnel_id, "6ff42ae2-765d-4adf-8112-31c55c1551ef");
        assert_eq!(c.account_tag, "0123456789abcdef0123456789abcdef");
        assert_eq!(c.endpoint, "", "an absent Endpoint is written empty");
        let env = r.gateway_env.expect("gatewayEnv must deserialise");
        assert_eq!(env.len(), 4);
        assert_eq!(env.get("PERMAURA_OWNER_SUB").map(String::as_str), Some("user_1"));
    }

    /// An older permaura.com answers with a run token for a remotely managed tunnel. It is refused by name, never run with `--token-file`.
    #[test]
    fn a_run_token_without_credentials_is_refused_as_a_remotely_managed_tunnel() {
        let body = r#"{"hostname":"vpstest.permaura.app","publicUrl":"https://vpstest.permaura.app",
            "token":"eyJ.tok","gatewayEnv":{"PERMAURA_PUBLIC_URL":"https://vpstest.permaura.app"}}"#;
        let r: TunnelResponse = serde_json::from_str(body).unwrap();
        let err = credentials_from(&r).err().expect("refused").to_string();
        assert!(err.contains("permaura.com handed out a remotely managed tunnel, which this version no longer runs"), "{err}");
        assert!(!err.contains("eyJ.tok") && !err.contains('\u{2014}'), "{err}");

        let neither: TunnelResponse = serde_json::from_str(r#"{"publicUrl":"https://vpstest.permaura.app"}"#).unwrap();
        assert!(credentials_from(&neither).err().unwrap().to_string().contains("did not return the tunnel's credentials"));
    }

    #[test]
    fn malformed_credentials_in_the_answer_are_refused_before_anything_is_written() {
        let body = r#"{"credentials":{"AccountTag":"acct","TunnelSecret":"c2hvcnQ=",
            "TunnelID":"6ff42ae2-765d-4adf-8112-31c55c1551ef"},"token":"eyJ.tok"}"#;
        let r: TunnelResponse = serde_json::from_str(body).unwrap();
        let err = credentials_from(&r).err().expect("refused").to_string();
        assert!(err.contains("cannot use") && err.contains("shorter than 32 bytes") && !err.contains("c2hvcnQ="), "{err}");
    }

    /// Enabling again and disabling are the operator's decisions, so both clear a stop the guard recorded.
    #[test]
    fn enable_and_disable_clear_a_recorded_stop() {
        let home = std::env::temp_dir().join(format!("permaura-remote-stop-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let marker = home.join(tunnel::STOP_MARKER_FILE);
        crate::cli::with_permaura_home(&home, || {
            let creds = Credentials::from_value(serde_json::json!({
                "AccountTag": "acct",
                "TunnelSecret": "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
                "TunnelID": "6ff42ae2-765d-4adf-8112-31c55c1551ef"
            }))
            .unwrap();
            tunnel::record_stop(&marker, "stopped").unwrap();
            write_credentials(&creds).unwrap();
            assert!(!marker.exists(), "remote enable clears it");

            tunnel::record_stop(&marker, "stopped").unwrap();
            let idle = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
            let ctx = Ctx::new(format!("http://{idle}"), None);
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(disable(&ctx)).unwrap();
            assert!(!marker.exists(), "remote disable clears it");
            assert!(!home.join(tunnel::CREDENTIALS_FILE).exists());
        });
        std::fs::remove_dir_all(&home).ok();
    }

    #[test]
    fn api_base_has_no_trailing_slash() {
        // A trailing slash would produce `…com//api/gateways/…`, which some proxies 404.
        assert!(!api_base().ends_with('/'));
    }

    /// A release build keeps the pinned account API unless `PERMAURA_API` is a loopback http(s) address (the installer smoke stubs the API there); a debug build takes any value.
    #[test]
    fn a_release_build_honors_permaura_api_only_on_loopback() {
        use super::super::enroll::api_base_for;
        let release = |v: &str| api_base_for(Some(v.to_string()), false);
        assert_eq!(api_base_for(Some("https://api.attacker.example/".into()), true), "https://api.attacker.example");
        assert_eq!(api_base_for(None, false), "https://permaura.com");
        for honored in ["http://127.0.0.1:4100", "http://127.0.0.1:4100/", "https://[::1]:9", "http://localhost:3000", "http://127.9.9.9"] {
            assert_eq!(release(honored), honored.trim_end_matches('/'), "{honored}");
        }
        for ignored in [
            "https://api.attacker.example/",
            "http://127.0.0.1.attacker.example",
            "http://localhost.attacker.example",
            "http://localhost@attacker.example",
            "http://127.0.0.1@attacker.example",
            "http://user@127.0.0.1:4100",
            "ftp://127.0.0.1",
            "http://0.0.0.0:4100",
            "http://10.0.0.1",
            "127.0.0.1:4100",
        ] {
            assert_eq!(release(ignored), "https://permaura.com", "{ignored}");
        }
    }

    /// An issuer or JWKS off the account API's origin is refused before config.toml is touched; the real answer's are written.
    #[test]
    fn remote_enable_writes_only_an_issuer_on_the_account_apis_origin() {
        let home = std::env::temp_dir().join(format!("permaura-remote-issuer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let config = home.join("config.toml");
        std::fs::write(&config, "# mine\n").unwrap();
        let answer = |issuer: &str, jwks: &str| -> std::collections::HashMap<String, String> {
            [
                ("PERMAURA_PUBLIC_URL", "https://vpstest.permaura.app"),
                ("PERMAURA_OWNER_SUB", "user_1"),
                ("PERMAURA_AS_ISSUER", issuer),
                ("PERMAURA_AS_JWKS", jwks),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
        };
        crate::cli::with_permaura_home(&home, || {
            for (issuer, jwks) in [
                ("https://attacker.example/api/auth", "https://permaura.com/api/auth/jwks"),
                ("https://permaura.com/api/auth", "https://attacker.example/jwks"),
                ("https://permaura.com.attacker.example/api/auth", "https://permaura.com/api/auth/jwks"),
                ("https://permaura.com@attacker.example/api/auth", "https://permaura.com/api/auth/jwks"),
                ("http://permaura.com/api/auth", "https://permaura.com/api/auth/jwks"),
            ] {
                let err = write_config(&answer(issuer, jwks), "https://permaura.com").expect_err(issuer).to_string();
                assert!(err.contains("nothing was written"), "{err}");
                assert_eq!(std::fs::read_to_string(&config).unwrap(), "# mine\n", "{issuer} {jwks}");
            }
            write_config(&answer("https://permaura.com/api/auth", "https://PERMAURA.com:443/api/auth/jwks"), "https://permaura.com").unwrap();
            let written = std::fs::read_to_string(&config).unwrap();
            assert!(written.contains("as_issuer = \"https://permaura.com/api/auth\""), "{written}");
        });
        std::fs::remove_dir_all(&home).ok();
    }

    fn edited(changed: bool) -> Edited {
        Edited { home: std::path::PathBuf::from("/home/op/.permaura"), changed, errors: Vec::new() }
    }

    fn answer(body: serde_json::Value) -> TurnedOffAnswer {
        judge_disable("http://127.0.0.1:47391", 200, &body).expect("a 200 answer")
    }

    /// Every answer short of a confirmed stop reads as remote access still on; only a confirmed one says it is off.
    #[test]
    fn remote_disable_reports_off_only_for_a_confirmed_stop() {
        let url = "http://127.0.0.1:47391";
        let stopped = answer(serde_json::json!({ "connector": "stopped", "connector_pid": 41, "remote_tokens": "refused", "environment": [], "supervised_by_app": false }));
        assert!(!forwarded_by_something_else(&stopped));
        let lines = report_disable(url, &RunningOff::Off(stopped), &edited(true), &[]);
        assert_eq!(lines, vec![format!("Remote access is off: the running gateway at {url} stopped its tunnel connector (pid 41) and refuses permaura.com tokens from now on.")]);

        let stuck = serde_json::json!({ "connector": "running", "connector_pid": 42, "detail": "it could not be signalled (permission denied)", "remote_tokens": "refused" });
        for (status, body, said) in [
            (500, stuck, "its tunnel connector (pid 42) did not stop: it could not be signalled (permission denied)"),
            (404, serde_json::json!({ "error": "not found" }), "older than this command"),
            (401, serde_json::json!({ "error": "invalid token" }), "refused this home's operator token"),
            (403, serde_json::json!({ "error": "operator plane is loopback-only" }), "answered 403: operator plane is loopback-only"),
        ] {
            let why = judge_disable(url, status, &body).err().unwrap_or_else(|| panic!("{status} is not a stop"));
            assert!(why.contains(said), "{why}");
            let lines = report_disable(url, &RunningOff::StillOn { why, ours: true }, &edited(true), &[]);
            assert!(lines[0].starts_with("Remote access stays on until the gateway restarts: "), "{lines:?}");
            assert!(lines[1].contains("Its files are changed") && lines[1].contains(&restart_hint()), "{lines:?}");
            assert!(lines.iter().all(|l| !l.contains("Remote access is off") && !l.contains('\u{2014}')), "{lines:?}");
        }
    }

    /// A restart is offered as the fix only when the running gateway proved it is this home's and something was removed from this home's files.
    #[test]
    fn a_restart_is_offered_only_for_this_homes_gateway_and_files_that_changed() {
        let url = "http://127.0.0.1:47396";
        let refused = || RunningOff::StillOn { why: "refusing to talk to 127.0.0.1:7376: there is no operator token".into(), ours: false };
        let nothing = report_disable(url, &refused(), &edited(false), &[]).join("\n");
        assert!(!nothing.contains("starts again without remote access"), "{nothing}");
        assert!(nothing.contains("Nothing was removed from /home/op/.permaura") && nothing.contains("as the account whose gateway it is"), "{nothing}");
        let elsewhere = report_disable(url, &refused(), &edited(true), &[]).join("\n");
        assert!(!elsewhere.contains("starts again without remote access"), "{elsewhere}");
        assert!(elsewhere.contains("The files removed were /home/op/.permaura's, which may not be the running gateway's"), "{elsewhere}");
        let ours_but_unchanged = report_disable(url, &RunningOff::StillOn { why: "x".into(), ours: true }, &edited(false), &[]).join("\n");
        assert!(!ours_but_unchanged.contains("starts again without remote access"), "{ours_but_unchanged}");
    }

    /// A gateway that runs no tunnel of its own while the Permaura app, a public URL from its environment or permaura.com tokens say remote access was on is not "off", and the claim about what it refuses is narrowed to permaura.com-signed tokens.
    #[test]
    fn a_gateway_with_no_tunnel_of_its_own_is_not_off() {
        let url = "http://127.0.0.1:47392";
        for body in [
            serde_json::json!({ "connector": "none", "remote_tokens": "refused", "environment": ["PERMAURA_PUBLIC_URL", "PERMAURA_AS_ISSUER"], "supervised_by_app": true }),
            serde_json::json!({ "connector": "none", "remote_tokens": "refused", "environment": [], "supervised_by_app": false }),
            serde_json::json!({ "connector": "none", "remote_tokens": "none", "environment": ["PERMAURA_PUBLIC_URL"], "supervised_by_app": false }),
        ] {
            let not_off = answer(body.clone());
            assert!(forwarded_by_something_else(&not_off), "{body}");
            let lines = report_disable(url, &RunningOff::NotOff(not_off), &edited(true), &[]).join("\n");
            assert!(lines.starts_with("Remote access is not off:") && !lines.contains("Remote access is off"), "{lines}");
            assert!(lines.contains("still reaches it") && lines.contains("agents enrolled with a code"), "{lines}");
        }
        let app = report_disable(
            url,
            &RunningOff::NotOff(answer(serde_json::json!({ "connector": "none", "remote_tokens": "refused", "environment": ["PERMAURA_PUBLIC_URL", "PERMAURA_AS_ISSUER"], "supervised_by_app": true }))),
            &edited(true),
            &[],
        )
        .join("\n");
        assert!(app.contains("turn remote access off in the app"), "{app}");
        assert!(app.contains("PERMAURA_PUBLIC_URL, PERMAURA_AS_ISSUER are set in the gateway's own environment"), "{app}");
        // A connector its guard had already stopped, or a gateway that never served remote access, is off. so is a gateway the app supervises with remote access never on, since the app supervises every gateway it starts.
        for body in [
            serde_json::json!({ "connector": "none", "remote_tokens": "refused", "environment": [], "supervised_by_app": false, "tunnel_before": "stopped" }),
            serde_json::json!({ "connector": "none", "remote_tokens": "refused", "environment": [], "tunnel_before": "local", "tunnel_after": "stopped", "tunnel_stop_reason": tunnel::TURNED_OFF }),
            serde_json::json!({ "connector": "none", "remote_tokens": "none", "environment": [], "supervised_by_app": false }),
            serde_json::json!({ "connector": "none", "remote_tokens": "none", "environment": [], "supervised_by_app": true }),
        ] {
            assert!(!forwarded_by_something_else(&answer(body.clone())), "{body}");
            let lines = report_disable(url, &RunningOff::Off(answer(body.clone())), &edited(false), &[]).join("\n");
            assert!(lines.starts_with("Remote access is off:") && !lines.contains("in the app"), "{lines}");
        }
    }

    /// A stop the gateway could not record is still a stop, and the CLI says the chain does not show it.
    #[test]
    fn an_unrecorded_stop_is_off_and_says_so() {
        let url = "http://127.0.0.1:47395";
        let unrecorded = answer(serde_json::json!({ "connector": "stopped", "connector_pid": 7, "remote_tokens": "refused", "environment": [], "supervised_by_app": false, "audited": false, "audit_error": "store unavailable" }));
        let lines = report_disable(url, &RunningOff::Off(unrecorded), &edited(true), &[]);
        assert!(lines[0].starts_with("Remote access is off:"), "{lines:?}");
        assert!(lines[1].contains("could not record this in its audit chain (store unavailable)"), "{lines:?}");
    }

    /// When the gateway could not say what its environment sets, a public URL found in this machine's env files is named, since the next start applies it again.
    #[test]
    fn remote_disable_names_a_public_url_an_env_file_sets_when_the_gateway_cannot() {
        let url = "http://127.0.0.1:47394";
        let set = vec!["/etc/permaura/gateway.env".to_string()];
        for outcome in [RunningOff::NoGateway, RunningOff::StillOn { why: "the gateway at u could not be reached".into(), ours: true }] {
            let lines = report_disable(url, &outcome, &edited(true), &set).join("\n");
            assert!(lines.contains("PERMAURA_PUBLIC_URL is set in /etc/permaura/gateway.env, which outranks config.toml"), "{lines}");
            assert!(!lines.contains("starts again without remote access"), "{lines}");
        }
        assert!(!report_disable(url, &RunningOff::NoGateway, &edited(true), &[]).join("\n").contains("PERMAURA_PUBLIC_URL"));
    }

    /// The installer's unit names the account and, through its environment file, the home the gateway runs with.
    #[test]
    fn the_service_unit_names_the_gateways_account_and_home() {
        let unit = "[Unit]\nDescription=Permaura gateway\n[Service]\nUser=permaura\nGroup=permaura\nEnvironmentFile=-/etc/permaura/gateway.env\nExecStart=/opt/permaura/bin/permaura start\n";
        let read = |path: &str| (path == "/etc/permaura/gateway.env").then(|| "# settings\nPERMAURA_HOME=/var/lib/permaura\nPERMAURA_ADDR=127.0.0.1:7376\n".to_string());
        assert_eq!(parse_unit(unit, read), ServiceInstall { user: Some("permaura".into()), home: Some("/var/lib/permaura".into()) });
        let inline = parse_unit("[Service]\nEnvironment=\"PERMAURA_HOME=/srv/permaura\" PERMAURA_ADDR=127.0.0.1:7377\n", |_| None);
        assert_eq!(inline, ServiceInstall { user: None, home: Some("/srv/permaura".into()) });
        assert_eq!(parse_unit("[Service]\nExecStart=/usr/local/bin/permaura start\n", |_| None), ServiceInstall::default());
    }

    /// Run as root (or the owner's login) with its own home on a service-account install, the command would edit files the gateway never reads, so it refuses and names `sudo -u`; run as the service account, or with the service's home, it goes ahead.
    #[test]
    fn a_command_from_another_accounts_home_is_refused_with_the_right_one() {
        let install = ServiceInstall { user: Some("permaura".into()), home: Some("/var/lib/permaura".into()) };
        let bin = "/opt/permaura/bin/permaura";
        let why = wrong_account(&install, std::path::Path::new("/root/.permaura"), Some("root"), "remote disable", bin).expect("refused");
        assert!(why.contains("`sudo -u permaura env PERMAURA_HOME=/var/lib/permaura /opt/permaura/bin/permaura remote disable`") && !why.contains('\u{2014}'), "{why}");
        // the service account itself, with another home (no stub env file, or a sudo that kept the invoker's HOME), is told to name the home, not to become itself.
        let itself = wrong_account(&install, std::path::Path::new("/home/permaura/.permaura"), Some("permaura"), "remote enable my-vps --yes", bin).expect("refused");
        assert!(itself.contains("run `env PERMAURA_HOME=/var/lib/permaura /opt/permaura/bin/permaura remote enable my-vps --yes`") && !itself.contains("sudo"), "{itself}");
        let root_unit = ServiceInstall { user: None, home: Some("/srv/permaura".into()) };
        let as_root = wrong_account(&root_unit, std::path::Path::new("/root/.permaura"), Some("root"), "remote disable", bin).expect("refused");
        assert!(as_root.contains("run `env PERMAURA_HOME=/srv/permaura ") && !as_root.contains("sudo"), "{as_root}");
        let as_owner = wrong_account(&root_unit, std::path::Path::new("/home/op/.permaura"), Some("op"), "remote disable", bin).expect("refused");
        assert!(as_owner.contains("run `sudo env PERMAURA_HOME=/srv/permaura "), "{as_owner}");
        assert!(wrong_account(&install, std::path::Path::new("/var/lib/permaura"), Some("permaura"), "remote disable", bin).is_none());
        assert!(wrong_account(&install, std::path::Path::new("/var/lib/permaura"), Some("root"), "remote disable", bin).is_none(), "root with the service's own home acts on the right files");
        let no_home = ServiceInstall { user: Some("permaura".into()), home: None };
        assert!(wrong_account(&no_home, std::path::Path::new("/root/.permaura"), Some("root"), "remote enable", bin).is_some_and(|w| w.contains("sudo -u permaura")));
        assert!(wrong_account(&no_home, std::path::Path::new("/var/lib/permaura"), Some("permaura"), "remote enable", bin).is_none());
        assert!(wrong_account(&ServiceInstall::default(), std::path::Path::new("/root/.permaura"), Some("root"), "remote disable", bin).is_none(), "a root unit with no account or home of its own names nothing else");
    }

    /// the command a refusal names is the one that was run, a name and its flags included, so `remote enable my-vps` is not told to run a bare `remote enable` that picks another name. A token is not printed.
    #[test]
    fn the_command_named_again_is_the_one_that_was_run() {
        let args = |line: &[&str]| this_command_line(line.iter().map(|a| a.to_string()));
        assert_eq!(args(&["/opt/permaura/bin/permaura", "remote", "enable", "my-vps", "--yes"]), "remote enable my-vps --yes");
        assert_eq!(args(&["permaura", "--url", "http://127.0.0.1:7377", "--token", "pgt_secret", "remote", "disable"]), "--url http://127.0.0.1:7377 remote disable");
        assert_eq!(args(&["permaura", "--token=pgt_secret", "remote", "status"]), "remote status");
        assert_eq!(args(&["permaura", "remote", "enable", "it's mine"]), "remote enable 'it'\\''s mine'");
    }

    /// a run that removed some files and could not change another says so, and never that nothing was removed; with no gateway running it never says remote access is off in one.
    #[test]
    fn a_file_that_could_not_be_changed_is_reported_as_that() {
        let url = "http://127.0.0.1:47397";
        let partial = Edited { home: std::path::PathBuf::from("/home/op/.permaura"), changed: true, errors: vec!["removing /home/op/.permaura/tunnel-credentials.json: permission denied".into()] };
        for ours in [true, false] {
            let lines = report_disable(url, &RunningOff::StillOn { why: "x".into(), ours }, &partial, &[]).join("\n");
            assert!(!lines.contains("Nothing was removed") && !lines.contains("starts again without remote access"), "{lines}");
            assert!(lines.contains("Some of /home/op/.permaura's files could not be changed (removing /home/op/.permaura/tunnel-credentials.json: permission denied)"), "{lines}");
        }
        let none = disable_failed(url, &RunningOff::NoGateway, &partial).expect("not every file changed");
        assert!(none.starts_with("no gateway is running") && !none.contains("off in the running gateway"), "{none}");
        assert!(disable_failed(url, &RunningOff::NoGateway, &edited(true)).is_none());
        let off = answer(serde_json::json!({ "connector": "stopped", "connector_pid": 9, "remote_tokens": "refused" }));
        assert!(disable_failed(url, &RunningOff::Off(off), &partial).is_some_and(|w| w.contains("off in the running gateway")));
        assert!(disable_failed(url, &RunningOff::StillOn { why: "x".into(), ours: true }, &edited(true)).is_some_and(|w| w.contains(url)));
    }

    /// on an install a user unit or a launchd agent runs, the restart a change needs goes through that service manager, never `permaura stop && permaura start`, which leaves the unit stopped and a gateway tied to the shell.
    #[test]
    fn the_restart_hint_follows_the_service_manager_that_runs_the_gateway() {
        let (unit, expected) = if cfg!(target_os = "linux") {
            (".config/systemd/user/permaura.service", "systemctl --user restart permaura")
        } else if cfg!(target_os = "macos") {
            ("Library/LaunchAgents/com.permaura.gateway.plist", "launchctl kickstart -k gui/")
        } else {
            return;
        };
        if UNIT_FILES.iter().any(|p| std::path::Path::new(p).exists()) {
            return;
        }
        let home = std::env::temp_dir().join(format!("permaura-c7r2-cli04-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(unit).parent().unwrap()).unwrap();
        std::fs::write(home.join(unit), "").unwrap();
        let hint = crate::cli::with_os_home(&home, restart_hint);
        let _ = std::fs::remove_dir_all(&home);
        assert!(hint.starts_with(expected), "{hint}");
    }

    #[test]
    fn status_reads_whether_the_running_gateway_still_serves_remote_access() {
        let running = serde_json::json!({ "tunnel_ingress": "local", "remote_tokens": "accepted" });
        assert!(still_serving(&running));
        assert!(still_serving(&serde_json::json!({ "tunnel_ingress": null, "remote_tokens": "accepted" })));
        let off = serde_json::json!({ "tunnel_ingress": "stopped", "tunnel_stop_reason": tunnel::TURNED_OFF, "remote_tokens": "refused" });
        assert!(!still_serving(&off));
        let said = describe_running("http://127.0.0.1:47393", &off);
        assert!(said.contains("tunnel connector stopped (remote access was turned off") && said.ends_with("it refuses permaura.com tokens"), "{said}");
        assert!(describe_running("u", &serde_json::json!({ "status": "ok" })).contains("does not say"));
    }
}
