//! `permaura announce`: the credentials this gateway announces held approvals to permaura.com with,
//! so the phones in its workspace hear about them.
//!
//! Linking a gateway hands it these already (see [`super::enroll`]). This is for a gateway linked
//! before that existed, for rotating them on a machine the console cannot reach, and for asking the
//! gateway what it thinks it has.

use std::path::PathBuf;

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;

use super::commands::Ctx;
use permaura_gateway::announce::{is_announce_secret, is_gateway_id};
use permaura_gateway::config::{write_announce, AnnounceLink, GatewayConfig};

/// What became of credentials handed to a gateway.
pub enum Applied {
    /// The running gateway took them; `persisted` is false when it has no config file to keep them in.
    Live { persisted: bool },
    /// Nothing was answering, so they went into the config file for the next start.
    OnDisk(PathBuf),
    /// The running gateway predates `/v1/announce`.
    TooOld,
    /// The gateway or the file refused them, and why.
    Refused(String),
}

/// One workspace link, as the gateway reports it.
#[derive(Deserialize, Clone)]
struct Link {
    gateway_id: String,
    fingerprint: Option<String>,
}

/// The gateway's own answer to `GET /v1/announce`.
#[derive(Deserialize)]
struct Status {
    #[serde(default)]
    configured: bool,
    /// Absent on a 1.3.25 gateway, which answered with a single link in the two fields below.
    #[serde(default)]
    links: Option<Vec<Link>>,
    #[serde(default)]
    gateway_id: Option<String>,
    #[serde(default)]
    fingerprint: Option<String>,
    settable: bool,
}

impl Status {
    /// The links this gateway holds, reading a 1.3.25 answer as the one link it could hold.
    fn links(&self) -> Vec<Link> {
        if let Some(links) = &self.links {
            return links.clone();
        }
        match (self.configured, self.gateway_id.as_deref()) {
            (true, Some(id)) => {
                vec![Link { gateway_id: id.to_string(), fingerprint: self.fingerprint.clone() }]
            }
            _ => Vec::new(),
        }
    }
}

fn client(url: &str) -> Result<reqwest::Client> {
    Ok(super::port::client_for(url, Some(std::time::Duration::from_secs(10)))?)
}

/// Hand credentials to the gateway at `base_url`, or to its config file when nothing is answering.
///
/// The file is only written when the gateway is unreachable. A gateway that answers 404 is running an
/// older build that would refuse to boot on the `gateway_id` key, so it is told to upgrade instead.
///
/// On this machine the bearer and the secret go only to a listener that has just proved it holds the bearer, the same rule as `port::bearer_for`.
pub async fn apply(base_url: &str, token: &str, gateway_id: &str, secret: &str) -> Applied {
    let reachable = super::port::reachable_url(base_url);
    let base_url = reachable.as_str();
    match super::port::local_addr_of(base_url) {
        Some(addr) => {
            let listener = super::port::listener_at(addr, &[token]).await;
            if let Err(refused) =
                super::port::local_bearer(addr, Some(token), None, listener, &super::port::operator_token_path())
            {
                return Applied::Refused(refused.0);
            }
        }
        // Elsewhere only TLS says who answers; over plain http a proof could be relayed and the bearer read on the way.
        None if !reqwest::Url::parse(base_url).is_ok_and(|u| u.scheme() == "https") => {
            return Applied::Refused(format!(
                "refusing to send the operator token to {base_url}: it is not on this machine and not https, so it would cross the network in the clear. Use the gateway's https address"
            ));
        }
        None => {}
    }
    let client = match client(base_url) {
        Ok(c) => c,
        Err(e) => return Applied::Refused(e.to_string()),
    };
    let sent = client
        .put(format!("{}/v1/announce", base_url.trim_end_matches('/')))
        .bearer_auth(token)
        .json(&serde_json::json!({ "gateway_id": gateway_id, "announce_secret": secret }))
        .send()
        .await;
    let resp = match sent {
        Ok(resp) => resp,
        Err(e) if e.is_connect() || e.is_timeout() => {
            return match GatewayConfig::default_path() {
                Some(path) => match merge_into_file(&path, gateway_id, secret) {
                    Ok(()) => Applied::OnDisk(path),
                    Err(e) => Applied::Refused(e),
                },
                None => Applied::Refused("could not resolve ~/.permaura: set PERMAURA_HOME or HOME".into()),
            };
        }
        Err(e) => return Applied::Refused(e.to_string()),
    };
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_else(|_| serde_json::json!({}));
    if status.is_success() {
        let persisted = body.get("persisted").and_then(|v| v.as_bool()).unwrap_or(false);
        return Applied::Live { persisted };
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Applied::TooOld;
    }
    let reason = body.get("error").and_then(|v| v.as_str()).unwrap_or("no reason given");
    Applied::Refused(format!("the gateway answered {}: {reason}", status.as_u16()))
}

/// Add or replace one link in the config file, leaving this gateway's other links in place.
///
/// Only for a gateway that is not running: a running one owns this file, and writing underneath it
/// would be overwritten by its next change.
fn merge_into_file(path: &std::path::Path, gateway_id: &str, secret: &str) -> Result<(), String> {
    let existing = GatewayConfig::load_from(path)?.unwrap_or_default();
    let mut links = existing.announce_links();
    let fresh = AnnounceLink {
        gateway_id: gateway_id.to_string(),
        announce_secret: secret.to_string(),
    };
    match links.iter().position(|l| l.gateway_id == gateway_id) {
        Some(at) => links[at] = fresh,
        None => links.push(fresh),
    }
    write_announce(path, &links)
}

/// Say what [`apply`] did, in the terms the operator acts on.
pub fn report(applied: &Applied) {
    match applied {
        Applied::Live { persisted: true } => {
            println!("\x1b[32m✓\x1b[0m Phone notifications: this gateway now tells permaura.com when it holds an approval.");
        }
        Applied::Live { persisted: false } => {
            println!("\x1b[32m✓\x1b[0m Phone notifications: on for this run. The gateway has no config file to keep them in, so they stop at the next restart.");
        }
        Applied::OnDisk(path) => {
            println!("\x1b[32m✓\x1b[0m Phone notifications: saved to {}; they start when the gateway next starts.", path.display());
        }
        Applied::TooOld => {
            eprintln!("\x1b[33m!\x1b[0m The running gateway is too old to send phone notifications through permaura.com.");
            eprintln!("    Run `permaura upgrade`, then `permaura announce rotate`.");
        }
        Applied::Refused(reason) => {
            eprintln!("\x1b[33m!\x1b[0m Phone notifications are not set up: {reason}");
            eprintln!("    Try again with `permaura announce rotate`.");
        }
    }
}

/// What asking the gateway about its credentials found.
enum Reach {
    /// It answered; `None` means it predates `/v1/announce`.
    Answered(Option<Status>),
    /// Nothing is listening.
    Unreachable,
}

async fn fetch_status(ctx: &Ctx) -> Result<Reach> {
    let mut req = client(&ctx.url)?.get(format!("{}/v1/announce", ctx.url.trim_end_matches('/')));
    if let Some(bearer) = ctx.bearer().await? {
        req = req.bearer_auth(bearer);
    }
    let sent = req.send().await;
    let resp = match sent {
        Ok(resp) => resp,
        Err(e) if e.is_connect() => return Ok(Reach::Unreachable),
        Err(e) => return Err(e).with_context(|| format!("reaching the gateway at {}", ctx.url)),
    };
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(Reach::Answered(None));
    }
    if !resp.status().is_success() {
        bail!("the gateway at {} answered {}", ctx.url, resp.status().as_u16());
    }
    Ok(Reach::Answered(Some(resp.json().await.context("reading the gateway's answer")?)))
}

/// `permaura announce status`
pub async fn status(ctx: &Ctx) -> Result<()> {
    let status = match fetch_status(ctx).await? {
        Reach::Answered(Some(status)) => status,
        Reach::Answered(None) => {
            println!("This gateway is too old to send phone notifications through permaura.com. Run `permaura upgrade`.");
            return Ok(());
        }
        Reach::Unreachable => bail!("nothing is answering at {}: start the gateway first", ctx.url),
    };
    let links = status.links();
    if links.is_empty() {
        println!("This gateway does not send phone notifications through permaura.com.");
        println!("Run `permaura announce rotate` to set it up.");
    } else {
        println!("This gateway tells permaura.com when it holds an approval, for {} link(s):", links.len());
        for link in &links {
            println!("  {} (fingerprint {})", link.gateway_id, link.fingerprint.as_deref().unwrap_or("?"));
        }
        println!("The console shows the same fingerprint on the workspace holding the matching secret.");
    }
    if !status.settable {
        println!("Its credentials come from its environment or its hosting, so they are changed there, not here.");
    }
    Ok(())
}

/// `permaura announce rotate`: ask permaura.com for a new secret as this machine, then apply it.
///
/// One link at a time, because each is a separate row on the control plane and rotating one retires
/// only its own secret. `--all` walks the links this gateway already holds.
pub async fn rotate(ctx: &Ctx, gateway: Option<String>, all: bool) -> Result<()> {
    // Checked before asking permaura.com, which retires the old secret the moment it mints a new
    // one: a gateway that cannot take the new one would otherwise be left with neither.
    let reported = match fetch_status(ctx).await? {
        Reach::Answered(None) => {
            bail!("the running gateway is too old to take announce credentials; run `permaura upgrade` first")
        }
        Reach::Answered(Some(status)) if !status.settable => {
            bail!("this gateway's announce credentials come from its environment or its hosting; change them there")
        }
        Reach::Answered(Some(status)) => Some(status),
        // Not running: the new secret goes into the config file for the next start.
        Reach::Unreachable => None,
    };
    let held: Vec<String> = reported
        .as_ref()
        .map(|s| s.links().iter().map(|l| l.gateway_id.clone()).collect())
        .unwrap_or_default();

    let targets: Vec<String> = match (gateway, all) {
        (Some(_), true) => bail!("name a gateway or pass --all, not both"),
        (Some(id), false) => vec![id],
        (None, true) if held.is_empty() => bail!("this gateway holds no links to rotate"),
        (None, true) => held,
        (None, false) => match held.len() {
            1 => held,
            0 => vec![super::remote::gateway_id()?],
            _ => {
                let names = held.join(", ");
                bail!("this gateway announces to several workspaces ({names}); name one with --gateway or pass --all")
            }
        },
    };

    for gateway_id in targets {
        rotate_one(ctx, &gateway_id).await?;
    }
    Ok(())
}

async fn rotate_one(ctx: &Ctx, gateway_id: &str) -> Result<()> {
    if !is_gateway_id(gateway_id) {
        bail!("{gateway_id} is not a gateway id");
    }
    // Before permaura.com is asked, which retires the old secret the moment it mints a new one.
    let bearer = ctx.bearer().await?.unwrap_or_default();
    let install = permaura_core::install::load().ok_or_else(|| {
        anyhow!("this machine has no install identity, so permaura.com cannot tell it owns the link; pair it with `PERMAURA_PAIR_CODE=<code> permaura pair`")
    })?;

    let api = super::enroll::api_base();
    let resp = super::enroll::api_client(&api, std::time::Duration::from_secs(10))?
        .post(format!("{api}/api/gateways/{gateway_id}/announce-secret"))
        .json(&serde_json::json!({ "installId": install.install_id, "installSecret": install.secret }))
        .send()
        .await
        .context("reaching the account API")
        .and_then(super::port::refuse_redirect)?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.unwrap_or_else(|_| serde_json::json!({}));
    if !status.is_success() {
        let reason = body.get("error").and_then(|v| v.as_str()).unwrap_or("no reason given");
        bail!("permaura.com refused ({}): {reason}", status.as_u16());
    }
    let secret = body
        .get("announceSecret")
        .and_then(|v| v.as_str())
        .filter(|s| is_announce_secret(s))
        .context("permaura.com did not send a usable secret")?;
    // permaura.com has already retired the old secret, so from here this link is silent until this
    // lands; the report says how to retry if it does not.
    let applied = apply(&ctx.url, &bearer, gateway_id, secret).await;
    report(&applied);
    match applied {
        Applied::Live { .. } | Applied::OnDisk(_) => Ok(()),
        Applied::TooOld => bail!("the running gateway cannot take the new secret"),
        Applied::Refused(reason) => bail!("{reason}"),
    }
}
