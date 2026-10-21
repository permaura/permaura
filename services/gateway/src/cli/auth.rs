//! `permaura auth login`: connect this machine to a Permaura account, from a box with no browser.
//!
//! The installer's `--pair` runs the other way round: a human opens a console somewhere, mints a
//! code, and carries it here. That is the right shape for a script, and it stays. It is the wrong
//! shape for a person sitting at a fresh VPS, because it sends them to a different computer before
//! anything can happen.
//!
//! So this asks first. It prints one link, waits, and picks up whatever the human decided: which
//! workspace the gateway belongs to, and whether it should have a public address. RFC 8628, using
//! `verification_uri_complete` so nobody retypes a code.
//!
//! The device code goes only back to the account API that issued it and is never printed. The LINK,
//! however, is a capability for as long as the request is live: approving it needs a signed-in
//! Permaura account and the code, and nothing ties the approver to whoever started it. So anyone who
//! reads that link off a CI log, a shared tmux pane or a screen share within the window can claim
//! this machine into their own account.
//!
//! Shortening the window is not enough on its own, so enrolment prints WHO claimed it and where it
//! landed. A takeover that is invisible is the dangerous one; a takeover that prints somebody else's
//! email address is one the operator can act on.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

use super::enroll;

#[derive(Deserialize)]
struct StartResponse {
    device_code: String,
    user_code: String,
    verification_uri_complete: String,
    #[serde(default)]
    expires_in: u64,
    #[serde(default)]
    interval: u64,
}

#[derive(Deserialize)]
struct PollResponse {
    status: String,
    #[serde(default)]
    pairing_code: Option<String>,
    #[serde(default)]
    tunnel_name: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Seconds to wait between polls when the server does not say.
const DEFAULT_INTERVAL: u64 = 5;

/// `permaura auth login`
///
/// `ctx.url` is the address this gateway answers on, handed to enrolment once a human approves,
/// the same value `--pair` sends, because the account API is being told the same thing either way.
/// The bearer handed to it is decided as for any request there, before the login starts: this home's
/// token only for a listener on this machine that proves it holds it, and elsewhere only `--token` over https.
pub async fn login(ctx: &super::commands::Ctx) -> Result<()> {
    let base_url = ctx.url.as_str();
    if super::port::local_addr_of(base_url).is_none() && ctx.token.as_deref().is_none_or(str::is_empty) {
        bail!(
            "{base_url} is not on this machine, and this home's operator token never leaves this machine: name that gateway's own operator token in PERMAURA_TOKEN"
        );
    }
    // As `pair` does: enrolling a gateway that is not answering spends the login on a row the console can never drive.
    if !ctx.is_healthy().await {
        bail!("nothing is answering at {base_url}: start the gateway first with `permaura start`, or name a different one with --url");
    }
    let token = ctx.bearer().await?.filter(|t| !t.is_empty()).ok_or_else(|| {
        anyhow::anyhow!("no operator token to hand over: expected one in ~/.permaura/operator.token, or set PERMAURA_TOKEN")
    })?;
    let api = enroll::api_base();
    let client = enroll::api_client(&api, std::time::Duration::from_secs(30))?;

    let start: StartResponse = client
        .post(format!("{api}/api/gateways/device/start"))
        .json(&serde_json::json!({ "name": enroll::hostname() }))
        .send()
        .await
        .context("reaching the account API")
        .and_then(super::port::refuse_redirect)?
        .error_for_status()
        .context("the account API refused to start a login")?
        .json()
        .await
        .context("the account API returned something this version cannot read")?;

    println!();
    println!("  Open this link to connect this machine to your Permaura account:");
    println!();
    println!("      \x1b[36m{}\x1b[0m", start.verification_uri_complete);
    println!();
    println!("  It should show the code \x1b[1m{}\x1b[0m.", start.user_code);
    println!();
    print!("  Waiting for approval… ");
    use std::io::Write as _;
    let _ = std::io::stdout().flush();

    let interval = std::time::Duration::from_secs(if start.interval == 0 {
        DEFAULT_INTERVAL
    } else {
        start.interval
    });
    // The server's own expiry is the authority; this is just a local stop so a forgotten terminal
    // does not poll for ever.
    let deadline = std::time::Instant::now()
        + std::time::Duration::from_secs(if start.expires_in == 0 { 900 } else { start.expires_in });

    loop {
        if std::time::Instant::now() >= deadline {
            println!();
            bail!("that request expired before it was approved. Run `permaura auth login` again");
        }
        tokio::time::sleep(interval).await;

        let resp = client
            .post(format!("{api}/api/gateways/device/poll"))
            .json(&serde_json::json!({ "device_code": start.device_code }))
            .send()
            .await;

        // A poll that could not be sent is a network blip, not an answer: keep waiting rather than
        // throwing away an approval the human may already have given.
        let Ok(resp) = resp else { continue };
        let resp = super::port::refuse_redirect(resp)?;
        let body: PollResponse = match resp.json().await {
            Ok(b) => b,
            Err(_) => continue,
        };

        match body.status.as_str() {
            "pending" => continue,
            "denied" => {
                println!();
                bail!("that request was refused in the browser");
            }
            "expired" => {
                println!();
                bail!("that request expired before it was approved. Run `permaura auth login` again");
            }
            "approved" => {
                let code = body
                    .pairing_code
                    .context("the account API approved the login but sent no pairing code")?;
                println!("\x1b[32m✓\x1b[0m");
                // Enrolment goes through the one path everything else uses, so there is exactly one
                // place that turns a code into a gateway row.
                enroll::enroll(base_url, &token, &code).await?;
                if let Some(name) = body.tunnel_name {
                    println!();
                    println!("  A public address was requested. Setting it up…");
                    super::remote::enable(if name.is_empty() { None } else { Some(&name) }, true)
                        .await?;
                }
                return Ok(());
            }
            other => {
                println!();
                bail!(
                    "{}",
                    body.error
                        .unwrap_or_else(|| format!("the account API answered with \"{other}\""))
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// A gateway that is not running is named as that, before the device flow starts, rather than blamed on an operator-token file that is there.
    #[test]
    fn login_with_the_gateway_stopped_says_it_is_not_running() {
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let ctx = super::super::commands::Ctx::new(format!("http://127.0.0.1:{port}"), Some("pgt_login_test".into()));
        let err = tokio::runtime::Runtime::new().unwrap().block_on(super::login(&ctx)).unwrap_err().to_string();
        assert!(err.contains("nothing is answering"), "{err}");
        assert!(!err.contains("operator.token"), "the token file is not blamed: {err}");
    }

    /// Elsewhere, with no token named, the refusal says this home's token never leaves this machine.
    #[test]
    fn login_against_a_gateway_elsewhere_without_a_token_says_why() {
        let ctx = super::super::commands::Ctx::new("https://gw.example.invalid".into(), None);
        let err = tokio::runtime::Runtime::new().unwrap().block_on(super::login(&ctx)).unwrap_err().to_string();
        assert!(err.contains("never leaves this machine"), "{err}");
    }
}
