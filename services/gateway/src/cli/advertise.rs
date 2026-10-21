//! Tell permaura.com where this gateway answers now.
//!
//! The address the console has on file is set once, at enrolment, from whatever the installer decided
//! to advertise. That is the right default and the wrong permanent answer: a gateway can be reinstalled
//! on another port, and a gateway inside a VM answers on an address the console cannot use at all,
//! because the address that matters there is the one the HOST forwards to it.
//!
//! So this exists for the case the installer cannot see: after `--port`, or on a guest whose reachable
//! address is a host-side port forward, run `permaura advertise` with the URL the console should call.

use anyhow::{Context, Result};

use super::enroll::api_base;
use super::port::{Health, Unproven};
use super::remote::gateway_id;

/// Point this gateway's account record at `url`.
///
/// The console sends this gateway's operator bearer to whatever answers at the advertised address, so the address first has to prove it is this gateway: the `/health` challenge, answered with an HMAC of this home's operator token over the port, which is what the launcher checks before it presents the token. `unproven` skips the proof for a VM guest whose advertised address is a host port forward the guest cannot dial, and says what that costs.
pub async fn run(url: &str, unproven: bool) -> Result<()> {
    let url = normalize(url)?;
    if unproven {
        println!(
            "Not checking that {url} is this gateway (--unproven). The console sends this gateway's operator token to whatever answers there, so use this only for a host port forward this machine cannot dial, and only when it forwards to this gateway."
        );
    } else {
        prove(&url).await?;
    }
    let install =
        permaura_core::install::ensure().context("reading this machine's install identity")?;
    let id = gateway_id()?;
    let api = api_base();

    let client = super::enroll::api_client(&api, std::time::Duration::from_secs(30))?;

    let resp = client
        .patch(format!("{api}/api/gateways/{id}"))
        .json(&serde_json::json!({
            "installId": install.install_id,
            "installSecret": install.secret,
            "baseUrl": url,
        }))
        .send()
        .await
        .context("reaching the account API")
        .and_then(super::port::refuse_redirect)?;

    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    for line in outcome(&url, status, &body)? {
        println!("{line}");
    }
    Ok(())
}

/// Refuse unless whatever answers at `url` proves it holds this home's operator token. Nothing but the challenge is sent to it.
async fn prove(url: &str) -> Result<()> {
    let addr = super::port::local_addr_of(url).with_context(|| format!("{url} is not an address on this machine"))?;
    let token = super::port::operator_token();
    let keys: Vec<&str> = token.as_deref().into_iter().collect();
    let why = match super::port::probe_health(addr, &keys).await {
        Health::Ours => return Ok(()),
        Health::Unconfirmed(Unproven::NoToken) => format!(
            "this home has no operator token to check {url} against ({})",
            super::port::operator_token_path().display()
        ),
        Health::Unconfirmed(_) => format!("whatever answers at {url} did not prove it is this gateway"),
        Health::NotPermaura => format!("something answers at {url}, but not as a Permaura gateway"),
        Health::Unreachable => format!("nothing answers at {url}"),
    };
    anyhow::bail!(
        "{why}, so permaura.com was not told about it: the console would send this gateway's operator token there. Advertise the address this gateway listens on. On a VM guest whose advertised address is the host's port forward, which the guest cannot dial, run again with --unproven."
    )
}

/// What to print for the account API's answer, or the error to exit with.
fn outcome(url: &str, status: u16, body: &serde_json::Value) -> Result<Vec<String>> {
    let error = body.get("error").and_then(|v| v.as_str());
    if !(200..300).contains(&status) {
        anyhow::bail!("{} ({status})", error.unwrap_or("the account API refused this"));
    }
    let mut lines = vec![format!("✓ permaura.com will reach this gateway at {url}")];
    if let Some(warning) = body.get("warning").and_then(|v| v.as_str()) {
        lines.push(format!("! {warning}"));
    }
    Ok(lines)
}

/// The URL the server will accept, or a refusal that says why before the round trip.
///
/// Mirrors `web/lib/gateways/rebind.ts`. Checking here as well is not belt and braces: the operator is
/// at a terminal, and "that is not a loopback address" is a far better answer than a 400.
fn normalize(raw: &str) -> Result<String> {
    let parsed = reqwest::Url::parse(raw.trim())
        .with_context(|| format!("'{raw}' is not a URL. Try http://127.0.0.1:7376"))?;
    anyhow::ensure!(
        matches!(parsed.scheme(), "http" | "https"),
        "the address must be http or https, not {}",
        parsed.scheme()
    );
    anyhow::ensure!(
        parsed.path() == "/" && parsed.query().is_none() && parsed.fragment().is_none(),
        "give the address only, with no path: http://127.0.0.1:7376"
    );
    let host = parsed
        .host_str()
        .context("the address has no host")?
        .trim_matches(|c| c == '[' || c == ']')
        .to_string();
    let loopback = host == "localhost"
        || host.ends_with(".localhost")
        || host
            .parse::<std::net::IpAddr>()
            .map(|ip| ip.is_loopback())
            .unwrap_or(false);
    anyhow::ensure!(
        loopback,
        "'{host}' is not this machine. The console reaches a gateway on your own machine directly, \
         so this address has to be a loopback one. A gateway reachable from elsewhere needs remote \
         access instead: permaura remote enable"
    );
    Ok(parsed.to_string().trim_end_matches('/').to_string())
}

#[cfg(test)]
mod tests {
    use super::{normalize, outcome};

    #[test]
    fn the_answer_prints_its_warning_and_a_refusal_prints_the_servers_error() {
        let lines = outcome("http://127.0.0.1:7377", 200, &serde_json::json!({ "warning": "point your own tunnel at it" })).unwrap();
        assert!(lines.iter().any(|l| l.contains("point your own tunnel at it")), "{lines:?}");
        for status in [403, 409, 502] {
            let err = outcome("http://127.0.0.1:7377", status, &serde_json::json!({ "error": "not this machine's link" })).unwrap_err().to_string();
            assert!(err.contains("not this machine's link") && err.contains(&status.to_string()), "{err}");
        }
    }

    /// permaura.com no longer moves a managed tunnel, so nothing printed says a port move was refused or that the tunnel follows this command, whatever an older account API answers.
    #[test]
    fn nothing_printed_says_the_tunnel_follows_the_address() {
        let lines = outcome("http://127.0.0.1:7377", 200, &serde_json::json!({ "tunnelPort": 7377 })).unwrap();
        assert_eq!(lines, ["✓ permaura.com will reach this gateway at http://127.0.0.1:7377"]);
        for body in [
            serde_json::json!({ "error": "x", "unprovenPort": true }),
            serde_json::json!({ "error": "x", "updateRequired": true }),
            serde_json::json!({ "error": "x", "restoreFailed": true }),
        ] {
            let err = outcome("http://127.0.0.1:7377", 409, &body).unwrap_err().to_string();
            assert_eq!(err, "x (409)");
        }
        let err = outcome("http://127.0.0.1:7377", 502, &serde_json::json!({})).unwrap_err().to_string();
        assert!(!err.contains("tunnel") && !err.contains("remote disable"), "{err}");
    }

    #[test]
    fn a_loopback_address_is_accepted_and_its_trailing_slash_dropped() {
        assert_eq!(normalize("http://127.0.0.1:7377").unwrap(), "http://127.0.0.1:7377");
        assert_eq!(normalize("http://localhost:7377/").unwrap(), "http://localhost:7377");
        assert_eq!(normalize(" http://[::1]:7377 ").unwrap(), "http://[::1]:7377");
    }

    /// The VM case is exactly why the rule needs saying out loud: the guest's own LAN address feels
    /// like the right answer and is not, because the console reaches a local gateway directly.
    #[test]
    fn a_routable_address_is_refused_and_points_at_remote_access() {
        let err = normalize("http://192.168.64.7:7377").unwrap_err().to_string();
        assert!(err.contains("not this machine"), "{err}");
        assert!(err.contains("permaura remote enable"), "{err}");
    }

    #[test]
    fn an_address_is_an_origin_and_nothing_else() {
        assert!(normalize("http://127.0.0.1:7376/v1").is_err());
        assert!(normalize("http://127.0.0.1:7376/?x=1").is_err());
        assert!(normalize("ftp://127.0.0.1:7376").is_err());
        assert!(normalize("not a url").is_err());
    }
}
