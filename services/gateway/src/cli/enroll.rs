//! Handing a gateway to a permaura.com account: the one exchange behind both `permaura pair` and
//! `permaura start --pair`.
//!
//! Enrolment is the pairing code, the address the gateway answers on and this machine's install identity, posted to `/api/gateways/enroll`. It never carries the operator token: that token is local wherever it arrives from, and a copy permaura.com held would be the owner at the keyboard once a configuration permaura.com's Cloudflare account pushed to the tunnel connector, or private-network traffic it routed through it, delivered it from loopback. A loopback-only gateway's console bearer is a console session the re-seal task hands each link within a poll of the pairing ([`permaura_gateway::reseal`]); a gateway with a public URL needs none, since permaura.com reaches it with the owner's own short-lived token.
//!
//! Shared rather than duplicated because the two entry points differ only in when they are sure the
//! gateway is up. A second copy would be a second answer to "which fields does enrolment take", and
//! the console has no way to tell a wrong one from a refusal.

use anyhow::Context as _;

/// The account API a release build talks to unless `PERMAURA_API` names a loopback address.
pub const PERMAURA_ORIGIN: &str = "https://permaura.com";

/// What a release build trusts as the account API, in its message when it ignores `PERMAURA_API`.
const RELEASE_API_TRUST: &str = "https://permaura.com or a loopback http(s) address";

/// Where the account API lives. A debug build takes any `PERMAURA_API` so a dev console can enrol against itself; a release build takes only a loopback one (the installer-pair smoke stubs the API there) and otherwise keeps https://permaura.com, because pairing and `permaura remote enable` hand that API the install identity and write back the issuer whose tokens the gateway accepts.
pub fn api_base() -> String {
    use permaura_gateway::release::{is_loopback_http_url, trust_root_override_unless};
    api_base_in(trust_root_override_unless("PERMAURA_API", RELEASE_API_TRUST, is_loopback_http_url))
}

/// [`api_base`] for a `PERMAURA_API` value in a build that is (`debug_build`) or is not a debug build.
#[cfg(test)]
pub(crate) fn api_base_for(value: Option<String>, debug_build: bool) -> String {
    use permaura_gateway::release::{is_loopback_http_url, trust_root_override_in};
    api_base_in(trust_root_override_in(value, debug_build, is_loopback_http_url))
}

fn api_base_in(over: Option<String>) -> String {
    over.unwrap_or_else(|| PERMAURA_ORIGIN.to_string()).trim_end_matches('/').to_string()
}

/// The client every request to the account API at `api` goes through. Each one carries something only permaura.com should see (the install secret, a pairing or device code), and a 307 or 308 would resend that body wherever it points, so a redirect is answered, not followed (see [`super::port::refuse_redirect`]); and anything but a loopback address is https only, on every hop.
pub fn api_client(api: &str, timeout: std::time::Duration) -> reqwest::Result<reqwest::Client> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .https_only(!permaura_gateway::release::is_loopback_http_url(api))
        .timeout(timeout)
        .build()
}

/// POST the pairing code and this gateway's address to the account API, then hand the link's announce secret to the gateway with `token`, the operator token, which goes only to that gateway and never to permaura.com.
///
/// The caller establishes that the gateway is ANSWERING first. Enrolling one that never came up
/// leaves the console holding a row it can never drive, and spends a single-use code doing it.
pub async fn enroll(base_url: &str, token: &str, code: &str) -> anyhow::Result<()> {
    let api = api_base();
    let client = api_client(&api, std::time::Duration::from_secs(20))?;

    // Mint (or reuse) this machine's identity and present it with the enrolment.
    //
    // The desktop app has always done this; a `curl | sh` install never did, and the row it created
    // could not afterwards be listed or revoked from the machine, nor could the machine ask for its
    // own tunnel, because it held nothing permaura.com would accept. It belongs HERE rather than in
    // either caller: `pair` and `start --pair` produce the same gateway, and one of them quietly
    // producing an unmanageable one is the kind of difference nothing downstream can see.
    //
    // Enrolment still succeeds if this fails: an identity is what makes a gateway manageable from
    // here, not what makes it work.
    let install = permaura_core::install::ensure()
        .map_err(|e| {
            eprintln!("permaura: could not store this machine's install identity ({e}); pairing anyway, but this gateway will not be able to manage its own links or remote access");
        })
        .ok();

    let resp: serde_json::Value = client
        .post(format!("{api}/api/gateways/enroll"))
        .json(&enroll_body(code, &hostname(), base_url, install.as_ref()))
        .send()
        .await
        .context("reaching the account API")
        .and_then(super::port::refuse_redirect)?
        .json()
        .await
        .unwrap_or_else(|_| serde_json::json!({}));

    if resp.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        // Keep the id the account API just gave us. Without it this machine can name itself to
        // permaura.com but cannot say WHICH gateway it is, so it could never ask about its own
        // tunnel: the enrolment response is the only place the id is ever offered, and it used to
        // be read for a success flag and then dropped.
        if let Some(gid) = resp.get("gatewayId").and_then(|v| v.as_str()) {
            if let Some(path) = permaura_core::paths::permaura_path("gateway.id") {
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                if let Err(e) = std::fs::write(&path, gid) {
                    eprintln!("permaura: could not record this gateway's id ({e}); `permaura remote` will not work until you pair again");
                }
            }
        }
        // Name WHO claimed this machine, and where it landed.
        //
        // The account API has always sent both back and this read only `ok`. That silence is what
        // made the flow unsafe to watch: the approval link is a capability for its lifetime, so
        // anyone who saw it in a CI log, a shared tmux, or over a shoulder could approve the machine
        // into THEIR account, and the operator would see a green tick and nothing else. Printing
        // the account is what turns that from invisible into obvious.
        let who = resp
            .get("user")
            .and_then(|u| u.get("email"))
            .and_then(|v| v.as_str());
        let where_ = resp
            .get("workspace")
            .and_then(|w| w.get("name"))
            .and_then(|v| v.as_str());
        println!("\x1b[32m✓\x1b[0m Connected.");
        match (who, where_) {
            (Some(email), Some(ws)) => {
                println!("  Claimed by \x1b[1m{email}\x1b[0m, in workspace \x1b[1m{ws}\x1b[0m.");
                // Names a real remedy. There is no `unpair` verb, and telling somebody mid-incident
                // to run a command that does not exist wastes the one minute that matters.
                println!(
                    "  \x1b[33mIf that is not your account, stop the gateway now\x1b[0m (`permaura stop`),"
                );
                println!(
                    "  then remove the gateway from that workspace at \x1b[36m{api}/console\x1b[0m."
                );
            }
            (Some(email), None) => println!("  Claimed by \x1b[1m{email}\x1b[0m."),
            (None, Some(ws)) => println!("  Landed in workspace \x1b[1m{ws}\x1b[0m."),
            (None, None) => {}
        }
        // The link's announce secret, so holds reach the workspace's phones. Minted once and never
        // shown again, so it is handed straight to the gateway rather than printed.
        if let (Some(gid), Some(secret)) = (
            resp.get("gatewayId").and_then(|v| v.as_str()),
            resp.get("announceSecret").and_then(|v| v.as_str()),
        ) {
            super::announce::report(&super::announce::apply(base_url, token, gid, secret).await);
        }
        println!("  Open \x1b[36m{api}/console\x1b[0m to see your gateway live.");
        return Ok(());
    }
    let reason = resp
        .get("error")
        .and_then(|v| v.as_str())
        .unwrap_or("the account API did not accept the pairing code");
    anyhow::bail!("{reason}")
}

/// The body `/api/gateways/enroll` takes, which has no `token` key whatever the gateway's address: see the module docs.
fn enroll_body(code: &str, name: &str, base_url: &str, install: Option<&permaura_core::install::Install>) -> serde_json::Value {
    serde_json::json!({
        "code": code,
        "name": name,
        "baseUrl": base_url.trim_end_matches('/'),
        "installId": install.map(|i| i.install_id.clone()),
        "installSecret": install.map(|i| i.secret.clone()),
    })
}

/// What to print when enrolment could not be completed: how to pair the running gateway once a code is at hand.
///
/// Printed rather than returned as an error because it is instructions, not a diagnosis, and both callers show it under their own failure line. It names no token and no file holding one: the console has no form that takes a token, and this output lands in service logs, CI logs and shared terminals.
pub fn manual_fallback(base_url: &str) {
    eprint!("{}", manual_fallback_text(base_url));
}

fn manual_fallback_text(base_url: &str) -> String {
    format!(
        "    To connect it to your permaura.com account, get a pairing code from Connect a gateway in the console, then run:\n        PERMAURA_PAIR_CODE=<code> permaura pair --url {base_url}\n    (in PowerShell, set $env:PERMAURA_PAIR_CODE first; in cmd, set \"PERMAURA_PAIR_CODE=<code>\")\n"
    )
}

/// The per-gateway operator bearer a clean bootstrap wrote. There is deliberately no constant
/// fallback: a predictable token would be a public operator credential on the very gateway someone
/// is about to put real secrets into.
pub fn operator_token() -> anyhow::Result<String> {
    let path = permaura_core::permaura_path("operator.token")
        .context("could not resolve ~/.permaura: set PERMAURA_HOME or HOME")?;
    let token = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?
        .trim()
        .to_string();
    anyhow::ensure!(!token.is_empty(), "{} is empty", path.display());
    Ok(token)
}

/// The name the console shows for this gateway. The machine's own hostname, because that is what the
/// operator will recognise in a list; renaming it later is a console concern.
pub fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::process::Command::new("hostname")
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
        })
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "Local".to_string())
}

#[cfg(test)]
mod tests {
    fn install() -> permaura_core::install::Install {
        permaura_core::install::Install {
            install_id: "gwi_AbCdEfGhIjKlMnOpQrStUvWxYz012345".into(),
            secret: "install-secret-value".into(),
        }
    }

    /// A one-shot loopback listener that records what reached it and answers `reply`.
    async fn recording_server(reply: String) -> (String, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                let (mut got, mut buf) = (Vec::new(), [0u8; 8192]);
                while !crate::cli::request_complete(&got) {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => got.extend_from_slice(&buf[..n]),
                    }
                }
                record.lock().unwrap().extend_from_slice(&got);
                let _ = sock.write_all(reply.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        (format!("http://{addr}"), seen)
    }

    /// Every request to the account API carries the install secret or a code, and a 307 or 308 resends the body wherever it points, so the client refuses the redirect rather than following it, and the caller names where it pointed.
    #[tokio::test]
    async fn the_account_api_client_does_not_follow_a_redirect_with_the_install_secret() {
        let (elsewhere, landed) = recording_server("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}".into()).await;
        let (api, _) = recording_server(format!(
            "HTTP/1.1 307 Temporary Redirect\r\nlocation: {elsewhere}/collect\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        ))
        .await;
        let client = super::api_client(&api, std::time::Duration::from_secs(5)).unwrap();
        let resp = client
            .post(format!("{api}/api/gateways/links"))
            .json(&serde_json::json!({ "installId": "inst_x", "installSecret": "is_synthetic_secret" }))
            .send()
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let got = String::from_utf8_lossy(&landed.lock().unwrap()).to_string();
        assert!(!got.contains("is_synthetic_secret"), "the install secret followed the redirect: {got}");
        assert_eq!(resp.status(), reqwest::StatusCode::TEMPORARY_REDIRECT);
        let refused = super::super::port::refuse_redirect(resp).unwrap_err().to_string();
        assert!(refused.contains("/collect"), "the refusal names where it pointed: {refused}");
    }

    /// Off this machine the account API is https only, for the first request and every hop after it.
    #[tokio::test]
    async fn the_account_api_client_is_https_only_off_this_machine() {
        let client = super::api_client("https://permaura.com", std::time::Duration::from_secs(5)).unwrap();
        let (plain, landed) = recording_server("HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}".into()).await;
        let sent = client.post(format!("{plain}/api/gateways/links")).body("is_synthetic_secret").send().await;
        assert!(sent.is_err(), "a plain http request is refused before it is sent");
        assert!(landed.lock().unwrap().is_empty(), "nothing reached the plain http listener");
    }

    /// No enrolment hands permaura.com the operator token, with or without a public URL or an install identity. The body has five keys and the token is in none of them.
    #[test]
    fn no_enrolment_carries_the_operator_token() {
        for install in [Some(install()), None] {
            let body = super::enroll_body("ABCD-1234", "box", "http://127.0.0.1:7376/", install.as_ref());
            assert!(body.get("token").is_none(), "{body}");
            assert!(!body.to_string().contains("pgt_"), "{body}");
            assert_eq!(body["code"], "ABCD-1234");
            assert_eq!(body["baseUrl"], "http://127.0.0.1:7376");
            assert_eq!(body["installId"], install.as_ref().map(|i| i.install_id.clone()).map_or(serde_json::Value::Null, Into::into));
            let keys: Vec<&str> = body.as_object().unwrap().keys().map(String::as_str).collect();
            assert_eq!(keys.len(), 5, "{keys:?}");
        }
    }

    /// The fallback points at the console's pairing flow, not the manual URL and token form it no longer has, and names no token.
    #[test]
    fn the_manual_fallback_points_at_pairing_and_names_no_token() {
        let text = super::manual_fallback_text("http://127.0.0.1:7376");
        assert!(text.contains("Connect a gateway"), "{text}");
        assert!(text.contains("PERMAURA_PAIR_CODE=<code> permaura pair --url http://127.0.0.1:7376"), "{text}");
        assert!(!text.contains("Add manually") && !text.contains("Settings then Gateway"), "{text}");
        assert!(!text.to_lowercase().contains("token"), "{text}");
        assert!(!text.contains('\u{2014}'), "{text}");
    }
}
