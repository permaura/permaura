//! `permaura upgrade`: replace this binary with the latest published release.
//!
//! The same three checks the npm launcher and the shell installer make, in the same order, because a
//! weaker one here would simply become the way in: the manifest's Ed25519 signature is verified
//! against the key pinned in [`permaura_gateway::release`], the download is checked against the
//! sha256 in that verified manifest, and the swap is rename-aside so a failure never leaves a
//! half-written binary where a working one was.
//!
//! It upgrades whatever `current_exe()` resolves to, which is the honest target: an install at
//! `~/.permaura/bin/permaura` upgrades itself, and nothing has to agree about a path.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};
use sha2::{Digest, Sha256};

/// How long [`confirm_running`] waits for a restarted gateway to answer as the new version.
const CONFIRM_WITHIN: std::time::Duration = std::time::Duration::from_secs(20);

/// Why [`confirm_running`] could not confirm the new version.
#[derive(Debug, PartialEq)]
enum Unconfirmed {
    /// The CLI would not send this request to the gateway (no operator token this account can read, a listener that did not prove it holds one, or one running as another account), so it cannot ask the version that way at all.
    Unreadable(String),
    /// It asked, and within the window the gateway did not answer as the new version.
    NotYet(String),
}

impl std::fmt::Display for Unconfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Unconfirmed::Unreadable(why) => write!(f, "this account cannot read the gateway's operator token to ask its version ({why})"),
            Unconfirmed::NotYet(why) => write!(f, "{why}"),
        }
    }
}

/// Wait for the gateway at `ctx` to report `latest` in its health document, so "Running" says what it runs rather than what the service manager was asked to do. A health read this account is refused is said at once, since waiting cannot change it.
async fn confirm_running(ctx: &super::commands::Ctx, latest: &str, within: std::time::Duration) -> Result<(), Unconfirmed> {
    let deadline = tokio::time::Instant::now() + within;
    loop {
        let seen = match ctx.get("/health").send().await {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = resp.json().await.unwrap_or_default();
                match body.get("version").and_then(|v| v.as_str()) {
                    Some(v) if v == latest => return Ok(()),
                    Some(v) => format!("it reports {v}"),
                    None => "it did not report its version".to_string(),
                }
            }
            Ok(resp) => format!("it answered {}", resp.status().as_u16()),
            Err(e) if e.is::<super::port::Refused>() => return Err(Unconfirmed::Unreadable(e.to_string())),
            Err(e) => e.to_string(),
        };
        if tokio::time::Instant::now() >= deadline {
            return Err(Unconfirmed::NotYet(seen));
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

/// Whether process `pid` runs the binary at `dest`, read from `/proc`: how an account that cannot ask the gateway its version confirms the restart. `None` where there is no `/proc` to read.
fn runs_binary(pid: u32, dest: &Path) -> Option<bool> {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    let dest = std::fs::canonicalize(dest).unwrap_or_else(|_| dest.to_path_buf());
    Some(exe == dest)
}

/// What to say once a restart has failed: whether a gateway still answers, which a failed `systemctl restart` may already have stopped.
fn after_a_failed_restart(still_answering: bool, url: &str, latest: &str, start: &str) -> String {
    if still_answering {
        format!("    The gateway at {url} is still answering, so it is still on the old binary. Restart it to pick up {latest}.")
    } else {
        format!("    The gateway is not running. Start it with `{start}`.")
    }
}

/// What to say once a restart went through but the gateway never answered as `latest`: whether anything answers at all, since a new binary that fails at boot leaves nothing running once the restart has stopped the old one.
fn after_an_unconfirmed_restart(still_answering: bool, latest: &str, old: &str, start: &str) -> String {
    if still_answering {
        format!("    Check it with `permaura status`; until it answers as {latest}, it may still be running {old}.")
    } else {
        format!("    The gateway is not answering, so the new binary may have failed to start: check its log, then start it with `{start}`.")
    }
}

pub async fn run(ctx: &super::commands::Ctx, no_restart: bool) -> anyhow::Result<()> {
    let key = platform_key().ok_or_else(|| {
        anyhow!(
            "unsupported platform {}/{}: prebuilt gateways cover macOS, Linux and Windows on arm64/x64",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;

    let url = permaura_gateway::release::manifest_url();
    let manifest = permaura_gateway::release::fetch_verified(&url)
        .await
        .map_err(|e| anyhow!("could not read the release channel: {e}"))?;

    let latest = manifest
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("the manifest carries no version"))?;
    let running = env!("CARGO_PKG_VERSION");
    if permaura_gateway::release::compare_versions(running, latest) >= 0 {
        println!("\x1b[32m✓\x1b[0m permaura {running} is up to date.");
        return Ok(());
    }

    let asset = manifest
        .get("assets")
        .and_then(|a| a.get(&key))
        .ok_or_else(|| anyhow!("the manifest has no build for {key}"))?;
    let asset_url = asset
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("the manifest's {key} entry has no url"))?;
    // Fail closed on a missing checksum. Warning and installing anyway would make the one check
    // available here optional at an attacker's discretion.
    let expected = asset
        .get("sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            anyhow!("the manifest has no sha256 for {key}, so the download cannot be checked")
        })?;

    let dest = std::env::current_exe().context("resolving this binary's own path")?;
    println!("\x1b[36m→\x1b[0m Updating permaura {running} → {latest} ({key})…");

    // Asked BEFORE the swap. Afterwards a gateway that is down is indistinguishable from one that was
    // never up, and those two want different endings: restart the first, leave the second alone.
    let was_running = ctx.is_healthy().await;

    let tmp = dest.with_extension("download");
    download(asset_url, &tmp).await?;

    let got = sha256_file(&tmp)?;
    if !got.eq_ignore_ascii_case(expected) {
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("checksum mismatch for the downloaded binary (expected {expected}, got {got})");
    }
    make_executable(&tmp)?;
    swap_into_place(&dest, &tmp)?;

    println!("\x1b[32m✓\x1b[0m permaura {latest} installed at {}", dest.display());

    // The swap alone changes nothing that is running: the live process holds the old inode and keeps
    // serving the old code. Reporting "installed" and stopping there is what made `permaura upgrade`
    // look equivalent to the installer's `--update` when it did strictly less.
    if no_restart {
        println!("    --no-restart: the running gateway is still on {running}. Restart it to pick this up.");
        return Ok(());
    }
    let owner = super::restart::detect();
    if was_running || owner != super::restart::Owner::Unmanaged {
        println!("\x1b[36m→\x1b[0m Restarting {}…", super::restart::describe(&owner));
    }
    match super::restart::restart(&owner, was_running) {
        // Nothing here restarted it, and `restart` has said so and what to do.
        Ok(()) if owner == super::restart::Owner::Unmanaged => {}
        Ok(()) => match confirm_running(ctx, latest, CONFIRM_WITHIN).await {
            Ok(()) => println!("\x1b[32m✓\x1b[0m Running {latest} at {}.", ctx.url),
            Err(why @ Unconfirmed::Unreadable(_)) => {
                let pid = super::restart::unit_main_pid(&owner);
                match pid.and_then(|pid| runs_binary(pid, &dest).map(|runs| (pid, runs))) {
                    Some((pid, true)) => println!("\x1b[32m✓\x1b[0m Running {latest}: the service's process ({pid}) runs {}.", dest.display()),
                    Some((pid, false)) => println!(
                        "\x1b[33m!\x1b[0m Restarted, but the service's process ({pid}) does not run {}: check it with `systemctl status permaura`.",
                        dest.display()
                    ),
                    None => {
                        let check = match super::restart::unit_user() {
                            Some(user) => format!("sudo -u {user} {} status", dest.display()),
                            None => format!("{} status", dest.display()),
                        };
                        println!("\x1b[33m!\x1b[0m Restarted, but {why}. Check its version with `{check}`.");
                    }
                }
            }
            Err(why) => {
                println!("\x1b[33m!\x1b[0m Restarted, but the gateway at {} has not answered as {latest} ({why}).", ctx.url);
                println!("{}", after_an_unconfirmed_restart(ctx.is_healthy().await, latest, running, &super::restart::start_hint(&owner)));
            }
        },
        // The upgrade itself succeeded; only the restart did not. Exiting non-zero here would have a
        // caller retry a download that is already on disk, so this reports and leaves the operator
        // holding an accurate picture instead.
        Err(e) => {
            println!("\x1b[33m!\x1b[0m The new binary is installed, but the restart failed: {e}");
            println!("{}", after_a_failed_restart(ctx.is_healthy().await, &ctx.url, latest, &super::restart::start_hint(&owner)));
        }
    }
    Ok(())
}

/// The manifest asset key for this platform: `darwin|linux|win32` × `arm64|amd64`. Rust reports
/// `x86_64` where the manifest says `amd64` (the release matrix keeps the Go-style convention), and
/// `windows` where it says `win32`, the same mapping as the npm launcher's `platformKey`.
fn platform_key() -> Option<String> {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        "windows" => "win32",
        _ => return None,
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        _ => return None,
    };
    Some(format!("{os}-{arch}"))
}

async fn download(url: &str, dest: &Path) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(300))
        .build()?;
    let bytes = client
        .get(url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .with_context(|| format!("downloading {url}"))?
        .bytes()
        .await
        .context("reading the download")?;
    std::fs::write(dest, &bytes).with_context(|| format!("writing {}", dest.display()))?;
    Ok(())
}

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(hex(&hasher.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(unix)]
fn make_executable(path: &Path) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod {}", path.display()))
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) -> anyhow::Result<()> {
    Ok(())
}

/// Rename-aside swap (the rustup pattern): park the current binary at `.old`, since Windows
/// cannot overwrite a running executable but CAN rename it, then move the verified download into
/// place. If that final rename fails the parked binary is restored, so there is a runnable binary
/// at `dest` on every exit path.
fn swap_into_place(dest: &Path, tmp: &Path) -> anyhow::Result<()> {
    let mut parked: Option<PathBuf> = None;
    if dest.exists() {
        let old = with_suffix(dest, ".old");
        let _ = std::fs::remove_file(&old);
        match std::fs::rename(dest, &old) {
            Ok(()) => parked = Some(old),
            Err(_) => {
                // `.old` is itself a locked running binary: park under a unique name instead.
                let unique = with_suffix(
                    dest,
                    &format!(
                        ".old-{}",
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0)
                    ),
                );
                std::fs::rename(dest, &unique)
                    .with_context(|| format!("parking {}", dest.display()))?;
                parked = Some(unique);
            }
        }
    }
    if let Err(e) = std::fs::rename(tmp, dest) {
        if let Some(old) = &parked {
            let _ = std::fs::rename(old, dest);
        }
        let _ = std::fs::remove_file(tmp);
        return Err(e).with_context(|| format!("installing {}", dest.display()));
    }
    if let Some(old) = parked {
        // Best-effort: on Windows a still-running old gateway keeps its file locked, and the next
        // upgrade collects it.
        let _ = std::fs::remove_file(old);
    }
    Ok(())
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "pgt_upgrade_confirm_fixture_only";

    /// A gateway that proves it holds [`TOKEN`] and reports `version` to an authenticated health read.
    async fn reporting(version: &'static str) -> String {
        use axum::response::IntoResponse as _;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = axum::Router::new().route(
            "/health",
            axum::routing::get(move |headers: axum::http::HeaderMap| async move {
                let authed = headers.get("authorization").and_then(|v| v.to_str().ok()) == Some(&format!("Bearer {TOKEN}"));
                let body = if authed {
                    serde_json::json!({ "service": "permaura-gateway", "status": "ok", "version": version })
                } else {
                    serde_json::json!({ "service": "permaura-gateway", "status": "ok" })
                };
                let mut resp = axum::Json(body).into_response();
                let challenge = headers.get(permaura_core::health_proof::CHALLENGE_HEADER).and_then(|v| v.to_str().ok());
                if let Some(proof) = challenge.and_then(|c| permaura_core::health_proof::proof(TOKEN, port, c)) {
                    resp.headers_mut().insert(permaura_core::health_proof::PROOF_HEADER, proof.parse().unwrap());
                }
                resp
            }),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://127.0.0.1:{port}")
    }

    /// An account the CLI will not send the gateway's operator token for (here, a home that holds no token for the gateway that answers) cannot confirm its version that way, so the confirmation says so at once rather than waiting out its window and suggesting the old version still runs.
    #[test]
    fn a_confirmation_this_account_cannot_make_says_so_at_once() {
        let home = std::env::temp_dir().join(format!("permaura-upgrade-confirm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        let outcome = crate::cli::with_permaura_home(&home, || {
            tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
                // A gateway this home holds no token for: it answers, and cannot be sent anything.
                let unproven = reporting("9.9.9").await;
                let ctx = super::super::commands::Ctx::new(unproven, None);
                let started = std::time::Instant::now();
                let outcome = confirm_running(&ctx, "9.9.9", std::time::Duration::from_secs(6)).await;
                (outcome, started.elapsed())
            })
        });
        std::fs::remove_dir_all(&home).ok();
        let (outcome, took) = outcome;
        assert!(took < std::time::Duration::from_secs(3), "it waited {took:?} for an answer it could never read");
        let why = outcome.unwrap_err();
        assert!(matches!(why, Unconfirmed::Unreadable(_)) && why.to_string().contains("cannot read"), "{why}");
    }

    /// A restart that failed is not said to have left the old version running unless something still answers, since `systemctl restart` stops the unit before it starts it.
    #[test]
    fn a_failed_restart_says_whether_anything_still_runs() {
        let gone = after_a_failed_restart(false, "http://127.0.0.1:7376", "9.9.9", "sudo systemctl start permaura");
        assert!(gone.contains("not running") && gone.contains("`sudo systemctl start permaura`") && !gone.contains("still"), "{gone}");
        let up = after_a_failed_restart(true, "http://127.0.0.1:7376", "9.9.9", "sudo systemctl start permaura");
        assert!(up.contains("still answering") && up.contains("9.9.9"), "{up}");
    }

    /// a restart that went through but never answered as the new version is said to be still on the old one only while something answers, since the restart already stopped the old one.
    #[test]
    fn an_unconfirmed_restart_says_whether_anything_answers() {
        let gone = after_an_unconfirmed_restart(false, "9.9.9", "1.0.0", "systemctl --user start permaura");
        assert!(gone.contains("not answering") && gone.contains("`systemctl --user start permaura`") && !gone.contains("1.0.0"), "{gone}");
        let up = after_an_unconfirmed_restart(true, "9.9.9", "1.0.0", "systemctl --user start permaura");
        assert!(up.contains("may still be running 1.0.0"), "{up}");
    }

    /// "Running" is what the restarted gateway reports, not what the service manager was asked to do.
    #[tokio::test]
    async fn running_is_said_only_once_the_gateway_reports_the_new_version() {
        let new = super::super::commands::Ctx::new(reporting("9.9.9").await, Some(TOKEN.into()));
        assert_eq!(confirm_running(&new, "9.9.9", std::time::Duration::from_secs(5)).await, Ok(()));

        let old = super::super::commands::Ctx::new(reporting("1.0.0").await, Some(TOKEN.into()));
        let why = confirm_running(&old, "9.9.9", std::time::Duration::from_millis(600)).await.unwrap_err();
        assert_eq!(why, Unconfirmed::NotYet("it reports 1.0.0".into()));

        let idle = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let none = super::super::commands::Ctx::new(format!("http://{idle}"), Some(TOKEN.into()));
        assert!(confirm_running(&none, "9.9.9", std::time::Duration::from_millis(300)).await.is_err());
    }
}
