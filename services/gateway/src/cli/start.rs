//! `permaura start`: run the enforcement gateway.
//!
//! This is the whole of what the old `permaura-gateway` binary did when invoked with no subcommand,
//! now behind an explicit verb, plus `--pair` so a gateway started this way can join a permaura.com
//! account without a second tool.

use std::net::SocketAddr;

use tracing_subscriber::EnvFilter;

use super::{enroll, StartArgs};
use permaura_gateway::{build_router, AppState};

/// Pin glibc's mmap threshold at [`permaura_gateway::MMAP_THRESHOLD_BYTES`], unless the operator set
/// `MALLOC_MMAP_THRESHOLD_` themselves. Returns whether it was pinned here. A no-op off glibc, whose
/// allocators do not keep freed blocks the way that constant's doc describes.
pub(crate) fn bound_allocator_retention() -> bool {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    {
        if std::env::var_os("MALLOC_MMAP_THRESHOLD_").is_none() {
            // SAFETY: mallopt only adjusts the allocator's tuning parameters, and glibc serialises it
            // against every arena, so it is sound from any thread at any time.
            let threshold = permaura_gateway::MMAP_THRESHOLD_BYTES as libc::c_int;
            return unsafe { libc::mallopt(libc::M_MMAP_THRESHOLD, threshold) } == 1;
        }
    }
    false
}

/// Exit [`permaura_gateway::store::migrations::EXIT_STORE_HELD`] at once when this home's store is held
/// and the address this start would bind is answered, with proof, by this home's own gateway: that one
/// is serving, not draining, so waiting out the store lock for it would only delay the same refusal.
#[cfg(feature = "sqlite")]
async fn refuse_beside_this_homes_running_gateway(addr: SocketAddr) {
    let Some(db) = permaura_gateway::store_path_from_env().filter(|db| db != ":memory:") else {
        return;
    };
    let Ok(Some(pid)) = permaura_gateway::store::lock::holder(&db) else {
        return;
    };
    let Some(token) = super::port::operator_token() else {
        return;
    };
    if matches!(super::port::probe_health(addr, &[&token]).await, super::port::Health::Ours) {
        tracing::error!(
            store = %db,
            "this home's gateway is already running on {addr} and holds its store ({}), so this start was refused. Use `permaura status` to see it, or `permaura stop` first to restart it",
            permaura_gateway::store::lock::describe(pid)
        );
        std::process::exit(permaura_gateway::store::migrations::EXIT_STORE_HELD);
    }
}

pub async fn run(mut args: StartArgs) -> anyhow::Result<()> {
    bound_allocator_retention();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,permaura_gateway=debug")),
        )
        // ANSI only when the stream this actually writes to is a terminal, and that stream is
        // STDOUT: `tracing_subscriber::fmt()`'s default writer is `io::stdout`, so testing stderr
        // would answer for the wrong file descriptor and `permaura start > gateway.log` from a live
        // shell would keep its escapes. `tracing_subscriber` decides colour from its feature set
        // rather than from where the output is going, which is why anything started by launchd,
        // systemd, the desktop supervisor or a plain redirect wrote escapes into a file nobody
        // renders. That is what made an earlier token scrape fail to match its own line.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .try_init()
        .ok();

    // Config is settled (main applied the file before clap parsed); now refuse a public URL this
    // gateway must not serve on, before anything is built. Coming up healthy with remote auth quietly
    // misconfigured is the shape that leaks tokens over plain http while everything looks fine.
    if let Err(e) = permaura_gateway::oauth::validate_public_url() {
        anyhow::bail!("{e}");
    }

    let addr: SocketAddr = demo_addr(args.demo, addr_flag_given(), &args.addr)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid --addr / PERMAURA_ADDR: {e}"))?;
    if let Some(why) = demo_bind_refusal(args.demo, addr) {
        anyhow::bail!("{why}");
    }

    // A demo or an in-memory store is a throwaway beside the real install: it takes none of that install's config, home writes, tunnel, relay or account.
    let throwaway = args.demo || super::in_memory_store_requested();
    // A throwaway would hand the real install's account a gateway it never paired, and a demo's has a public bearer.
    if throwaway && args.pair.is_some() {
        if pair_flag_given() {
            if args.demo {
                anyhow::bail!("--demo cannot be paired: it is a throwaway gateway with a public operator bearer. Start without --demo to pair this machine.");
            }
            anyhow::bail!("an in-memory store (PERMAURA_STORE_PATH=:memory:) cannot be paired: it is a throwaway gateway that keeps nothing. Start with a persistent store to pair this machine.");
        }
        eprintln!("permaura: a throwaway gateway ignores the PERMAURA_PAIR_CODE in its environment; it is never paired.");
        args.pair = None;
    }
    if args.pair.is_some() && pair_flag_given() {
        eprintln!(
            "\x1b[33m!\x1b[0m warning: a pairing code given with --pair is in your shell history and, while this runs, in the process list, where every local user can read it. Set PERMAURA_PAIR_CODE instead."
        );
    }

    let mock = args.mock || args.demo;
    if mock {
        tracing::warn!("MOCK transports (--mock/--demo): HTTP, command execution and SSH return canned results: not a real install");
    } else {
        tracing::info!("real transports live: HTTP, command execution and SSH");
    }

    // A configured revocation list that does not verify would otherwise leave every connector it revokes installable as Permaura-signed.
    if let Err(why) = permaura_gateway::manifest::configured_revocation() {
        anyhow::bail!("{why}: refusing to start. Fix the list or unset PERMAURA_PMCONN_REVOCATION.");
    }

    #[cfg(feature = "sqlite")]
    if !throwaway {
        refuse_beside_this_homes_running_gateway(addr).await;
    }

    // `--demo` is the ONLY way to get demo data, and it is always in-memory + mock: the demo estate
    // carries a public operator bearer, so it must never sit in a persistent store or behind real
    // transports. Every other invocation selects a persistent store from the environment
    // (PERMAURA_STORE_PATH) and clean-bootstraps it when empty; no env var can seed it.
    let state = if args.demo {
        tracing::warn!("--demo: IN-MEMORY seeded gateway with a PUBLIC operator bearer: do not expose this to a network");
        AppState::in_memory_seeded().local_only()
    } else {
        AppState::from_env(mock)
    };
    // Ask the release channel, in the background, whether this gateway is behind: the only outbound
    // security-response signal an install has, since `curl | sh` pins an immutable tag and never
    // self-upgrades. Reports into `/health` as `manifest_behind`; installs nothing; skipped on a
    // mock/demo posture and with PERMAURA_NO_UPGRADE=1.
    permaura_gateway::release::spawn_update_check(state.posture);

    // If relay (Mode B) is configured via env, dial the control plane and serve relayed invokes for
    // remote agents over the SAME EnforcementService; the secret never leaves this host. The
    // `relay_shutdown` watch lets us close its WebSocket cleanly (below) after the HTTP surface has
    // drained, rather than dropping the socket and leaving the CP to time the worker out.
    let (relay_shutdown_tx, relay_shutdown_rx) = tokio::sync::watch::channel(false);
    let relay = if throwaway {
        None
    } else {
        permaura_gateway::relay::spawn_from_env(state.service.clone(), Some(relay_shutdown_rx))
    };
    // Arm the graceful-stop signal so an authenticated loopback `POST /v1/shutdown` can drain and exit
    // (the portable stop path `permaura stop`, the desktop supervisor and the npm launcher all use
    // before any hard kill). An interrupt and, on Unix, SIGTERM drain the same way: SIGTERM is how
    // Cloud Run and systemd stop a process, and a windowless GUI child on Windows sees neither.
    let shutdown = std::sync::Arc::new(tokio::sync::Notify::new());
    let token_store = state.service.store().clone();
    let published_token = state.published_token.clone();
    // Once, before the listener: a delayed recovery an older build queued would otherwise sit in
    // `GET /v1/recovery` as a change that is still coming, and hold an approval nobody can resolve
    // into anything. Recovery no longer completes on a timer, so there is nothing to sweep.
    match state.service.cancel_delayed_recovery(permaura_gateway::service::now_ms()) {
        Ok(Some(record)) => tracing::warn!(
            summary = %record.summary,
            "cancelled a delayed recovery left by an older build: recovery that completes on a timer has been removed"
        ),
        Ok(None) => {}
        Err(e) => tracing::warn!(error = %e, "could not cancel a delayed recovery left by an older build"),
    }
    // A throwaway shares the real install's home, so everything below that writes to it, announces for it or fronts it is the real gateway's alone.
    if throwaway {
        state.service.set_announce(Vec::new());
    }
    let config_path = if throwaway { None } else { permaura_gateway::config::GatewayConfig::default_path() };
    // Run the tunnel connector as a CHILD of this process, once the gateway answers (below). The slot is the state's too, so an authenticated loopback `POST /v1/remote/disable` can stop it while the gateway runs.
    let tunnel_child: permaura_gateway::tunnel::ConnectorSlot = std::sync::Arc::new(std::sync::Mutex::new(None));
    let state = state
        .with_shutdown(shutdown.clone())
        .with_config_path(config_path.clone())
        .with_tunnel(tunnel_child.clone());
    let service = state.service.clone();
    let held_console_sessions = state.held_console_sessions.clone();
    let hosted = state.hosted;
    // Before the bind, so a SIGTERM that arrives while this gateway is still coming up drains it.
    let stop = permaura_gateway::drain::stop_requested(shutdown);
    let app = build_router(state, addr);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        // The bare `Address already in use (os error 48)` was the whole message for a port our own
        // stale gateway held, so it is replaced with who holds it and what to do about them.
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            anyhow::bail!("{}", super::port::diagnose_addr_in_use(addr).await);
        }
        Err(e) => return Err(anyhow::anyhow!(e).context(format!("binding {addr}"))),
    };
    if service.oauth().is_some() && !throwaway {
        permaura_gateway::republish_operator_token_once_bound(token_store.as_ref(), &published_token);
        if !hosted {
            record_remote_serving(&service);
        }
    }

    // Logged only once the socket is ours. Announcing the address before the bind meant every
    // collision printed "listening" and then the failure underneath it, and anything reading the log
    // to find out whether the gateway came up (a person, or the desktop supervisor's drain) read
    // the announcement and believed it.
    tracing::info!(%addr, "Permaura gateway listening: give agents permission, not keys");

    // The published operator token now expires, so something has to keep it fresh while the gateway
    // runs. Started here rather than in `build_router` because it belongs to a SERVING gateway: a CLI
    // subcommand that builds state to read from it must not start rewriting the token file.
    // permaura.com's sealed console bearer is kept current beside it, never this token itself. Not on a hosted worker, which has none.
    if !hosted && !throwaway {
        permaura_gateway::reseal::spawn(service.clone(), held_console_sessions, published_token.clone(), config_path);
    }
    if !throwaway {
        permaura_gateway::spawn_operator_token_refresher(service.clone(), published_token);
    }

    // Enrol only once the gateway is actually answering, and never let it stop the gateway: a box
    // that cannot reach permaura.com should still end up with a running gateway and printed
    // instructions, which is what the shell installer does too.
    if let Some(code) = args.pair.clone() {
        tokio::spawn(async move { pair(&code, addr).await });
    }

    // The tunnel connector, once the gateway answers.
    //
    // A public address without a connector is a hostname pointing at nothing, and the first real VPS
    // run ended exactly there: `remote enable` had fetched cloudflared and written the token, and
    // nothing ever started it. It runs here rather than under a second systemd unit on purpose: a
    // plain child cannot outlive the gateway, so the tunnel can never front a gateway that has gone
    // away, which is the property the desktop app's watchdog exists to enforce. A guard stops it if the
    // configuration it runs ever stops being the one written here; nothing restarts it: a connector
    // that dies or is stopped stays down until the gateway restarts.
    if !throwaway {
        let slot = tunnel_child.clone();
        tokio::spawn(async move {
            match spawn_tunnel_when_healthy(addr).await {
                Ok(Some((child, pin, records))) => {
                    *slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(child);
                    match super::port::local_client(Some(permaura_gateway::tunnel::GUARD_REQUEST_TIMEOUT)).build() {
                        Ok(client) => permaura_gateway::tunnel::guard(slot, pin, client, records).await,
                        Err(e) => permaura_gateway::tunnel::stop_connector(
                            &slot,
                            &permaura_gateway::tunnel::Stop::Unconfirmed(format!(
                                "Permaura could not confirm the connector's configuration, so it stopped the tunnel: no client to read it with ({e})"
                            )),
                            &records.stop_marker,
                        ),
                    }
                }
                Ok(None) => {}
                Err(e) => tracing::warn!("remote access: the tunnel connector did not start: {e}"),
            }
        });
    }

    // An approval an earlier process left claimed and running is settled once this one holds the
    // address, so a second `permaura start` that loses the bind never touches a live gateway's calls.
    permaura_gateway::drain::spawn_interrupted_settlement(service.clone(), hosted);
    permaura_gateway::service::spawn_hold_expiry_sweep(service.clone());

    // Stop admitting executions, let open requests and running executions finish inside the window,
    // carry anything the store still holds, then exit; see `permaura_gateway::drain`. The SQLite store
    // commits each write with an fsync, so once this returns the on-disk state is already consistent.
    permaura_gateway::drain::serve_until_stopped(
        listener,
        app,
        service,
        stop,
        permaura_gateway::drain::DRAIN_WINDOW,
    )
    .await?;

    // The gateway is no longer serving, so the tunnel must not either: a connector left running
    // would keep answering on the public hostname for a gateway that has stopped.
    if let Ok(mut g) = tunnel_child.lock() {
        if let Some(mut child) = g.take() {
            let _ = child.kill();
            let _ = child.wait();
            tracing::info!("remote access: tunnel connector stopped with the gateway");
        }
    }

    // HTTP has drained. Now tell the relay worker (if any) to close its WS cleanly and give it a
    // brief window to send the Close frame before the process exits.
    let _ = relay_shutdown_tx.send(true);
    if let Some(handle) = relay {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), handle).await;
    }
    Ok(())
}

/// Record that this start serves remote access, so the audit chain shows it coming back after a `permaura remote disable` as well as going: where the public URL came from (the environment outranks the file, so `remote disable` cannot remove one set there), whether the Permaura app supervises this gateway, and whether a tunnel connector is configured to front it. A failed append is logged and changes nothing, like the rest of boot.
fn record_remote_serving(service: &permaura_gateway::service::EnforcementService) {
    let from = if permaura_gateway::config::pinned_by_environment("PERMAURA_PUBLIC_URL") { "environment" } else { "file" };
    let tunnel = permaura_core::permaura_home().map(|home| remote_tunnel_state(&home)).unwrap_or("none");
    let mut payload = permaura_core::AuditPayload::new(permaura_gateway::rest::REMOTE_SERVING_ACTION, "remote-access", "allow");
    payload.summary = serde_json::json!({
        "public_url_from": from,
        "supervised_by_app": permaura_gateway::config::supervised_by_app(),
        "tunnel": tunnel,
    });
    if let Err(e) = service.store().append_audit(payload) {
        tracing::warn!(error = %e, "this gateway serves remote access, but the audit chain could not record that it does");
    }
}

fn remote_tunnel_state(home: &std::path::Path) -> &'static str {
    use permaura_gateway::tunnel;
    let configured = permaura_gateway::config::GatewayConfig::load_from(&home.join("config.toml")).ok().flatten()
        .and_then(|cfg| cfg.public_url).is_some_and(|url| !url.is_empty());
    if !configured { return "none"; }
    if tunnel::recorded_stop(&home.join(tunnel::STOP_MARKER_FILE)).is_some() { return "stopped"; }
    if std::fs::read(home.join(tunnel::CREDENTIALS_FILE)).ok().and_then(|bytes| tunnel::Credentials::from_slice(&bytes).ok()).is_some() {
        "configured"
    } else { "none" }
}

/// Why a `--demo` gateway may not bind `addr`, when it may not. Its operator bearer is the published demo token, so on any address but loopback whoever can reach the machine holds the operator.
fn demo_bind_refusal(demo: bool, addr: SocketAddr) -> Option<String> {
    (demo && !addr.ip().is_loopback()).then(|| {
        format!(
            "--demo binds only a loopback address, so it refused {addr}: its operator bearer is the published demo token, and anyone who could reach that address would hold it. Use --addr 127.0.0.1:<port>, or start without --demo for a real gateway."
        )
    })
}

/// Start cloudflared for this gateway's address, if it has one, after the gateway is answering.
///
/// Three things have to be true, and the absence of any of them is "no tunnel", never an error:
/// `config.toml` names a `public_url` (remote access is on), the tunnel's credentials are stored
/// (`permaura remote enable` wrote them), and a cloudflared binary can be found (`remote enable`
/// fetches one when the machine has none). A stop the guard recorded starts nothing until the
/// operator clears it, and says so in the log and in `/health`. The connector gets its whole configuration from a file
/// written here, naming one destination; argv carries only that file's path, a flag and the tunnel
/// id, so `ps` hands nothing secret to every user on the box.
async fn spawn_tunnel_when_healthy(
    addr: SocketAddr,
) -> anyhow::Result<Option<Started>> {
    use anyhow::Context as _;
    use permaura_gateway::tunnel;
    let Some(cfg_path) = permaura_gateway::config::GatewayConfig::default_path() else {
        return Ok(None);
    };
    let Some(cfg) = permaura_gateway::config::GatewayConfig::load_from(&cfg_path)
        .map_err(|e| anyhow::anyhow!(e))?
    else {
        return Ok(None);
    };
    let Some(public_url) = cfg.public_url.filter(|u| !u.is_empty()) else {
        return Ok(None);
    };
    let stop_marker = permaura_core::permaura_path(tunnel::STOP_MARKER_FILE).context("resolving the tunnel's stop marker")?;
    if let Some(why) = tunnel::recorded_stop(&stop_marker) {
        return Ok(refuse_tunnel(&why));
    }
    let Some(credentials_path) = permaura_core::permaura_path(tunnel::CREDENTIALS_FILE).filter(|p| p.is_file()) else {
        if permaura_core::permaura_path(tunnel::LEGACY_TOKEN_FILE).is_some_and(|p| p.is_file()) {
            tracing::warn!(
                "remote access: {public_url} is configured, but the only tunnel credential stored is a run token for a remotely managed tunnel, which this version no longer runs; run `permaura remote enable` to replace it"
            );
        } else {
            tracing::warn!(
                "remote access: {public_url} is configured but no tunnel credentials are stored; run `permaura remote enable`"
            );
        }
        return Ok(None);
    };
    let credentials = std::fs::read(&credentials_path)
        .map_err(|e| e.to_string())
        .and_then(|bytes| tunnel::Credentials::from_slice(&bytes))
        .map_err(|why| {
            anyhow::anyhow!(
                "{} cannot be used ({why}); run `permaura remote enable` to replace it",
                credentials_path.display()
            )
        })?;
    let host = match super::remote::host_of(&public_url).ok_or_else(|| format!("{public_url} names no host")).and_then(|h| tunnel::tunnel_hostname(&h)) {
        Ok(host) => host,
        Err(why) => return Ok(refuse_tunnel(&why)),
    };
    let origin = match tunnel::origin_for(addr) {
        Ok(origin) => origin,
        Err(why) => return Ok(refuse_tunnel(&why)),
    };
    let Some(bin) = super::cloudflared::find_existing() else {
        tracing::warn!("remote access: cloudflared is not installed; run `permaura remote enable`");
        return Ok(None);
    };

    // Same wait as pairing, at the origin the connector will dial: front a gateway that is actually up.
    let client = super::port::local_client(Some(std::time::Duration::from_secs(2))).build()?;
    let health = format!("{origin}/health");
    let mut healthy = false;
    for _ in 0..20 {
        if matches!(client.get(&health).send().await, Ok(r) if r.status().is_success()) {
            healthy = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    anyhow::ensure!(healthy, "the gateway did not become healthy at {health}");

    let metrics_port = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .and_then(|l| l.local_addr())
        .context("finding a free loopback port for the connector's metrics server")?
        .port();
    let pin = tunnel::Pin { host, origin, metrics_port };
    let credentials_abs = std::path::absolute(&credentials_path)
        .with_context(|| format!("resolving {}", credentials_path.display()))?;
    let credentials_abs = credentials_abs
        .to_str()
        .with_context(|| format!("{} is not a UTF-8 path", credentials_abs.display()))?;
    let config_path = permaura_core::permaura_path(tunnel::CONFIG_FILE).context("resolving the connector's config path")?;
    let config = tunnel::render_config(&credentials.tunnel_id, credentials_abs, &pin);
    permaura_core::replace_secret_file(&config_path, config.as_bytes())
        .with_context(|| format!("writing {}", config_path.display()))?;
    permaura_credential_store::restrict_to_owner(&config_path)
        .with_context(|| format!("restricting {} to its owner", config_path.display()))?;
    if let Some(legacy) = permaura_core::permaura_path(tunnel::LEGACY_TOKEN_FILE) {
        if let Err(e) = std::fs::remove_file(&legacy) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!("remote access: could not remove {}: {e}", legacy.display());
            }
        }
    }

    let log_path = permaura_core::permaura_path("cloudflared.log").context("resolving the log path")?;
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("opening {}", log_path.display()))?;
    let log_err = log.try_clone().context("cloning the log handle")?;
    let log_start = log.metadata().map(|m| m.len()).unwrap_or(0);

    let mut cmd = connector_command(
        &bin,
        &config_path,
        &credentials.tunnel_id,
        std::env::vars_os().map(|(name, _)| name),
    );
    cmd.stdin(std::process::Stdio::null()).stdout(log).stderr(log_err);
    // Die WITH the gateway, not merely after it asks: left running, cloudflared kept answering on the public hostname for a gateway that was already dead, and systemd sat in "deactivating" for thirty seconds waiting for it.
    let child = permaura_platform::child::spawn_std_dying_with_this_process(cmd).await
        .with_context(|| format!("starting {}", bin.display()))?;
    tracing::info!(
        "remote access: tunnel connector started for {public_url} (pid {}, config {}, log {})",
        child.id(),
        config_path.display(),
        log_path.display()
    );
    tunnel::connector().note_local();
    tracing::info!("{}", tunnel::STARTED_NOTE);
    Ok(Some((child, pin, tunnel::Records { stop_marker, log: Some((log_path, log_start)) })))
}

/// A connector this process started, what it is pinned to, and where its guard records a stop.
type Started = (std::process::Child, permaura_gateway::tunnel::Pin, permaura_gateway::tunnel::Records);

/// Start no connector, and say why in the log and in `/health`.
fn refuse_tunnel(why: &str) -> Option<Started> {
    permaura_gateway::tunnel::connector().note_stopped(why);
    tracing::error!("remote access: {why}");
    None
}

/// `cloudflared tunnel --config <config> --management-diagnostics=false --no-autoupdate --label permaura run <tunnel id>`, without any variable from `inherited` whose name starts with `TUNNEL_`: cloudflared reads those as flag values (`TUNNEL_TOKEN`, `TUNNEL_URL`, `TUNNEL_CRED_FILE`, `TUNNEL_METRICS` and more), so one left in the gateway's environment would change what the connector runs. Matched without regard to case, as Windows reads them. `--management-diagnostics` (default true) would expose `/debug/pprof`, `/metrics` and more to the account over Cloudflare's management service; cloudflared defines it on `tunnel`, not `run`, and refuses it after `run`. `--no-autoupdate` because cloudflared otherwise updates itself a day in: it replaces the pinned, digest-checked binary and exits with code 11, which leaves the tunnel down, and on a machine without systemd it re-executes a copy that is not this process's child and so is not guarded. `--label permaura` names the connector in place of this machine's hostname, which the management service would otherwise hand the account.
fn connector_command(
    bin: &std::path::Path,
    config: &std::path::Path,
    tunnel_id: &str,
    inherited: impl IntoIterator<Item = std::ffi::OsString>,
) -> std::process::Command {
    let mut cmd = std::process::Command::new(bin);
    cmd.arg("tunnel")
        .arg("--config")
        .arg(config)
        .arg("--management-diagnostics=false")
        .arg("--no-autoupdate")
        .arg("--label")
        .arg("permaura")
        .arg("run")
        .arg(tunnel_id);
    for name in inherited {
        if name.as_encoded_bytes().get(..7).is_some_and(|p| p.eq_ignore_ascii_case(b"TUNNEL_")) {
            cmd.env_remove(name);
        }
    }
    cmd
}

/// Whether `--addr` was on the command line, rather than taken from `PERMAURA_ADDR` or the default.
fn addr_flag_given() -> bool {
    std::env::args_os().any(|a| a == "--addr" || a.to_string_lossy().starts_with("--addr="))
}

/// Where a demo listens unless `--addr` says otherwise: a port of its own, never the one the real gateway and every tunnel or proxy for this install point at.
pub(crate) const DEMO_ADDR: &str = "127.0.0.1:7399";

/// The address to bind: `resolved` (the flag, `PERMAURA_ADDR` or the default), except that a demo takes [`DEMO_ADDR`] unless `--addr` itself named one, since `PERMAURA_ADDR` is usually the real install's.
fn demo_addr(demo: bool, flag_given: bool, resolved: &str) -> String {
    if demo && !flag_given {
        DEMO_ADDR.to_string()
    } else {
        resolved.to_string()
    }
}

/// Whether `--pair` is on this process's command line, as opposed to a code clap read from `PERMAURA_PAIR_CODE`.
fn pair_flag_given() -> bool {
    std::env::args_os().any(|a| a == "--pair" || a.to_string_lossy().starts_with("--pair="))
}

/// Wait for the gateway we have just launched to answer, then enrol it.
///
/// Never fails the process: a box that cannot reach permaura.com should still end up with a running
/// gateway and printed instructions, which is what the shell installer does too. `permaura pair` is
/// the other half of this and does the opposite, because there enrolling IS the job.
async fn pair(code: &str, addr: SocketAddr) {
    let base = super::port::reachable_url(&format!("http://{addr}"));
    if let Err(e) = try_pair(code, &base).await {
        eprintln!("\x1b[33m!\x1b[0m Could not connect this gateway to your account: {e}");
        eprintln!("    A gateway that is already running can be paired later with `PERMAURA_PAIR_CODE=<code> permaura pair`.");
        enroll::manual_fallback(&base);
    }
}

async fn try_pair(code: &str, base: &str) -> anyhow::Result<()> {
    let client = super::port::local_client(Some(std::time::Duration::from_secs(20))).build()?;

    // Blocking on health first: enrolling a gateway that never came up would give the console a row
    // it can never drive. Generous here because this call raced the listener we started a moment ago.
    let health = format!("{base}/health");
    let mut healthy = false;
    for _ in 0..20 {
        if matches!(client.get(&health).send().await, Ok(r) if r.status().is_success()) {
            healthy = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    anyhow::ensure!(healthy, "the gateway did not become healthy at {base}");

    enroll::enroll(base, &enroll::operator_token()?, code).await
}

#[cfg(test)]
mod tests {
    /// A demo takes a port of its own unless `--addr` names one, whatever `PERMAURA_ADDR` says; a real gateway takes what it is given.
    #[test]
    fn a_demo_listens_on_its_own_port_unless_told_otherwise() {
        assert_eq!(super::demo_addr(true, false, "127.0.0.1:7376"), super::DEMO_ADDR);
        assert_eq!(super::demo_addr(true, true, "127.0.0.1:7411"), "127.0.0.1:7411");
        assert_eq!(super::demo_addr(false, false, "127.0.0.1:7376"), "127.0.0.1:7376");
        assert_ne!(super::DEMO_ADDR, "127.0.0.1:7376");
    }

    /// A demo binds loopback or nothing, the wildcard addresses included; a real gateway's bind is not this check's business.
    #[test]
    fn a_demo_binds_only_loopback() {
        for refused in ["0.0.0.0:7399", "[::]:7399", "192.168.1.20:7399", "[2001:db8::1]:7399", "[::ffff:127.0.0.1]:7399"] {
            let why = super::demo_bind_refusal(true, refused.parse().unwrap()).unwrap_or_else(|| panic!("{refused} is refused"));
            assert!(why.starts_with("--demo binds only a loopback address") && !why.contains('\u{2014}'), "{why}");
            assert!(super::demo_bind_refusal(false, refused.parse().unwrap()).is_none(), "{refused} without --demo");
        }
        for allowed in ["127.0.0.1:7399", "127.0.0.2:7399", "[::1]:7399"] {
            assert!(super::demo_bind_refusal(true, allowed.parse().unwrap()).is_none(), "{allowed}");
        }
    }

    /// The contract's argv, its flags before `run` where cloudflared accepts them, and nothing else (it pins `--no-autoupdate` and `--label permaura`), and every `TUNNEL_` variable the gateway inherited removed from the child, whatever its case; other variables pass through untouched.
    #[test]
    fn the_connector_command_is_the_contracts_and_carries_no_tunnel_variables() {
        use std::ffi::{OsStr, OsString};
        let inherited = ["PATH", "TUNNEL_TOKEN", "TUNNEL_URL", "TUNNEL_CRED_FILE", "TUNNEL_METRICS", "tunnel_token_file", "NO_AUTOUPDATE", "HOME", "XTUNNEL_URL", "TUNNEL"];
        let cmd = super::connector_command(
            std::path::Path::new("/opt/bin/cloudflared"),
            std::path::Path::new("/home/op/.permaura/cloudflared.yml"),
            "6ff42ae2-765d-4adf-8112-31c55c1551ef",
            inherited.iter().map(OsString::from),
        );
        assert_eq!(cmd.get_program(), OsStr::new("/opt/bin/cloudflared"));
        let args: Vec<&OsStr> = cmd.get_args().collect();
        assert_eq!(
            args,
            [
                "tunnel",
                "--config",
                "/home/op/.permaura/cloudflared.yml",
                "--management-diagnostics=false",
                "--no-autoupdate",
                "--label",
                "permaura",
                "run",
                "6ff42ae2-765d-4adf-8112-31c55c1551ef"
            ]
        );
        let mut removed: Vec<&OsStr> = cmd.get_envs().map(|(name, value)| {
            assert!(value.is_none(), "nothing is set, only removed: {name:?}");
            name
        }).collect();
        removed.sort();
        assert_eq!(removed, ["TUNNEL_CRED_FILE", "TUNNEL_METRICS", "TUNNEL_TOKEN", "TUNNEL_URL", "tunnel_token_file"]);
    }

    /// On glibc the threshold is pinned, unless the operator set it; elsewhere nothing is
    /// touched. `MALLOC_MMAP_THRESHOLD_` is only ever read here, so no other test's view changes.
    #[test]
    fn the_mmap_threshold_is_pinned_on_glibc_and_left_alone_elsewhere() {
        let pinned = super::bound_allocator_retention();
        let glibc = cfg!(all(target_os = "linux", target_env = "gnu"));
        assert_eq!(pinned, glibc && std::env::var_os("MALLOC_MMAP_THRESHOLD_").is_none());
    }
}

#[cfg(test)]
mod remote_state_tests {
    use super::*;
    #[test]
    fn boot_reports_only_a_connector_it_can_start() {
        let home = std::env::temp_dir().join(format!("pm-p3-boot-{}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        let credentials = serde_json::json!({"AccountTag":"a".repeat(32), "TunnelSecret":"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXphYmNkZWY=", "TunnelID":"12345678-1234-1234-1234-123456789abc"});
        std::fs::write(home.join(permaura_gateway::tunnel::CREDENTIALS_FILE), credentials.to_string()).unwrap();
        assert_eq!(remote_tunnel_state(&home), "none", "credentials without a file public URL start nothing");
        std::fs::write(home.join("config.toml"), "public_url = \"https://synthetic.permaura.test\"\n").unwrap();
        assert_eq!(remote_tunnel_state(&home), "configured");
        permaura_gateway::tunnel::record_stop(&home.join(permaura_gateway::tunnel::STOP_MARKER_FILE), "synthetic evidence stop").unwrap();
        assert_eq!(remote_tunnel_state(&home), "stopped");
        std::fs::remove_dir_all(home).unwrap();
    }
}
