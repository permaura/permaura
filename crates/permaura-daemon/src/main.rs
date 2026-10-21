//! # permad: a demo broker
//!
//! A thin binary over [`permaura_gateway::build_router`]: a seeded in-memory
//! [`AppState`](permaura_gateway::AppState) with mock transports, carrying the demo estate and its
//! published operator bearer, bound to loopback only (`127.0.0.1:7399` by default, not the real
//! gateway's port). It is not the gateway people run, which is `permaura start`; it supervises
//! nothing, has no Touch ID or other OS integration, and neither the desktop app nor the CLI talks
//! to it. It is kept for tests and demos.
//!
//! Because its operator bearer is published, it is a throwaway: no relay, no announce links, nothing written to the Permaura home, and nothing answered that carries a tunnel or proxy's forwarding header or comes from another address. A raw forwarder on loopback adds no header, which is why it takes a port of its own.

use std::net::SocketAddr;

use permaura_gateway::{build_router, seed, AppState};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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
        // renders, and those escapes once made a token scrape of that log fail to match its own line.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();

    // Loopback only, and by default a port of its own rather than the real gateway's 7376, which a tunnel or proxy for this install may still point at. `PERMAURA_ADDR` picks another, but never a non-loopback address.
    let addr: SocketAddr = std::env::var("PERMAURA_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:7399".to_string())
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid PERMAURA_ADDR: {e}"))?;
    if !addr.ip().is_loopback() {
        anyhow::bail!("the local broker only binds loopback; refusing to bind {addr}");
    }

    // The daemon reuses the gateway as a library. Today: seeded in-memory store +
    // deterministic offline HTTP client. The local config story (SQLite path, vault
    // passphrase from Keychain) plugs in here via AppState::from_parts.
    let state = build_local_state().local_only();
    // The seeded estate's operator bearer is published, so this is a throwaway beside the real install, as `permaura start --demo` is: it takes none of the install's relay or announce settings, even when the shell it starts in still carries them, and so never dials the control plane as the install's worker, writes a worker key into its home, or announces as its gateway.
    state.service.set_announce(Vec::new());
    let app = build_router(state, addr);

    tracing::info!(%addr, "permad (Permaura local broker) listening on loopback");
    tracing::info!(token = seed::DEMO_TOKEN, "seeded local session ready");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum_serve(listener, app).await
}

/// Build the daemon's local-first application state.
///
/// For the MVP this is the in-memory seeded store with the offline mock HTTP client,
/// which is what makes `cargo run -p permaura-daemon` work with zero setup. When the
/// `sqlite` feature on the gateway is enabled, swap this for a
/// `SqliteStore`-backed `AppState::from_parts(...)` pointing at `~/.permaura/db`.
fn build_local_state() -> AppState {
    AppState::in_memory_seeded()
}

/// Serve `app` on the already-bound loopback `listener` until the server stops. Plain TCP only:
/// there is no Unix-domain socket and no approval hook here.
async fn axum_serve(
    listener: tokio::net::TcpListener,
    app: axum::Router,
) -> anyhow::Result<()> {
    axum::serve(listener, app).await?;
    Ok(())
}
