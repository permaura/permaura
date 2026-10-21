//! `permaura`: one binary, one front door.
//!
//! `permaura start` runs the enforcement runtime; every other subcommand drives one over its REST v1
//! surface. It used to be two binaries: `permaura-gateway`, which had no subcommands and was the
//! only thing ever published, and `perma`, which had the whole operator surface and shipped nowhere.
//! So the artifact people installed could not do most of what the docs described. They were always
//! the same program: the CLI already depended on the gateway as a library.
//!
//! **Bare `permaura` prints help and starts nothing.** A multi-command CLI that boots a long-running
//! server when invoked with no arguments is a surprise, and an unrecognised subcommand is an error
//! rather than an instruction to bind a port.
//!
//! Posture is chosen by flags on `start`, never by env vars. You opt *out* of real, so a feature is
//! never silently canned for an end user:
//!
//! - `--mock`:   connector calls get deterministic mock transports (no upstream HTTP, no shelling out, no real SSH) over the real
//!   persistent store; the gateway's own control-plane, relay and secret-backend traffic is unchanged.
//! - `--demo`:   a throwaway demo gateway: an IN-MEMORY store carrying the seeded demo estate, served on loopback only
//!   with mock transports so a demo key never fires a real call. Nothing it serves persists, but sealing the demo secrets resolves
//!   this install's vault KEK, and on a machine that has none it mints one and keeps it in the OS credential store or `vault-kek`.
//!
//! That principle is why demo data is a flag and not an env var. The seed installs an *operator*
//! session under a token constant published in the README, so a seeded gateway that is reachable from
//! a network is a public operator bearer. It used to be on unless `PERMAURA_SEED=0` said otherwise,
//! which made every install path responsible for opting out; the hosted provisioner forgot, and put
//! that bearer on an `--allow-unauthenticated` URL. There is no longer an env var that can seed a
//! gateway.

mod cli;

/// Present a deliberate refusal as a refusal, not as a crash.
///
/// The custody checks refuse by panicking, because they run inside a `LazyLock` initialiser that has
/// no way to return an error to a caller. That is sound, and it reads terribly: a correct, carefully
/// worded explanation arrives under `thread 'main' panicked at src/service.rs:204` and above a note
/// about `RUST_BACKTRACE`, so the one message we most want acted on looks like the one thing a user
/// should report as a bug instead.
///
/// It matters more since the docs began promising a refusal by name, and since a vault key sealed to
/// a TPM can stop opening after an ordinary firmware update. That is an operational event, not a
/// crash, and it should not be dressed as one.
///
/// Every such message begins `refusing to start:`, which is what this recognises. Anything else keeps
/// the default hook, backtrace and all, because a genuine panic IS a bug and should look like one.
fn frame_deliberate_refusals() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let message = info
            .payload()
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| info.payload().downcast_ref::<&str>().copied());
        match message.filter(|m| is_deliberate_refusal(m)) {
            Some(m) => eprintln!("\n{m}\n"),
            None => default_hook(info),
        }
    }));
}

/// Whether a panic payload is one of the custody refusals rather than a real crash.
///
/// Deliberately a prefix match on the exact opening the refusals use, not a substring search: a
/// genuine panic whose message merely quotes one of these (an assertion carrying it as context, say)
/// must still get the backtrace, because it is a bug and the refusal is not.
fn is_deliberate_refusal(message: &str) -> bool {
    message.starts_with("refusing to start:")
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    frame_deliberate_refusals();

    // BEFORE `Cli::parse()`, and before anything spawns a thread. The file populates only the
    // environment variables that are not already set, so clap's own flag-over-env precedence then
    // yields flag > env > file > default with no further plumbing.
    //
    // A bad file is fatal to `start` and to nothing else: the keys it carries (bind address, store
    // path, allowed hosts) are the running gateway's, so refusing to *serve* on a config nobody can
    // parse is right, while refusing to print `--help` or query a healthy gateway over it is not.
    // `cli::run` decides, which is why the error is carried rather than raised here.
    let config = if cli::is_throwaway_start() { Ok(()) } else { permaura_gateway::config::load_and_apply() };

    cli::exit_status(cli::run(config).await)
}

#[cfg(test)]
mod tests {
    use super::is_deliberate_refusal;

    /// The refusals this exists to reframe. Their wording is load-bearing here, so a rewrite that
    /// drops the opening silently turns them back into what look like crashes.
    #[test]
    fn the_custody_refusals_are_recognised() {
        assert!(is_deliberate_refusal(
            "refusing to start: vault-kek lives in this machine's OS credential store"
        ));
        assert!(is_deliberate_refusal(
            "refusing to start: vault-kek is provisioned to this unit by systemd"
        ));
        assert!(is_deliberate_refusal("refusing to start: no vault KEK is available"));
    }

    /// And the half that matters more: a real panic keeps its backtrace. Swallowing one of those
    /// would trade a cosmetic problem for a debugging one.
    #[test]
    fn a_genuine_panic_is_left_alone() {
        assert!(!is_deliberate_refusal("index out of bounds: the len is 3 but the index is 7"));
        assert!(!is_deliberate_refusal("called `Option::unwrap()` on a `None` value"));
        // Including one that merely quotes a refusal as context. A prefix match, not a search.
        assert!(!is_deliberate_refusal(
            "assertion failed: expected \"refusing to start: ...\" in the log"
        ));
    }
}
