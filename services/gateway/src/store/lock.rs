//! One writer per self-run store: the cross-process lock a [`super::sqlite::SqliteStore`] opened on a
//! file holds for as long as it lives.
//!
//! Each store process seals audit events from the chain it loaded at open and never reads the table
//! again, so two processes on one file each issue the seq after the last row they know. A gateway
//! asked to stop gives its address up as its drain begins and goes on executing for the rest of its
//! window, so the overlap was an ordinary stop and start, not an attack. The lock is taken before the
//! database is opened or migrated, and the OS releases it when the process ends however it ends, so it
//! covers every write a process can make, its drain included.
//!
//! A gateway built before this lock takes none, so until every such gateway on a home has exited, one
//! can still write beside a new one: one that is stopping, for as long as its drain and any task still
//! running keep it alive, and one still serving another port of the same home, for as long as it runs.
//! For the first upgrade, stop the old gateway and wait for it to exit (`permaura stop` now waits for
//! the process, about 15 seconds at most) or let a supervisor restart it. A new gateway that meets such
//! a writer sees its own append refused at a seq the other already wrote, reports the store degraded,
//! and `permaura start` exits [`super::migrations::EXIT_STORE_HELD`] so a restart reloads the chain.
//!
//! The lock file is never deleted, by design: removing it while a holder still has it open would let
//! the next opener lock a new file at the same path beside the old holder. It is keyed by the store
//! file's real path, so two spellings of one store share one lock.

use std::io::{Read, Seek, SeekFrom, Write};
use std::time::{Duration, Instant};

use crate::error::GatewayError;

/// How long `permaura start` waits for another process to let the store go before it refuses.
///
/// Longer than a predecessor that was asked to stop can go on running: its drain window and last
/// carry ([`crate::drain::DRAIN_WINDOW`], [`crate::drain::CARRY_BUDGET`]), the tunnel and relay
/// teardown after them, and the exit. Shorter than the desktop supervisor's 30 second quiet startup
/// window, so a gateway it spawns while an adopted one drains comes up inside it.
pub const STORE_LOCK_WAIT: Duration = Duration::from_secs(20);

/// How long an ordinary open waits before refusing. A handle closed a moment ago can keep its lock for
/// an instant longer: another thread forking a child copies every descriptor, and the copy holds the
/// lock until the child execs and closes it.
pub const BRIEF_WAIT: Duration = Duration::from_secs(2);

/// How often a waiting open asks again.
const POLL: Duration = Duration::from_millis(100);

/// The lock file for the store at `db`: beside the store file's real path, so a store reached through
/// a link or a relative spelling is held by the same lock as the file it names.
pub fn lock_path(db: &str) -> String {
    let path = std::path::Path::new(db);
    let real = std::fs::canonicalize(path).ok().or_else(|| {
        let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
        Some(std::fs::canonicalize(parent).ok()?.join(path.file_name()?))
    });
    match real {
        Some(real) => format!("{}.lock", real.display()),
        None => format!("{db}.lock"),
    }
}

/// Exclusive ownership of a self-run store, released when this value is dropped or the process ends.
#[derive(Debug)]
pub struct StoreLock {
    _file: std::fs::File,
}

impl StoreLock {
    /// Take the store at `db`, waiting up to `wait` for another holder to let it go.
    ///
    /// Says once, naming the holder, that it is waiting. Refuses with [`GatewayError::StoreHeld`] when
    /// the holder is still there at the deadline; a zero `wait` refuses at once. The refusal says who
    /// holds the store and why that matters; what to do about it is the caller's to add, because it
    /// differs between `permaura start` and a command that edits the store.
    pub fn acquire(db: &str, wait: Duration) -> Result<StoreLock, GatewayError> {
        let path = lock_path(db);
        let mut file = open_lock_file(&path, true)?;
        let deadline = Instant::now() + wait;
        let mut told = false;
        loop {
            match permaura_platform::try_lock_exclusive(&file) {
                Ok(true) => break,
                Ok(false) => {
                    let holder = describe(holder_pid(&mut file));
                    if Instant::now() >= deadline {
                        return Err(GatewayError::StoreHeld(format!(
                            "{db} is held by {holder}, so it was not opened again{}: two writers of one store overwrite each other's audit records.",
                            if wait.is_zero() { String::new() } else { format!(" after waiting {} s for it to let go", wait.as_secs()) }
                        )));
                    }
                    if !told {
                        told = true;
                        tracing::warn!(
                            store = db,
                            "{holder} holds this store; waiting up to {} s for it to let the store go before opening it",
                            wait.as_secs()
                        );
                    }
                    std::thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
                }
                Err(e) => {
                    return Err(GatewayError::Internal(format!(
                        "could not lock {path}, which keeps a second process off this store: {e}"
                    )))
                }
            }
        }
        // Best effort: the pid is only ever shown to the next opener, and the lock itself is what holds.
        let _ = file.set_len(0).and_then(|()| file.seek(SeekFrom::Start(0))).and_then(|_| {
            file.write_all(format!("{}\n", std::process::id()).as_bytes())
        });
        Ok(StoreLock { _file: file })
    }
}

/// Who holds the store at `db` right now, asked without waiting: `None` when nothing does (including a
/// store no lock-aware process has opened), `Some(pid)` when a process does, with its pid when it wrote
/// one. The probe takes the lock for an instant and gives it straight back, so a gateway starting in
/// that instant waits one poll. This is the liveness question for a command that must not act under a
/// running gateway: a gateway stops answering its address as its drain begins, and one on another port
/// of the same home never answers the default address at all, but either still holds this.
pub fn holder(db: &str) -> Result<Option<Option<u32>>, GatewayError> {
    let path = lock_path(db);
    if !std::path::Path::new(&path).exists() {
        return Ok(None);
    }
    let mut file = open_lock_file(&path, false)?;
    match permaura_platform::try_lock_exclusive(&file) {
        Ok(true) => Ok(None),
        Ok(false) => Ok(Some(holder_pid(&mut file))),
        Err(e) => Err(GatewayError::Internal(format!(
            "could not ask {path} whether a gateway holds this store: {e}"
        ))),
    }
}

/// The holder [`holder`] found, as a sentence fragment: `another Permaura process (pid N)`.
pub fn describe(pid: Option<u32>) -> String {
    match pid {
        Some(pid) if pid == std::process::id() => format!("this same process (pid {pid}) through a handle still open"),
        Some(pid) => format!("another Permaura process (pid {pid})"),
        None => "another Permaura process".to_string(),
    }
}

fn open_lock_file(path: &str, create: bool) -> Result<std::fs::File, GatewayError> {
    let (file, _created) = permaura_platform::open_lock_file(std::path::Path::new(path), create)
        .map_err(|e| GatewayError::Internal(format!("could not open the store lock {path}: {e}")))?;
    // Mode bits are set on the open handle above; Windows has none, so it gets the owner-only DACL, on a path just checked to be the regular file opened.
    #[cfg(all(windows, feature = "sqlite"))]
    super::sqlite::restrict_to_owner(path);
    Ok(file)
}

/// The pid the holder wrote, when it wrote one.
fn holder_pid(file: &mut std::fs::File) -> Option<u32> {
    let mut text = String::new();
    file.seek(SeekFrom::Start(0))
        .and_then(|_| file.read_to_string(&mut text))
        .ok()
        .and_then(|_| text.trim().parse::<u32>().ok())
}
