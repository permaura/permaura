//! `permaura link` / `permaura unlink`: put the command on PATH, and take it off again.
//!
//! Every install route drops the binary at `~/.permaura/bin/permaura`, which is on nobody's PATH.
//! That was invisible while the binary was a server with three flags; the moment it grew `status`,
//! `grant` and `approve` it meant two of the three install routes shipped a CLI the user could not
//! type. Rather than teach the shell installer and the desktop app the same rules twice, both call
//! this.
//!
//! **Why a ladder and not a location.** Neither obvious target is reliable. `/usr/local/bin` is on
//! PATH everywhere but is root-owned on a clean macOS (it is user-writable on many dev machines only
//! because Homebrew chowned it). `~/.local/bin` is always writable but is not on PATH on macOS
//! unless something else put it there. So: take `/usr/local/bin` when we can actually write to it,
//! fall back to `~/.local/bin`, and say the one line that fixes PATH when the directory we chose is
//! not already reachable. No `sudo`, ever: an installer that asks for a password to add a
//! convenience symlink has mispriced the convenience.
//!
//! **What it links to, and why not `current_exe()`.** The link points at the maintained install path
//! whenever that exists, NOT at whichever binary happens to be running. `permaura link` invoked from
//! the sidecar inside `Permaura.app` would otherwise write a link into an app bundle that the next
//! app update replaces. The install path is the one the desktop's `binupdate` keeps current and the
//! one `permaura upgrade` swaps in place, so a link made once stays correct across every later
//! upgrade with nothing to re-run.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};

/// The file name the link takes, which is also the command the user types.
const COMMAND: &str = "permaura";

pub fn link() -> anyhow::Result<()> {
    // Refuse before touching anything. `symlink` at the bottom refuses on its own, but by then the
    // stale-link arm below has already removed what it found, so a platform that can never make a
    // link would delete a working command and leave nothing in its place.
    //
    // A runtime check rather than a second cfg'd `link`: splitting the function leaves link_target,
    // choose_dir, writable_dir, warn_if_unreachable and on_path reachable from nothing on Windows,
    // and five dead_code warnings is how a real one goes unnoticed later.
    if let Some(why) = unsupported_here() {
        return Err(anyhow!(why));
    }

    let target = link_target()?;
    let dir = choose_dir()?;
    let path = dir.join(COMMAND);

    match existing_kind(&path)? {
        // Ours already, and pointing at the right place: say so and stop. Running `link` twice is a
        // no-op rather than an error, because the shell installer runs it on every re-install.
        Existing::OursPointingAt(cur) if cur == target => {
            println!("`{COMMAND}` is already linked: {} -> {}", path.display(), target.display());
            warn_if_unreachable(&dir, &path);
            return Ok(());
        }
        // Ours, but stale (an older install path, or a dangling link left by `rm -rf ~/.permaura`).
        // Repointing is the whole job.
        Existing::OursPointingAt(_) | Existing::Dangling => {
            std::fs::remove_file(&path)
                .with_context(|| format!("replacing the stale link at {}", path.display()))?;
        }
        // NOT ours. Refuse rather than guess: a real file here is someone else's program, and a
        // symlink somewhere we do not recognise is a decision the user made and we did not.
        Existing::Foreign(what) => {
            return Err(anyhow!(
                "{} already exists and Permaura did not put it there ({what}). Remove it yourself if \
                 you want `{COMMAND}` to point at this install; nothing has been changed.",
                path.display()
            ));
        }
        Existing::Nothing => {}
    }

    symlink(&target, &path)
        .with_context(|| format!("linking {} -> {}", path.display(), target.display()))?;
    println!("linked {} -> {}", path.display(), target.display());
    warn_if_unreachable(&dir, &path);
    Ok(())
}

pub fn unlink() -> anyhow::Result<()> {
    let mut removed = 0usize;
    // Both rungs are swept, not just the one this machine would choose today: the ladder's answer
    // depends on directory permissions, which can change between the link and the unlink.
    for dir in candidate_dirs() {
        let path = dir.join(COMMAND);
        match existing_kind(&path)? {
            Existing::OursPointingAt(_) | Existing::Dangling => {
                std::fs::remove_file(&path)
                    .with_context(|| format!("removing {}", path.display()))?;
                println!("removed {}", path.display());
                removed += 1;
            }
            // Left alone on purpose, and said out loud: silence here reads as "removed" to someone
            // who then deletes ~/.permaura and is left with a broken command.
            Existing::Foreign(what) => {
                println!("left {} alone: Permaura did not put it there ({what})", path.display());
            }
            Existing::Nothing => {}
        }
    }
    if removed == 0 {
        println!("nothing to remove: `{COMMAND}` is not linked onto PATH by Permaura");
    }
    Ok(())
}

/// What the link should point at: the maintained install path when it exists, else whatever is
/// running now.
fn link_target() -> anyhow::Result<PathBuf> {
    let installed = permaura_core::permaura_path("bin").map(|p| p.join(exe_name()));
    if let Some(p) = installed.filter(|p| p.is_file()) {
        return Ok(p);
    }
    let running = std::env::current_exe().context("resolving this binary's own path")?;
    // Not fatal: linking into a bundle still works today, and refusing would leave a user who has
    // only the app with no way to get the command at all. It just will not survive an app update.
    if running.components().any(|c| c.as_os_str().to_string_lossy().ends_with(".app")) {
        eprintln!(
            "note: linking to {} because nothing is installed at ~/.permaura/bin yet. That path is \
             inside an application bundle, so the link will break when the app updates. Re-run \
             `{COMMAND} link` afterwards, or let the app install the gateway first.",
            running.display()
        );
    }
    Ok(running)
}

#[cfg(windows)]
fn exe_name() -> &'static str {
    "permaura.exe"
}

#[cfg(not(windows))]
fn exe_name() -> &'static str {
    COMMAND
}

/// The rungs, in order. `/usr/local/bin` first because it is already on PATH everywhere this
/// matters, so choosing it means the user has nothing further to do.
fn candidate_dirs() -> Vec<PathBuf> {
    let mut v = vec![PathBuf::from("/usr/local/bin")];
    if let Some(home) = home_dir() {
        v.push(home.join(".local").join("bin"));
    }
    v
}

fn choose_dir() -> anyhow::Result<PathBuf> {
    let usr_local = PathBuf::from("/usr/local/bin");
    if writable_dir(&usr_local) {
        return Ok(usr_local);
    }
    let home = home_dir().ok_or_else(|| anyhow!("could not resolve a home directory: set HOME"))?;
    let local = home.join(".local").join("bin");
    std::fs::create_dir_all(&local)
        .with_context(|| format!("creating {}", local.display()))?;
    Ok(local)
}

/// Writability by probing, not by reading mode bits: the mode says what the permissions are, this
/// says whether we can actually write, which is the only question that matters and the only one that
/// accounts for ownership, ACLs and read-only mounts.
fn writable_dir(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let probe = dir.join(format!(".permaura-write-probe-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

enum Existing {
    Nothing,
    /// A symlink we recognise as ours, resolving to this path.
    OursPointingAt(PathBuf),
    /// A symlink into a Permaura-owned location whose target is gone: what `rm -rf ~/.permaura`
    /// leaves behind. Ours to clean up.
    Dangling,
    Foreign(String),
}

fn existing_kind(path: &Path) -> anyhow::Result<Existing> {
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return Ok(Existing::Nothing);
    };
    if !meta.file_type().is_symlink() {
        return Ok(Existing::Foreign("it is a regular file, not a symlink".into()));
    }
    let dest = std::fs::read_link(path).with_context(|| format!("reading {}", path.display()))?;
    if !ours(&dest) {
        return Ok(Existing::Foreign(format!("it points at {}", dest.display())));
    }
    if dest.is_file() {
        Ok(Existing::OursPointingAt(dest))
    } else {
        Ok(Existing::Dangling)
    }
}

/// Whether a link destination is one of ours.
///
/// Compared against the install path this process would compute, NOT against a hardcoded
/// `/.permaura/bin/` shape: `PERMAURA_HOME` is a supported override that the hosted workers and the
/// tests both use, and a shape test disowns its own link the moment it is set. The literal
/// `.permaura` shape is still accepted alongside it, because a link may well have been made by a
/// default install and be getting swept by a session that has an override set.
///
/// Every arm is a string comparison rather than a resolved one, so a link into a `~/.permaura` that
/// no longer exists is still recognised as ours and can be swept. That is exactly the state
/// `rm -rf ~/.permaura` leaves, and refusing to clean it up would strand a broken command on PATH.
fn ours(dest: &Path) -> bool {
    if let Some(installed) = permaura_core::permaura_path("bin").map(|p| p.join(exe_name())) {
        if dest == installed {
            return true;
        }
    }
    let s = dest.to_string_lossy();
    s.contains("/.permaura/bin/") || s.contains("Permaura.app/")
}

fn warn_if_unreachable(dir: &Path, path: &Path) {
    if on_path(dir) {
        return;
    }
    println!();
    println!("{} is not on your PATH. Add it:", dir.display());
    println!();
    println!("  export PATH=\"{}:$PATH\"", dir.display());
    println!();
    println!("Put that in your shell profile (~/.zshrc on macOS) to make it stick.");
    let _ = path;
}

fn on_path(dir: &Path) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|p| p == dir)
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").filter(|v| !v.is_empty()).map(PathBuf::from)
}

#[cfg(unix)]
fn symlink(target: &Path, at: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

/// Whether `link` can work on this platform at all, and if not, why.
///
/// `Some` is a refusal the user reads, so it says where the command comes from instead.
#[cfg(windows)]
fn unsupported_here() -> Option<&'static str> {
    Some(WINDOWS_UNSUPPORTED)
}

#[cfg(not(windows))]
fn unsupported_here() -> Option<&'static str> {
    None
}

/// Why `link` cannot work here. Held in one place because the guard in [`link`] and the stub below
/// must say the same thing: the guard is what a user actually hits, the stub is the backstop.
#[cfg(windows)]
const WINDOWS_UNSUPPORTED: &str =
    "PATH on Windows is a user environment variable rather than a directory of symlinks, so \
     `permaura link` does not apply. Install the launcher with `npm i -g permaura`, which puts \
     the command on PATH for you.";

#[cfg(windows)]
fn symlink(_target: &Path, _at: &Path) -> std::io::Result<()> {
    Err(std::io::Error::new(std::io::ErrorKind::Unsupported, WINDOWS_UNSUPPORTED))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_into_the_install_dir_is_recognised_as_ours() {
        assert!(ours(Path::new("/Users/x/.permaura/bin/permaura")));
        assert!(ours(Path::new("/Applications/Permaura.app/Contents/MacOS/permaura")));
    }

    /// The bug this exists to prevent, found by running the round trip rather than by reading it: a
    /// shape test on `/.permaura/bin/` disowns our own link under a `PERMAURA_HOME` override, so
    /// `link` reported its own handiwork as somebody else's and refused to run twice.
    #[test]
    fn our_own_link_is_recognised_under_a_permaura_home_override() {
        let home = std::env::temp_dir().join(format!("pm-home-{}", std::process::id()));
        let installed = home.join("bin").join(exe_name());
        crate::cli::with_permaura_home(&home, || {
            assert!(ours(&installed), "the install path under an override must read as ours");
        });
    }

    #[test]
    fn a_link_to_somebody_elses_program_is_not_ours() {
        // The whole point of the foreign check: these must never be removed by `unlink`.
        assert!(!ours(Path::new("/opt/homebrew/bin/permaura")));
        assert!(!ours(Path::new("/usr/bin/python3")));
    }

    #[test]
    fn a_regular_file_in_the_way_is_foreign_not_ours() {
        let dir = std::env::temp_dir().join(format!("permaura-link-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("permaura");
        std::fs::write(&f, b"someone else's program").unwrap();
        assert!(matches!(existing_kind(&f).unwrap(), Existing::Foreign(_)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    // Creating a symlink is the one thing this module cannot do on Windows, by design, so the
    // round-trip test is Unix-only. Windows gets its own below, asserting the refusal rather than
    // simply skipping: a platform with no test is a platform where the contract can quietly change.
    #[cfg(unix)]
    #[test]
    fn a_link_whose_target_is_gone_is_ours_to_sweep() {
        // `rm -rf ~/.permaura` with a link still standing. It must read as Dangling (ours) rather
        // than Foreign, or `unlink` would refuse to clean up after an uninstall.
        let dir = std::env::temp_dir().join(format!("permaura-dangle-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let at = dir.join("permaura");
        symlink(Path::new("/nonexistent/.permaura/bin/permaura"), &at).unwrap();
        assert!(matches!(existing_kind(&at).unwrap(), Existing::Dangling));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn nothing_there_is_nothing() {
        let p = std::env::temp_dir().join(format!("permaura-absent-{}", std::process::id()));
        assert!(matches!(existing_kind(&p).unwrap(), Existing::Nothing));
    }

    /// `link` must refuse on Windows, and must say where the command actually comes from there.
    /// Asserted rather than assumed because the failure it prevents is silent: the Unix body removes
    /// a stale link before it makes a new one, so reaching that code on a platform which cannot make
    /// one would delete a working command and leave nothing behind it.
    #[cfg(windows)]
    #[test]
    fn link_refuses_on_windows_and_points_at_npm() {
        let e = link().expect_err("link must refuse on Windows");
        let msg = e.to_string();
        assert!(msg.contains("npm i -g permaura"), "the refusal must say how to get the command: {msg}");
    }

    /// The stub behind it, kept in step with the guard.
    #[cfg(windows)]
    #[test]
    fn the_symlink_stub_reports_unsupported() {
        let e = symlink(Path::new("target"), Path::new("at")).expect_err("no symlinks here");
        assert_eq!(e.kind(), std::io::ErrorKind::Unsupported);
    }
}
