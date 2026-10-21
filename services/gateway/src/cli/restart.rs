//! Restarting the gateway onto a binary that has just been replaced.
//!
//! **Why an upgrade has to do this.** Swapping the file does nothing to the process: it holds the
//! old inode and keeps serving the old code until something restarts it. An upgrade that stops after
//! the swap has not upgraded anything that is running, it has downloaded a file, and it says
//! "installed", which is the part that misleads.
//!
//! **Why it cannot simply stop and let the supervisor take over.** Both units the installer writes
//! are deliberately configured so a clean exit stays exited: systemd `Restart=on-failure`, launchd
//! `KeepAlive/SuccessfulExit=false`. That is right (`permaura stop` should stay stopped), but it
//! means a graceful drain leaves the gateway down rather than restarting it onto the new binary.
//!
//! **So the restart has to know who owns the process.** Issuing `stop` then `start` against a
//! systemd-managed gateway races the unit; doing nothing where the desktop app supervises is
//! correct, because the app watches the binary and restarts on its own. Guessing wrong here either
//! double-starts a gateway or leaves one down, so this detects and says which it found.

use std::path::PathBuf;
use std::process::Command;

/// How the gateway on this machine is kept running.
///
/// The unit names and paths are the SAME ones `app/install/route.ts` writes in the web repo. They
/// are a two-sided contract like the codesign requirement string: if these drift, an upgrade quietly
/// stops restarting anything and reports success. Changing either side means changing both.
#[derive(Debug, PartialEq, Eq)]
pub enum Owner {
    /// A root-owned systemd unit at `/etc/systemd/system/permaura.service`.
    SystemdSystem,
    /// A per-user systemd unit at `~/.config/systemd/user/permaura.service`.
    SystemdUser,
    /// A launchd agent at `~/Library/LaunchAgents/com.permaura.gateway.plist`.
    Launchd,
    /// Nothing manages it: a bare process someone started, or nothing running at all.
    Unmanaged,
}

const SERVICE_NAME: &str = "permaura";
const LAUNCHD_LABEL: &str = "com.permaura.gateway";

pub fn detect() -> Owner {
    if cfg!(target_os = "linux") {
        // Only a root run owns the system unit. Claiming it from an unprivileged account would have
        // the upgrade try to restart another user's gateway and fail confusingly; the installer
        // draws the same line for the same reason.
        if is_root() && PathBuf::from("/etc/systemd/system/permaura.service").is_file() {
            return Owner::SystemdSystem;
        }
        if let Some(home) = home_dir() {
            if home.join(".config/systemd/user").join(format!("{SERVICE_NAME}.service")).is_file() {
                return Owner::SystemdUser;
            }
        }
    }
    if cfg!(target_os = "macos") {
        if let Some(home) = home_dir() {
            if home.join("Library/LaunchAgents").join(format!("{LAUNCHD_LABEL}.plist")).is_file() {
                return Owner::Launchd;
            }
        }
    }
    Owner::Unmanaged
}

/// Restart the gateway so it runs the binary that was just installed.
///
/// `running` is whether a gateway was answering before the swap: an unmanaged install that was not
/// running has nothing to restart, and starting one the user had deliberately stopped would be the
/// upgrade making a decision that is not its to make.
pub fn restart(owner: &Owner, running: bool) -> anyhow::Result<()> {
    match owner {
        Owner::SystemdSystem => run("systemctl", &["restart", SERVICE_NAME]),
        Owner::SystemdUser => run("systemctl", &["--user", "restart", SERVICE_NAME]),
        // `kickstart -k` restarts a loaded agent in one step. bootout+bootstrap would also work and
        // is two commands with a window in between where the agent is not loaded at all.
        Owner::Launchd => {
            let target = format!("gui/{}/{}", uid(), LAUNCHD_LABEL);
            run("launchctl", &["kickstart", "-k", &target])
        }
        Owner::Unmanaged if !running => {
            println!("    No gateway was running, so there is nothing to restart.");
            Ok(())
        }
        Owner::Unmanaged => {
            // Deliberately NOT spawning a replacement. A bare gateway was started by someone, in a
            // terminal or from the desktop app, with arguments and an environment this process
            // cannot see and must not invent. The desktop app is the common case here and needs no
            // help: it watches the binary and restarts onto the new one by itself.
            println!(
                "    A gateway is running but nothing here manages it. If the desktop app started \
                 it, it will pick the new binary up on its own. Otherwise restart it yourself: \
                 permaura stop, then permaura start."
            );
            Ok(())
        }
    }
}

pub fn describe(owner: &Owner) -> &'static str {
    match owner {
        Owner::SystemdSystem => "the systemd system service",
        Owner::SystemdUser => "the systemd user service",
        Owner::Launchd => "the launchd agent",
        Owner::Unmanaged => "an unmanaged process",
    }
}

fn run(bin: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| anyhow::anyhow!("could not run {bin}: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&out.stderr);
    anyhow::bail!("{bin} {} failed: {}", args.join(" "), stderr.trim())
}

/// The command that starts the gateway again under `owner`, for a restart that stopped it and failed to bring it back.
pub fn start_hint(owner: &Owner) -> String {
    match owner {
        Owner::SystemdSystem => format!("sudo systemctl start {SERVICE_NAME}"),
        Owner::SystemdUser => format!("systemctl --user start {SERVICE_NAME}"),
        Owner::Launchd => format!("launchctl kickstart gui/{}/{LAUNCHD_LABEL}", uid()),
        Owner::Unmanaged => "permaura start".to_string(),
    }
}

/// The command that restarts the gateway under `owner`, for a change only a restart applies. `system_unit` is whether a system unit is installed, which an account other than root restarts with sudo. Only an unmanaged gateway is told to stop and start: under a unit or an agent that leaves the unit stopped and a gateway in the foreground that ends with the session.
pub fn restart_hint(owner: &Owner, system_unit: bool) -> String {
    match owner {
        Owner::SystemdSystem => format!("sudo systemctl restart {SERVICE_NAME}"),
        Owner::SystemdUser => format!("systemctl --user restart {SERVICE_NAME}"),
        Owner::Launchd => format!("launchctl kickstart -k gui/{}/{LAUNCHD_LABEL}", uid()),
        Owner::Unmanaged if system_unit => format!("sudo systemctl restart {SERVICE_NAME}"),
        Owner::Unmanaged => "permaura stop && permaura start".to_string(),
    }
}

/// The service's main process as systemd reports it, for an `owner` that is a systemd unit with one running.
pub fn unit_main_pid(owner: &Owner) -> Option<u32> {
    let mut args = match owner {
        Owner::SystemdSystem => vec![],
        Owner::SystemdUser => vec!["--user"],
        Owner::Launchd | Owner::Unmanaged => return None,
    };
    args.extend(["show", SERVICE_NAME, "-p", "MainPID", "--value"]);
    let out = Command::new("systemctl").args(&args).output().ok()?;
    main_pid_from(&String::from_utf8_lossy(&out.stdout))
}

/// `systemctl show -p MainPID --value`'s answer, where 0 means no process.
fn main_pid_from(text: &str) -> Option<u32> {
    text.trim().parse().ok().filter(|pid| *pid != 0)
}

/// The account the system unit runs the gateway as, from its `User=` line, the same way the installer reads it.
pub fn unit_user() -> Option<String> {
    let unit = std::fs::read_to_string("/etc/systemd/system/permaura.service").ok()?;
    unit.lines().find_map(|l| l.trim().strip_prefix("User=").map(str::trim).filter(|u| !u.is_empty()).map(str::to_string))
}

fn is_root() -> bool {
    // Avoiding a libc dependency for one question: `id -u` is present everywhere this runs, and a
    // failure to read it is answered "not root", which is the safe direction: it declines to claim
    // a unit rather than claiming one it cannot manage.
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim() == "0")
        .unwrap_or(false)
}

fn uid() -> String {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "501".to_string())
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").filter(|v| !v.is_empty()).map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_main_pid_of_zero_is_no_process() {
        assert_eq!(super::main_pid_from("4242\n"), Some(4242));
        assert_eq!(super::main_pid_from("0\n"), None);
        assert_eq!(super::main_pid_from(""), None);
    }

    use super::*;

    #[test]
    fn an_unmanaged_install_with_nothing_running_is_a_no_op() {
        assert!(restart(&Owner::Unmanaged, false).is_ok());
    }

    #[test]
    fn an_unmanaged_install_that_is_running_does_not_try_to_spawn_one() {
        // It must succeed (the upgrade itself worked) while leaving the process alone: the desktop
        // app is the usual owner here and restarting behind its back would double-start a gateway.
        assert!(restart(&Owner::Unmanaged, true).is_ok());
    }

    /// the restart for a change is the one each service manager does. Only an unmanaged gateway is told to stop and start, which under a unit or an agent leaves it stopped and a gateway in the foreground.
    #[test]
    fn the_restart_hint_is_the_service_managers_own() {
        assert_eq!(restart_hint(&Owner::SystemdSystem, true), "sudo systemctl restart permaura");
        assert_eq!(restart_hint(&Owner::SystemdUser, false), "systemctl --user restart permaura");
        assert!(restart_hint(&Owner::Launchd, false).starts_with("launchctl kickstart -k gui/"), "{}", restart_hint(&Owner::Launchd, false));
        assert!(restart_hint(&Owner::Launchd, false).ends_with("/com.permaura.gateway"));
        assert_eq!(restart_hint(&Owner::Unmanaged, true), "sudo systemctl restart permaura", "another account's system unit");
        assert_eq!(restart_hint(&Owner::Unmanaged, false), "permaura stop && permaura start");
    }

    #[test]
    fn every_owner_has_a_description() {
        for o in [Owner::SystemdSystem, Owner::SystemdUser, Owner::Launchd, Owner::Unmanaged] {
            assert!(!describe(&o).is_empty());
        }
    }

    /// Detection must never claim a unit that is not there. On a developer machine with no installed
    /// service this is the only answer that is correct, and getting it wrong means an upgrade tries
    /// to restart something imaginary.
    #[test]
    fn detection_without_any_unit_file_is_unmanaged() {
        let empty = std::env::temp_dir().join(format!("permaura-no-units-{}", std::process::id()));
        std::fs::create_dir_all(&empty).unwrap();
        // Shares the suite's home lock: moving HOME moves where PERMAURA_HOME falls back to, and
        // with it the account the credential store derives, so an unlocked swap here can land
        // another test's Keychain delete on the developer's real entry.
        let got = crate::cli::with_os_home(&empty, || {
            // Not asserting a bare `== Unmanaged`: a root CI runner with a real /etc unit would fail
            // it for a reason that is not this test's business.
            detect()
        });
        assert!(
            got == Owner::Unmanaged || got == Owner::SystemdSystem,
            "a HOME with no unit files must not resolve to a per-user owner, got {got:?}"
        );
        let _ = std::fs::remove_dir_all(&empty);
    }
}
