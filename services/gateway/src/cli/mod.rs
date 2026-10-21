//! The `permaura` command surface.
//!
//! A `clap`-derive front end over the local broker: it creates the Permaura home (`init`), runs the
//! gateway (`start`), stops it (`stop`), keeps the binary current (`upgrade`), reports health
//! (`status`), manages agents, grants, connections, approvers and the vault, prints the audit log as
//! a table, and evaluates a policy decision locally via [`permaura_policy`].
//!
//! Most subcommands talk to a gateway over its REST v1 surface, so they work the same against the
//! one this binary started, a remote self-run gateway, or a hosted worker; `init`, `link`, `unlink`,
//! `upgrade`, `uninstall`, `vault verify`, `vault forget-key`, `policy test`, `approver reset`,
//! `auth`, `remote` and `advertise` act on this machine or on permaura.com instead.
//!
//! Compiled into the binary only: `lib.rs` does not declare these modules, so nothing here is part
//! of the `permaura_gateway` library the daemon links.

mod advertise;
mod announce;
mod commands;
mod enroll;
mod start;
mod restart;
mod link;
mod port;
mod uninstall;
mod auth;
mod cloudflared;
pub(crate) mod remote;
mod upgrade;

/// Run `f` with `PERMAURA_HOME` pointed at `home`, restoring whatever was there before.
///
/// One lock for the whole binary's tests, because the environment is process-wide: two modules each
/// holding a lock of their own is the same as no lock at all, which is exactly what went wrong. A
/// test that set the variable without this could move another test's custody paths out from under
/// it mid-run, and the loser then resolved the REAL `~/.permaura`, where it went on to delete a
/// live Keychain entry it had no business touching.
#[cfg(test)]
pub(crate) fn with_permaura_home<T>(home: &std::path::Path, f: impl FnOnce() -> T) -> T {
    with_home_var("PERMAURA_HOME", home, f)
}

/// The same, for tests that move `HOME` instead.
///
/// It shares the lock rather than having one of its own, because the two variables are not
/// independent: `HOME` is where `PERMAURA_HOME` falls back to, and both feed the account name the
/// credential store derives. Serialising them separately would leave exactly the gap this exists to
/// close.
#[cfg(test)]
pub(crate) fn with_os_home<T>(home: &std::path::Path, f: impl FnOnce() -> T) -> T {
    with_home_var("HOME", home, f)
}

#[cfg(test)]
fn with_home_var<T>(var: &str, home: &std::path::Path, f: impl FnOnce() -> T) -> T {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    // Poison is ignored on purpose: a test that panics inside the closure has already failed, and
    // taking the rest of the suite down with it would hide which one.
    let _guard = LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let prev = std::env::var_os(var);
    std::env::set_var(var, home);
    let out = f();
    match prev {
        Some(v) => std::env::set_var(var, v),
        None => std::env::remove_var(var),
    }
    out
}

use clap::{CommandFactory, Parser, Subcommand};

/// `permaura`: give agents permission, not keys.
#[derive(Parser)]
#[command(
    name = "permaura",
    version,
    about = "Permaura: give agents permission, not keys. `permaura start` runs the gateway; every other command drives one.",
    long_about = "permaura is the permission layer that sits between AI agents and real systems and credentials. `permaura start` runs the enforcement gateway on this machine; the other commands manage agents, grants, connections, secrets, approvals, the audit log and policy against a running one: all without ever handing a raw secret to an agent.",
    after_long_help = "Exit status: 0 when the command did what it reports; 1 when it failed or the gateway refused it; 2 for a usage error; 3 when a write is held for a paired device to approve and has not been applied yet (the output names the approval).",
    propagate_version = true
)]
struct Cli {
    /// Base URL of the gateway to talk to.
    #[arg(long, global = true, default_value = "http://127.0.0.1:7376", env = "PERMAURA_URL")]
    url: String,

    /// Bearer token for authenticated calls. Defaults to ~/.permaura/operator.token if the local
    /// gateway published one.
    #[arg(long, global = true, env = "PERMAURA_TOKEN", hide_env_values = true)]
    token: Option<String>,

    /// Absent means "no arguments at all", which prints help and starts nothing. An unrecognised
    /// subcommand is still a parse ERROR; the distinction is the point: typing the bare command is
    /// someone asking what it does, while a typo must never boot a long-running server and bind a
    /// port.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Start the gateway on this machine (binds 127.0.0.1:7376 by default).
    Start(StartArgs),

    /// Ask a running gateway to drain in-flight calls and exit.
    Stop {
        /// If the gateway on the address rejects this home's operator token (it is serving another
        /// home, or a store that has since been recreated), end it anyway: TERM the process holding
        /// the port, once it has answered /health as a Permaura gateway.
        #[arg(long)]
        force: bool,
    },

    /// Remove Permaura from this machine: revoke its account links, stop the gateway, remove the boot
    /// service, the PATH link and the binary. Data stays unless --purge-data.
    Uninstall {
        /// Also delete the gateway's store, vault key, operator token, tunnel credentials and this
        /// machine's install identity; config.toml (with its announce secrets) and logs stay.
        /// Without it a reinstall resumes with everything it had (pair again to reconnect).
        #[arg(long)]
        purge_data: bool,
        /// Skip the confirmation.
        #[arg(long)]
        yes: bool,
    },

    /// Connect a gateway that is ALREADY running to your permaura.com account.
    ///
    /// `start --pair` can only enrol at boot, which is no use for the gateway a machine actually has:
    /// one the desktop app supervises, one a service manager brought up, or one started before the
    /// pairing code existed. Restarting a serving gateway just to pair it is not a reasonable price,
    /// so this does the same exchange against the running one.
    ///
    /// Run it on the gateway's own host: it reads the operator token from `~/.permaura`.
    Pair {
        /// The pairing code from Connect a gateway in the console. Read from PERMAURA_PAIR_CODE
        /// when omitted, which keeps it out of the process list, where every local user can read it.
        #[arg(env = "PERMAURA_PAIR_CODE", hide_env_values = true)]
        code: String,
    },

    /// Fetch the latest published gateway and replace this binary with it.
    Upgrade {
        /// Install the new binary but leave the running gateway on the old one.
        #[arg(long)]
        no_restart: bool,
    },

    /// Connect this machine to a Permaura account.
    #[command(subcommand)]
    Auth(AuthCmd),

    /// Remote access: give this gateway a public address, or take it away again.
    #[command(subcommand)]
    Remote(RemoteCmd),

    /// Tell permaura.com the address the console should call this gateway on.
    ///
    /// Enrolment sets this once, from whatever the installer advertised. Run this after moving the
    /// gateway to another port, or on a machine whose reachable address the installer could not know:
    /// inside a VM the console has to call the port the HOST forwards, not the one the guest binds.
    Advertise {
        /// The address, e.g. http://127.0.0.1:7377
        url: String,
        /// Send the address without checking that this gateway answers there. Only for a VM guest
        /// whose advertised address is a host port forward the guest cannot dial: the console sends
        /// this gateway's operator token to whatever answers at it.
        #[arg(long)]
        unproven: bool,
    },

    /// Phone notifications: how this gateway tells permaura.com it is holding an approval.
    ///
    /// Linking a gateway sets this up. Use it to rotate the secret on a machine the console cannot
    /// reach, or to set it up on a gateway linked before this existed.
    #[command(subcommand)]
    Announce(AnnounceCmd),

    /// Put the `permaura` command on your PATH (a symlink; no sudo, nothing copied).
    Link,

    /// Remove the `permaura` command from your PATH.
    Unlink,

    /// Create the Permaura home directory (settings live in ~/.permaura/config.toml).
    Init,

    /// Check the gateway's health and print a summary.
    Status,

    /// Manage agents.
    #[command(subcommand)]
    Agent(AgentCmd),

    /// Create a grant for an agent against a resource.
    Grant(GrantArgs),

    /// Print the audit log as a table; `audit verify` says whether the chain holds, `audit rekey` replaces a lost audit key.
    Audit {
        #[command(subcommand)]
        action: Option<AuditCmd>,
        /// Maximum number of recent events to show.
        #[arg(long, default_value_t = 20)]
        limit: usize,
    },

    /// List the pending approval queue (held calls awaiting a human yes/no).
    Pending,

    /// Approve a held call by id; the gateway runs it and returns a redacted result.
    Approve {
        /// The approval id to approve (e.g. appr_abc).
        approval_id: String,
    },

    /// Deny a held call by id; nothing runs upstream.
    Deny {
        /// The approval id to deny (e.g. appr_abc).
        approval_id: String,
    },

    /// Manage the vault (secret values are never echoed).
    #[command(subcommand)]
    Vault(VaultCmd),

    /// Evaluate a policy decision locally, with no gateway.
    #[command(subcommand)]
    Policy(PolicyCmd),

    /// Manage connections (configured integration instances).
    #[command(subcommand)]
    Connection(ConnectionCmd),

    /// Manage the trusted approver keys that may sign approval decisions.
    #[command(subcommand)]
    Approver(ApproverCmd),
}

/// Arguments for `permaura start`.
#[derive(clap::Args)]
pub struct StartArgs {
    /// Address to bind. A --demo takes 127.0.0.1:7399, a port of its own, unless this flag names another loopback address; it ignores PERMAURA_ADDR, which is usually the real install's.
    #[arg(long, env = "PERMAURA_ADDR", default_value = "127.0.0.1:7376")]
    pub addr: String,

    /// Use deterministic MOCK transports (HTTP, commands, SSH return canned results). A convenience
    /// for local exploration and tests; real is the default so features are never silently canned.
    #[arg(long)]
    pub mock: bool,

    /// A throwaway demo gateway: an in-memory store carrying the seeded demo estate, with mock
    /// transports so a demo credential never makes a real call. Nothing persists, and its operator
    /// bearer is the published demo constant, so it binds only a loopback address, on a port of its own
    /// (127.0.0.1:7399 unless --addr says otherwise), and refuses any request that comes from another address
    /// or carries a tunnel's or proxy's forwarding header; a raw forwarder that adds no header and connects from
    /// loopback cannot be told apart.
    #[arg(long)]
    pub demo: bool,

    /// Connect this gateway to your permaura.com account, using a pairing code from the console.
    ///
    /// Enrolment happens once the gateway is up and answering, and a failure to reach the account
    /// never stops the gateway; it prints the `permaura pair` command to run once a pairing code is
    /// at hand. Read from PERMAURA_PAIR_CODE when the flag is absent, which keeps the code out of the
    /// process list.
    #[arg(long, value_name = "CODE", env = "PERMAURA_PAIR_CODE", hide_env_values = true)]
    pub pair: Option<String>,
}

/// Whether `flag` (as `--flag value` or `--flag=value`) is among this process's arguments, as opposed to a value clap read from the environment.
fn given_on_the_command_line(flag: &str) -> bool {
    std::env::args_os().skip(1).any(|a| a == flag || a.to_string_lossy().starts_with(&format!("{flag}=")))
}

/// `permaura auth …`
#[derive(Subcommand)]
enum AuthCmd {
    /// Connect this machine to a Permaura account by approving it in a browser, anywhere.
    Login,
}

/// `permaura remote …`
#[derive(Subcommand)]
enum RemoteCmd {
    /// Give this gateway a public address, which it serves once it restarts.
    ///
    /// With no NAME the account API picks one. Re-running with a different NAME moves the address:
    /// the old one is released and agents pointed at it stop working, so it asks first.
    Enable {
        /// The label to answer on, e.g. `my-vps` for `my-vps.permaura.app`.
        name: Option<String>,
        /// Skip the confirmation when moving an address that is already in use.
        #[arg(long)]
        yes: bool,
    },
    /// Stop serving the public address, keeping the name reserved for this gateway: in its files, and in the gateway running at --url, which stops its tunnel connector and refuses permaura.com tokens at once.
    Disable,
    /// What this gateway is reachable at, if anything, by its files and by the gateway running at --url.
    Status,
}

/// `permaura announce …`
#[derive(Subcommand)]
enum AnnounceCmd {
    /// Whether this gateway announces, and as which gateway.
    Status,
    /// Get a new secret from permaura.com and give it to this gateway. The old one stops working.
    Rotate {
        /// The gateway's id on permaura.com. Defaults to the single link this gateway reports.
        #[arg(long)]
        gateway: Option<String>,
        /// Rotate every link this gateway holds, one at a time.
        #[arg(long)]
        all: bool,
    },
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Register a new agent.
    Add {
        /// The agent name (also used to derive its id).
        name: String,
    },
    /// Mint a one-time enrolment code for a new agent, and print it or write it to a file.
    ///
    /// The code is the agent's bearer once its first call redeems it. Run on the gateway's own machine, this
    /// presents the operator token only to a listener that proves it holds it, so no command needs the token
    /// in its arguments, where every local user can read it in the process list.
    Enroll {
        /// A suggested name shown beside the pending agent.
        #[arg(long)]
        label: Option<String>,
        /// Write the code to this new file, readable only by you, instead of printing it: give the bridge
        /// its path in PERMAURA_AGENT_TOKEN_FILE, and the code never sits in a terminal or a command line.
        #[arg(long, value_name = "PATH")]
        out: Option<std::path::PathBuf>,
    },
    /// List the gateway's agents with their status.
    List,
    /// Approve a pending agent, so its calls are judged by its grants.
    Approve {
        /// The agent's id, as `permaura agent list` shows it.
        id: String,
    },
}

#[derive(Subcommand)]
enum ConnectionCmd {
    /// Add an SSH connection (host/user/host-key pinned server-side) plus its exec and SFTP
    /// capabilities, seal the credential, and optionally grant it to an agent, in one shot.
    AddSsh(SshConnArgs),
    /// List configured connections.
    List,
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Say whether the running gateway's audit chain verifies, and name any recorded rekey.
    Verify,
    /// Give a store whose gateway.db.auditkey is gone for good a new audit key, with the gateway stopped.
    ///
    /// The events already recorded keep their hashes and links, but the key that signed them is gone,
    /// so their signatures can never be checked again. The new key's first event names the old chain's
    /// head (seq and hash) as a recorded fork, and verification reports that fork rather than a break.
    /// Restoring the original key file from a backup, or from the machine the store came from, is
    /// always the better repair. Refused while a gateway holds the store, while the key file is there,
    /// and without --yes.
    Rekey {
        /// Confirm. There is no prompt.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum ApproverCmd {
    /// Trust a device's signing key from a pairing blob it produced.
    ///
    /// The blob is a self-verifying possession proof, so it can travel over any channel (QR code,
    /// AirDrop, paste): the gateway checks the signature against the very key being trusted. This
    /// command is how a device that cannot reach the gateway on loopback (a phone, an Apple Watch)
    /// gets paired: run it here, on the gateway's own host.
    ///
    /// A hosted gateway has no host to run it on, so there the same enrolment is anchored to a
    /// fresh re-authentication as the account that owns the gateway; see --ticket.
    Pair {
        /// The base64url pairing blob. Omit to read it from stdin.
        #[arg(long)]
        blob: Option<String>,
        /// A pairing ticket from permaura.com, for a hosted gateway only.
        ///
        /// A hosted worker is internet-exposed and has no loopback client, so "run it on the
        /// gateway's own host" is not a thing anyone can do. In its place the gateway accepts a
        /// single-use ticket that permaura.com mints after re-authenticating the owning account,
        /// bound to this one device. Ignored wherever the gateway answers on 127.0.0.1, which is
        /// the stronger anchor and is used in preference.
        ///
        /// Give the flag on its own to be asked for the ticket with the input hidden, or set
        /// PERMAURA_TICKET. A ticket typed after the flag still works, with a warning: it lands in
        /// shell history and, while the command runs, in the process list.
        #[arg(long, value_name = "TICKET", num_args = 0..=1, default_missing_value = "")]
        ticket: Option<String>,
        /// Who this device approves for (for example the account the phone is signed in as), so a
        /// two-person rule counts its owner once however many devices they pair. Overrides any person
        /// the blob names, and `--person ''` sends none. A hosted gateway binds the account that
        /// stepped up and refuses any other person, so there give `--person ''` when the blob names
        /// someone else.
        #[arg(long)]
        person: Option<String>,
        /// Skip the confirmation prompt.
        #[arg(long)]
        yes: bool,
    },
    /// List every approver key this gateway trusts, and whether each is still usable.
    ///
    /// This reads the gateway's KEYRING, which is not the same set as the console's device list:
    /// that reads the push registry, which a device only joins once it has registered for
    /// notifications. An Apple Watch, a simulator build, or anyone who declined
    /// notifications is trusted to sign approvals and absent from that list. Revocation takes an
    /// approver id, so this is where to find the id of a key nothing else shows.
    List,
    /// Stop trusting an approver's signing key (a lost or rotated device).
    ///
    /// From anywhere but a self-run gateway's own machine this takes a fresh step-up ticket bound to
    /// the approver id. See --ticket.
    Revoke {
        /// The approver id to untrust (e.g. device:a1b2c3d4e5f6).
        approver_id: String,
        /// A single-use ticket from permaura.com, minted after re-authenticating the owning account.
        ///
        /// An `approver-revoke` ticket bound to this approver id is required on a HOSTED worker, and on
        /// a self-run gateway when this command is not run on its own machine. On a self-run gateway
        /// with remote access configured, a `recovery` ticket is instead the third authority for
        /// revoking its last trusted key, for the owner whose device and codes are both gone.
        ///
        /// A gateway with no remote-access configuration accepts neither: it has no authorization
        /// server to re-authenticate at. With its device and codes both gone, the remaining step there
        /// is `permaura uninstall --purge-data`, which destroys every credential the gateway holds.
        ///
        /// Give the flag on its own to be asked for the ticket with the input hidden, or set
        /// PERMAURA_TICKET. A ticket typed after the flag still works, with a warning: it lands in
        /// shell history and, while the command runs, in the process list.
        #[arg(long, value_name = "TICKET", num_args = 0..=1, default_missing_value = "")]
        ticket: Option<String>,
        /// One of the recovery codes shown when this gateway's first device was paired.
        ///
        /// Revoking the LAST trusted key on a self-run gateway switches every device hold off, so it
        /// takes more than the operator token: that device signs it, a code applies it now, or a
        /// recovery ticket does where this gateway has remote access configured (see --ticket).
        ///
        /// Give the flag on its own to be asked for the code with the input hidden, or set
        /// PERMAURA_RECOVERY_CODE. A code typed after the flag still works, with a warning: it lands
        /// in shell history and, while the command runs, in the process list.
        #[arg(long, value_name = "CODE", num_args = 0..=1, default_missing_value = "")]
        recovery_code: Option<String>,
    },
    /// Issue a fresh set of recovery codes, and show them once.
    ///
    /// Two authorities, and the operator token is neither: one of the CURRENT codes, or a signature
    /// from a device this gateway already trusts. The second is what a phone or the desktop app uses,
    /// and it is also the route for two states a code alone cannot reach: a gateway that was already
    /// paired before recovery codes existed and so has no set to present, and an owner who has spent
    /// or lost their set while the device still works.
    ///
    /// Run it on the gateway's own host: from anywhere else the gateway also wants a step-up ticket
    /// this command cannot send, and a hosted gateway issues no codes.
    ///
    /// The gateway keeps only Argon2id hashes, so the codes are shown once and never again.
    Codes {
        /// One of the current codes.
        ///
        /// Give the flag on its own to be asked for the code with the input hidden, or set
        /// PERMAURA_RECOVERY_CODE. A code typed after the flag still works, with a warning: it lands
        /// in shell history and, while the command runs, in the process list.
        #[arg(long, value_name = "CODE", num_args = 0..=1, default_missing_value = "")]
        recovery_code: Option<String>,
        /// The approver id whose trusted key signed this request. With --issued-at and --sig.
        #[arg(long)]
        approver_id: Option<String>,
        /// Unix ms the signature was made at. Must be within the freshness window.
        #[arg(long)]
        issued_at: Option<i64>,
        /// base64 ed25519 signature over device_control_preimage_v2(audience, "recovery-codes",
        /// approver_id, "", issued_at), or over the v1 device_control_preimage when --audience is
        /// not given.
        #[arg(long)]
        sig: Option<String>,
        /// The gateway's approval audience the signature binds (GET /v1/approver-keys serves it).
        #[arg(long)]
        audience: Option<String>,
        /// A single-use `recovery-codes-issue` ticket from permaura.com, for running this from anywhere but the gateway's own machine.
        ///
        /// Off the machine, a self-run gateway with remote access configured takes it beside a current code or a device signature; against its loopback address none is needed. A hosted gateway issues no recovery codes at all.
        ///
        /// Give the flag on its own to be asked for the ticket with the input hidden, or set
        /// PERMAURA_TICKET. A ticket typed after the flag still works, with a warning: it lands in
        /// shell history and, while the command runs, in the process list.
        #[arg(long, value_name = "TICKET", num_args = 0..=1, default_missing_value = "")]
        ticket: Option<String>,
    },
    /// Set what the web console, CLI and phone may resolve without a device signature.
    ///
    /// Pairing any device raises this floor to `device_signed`, and it stays raised when that
    /// device is revoked, so `approve` here is how an operator re-opens ordinary approvals
    /// afterwards, and the only way back short of never pairing at all.
    ///
    /// The floor is a global minimum, not a per-action override. An action a policy puts on the
    /// `device_signed` rung still takes a paired device at either floor; lowering only stops the
    /// floor from overriding every LOWER rung as well.
    ///
    /// Raising to `device_signed` is fail-safe and accepted from anywhere. Lowering is not, so on a
    /// self-run or tunnelled gateway it is accepted only from the gateway's own host.
    Floor {
        /// `approve` (console and CLI may resolve approve-tier approvals), `device_signed` (refuse
        /// every unsigned resolution), or `default` (clear the override; enrolment decides).
        floor: String,
        /// One of the recovery codes shown when this gateway's first device was paired.
        ///
        /// Lowering the floor while a device is trusted switches the device holds off, so it takes
        /// more than the operator token: that device signs it, or a code applies it now.
        ///
        /// Give the flag on its own to be asked for the code with the input hidden, or set
        /// PERMAURA_RECOVERY_CODE. A code typed after the flag still works, with a warning: it lands
        /// in shell history and, while the command runs, in the process list.
        #[arg(long, value_name = "CODE", num_args = 0..=1, default_missing_value = "")]
        recovery_code: Option<String>,
        /// A single-use `recovery` ticket from permaura.com, for a gateway with remote access on.
        ///
        /// The third authority, for the owner whose device and codes are both gone: re-authenticate
        /// at permaura.com and present the ticket here. A gateway with no remote-access
        /// configuration has no authorization server and does not accept one.
        ///
        /// Give the flag on its own to be asked for the ticket with the input hidden, or set
        /// PERMAURA_TICKET. A ticket typed after the flag still works, with a warning: it lands in
        /// shell history and, while the command runs, in the process list.
        #[arg(long, value_name = "TICKET", num_args = 0..=1, default_missing_value = "")]
        ticket: Option<String>,
    },
    /// Untrust every paired device and clear the approval-floor override, from this host, with the
    /// gateway stopped.
    ///
    /// The recovery for an owner whose device is gone on a gateway that has no authorization server
    /// to re-authenticate at. While a device is trusted it takes one of the recovery codes shown at
    /// pairing, because anything running as the owner can stop the gateway too. With neither the
    /// device nor a code, `permaura uninstall --purge-data` is what is left, and it destroys every
    /// credential the gateway holds. Approvals fall back to the operator token until a device is
    /// paired again, so this is refused while a gateway is running and requires --yes.
    Reset {
        /// Confirm. There is no prompt.
        #[arg(long)]
        yes: bool,
        /// One of the recovery codes shown when this gateway's first device was paired. Required
        /// while a device is trusted; spent by the reset. Asked for only once no gateway is answering.
        ///
        /// Give the flag on its own to be asked for the code with the input hidden, or set
        /// PERMAURA_RECOVERY_CODE. A code typed after the flag still works, with a warning: it lands
        /// in shell history and, while the command runs, in the process list.
        #[arg(long, value_name = "CODE", num_args = 0..=1, default_missing_value = "")]
        recovery_code: Option<String>,
    },
}

/// Arguments for `permaura connection add-ssh`.
#[derive(clap::Args)]
struct SshConnArgs {
    /// Connection id (e.g. `db1`). Capabilities are namespaced under it (`db1.uptime`, …).
    id: String,
    /// SSH host to dial. Pinned server-side; never agent-supplied.
    #[arg(long)]
    host: String,
    /// SSH port.
    #[arg(long, default_value_t = 22)]
    port: u16,
    /// Remote login user.
    #[arg(long)]
    user: String,
    /// Expected SHA256 host-key fingerprint, e.g. from
    /// `ssh-keyscan -t ed25519 <host> | ssh-keygen -lf -`. Required unless --insecure.
    #[arg(long = "host-key-sha256", conflicts_with = "insecure")]
    host_key_sha256: Option<String>,
    /// Disable host-key verification (dev/local only; prefer --host-key-sha256).
    #[arg(long)]
    insecure: bool,
    /// Path to an unencrypted private key to seal in the vault (publickey auth).
    #[arg(long = "key-file")]
    key_file: Option<String>,
    /// Read a password from this env var and use password auth instead of a key.
    #[arg(long = "password-env")]
    password_env: Option<String>,
    /// Expose path-scoped SFTP get/put/list under this remote root (e.g. /var/data).
    #[arg(long = "sftp-root")]
    sftp_root: Option<String>,
    /// An exec command as `action:program,arg,arg` (repeatable). `{name}` args become allow-listed
    /// placeholders, e.g. --exec 'restart:systemctl,restart,{service}'.
    #[arg(long = "exec")]
    exec: Vec<String>,
    /// After creating it, allow the declared actions and grant them to this agent id.
    #[arg(long)]
    agent: Option<String>,
    /// Mark the --exec commands as requiring human approval (High risk) rather than Low/auto.
    #[arg(long = "require-approval")]
    require_approval: bool,
}

/// Arguments for `permaura grant`.
#[derive(clap::Args)]
struct GrantArgs {
    /// The agent the grant is for.
    #[arg(long)]
    agent: String,
    /// The resource short name (e.g. braintree_production).
    #[arg(long)]
    resource: String,
    /// A capability action to allow (repeatable).
    #[arg(long = "allow")]
    allow: Vec<String>,
    /// A capability action to deny (repeatable). Deny always wins.
    #[arg(long = "deny")]
    deny: Vec<String>,
    /// Expiry as an RFC3339 timestamp.
    #[arg(long)]
    expires: Option<String>,
    /// Maximum number of calls this grant authorizes.
    #[arg(long = "max-calls")]
    max_calls: Option<u64>,
}

#[derive(Subcommand)]
enum VaultCmd {
    /// Add a secret. The value is read from --env-var or stdin, never an argument.
    Add {
        /// The secret id.
        id: String,
        /// Read the value from this environment variable instead of stdin.
        #[arg(long = "env-var")]
        env_var: Option<String>,
    },
    /// Check the gateway is up and confirm secret values are sealed (it lists no ids).
    List,
    /// Export the whole vault as one encrypted bundle you hold yourself.
    ///
    /// Prompts for a passphrase; it is never taken as an argument, which would leave it in shell
    /// history and in `ps`. Permaura keeps no copy of the bundle or the passphrase.
    Export {
        /// Where to write the bundle. Created owner-only; an existing file is never overwritten.
        #[arg(long)]
        out: String,
    },
    /// Check a bundle file offline: does this passphrase open it, and what is inside?
    ///
    /// Runs entirely on this machine. No gateway, no network, and nothing is written or imported.
    /// Prompts for the passphrase at the terminal; set PERMAURA_BUNDLE_PASSPHRASE to run it from a
    /// script or from CI, where a backup deserves exactly this check and there is no tty to type into.
    Verify {
        /// The bundle file to open.
        file: String,
    },
    /// Remove this machine's copy of the key that seals the vault, wherever it is held.
    ///
    /// The last step of uninstalling: the OS credential store entry, the fallback file under the
    /// Permaura home, and the marker recording which of the two the key was in. Everything the vault
    /// holds becomes unreadable, on this machine and on any copy of `gateway.db` taken from it. An
    /// exported bundle opens with its own passphrase and is unaffected.
    ForgetKey {
        /// Required. Without it nothing is removed, because there is no undo for this.
        #[arg(long)]
        yes: bool,
    },
    /// Import a vault bundle into this gateway, after previewing what it would change.
    Import {
        /// The bundle file to read.
        file: String,
        /// Overwrite anything whose id already exists here. Off by default: an import never
        /// silently replaces what you already have.
        #[arg(long)]
        replace: bool,
        /// Allow capabilities that run a program on this machine. Off by default.
        #[arg(long = "allow-command-capabilities")]
        allow_command_capabilities: bool,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    /// Evaluate a single capability for an agent/resource locally, printing the Decision.
    Test {
        /// The capability action id (e.g. transactions.refund).
        #[arg(long)]
        capability: String,
        /// The normalized action verb (e.g. refund).
        #[arg(long)]
        action: String,
        /// The resource short name.
        #[arg(long)]
        resource: String,
        /// The risk tier (low|medium|high|critical).
        #[arg(long, default_value = "high")]
        risk: String,
        /// A capability action to allow on the synthetic grant (repeatable).
        #[arg(long = "allow")]
        allow: Vec<String>,
        /// A capability action to deny on the synthetic grant (repeatable).
        #[arg(long = "deny")]
        deny: Vec<String>,
        /// Optional monetary amount for the action.
        #[arg(long)]
        amount: Option<f64>,
    },
}

/// Parse the command line and run what it asks for.
///
/// `config` is the result of loading `~/.permaura/config.toml`, carried in from `main` because it
/// has to be applied to the environment BEFORE clap parses (that ordering is what gives
/// flag > env > file precedence). Only `start` treats a broken file as fatal: its keys are the
/// serving gateway's, so refusing to serve on a config nobody can parse is right, while refusing to
/// print help or query a healthy gateway over it is not.
/// Adopt the installer's home when running as the service account without its environment.
///
/// A `--service-user` install keeps everything under `/var/lib/permaura` and records that as
/// `PERMAURA_HOME` in `gateway.env`, which the systemd unit loads. An operator at a shell does not
/// get that: `sudo -u permaura permaura remote enable` arrives with `HOME=/var/lib/permaura` and
/// `PERMAURA_HOME` unset, so every path resolved to `/var/lib/permaura/.permaura/`, a directory that
/// did not exist, which this then created and minted a SECOND machine identity into, while the
/// gateway id it needed sat one level up. The first real VPS run failed exactly this way.
///
/// Only the service layout has a `gateway.env` directly under `$HOME`, and an explicit
/// `PERMAURA_HOME` is never overridden, so this fires for precisely the case it exists for.
fn adopt_installer_home() {
    if std::env::var_os("PERMAURA_HOME").is_some_and(|v| !v.is_empty()) {
        return;
    }
    // `HOME` directly rather than a home-dir crate: this layout only exists on Unix service installs,
    // and `su`/`sudo -u` set HOME to the account's directory, which is exactly the one that matters.
    let Some(home) = std::env::var_os("HOME").filter(|h| !h.is_empty()) else { return };
    let Ok(env) = std::fs::read_to_string(std::path::Path::new(&home).join("gateway.env")) else {
        return;
    };
    if let Some(dir) = installer_home_from_env(&env) {
        std::env::set_var("PERMAURA_HOME", dir);
    }
}

/// The `PERMAURA_HOME=` value in an installer-written `gateway.env`, if any. Pure, for the test.
pub(super) fn installer_home_from_env(env: &str) -> Option<String> {
    env_file_value(env, "PERMAURA_HOME")
}

/// The value `key` is given in an env file such as the installer's `gateway.env`, unquoted, if it is set and not empty.
pub(super) fn env_file_value(env: &str, key: &str) -> Option<String> {
    env.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
        .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_string())
        .filter(|v| !v.is_empty())
}

/// The process exit status for how [`run`] ended. Any error but a hold prints exactly as `main` returning it would; a hold has already been explained on stdout.
pub fn exit_status(outcome: anyhow::Result<()>) -> std::process::ExitCode {
    match outcome {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) if e.is::<commands::Pending>() => std::process::ExitCode::from(commands::EXIT_PENDING_APPROVAL),
        Err(e) => {
            eprintln!("Error: {e:?}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Whether this invocation is a throwaway `permaura start` (`--demo`, or an in-memory store), read before `config.toml` is applied: a throwaway runs beside the real install and must take none of its settings.
pub fn is_throwaway_start() -> bool {
    matches!(Cli::try_parse().ok().and_then(|cli| cli.command), Some(Command::Start(args)) if args.demo || in_memory_store_requested())
}

/// Whether `PERMAURA_STORE_PATH` selects the in-memory store, which keeps nothing past this process.
pub fn in_memory_store_requested() -> bool {
    std::env::var("PERMAURA_STORE_PATH").ok().as_deref() == Some(":memory:")
}

pub async fn run(config: Result<(), String>) -> anyhow::Result<()> {
    adopt_installer_home();
    let cli = Cli::parse();

    let Some(command) = cli.command else {
        // Bare `permaura`: say what it does, start nothing, and succeed: this is someone asking,
        // not someone making a mistake.
        Cli::command().print_help()?;
        println!();
        return Ok(());
    };

    if let Err(e) = &config {
        if matches!(command, Command::Start(_)) {
            anyhow::bail!("{e}");
        }
        eprintln!("\x1b[33m!\x1b[0m ignoring ~/.permaura/config.toml: {e}");
    }

    // Keys a newer Permaura wrote into the same home. Said once, plainly, because the usual cause is
    // an updated gateway beside a stale CLI, and the fix is to update this binary.
    let unknown = permaura_gateway::config::unknown_keys_in_file();
    if !unknown.is_empty() {
        eprintln!(
            "\x1b[33m!\x1b[0m ~/.permaura/config.toml holds {} this version does not know ({}); the rest of the file was applied. Update permaura if a newer gateway wrote it.",
            if unknown.len() == 1 { "a setting" } else { "settings" },
            unknown.join(", "),
        );
    }

    // The variable keeps a token out of the process list; the flag puts it there for as long as the command runs.
    if cli.token.is_some() && given_on_the_command_line("--token") {
        eprintln!(
            "\x1b[33m!\x1b[0m warning: a token given with --token is in your shell history and, while this runs, in the process list, where every local user can read it. Set PERMAURA_TOKEN instead."
        );
    }
    if let Command::Pair { code } = &command {
        if std::env::args_os().skip(1).any(|a| a == code.as_str()) {
            eprintln!(
                "\x1b[33m!\x1b[0m warning: a pairing code typed after `pair` is in your shell history and, while this runs, in the process list. Set PERMAURA_PAIR_CODE and run `permaura pair` instead."
            );
        }
    }
    let ctx = commands::Ctx::new(cli.url, cli.token);

    match command {
        Command::Start(args) => start::run(args).await,
        Command::Stop { force } => commands::stop(&ctx, force).await,
        Command::Uninstall { purge_data, yes } => uninstall::run(&ctx, purge_data, yes).await,
        Command::Pair { code } => commands::pair(&ctx, &code).await,
        Command::Upgrade { no_restart } => upgrade::run(&ctx, no_restart).await,
        Command::Auth(AuthCmd::Login) => auth::login(&ctx).await,
        Command::Remote(RemoteCmd::Status) => remote::status(&ctx).await,
        Command::Remote(RemoteCmd::Enable { name, yes }) => remote::enable(name.as_deref(), yes).await,
        Command::Remote(RemoteCmd::Disable) => remote::disable(&ctx).await,
        Command::Advertise { url, unproven } => advertise::run(&url, unproven).await,
        Command::Announce(AnnounceCmd::Status) => announce::status(&ctx).await,
        Command::Announce(AnnounceCmd::Rotate { gateway, all }) => announce::rotate(&ctx, gateway, all).await,
        Command::Link => link::link(),
        Command::Unlink => link::unlink(),
        Command::Init => commands::init(),
        Command::Status => commands::status(&ctx).await,
        Command::Agent(AgentCmd::Add { name }) => commands::agent_add(&ctx, &name).await,
        Command::Agent(AgentCmd::Enroll { label, out }) => commands::agent_enroll(&ctx, label.as_deref(), out.as_deref()).await,
        Command::Agent(AgentCmd::List) => commands::agent_list(&ctx).await,
        Command::Agent(AgentCmd::Approve { id }) => commands::agent_approve(&ctx, &id).await,
        Command::Grant(args) => {
            commands::grant(
                &ctx,
                commands::GrantSpec {
                    agent: args.agent,
                    resource: args.resource,
                    allow: args.allow,
                    deny: args.deny,
                    expires: args.expires,
                    max_calls: args.max_calls,
                },
            )
            .await
        }
        Command::Audit { action: None, limit } => commands::audit(&ctx, limit).await,
        Command::Audit { action: Some(AuditCmd::Verify), .. } => commands::audit_verify(&ctx).await,
        Command::Audit { action: Some(AuditCmd::Rekey { yes }), .. } => commands::audit_rekey(&ctx, yes).await,
        Command::Pending => commands::pending(&ctx).await,
        Command::Approve { approval_id } => commands::approve(&ctx, &approval_id).await,
        Command::Deny { approval_id } => commands::deny_approval(&ctx, &approval_id).await,
        Command::Vault(VaultCmd::Add { id, env_var }) => commands::vault_add(&ctx, &id, env_var).await,
        Command::Vault(VaultCmd::List) => commands::vault_list(&ctx).await,
        Command::Vault(VaultCmd::Export { out }) => commands::vault_export(&ctx, &out).await,
        Command::Vault(VaultCmd::Verify { file }) => commands::vault_verify(&file),
        Command::Vault(VaultCmd::ForgetKey { yes }) => commands::vault_forget_key(&ctx, yes).await,
        Command::Vault(VaultCmd::Import { file, replace, allow_command_capabilities }) => {
            commands::vault_import(
                &ctx,
                commands::VaultImportSpec { file, replace, allow_command_capabilities },
            )
            .await
        }
        Command::Policy(PolicyCmd::Test {
            capability,
            action,
            resource,
            risk,
            allow,
            deny,
            amount,
        }) => commands::policy_test(commands::PolicyTestSpec {
            capability,
            action,
            resource,
            risk,
            allow,
            deny,
            amount,
        }),
        Command::Approver(ApproverCmd::List) => commands::approver_list(&ctx).await,
        Command::Approver(ApproverCmd::Pair { blob, ticket, person, yes }) => {
            commands::approver_pair(&ctx, blob, ticket, person, yes).await
        }
        Command::Approver(ApproverCmd::Revoke { approver_id, ticket, recovery_code }) => {
            commands::approver_revoke(&ctx, &approver_id, ticket, recovery_code).await
        }
        Command::Approver(ApproverCmd::Floor { floor, recovery_code, ticket }) => {
            commands::approver_floor(&ctx, &floor, recovery_code, ticket).await
        }
        Command::Approver(ApproverCmd::Reset { yes, recovery_code }) => {
            commands::approver_reset(&ctx, yes, recovery_code).await
        }
        Command::Approver(ApproverCmd::Codes { recovery_code, approver_id, issued_at, sig, audience, ticket }) => {
            commands::approver_codes(
                &ctx,
                commands::RecoveryCodesSpec { recovery_code, approver_id, issued_at, sig, audience, ticket },
            )
            .await
        }
        Command::Connection(ConnectionCmd::List) => commands::connection_list(&ctx).await,
        Command::Connection(ConnectionCmd::AddSsh(a)) => {
            commands::connection_add_ssh(
                &ctx,
                commands::SshConnSpec {
                    id: a.id,
                    host: a.host,
                    port: a.port,
                    user: a.user,
                    host_key_sha256: a.host_key_sha256,
                    insecure: a.insecure,
                    key_file: a.key_file,
                    password_env: a.password_env,
                    sftp_root: a.sftp_root,
                    exec: a.exec,
                    agent: a.agent,
                    require_approval: a.require_approval,
                },
            )
            .await
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};

    /// A host-key fingerprint and --insecure say opposite things, and the gateway would drop the fingerprint, so the CLI refuses the pair.
    #[test]
    fn an_ssh_connection_takes_a_fingerprint_or_insecure_not_both() {
        let both = super::Cli::try_parse_from([
            "permaura", "connection", "add-ssh", "db1", "--host", "db1.example", "--user", "deploy", "--host-key-sha256", "SHA256:abc", "--insecure",
        ]);
        assert!(both.is_err(), "both are refused");
        let one = super::Cli::try_parse_from(["permaura", "connection", "add-ssh", "db1", "--host", "db1.example", "--user", "deploy", "--insecure"]);
        assert!(one.is_ok(), "either alone parses");
    }

    /// One test for both variables, because the environment is process-wide and these are the only
    /// tests that set them.
    #[test]
    fn the_pairing_code_and_token_come_from_the_environment_and_help_never_shows_them() {
        std::env::set_var("PERMAURA_PAIR_CODE", "PGW-ENVONLY123");
        std::env::set_var("PERMAURA_TOKEN", "pgt_helpneverprints");
        let parsed = super::Cli::try_parse_from(["permaura", "pair"]);
        let argv = super::Cli::try_parse_from(["permaura", "pair", "PGW-ARGV456"]);
        let start = super::Cli::try_parse_from(["permaura", "start"]);
        let start_flag = super::Cli::try_parse_from(["permaura", "start", "--pair", "PGW-FLAG789"]);
        let help = super::Cli::command().find_subcommand_mut("pair").unwrap().render_long_help().to_string();
        let start_help = super::Cli::command().find_subcommand_mut("start").unwrap().render_long_help().to_string();
        let top = super::Cli::command().render_long_help().to_string();
        std::env::remove_var("PERMAURA_PAIR_CODE");
        std::env::remove_var("PERMAURA_TOKEN");

        match parsed.expect("the code may come from PERMAURA_PAIR_CODE alone").command {
            Some(super::Command::Pair { code }) => assert_eq!(code, "PGW-ENVONLY123"),
            _ => panic!("parsed as pair"),
        }
        match argv.unwrap().command {
            Some(super::Command::Pair { code }) => assert_eq!(code, "PGW-ARGV456", "an argument still wins"),
            _ => panic!("parsed as pair"),
        }
        match start.expect("start parses").command {
            Some(super::Command::Start(args)) => assert_eq!(args.pair.as_deref(), Some("PGW-ENVONLY123"), "start --pair reads it too"),
            _ => panic!("parsed as start"),
        }
        match start_flag.unwrap().command {
            Some(super::Command::Start(args)) => assert_eq!(args.pair.as_deref(), Some("PGW-FLAG789")),
            _ => panic!("parsed as start"),
        }
        assert!(help.contains("PERMAURA_PAIR_CODE"), "{help}");
        assert!(!help.contains("PGW-ENVONLY123"), "help must not print the code: {help}");
        assert!(!start_help.contains("PGW-ENVONLY123"), "{start_help}");
        assert!(!top.contains("pgt_helpneverprints"), "help must not print the token: {top}");
    }

    /// `permaura audit` keeps printing the table with `--limit`, beside its `verify` and `rekey` subcommands.
    #[test]
    fn audit_parses_with_its_limit_and_its_subcommands() {
        match super::Cli::try_parse_from(["permaura", "audit", "--limit", "5"]).unwrap().command {
            Some(super::Command::Audit { action: None, limit: 5 }) => {}
            _ => panic!("parsed as the audit table"),
        }
        match super::Cli::try_parse_from(["permaura", "audit", "verify"]).unwrap().command {
            Some(super::Command::Audit { action: Some(super::AuditCmd::Verify), .. }) => {}
            _ => panic!("parsed as audit verify"),
        }
        match super::Cli::try_parse_from(["permaura", "audit", "rekey"]).unwrap().command {
            Some(super::Command::Audit { action: Some(super::AuditCmd::Rekey { yes: false }), .. }) => {}
            _ => panic!("parsed as audit rekey without its confirmation"),
        }
        match super::Cli::try_parse_from(["permaura", "audit", "rekey", "--yes"]).unwrap().command {
            Some(super::Command::Audit { action: Some(super::AuditCmd::Rekey { yes: true }), .. }) => {}
            _ => panic!("parsed as a confirmed audit rekey"),
        }
    }

    #[test]
    fn installer_home_is_read_past_comments_quotes_and_other_keys() {
        let env = "# Permaura gateway settings\nPERMAURA_SEED=abc\nPERMAURA_HOME=\"/var/lib/permaura\"\nPERMAURA_ADDR=127.0.0.1:7376\n";
        assert_eq!(super::installer_home_from_env(env).as_deref(), Some("/var/lib/permaura"));
        assert_eq!(super::installer_home_from_env("# only a comment\n"), None);
        assert_eq!(super::installer_home_from_env("PERMAURA_HOME=\n"), None);
    }
}
