//! `~/.permaura/config.toml`: the settings a self-hosted gateway keeps between restarts.
//!
//! Everything here used to be environment-only, which is fine for a gateway a supervisor launches
//! and invisible for one a person runs. A self-hosted install is the second kind: someone exports
//! `PERMAURA_PUBLIC_URL`, starts the gateway, and the setting lives exactly as long as that shell.
//! Restart it by hand (never mind reboot the box) and the gateway comes back on loopback with its
//! resource server switched off, having said nothing about why. `~/.permaura/gateway.addr` looks
//! like it solves this and does not: it is written and read only by the install script, so it
//! survives `--update` and nothing else.
//!
//! ## What may live here, and what may not
//!
//! Operational settings only. **Posture (`--mock` and `--demo`) is deliberately absent and is
//! rejected rather than ignored.** `main.rs` explains why those are CLI flags: you opt out of real
//! behaviour, never into it, so that no install path can silently hand an end user a gateway whose
//! transports are canned. A config file is the strongest possible version of the thing that rule
//! exists to prevent, because it is invisible at the point of launch and it persists. Rejecting a
//! `mock = true` loudly is the point: silently ignoring it would let someone believe they had
//! disabled something.
//!
//! **No vault key may be set here either.** The announce secrets and the webhook URL this file may hold open no sealed credential, which is why they are allowed. The vault KEK has a custody ladder in
//! [`crate::service::vault_passphrase`] whose whole purpose is that the key is not sitting in a file
//! that anything reading the Permaura home can lift. A `vault_passphrase` key would be that file. A
//! *path* to a secret is fine and is what `vault_passphrase_file` already is, so that one is allowed.
//!
//! ## Precedence, and why the file is at the bottom
//!
//! Explicit flag, then environment, then this file, then the built-in default. The file loses to the
//! environment on purpose: the desktop supervisor and the hosted worker both inject env, and a config
//! file left behind on a machine that later gets a supervisor must not quietly outrank what the
//! supervisor asks for.
//!
//! One exception: an `owner_sub` a check-in re-pin wrote outranks the exact environment value it replaced, unless an app supervises the gateway (see [`GatewayConfig::owner_sub_replaces_env`]).
//!
//! That ordering is not implemented by threading a config struct through the twenty-odd places that
//! read env; it is implemented by [`GatewayConfig::apply`] setting only the variables that are not
//! already set, before `Cli::parse()` runs. clap already resolves flag-over-env, so populating env
//! first gets the whole ladder for free and every existing reader keeps working untouched.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// The file's name inside the Permaura home. Stable: renaming it strands existing installs.
pub const FILE_NAME: &str = "config.toml";

/// The settings a gateway can be given without a supervisor.
///
/// Top-level keys are screened before this struct is deserialized: `mock`, `demo` and `vault_passphrase` are refused by name ([`REFUSED_KEYS`]), a key within two edits of a known one is refused as a typo (so `public_utl` cannot leave the gateway on loopback with no resource server and no complaint), and any other unknown key, one a newer Permaura wrote, is skipped with a warning.
/// `deny_unknown_fields` still refuses an unknown key inside a table such as an `[[announce]]` entry; see the module comment for why those three keys in particular.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    /// Address to bind, e.g. `127.0.0.1:7376` or `0.0.0.0:7376`.
    pub addr: Option<String>,
    /// The HTTPS origin this gateway is reachable at, e.g. `https://gw.example.com`. Setting it
    /// turns the gateway into an OAuth resource server; see [`crate::oauth`].
    pub public_url: Option<String>,
    /// The account whose sign-ins this gateway accepts. Without it a public gateway fails closed and
    /// rejects every remote token, so it is not optional in practice once `public_url` is set.
    pub owner_sub: Option<String>,
    /// Written beside `owner_sub` when a check-in moved the owner of a gateway whose own environment sets `PERMAURA_OWNER_SUB` (a VPS's `gateway.env`): the value it replaced. While no app supervises the gateway and the environment still says exactly this, `owner_sub` here outranks it.
    pub owner_sub_replaces_env: Option<String>,
    /// Authorization Server issuer. Defaults to Permaura's; only set it for a self-hosted AS.
    pub as_issuer: Option<String>,
    /// Where to fetch the AS signing keys.
    pub as_jwks: Option<String>,
    /// Extra `Host` values to accept, beyond loopback and `public_url`. Comma-joined into
    /// `PERMAURA_ALLOWED_HOSTS`.
    pub allowed_hosts: Option<Vec<String>>,
    /// Where the store lives, if not the default under the Permaura home.
    pub store_path: Option<String>,
    /// A *path* to the vault KEK. The key itself must never appear in this file.
    pub vault_passphrase_file: Option<String>,
    /// Where the vault KEK is kept: `auto` (the default) or `file`.
    ///
    /// `file` is an operator saying "do not use this machine's credential store", and it is here
    /// rather than on the command line because the one case that needs it is a machine nobody types
    /// on. A signed gateway on a headless Mac adopts its key into the Keychain during a GUI session
    /// and then cannot read it back over SSH or from a launchd daemon, at which point the file it
    /// would have fallen back to is already gone. Set before the first start it is a working
    /// install; set afterwards it recovers nothing, so it has to be the kind of setting that
    /// survives a reboot.
    ///
    /// Unlike `mock` and `demo` this is not a posture: it does not turn real behaviour off, it picks
    /// between two custodies that both seal the vault for real, and the weaker of the two is what
    /// every non-desktop install already had.
    pub vault_custody: Option<String>,
    /// Where to POST a JSON notification when an action is held or runs unattended: ntfy,
    /// Pushover, Home Assistant, a script. Must be `https://`; see [`crate::notify`].
    ///
    /// Here rather than only in the environment because the operator who most needs it is the one
    /// running a gateway by hand, and a notification path that evaporates with the shell is worse
    /// than none: it is a channel you believe you have. Deliberately NOT settable over REST (that
    /// would hand the broker an outbound-request primitive aimed at a host of its choosing), and
    /// this file is the same authority as the environment, a person with access to the gateway's
    /// own home directory.
    ///
    /// It is a URL and often carries a token in its path, which is as much of a secret as an
    /// incoming-webhook URL ever is. That is the same exposure the env var already had, and unlike
    /// the vault KEK it opens nothing but the ability to send this operator a message.
    pub webhook_url: Option<String>,
    /// The per-gateway secret this gateway announces held approvals to the control plane with, so a
    /// phone can see one queue across every workspace. Paired with `PERMAURA_GATEWAY_ID`; without
    /// both, announcing stays off. See [`crate::announce`].
    ///
    /// A secret in a config file, unlike the vault KEK which is deliberately refused here. The
    /// difference is what it opens: the KEK opens every sealed credential in the estate, whereas
    /// this authorizes only statements about one gateway (a hold or a waiting agent, a decided hold,
    /// its fair-use state) and its check-in, whose answer can move this gateway's owner pin. Somebody who can read this file can already read `operator.token`
    /// beside it and do anything the gateway can do, so keeping this one out would protect nothing
    /// and would leave a self-run gateway unable to announce across a restart.
    ///
    /// The 1.3.25 form, kept because gateways in the field were written with it: it means one link,
    /// and the next write replaces it with `announce`.
    pub announce_secret: Option<String>,
    /// This gateway's id on the control plane, which `announce_secret` speaks for. The 1.3.25 form,
    /// alongside it; a hosted worker gets both from its environment instead.
    pub gateway_id: Option<String>,
    /// One entry per workspace this gateway is linked into. A machine can be linked into several, and
    /// every link can already drive this gateway, so each one is told about every hold.
    #[serde(default)]
    pub announce: Vec<AnnounceLink>,
}

/// One `[[announce]]` entry: a gateway row on the control plane and the secret that speaks for it.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnnounceLink {
    /// The control plane's id for this gateway in that workspace.
    pub gateway_id: String,
    /// The secret permaura.com minted for that link.
    pub announce_secret: String,
}

/// Every top-level key this binary understands. Kept beside the struct because a key that is merely
/// unknown has to be told from one that is a typo or is forbidden, and serde cannot make that call.
/// A field missing from this list would be silently dropped, which `every_field_is_a_known_key` catches.
const KNOWN_KEYS: &[&str] = &[
    "addr",
    "public_url",
    "owner_sub",
    "owner_sub_replaces_env",
    "as_issuer",
    "as_jwks",
    "allowed_hosts",
    "store_path",
    "vault_passphrase_file",
    "vault_custody",
    "webhook_url",
    "announce_secret",
    "gateway_id",
    "announce",
];

/// Keys that must be refused by name however old or new the binary is, with why. Skipping one of
/// these quietly is the failure the module comment exists to prevent: posture you did not opt into,
/// or a vault key sitting in a readable file.
const REFUSED_KEYS: &[(&str, &str)] = &[
    ("mock", "posture is a CLI flag, so that no file can hand someone canned transports (`permaura start --mock`)"),
    ("demo", "posture is a CLI flag, so that no file can hand someone a demo estate (`permaura start --demo`)"),
    ("vault_passphrase", "a vault key is never read from this file; point `vault_passphrase_file` at one instead"),
];

/// The known key `candidate` is probably a misspelling of, if any: within two single-character edits,
/// which covers a swap, a dropped letter and a stray one, and does not reach an unrelated new key.
fn typo_of(candidate: &str) -> Option<&'static str> {
    KNOWN_KEYS
        .iter()
        .filter(|known| edit_distance(candidate, known) <= 2)
        .min_by_key(|known| edit_distance(candidate, known))
        .copied()
}

/// Levenshtein distance, bounded by the lengths involved: these are config key names, never text.
fn edit_distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut previous: Vec<usize> = (0..=b.len()).collect();
    for (i, ac) in a.iter().enumerate() {
        let mut current = vec![i + 1];
        for (j, bc) in b.iter().enumerate() {
            let cost = usize::from(ac != bc);
            current.push((previous[j] + cost).min(previous[j + 1] + 1).min(current[j] + 1));
        }
        previous = current;
    }
    previous[b.len()]
}

impl GatewayConfig {
    /// The links this file names, in the order a hold is announced to them.
    ///
    /// The list wins over the 1.3.25 single form rather than merging with it: a file holding both is
    /// mid-migration, and the list is what the gateway itself wrote last.
    pub fn announce_links(&self) -> Vec<AnnounceLink> {
        if !self.announce.is_empty() {
            return self.announce.clone();
        }
        match (self.gateway_id.as_deref(), self.announce_secret.as_deref()) {
            (Some(id), Some(secret)) if !id.trim().is_empty() && !secret.trim().is_empty() => {
                vec![AnnounceLink { gateway_id: id.to_string(), announce_secret: secret.to_string() }]
            }
            _ => Vec::new(),
        }
    }

    /// Read the file, or `Ok(None)` when there is none. A malformed file is an error, never a
    /// shrug: a gateway that ignored a config it could not parse would come up in a posture nobody
    /// asked for.
    pub fn load_from(path: &Path) -> Result<Option<Self>, String> {
        Ok(Self::load_reporting_unknown(path)?.map(|(config, _)| config))
    }

    /// The same read, also naming the top-level keys this binary tolerated but does not understand.
    ///
    /// A key from a NEWER Permaura must not cost an older one its whole file. Before this, one
    /// `[[announce]]` entry written by a 1.3.26 gateway made a 1.3.17 binary on the same home reject
    /// the config outright: the CLI carried on with every setting dropped, and a gateway refused to
    /// boot. The file is written by the product as well as by a person, so meeting a key from the
    /// future is ordinary and has to degrade to "use what I understand, say what I skipped".
    ///
    /// What stays fatal is what this file's rules were written for: posture and inline secrets
    /// ([`REFUSED_KEYS`]), malformed TOML, a wrong type, and a key close enough to a known one to be
    /// a typo ([`typo_of`]). A misspelled `public_utl` still refuses rather than reading as unset.
    pub fn load_reporting_unknown(path: &Path) -> Result<Option<(Self, Vec<String>)>, String> {
        let raw = match std::fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("reading {} failed: {e}", path.display())),
        };
        let bad = |detail: String| format!("{} is not valid config: {detail}", path.display());
        let table: toml::Table = toml::from_str(&raw).map_err(|e| bad(e.to_string()))?;

        let mut known = toml::Table::new();
        let mut unknown = Vec::new();
        for (key, value) in table {
            if let Some((refused, why)) = REFUSED_KEYS.iter().find(|(k, _)| *k == key) {
                return Err(bad(format!("`{refused}` cannot be set here: {why}")));
            }
            if KNOWN_KEYS.contains(&key.as_str()) {
                known.insert(key, value);
            } else if let Some(meant) = typo_of(&key) {
                return Err(bad(format!(
                    "unknown key `{key}`; did you mean `{meant}`? A key this close to a real one is \
                     read as a mistake rather than skipped, because a dropped setting is invisible"
                )));
            } else {
                unknown.push(key);
            }
        }
        let config = toml::Value::Table(known)
            .try_into::<Self>()
            .map_err(|e| bad(e.to_string()))?;
        unknown.sort();
        Ok(Some((config, unknown)))
    }

    /// The default location, `~/.permaura/config.toml` (or `$PERMAURA_HOME/config.toml`).
    pub fn default_path() -> Option<PathBuf> {
        permaura_core::permaura_path(FILE_NAME)
    }

    /// Populate the environment from this config, leaving anything already set alone.
    ///
    /// Returns the variable names it actually set, for the startup log: a self-hosted operator
    /// debugging "why is it on loopback again" needs to see which of the two sources won.
    ///
    /// Must run before `Cli::parse()`, and before anything spawns a thread: it mutates process
    /// environment, which is only sound while the process is still single-threaded.
    pub fn apply(&self) -> Vec<&'static str> {
        let supervised = supervised_by_app();
        let mut set = Vec::new();
        for (key, value) in self.env_pairs() {
            let Some(value) = value else { continue };
            if value.trim().is_empty() {
                continue;
            }
            if std::env::var_os(key).is_some_and(|v| !v.is_empty())
                && !(key == OWNER_SUB_ENV && self.owner_outranks_environment(std::env::var(key).ok().as_deref(), supervised))
            {
                continue;
            }
            std::env::set_var(key, value);
            set.push(key);
        }
        set
    }

    /// Whether this file's `owner_sub` outranks the `environment` value of `PERMAURA_OWNER_SUB`: only one a check-in re-pin wrote over exactly that value, and never under an app that supervises the gateway.
    pub(crate) fn owner_outranks_environment(&self, environment: Option<&str>, supervised: bool) -> bool {
        fn named(v: Option<&str>) -> Option<&str> {
            v.map(str::trim).filter(|v| !v.is_empty())
        }
        !supervised
            && named(self.owner_sub.as_deref()).is_some()
            && named(environment).is_some()
            && named(self.owner_sub_replaces_env.as_deref()) == named(environment)
    }

    /// Each setting paired with the variable it becomes. Separate from [`Self::apply`] so the mapping
    /// can be tested without touching the process environment, which the suite shares.
    fn env_pairs(&self) -> Vec<(&'static str, Option<String>)> {
        vec![
            ("PERMAURA_ADDR", self.addr.clone()),
            ("PERMAURA_PUBLIC_URL", self.public_url.clone()),
            ("PERMAURA_OWNER_SUB", self.owner_sub.clone()),
            ("PERMAURA_AS_ISSUER", self.as_issuer.clone()),
            ("PERMAURA_AS_JWKS", self.as_jwks.clone()),
            ("PERMAURA_STORE_PATH", self.store_path.clone()),
            ("PERMAURA_VAULT_PASSPHRASE_FILE", self.vault_passphrase_file.clone()),
            ("PERMAURA_VAULT_CUSTODY", self.vault_custody.clone()),
            ("PERMAURA_ALLOWED_HOSTS", self.allowed_hosts.as_ref().map(|h| h.join(","))),
            ("PERMAURA_WEBHOOK_URL", self.webhook_url.clone()),
            // Only the single form travels through the environment; a list cannot be expressed there,
            // so `announce` is read straight off the file by `announce_links_at_boot`.
            ("PERMAURA_ANNOUNCE_SECRET", self.announce_secret.clone()),
            ("PERMAURA_GATEWAY_ID", self.gateway_id.clone()),
        ]
    }
}

/// The variables [`load_and_apply`] took from the file, so a caller can tell a value the operator's
/// environment pinned (which a runtime change must not quietly outrank) from one the file supplied.
static APPLIED_FROM_FILE: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();

/// Top-level keys the file held that this binary does not understand, for the CLI to report.
static UNKNOWN_IN_FILE: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

/// The keys [`load_and_apply`] skipped because this binary is older than whatever wrote them.
pub fn unknown_keys_in_file() -> Vec<String> {
    UNKNOWN_IN_FILE.get().cloned().unwrap_or_default()
}

const OWNER_SUB_ENV: &str = "PERMAURA_OWNER_SUB";

/// The `PERMAURA_OWNER_SUB` the process environment set before [`load_and_apply`] read the file, which a re-pinned `owner_sub` may have replaced since.
static ENVIRONMENT_OWNER_SUB: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// The owner the process environment itself names, if any, whether or not a re-pinned `owner_sub` in the file outranks it now.
pub fn environment_owner_sub() -> Option<String> {
    match ENVIRONMENT_OWNER_SUB.get() {
        Some(captured) => captured.clone(),
        None => std::env::var(OWNER_SUB_ENV).ok().filter(|v| !v.trim().is_empty()),
    }
}

/// Whether the desktop app launched this gateway: it sets `PERMAURA_SUPERVISED_BY_APP` on every gateway it spawns and on nothing else.
pub fn supervised_by_app() -> bool {
    std::env::var_os("PERMAURA_SUPERVISED_BY_APP").is_some_and(|v| !v.is_empty())
}

/// Whether `key` was set by the environment itself rather than by `config.toml`.
pub fn pinned_by_environment(key: &str) -> bool {
    let from_file = APPLIED_FROM_FILE.get().is_some_and(|keys| keys.contains(&key));
    !from_file && std::env::var_os(key).is_some_and(|v| !v.is_empty())
}

/// The links the config file named at boot, so [`crate::announce::Announcer`] can be built without
/// threading the file through every constructor. Empty when there was no file, when it named none,
/// or when the environment named one instead (the environment is one link and outranks the file).
static BOOT_LINKS: std::sync::OnceLock<Vec<crate::announce::Config>> = std::sync::OnceLock::new();

/// See [`BOOT_LINKS`]. A runtime change goes to the announcer, never here: this is what the file said
/// when the process started and nothing else.
pub fn announce_links_at_boot() -> Vec<crate::announce::Config> {
    BOOT_LINKS.get().cloned().unwrap_or_default()
}

/// Held across every read-modify-write of the config file this process makes: a check-in's owner re-pin landing during a `PUT /v1/announce` would otherwise read the file before the other wrote it and put back what the other removed, dropping a link or the new owner at the next restart.
static CONFIG_EDIT: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Write this gateway's announce links into the config file at `path`, replacing whatever it named
/// before and leaving every other key and comment as the operator left them.
///
/// Written to a sibling and renamed over the original, so a crash mid-write leaves the old file
/// rather than half of one, and the result is parsed back first: `deny_unknown_fields` makes a file
/// this gateway cannot read a gateway that will not boot. The file holds secrets, so it is
/// owner-only on unix whatever it was before. The 1.3.25 single form is removed on every write, so a
/// file never states its links twice.
pub fn write_announce(path: &Path, links: &[AnnounceLink]) -> Result<(), String> {
    use toml_edit::{value, ArrayOfTables, DocumentMut, Item, Table};

    let _edit = CONFIG_EDIT.lock().unwrap_or_else(|e| e.into_inner());
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && links.is_empty() => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("reading {} failed: {e}", path.display())),
    };
    let mut doc = existing
        .parse::<DocumentMut>()
        .map_err(|e| format!("{} is not valid config: {e}", path.display()))?;
    doc.remove("gateway_id");
    doc.remove("announce_secret");
    doc.remove("announce");
    if !links.is_empty() {
        let mut tables = ArrayOfTables::new();
        for link in links {
            let mut t = Table::new();
            t["gateway_id"] = value(link.gateway_id.as_str());
            t["announce_secret"] = value(link.announce_secret.as_str());
            tables.push(t);
        }
        doc["announce"] = Item::ArrayOfTables(tables);
    }
    let rendered = doc.to_string();
    toml::from_str::<GatewayConfig>(&rendered)
        .map_err(|e| format!("{} would not be valid config: {e}", path.display()))?;

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {} failed: {e}", dir.display()))?;
    }
    // The file holds the announce secret, so it is written like every other secret: owner-only from
    // its first byte (a protected DACL at creation on Windows), then swapped in whole.
    permaura_core::replace_secret_file(path, rendered.as_bytes())
        .and_then(|()| permaura_credential_store::restrict_to_owner(path))
        .map_err(|e| format!("writing {} failed: {e}", path.display()))
}

/// Write the owner this gateway accepts tokens for into the config file at `path`, leaving every other key and comment as the operator left them: the re-pin a check-in brings has to survive a restart. Written and protected the way [`write_announce`] writes, since the same file holds the announce secret.
///
/// `replaces_env` is the environment's own `PERMAURA_OWNER_SUB` when it sets one, recorded so the new owner outranks it at the next boot; `None` removes any earlier record.
pub fn write_owner_sub(path: &Path, owner_sub: &str, replaces_env: Option<&str>) -> Result<(), String> {
    use toml_edit::{value, DocumentMut};

    let _edit = CONFIG_EDIT.lock().unwrap_or_else(|e| e.into_inner());
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(format!("reading {} failed: {e}", path.display())),
    };
    let mut doc = existing
        .parse::<DocumentMut>()
        .map_err(|e| format!("{} is not valid config: {e}", path.display()))?;
    doc["owner_sub"] = value(owner_sub);
    match replaces_env {
        Some(replaced) => doc["owner_sub_replaces_env"] = value(replaced),
        None => {
            doc.remove("owner_sub_replaces_env");
        }
    }
    let rendered = doc.to_string();
    toml::from_str::<GatewayConfig>(&rendered)
        .map_err(|e| format!("{} would not be valid config: {e}", path.display()))?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("creating {} failed: {e}", dir.display()))?;
    }
    permaura_core::replace_secret_file(path, rendered.as_bytes())
        .and_then(|()| permaura_credential_store::restrict_to_owner(path))
        .map_err(|e| format!("writing {} failed: {e}", path.display()))
}

/// Load the config from its default location and apply it, logging what it did.
///
/// Every failure here is fatal by design. The alternative (carry on without the file) produces a
/// gateway that is up, healthy, and quietly not the gateway that was configured: bound to loopback,
/// resource server off, remote agents refused. That is far worse to diagnose than a refusal at boot
/// which names the file and the problem.
pub fn load_and_apply() -> Result<(), String> {
    let Some(path) = GatewayConfig::default_path() else {
        return Ok(());
    };
    let Some((config, unknown)) = GatewayConfig::load_reporting_unknown(&path)? else {
        return Ok(());
    };
    if !unknown.is_empty() {
        let _ = UNKNOWN_IN_FILE.set(unknown.clone());
        // Loud, and not fatal: these are keys a newer Permaura wrote. Everything this binary does
        // understand has still been applied.
        tracing::warn!(
            path = %path.display(),
            keys = unknown.join(", "),
            "config file holds keys this gateway does not know, probably written by a newer version; they were skipped and the rest applied"
        );
    }
    let _ = ENVIRONMENT_OWNER_SUB.set(std::env::var(OWNER_SUB_ENV).ok().filter(|v| !v.trim().is_empty()));
    let applied = config.apply();
    let _ = APPLIED_FROM_FILE.set(applied.clone());
    if applied.contains(&OWNER_SUB_ENV) && environment_owner_sub().is_some() {
        tracing::warn!(
            path = %path.display(),
            "PERMAURA_OWNER_SUB in this gateway's environment still names the owner before the last hand-over, so the owner permaura.com named since, kept in the config file, is used; set PERMAURA_OWNER_SUB to the new owner where it is set (for a VPS, /etc/permaura/gateway.env)"
        );
    }
    // The environment is one link and outranks the file, so the file's list is only consulted when it
    // named none. `Config::new` drops anything malformed rather than announcing with it.
    if crate::announce::Config::from_env().is_none() {
        let links: Vec<crate::announce::Config> = config
            .announce_links()
            .iter()
            .filter_map(|l| crate::announce::Config::new(&l.gateway_id, &l.announce_secret))
            .collect();
        let _ = BOOT_LINKS.set(links);
    }
    if applied.is_empty() {
        tracing::info!(path = %path.display(), "config file read; the environment already set every value in it");
    } else {
        tracing::info!(path = %path.display(), applied = applied.join(", "), "config file applied");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(name: &str, body: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "permaura-cfg-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let missing = std::env::temp_dir().join("permaura-cfg-definitely-absent/config.toml");
        assert_eq!(GatewayConfig::load_from(&missing).unwrap(), None);
    }

    #[test]
    fn the_settings_a_self_hosted_gateway_needs_round_trip() {
        let p = write(
            "ok.toml",
            r#"
addr = "0.0.0.0:7376"
public_url = "https://gw.example.com"
owner_sub = "user_123"
allowed_hosts = ["gw.example.com", "gw.internal:7376"]
"#,
        );
        let c = GatewayConfig::load_from(&p).unwrap().unwrap();
        assert_eq!(c.addr.as_deref(), Some("0.0.0.0:7376"));
        assert_eq!(c.public_url.as_deref(), Some("https://gw.example.com"));
        assert_eq!(c.owner_sub.as_deref(), Some("user_123"));
        assert_eq!(c.allowed_hosts.unwrap().len(), 2);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// Posture must not be settable here. `main.rs` makes `--mock`/`--demo` CLI-only so that no
    /// install path can hand an end user canned transports without saying so; a config file is the
    /// most invisible possible way to do exactly that. Rejected, not ignored: a silently dropped
    /// `mock = true` would leave someone believing they had turned something off.
    #[test]
    fn posture_cannot_be_set_from_the_config_file() {
        for body in ["mock = true", "demo = true"] {
            let p = write("posture.toml", body);
            let err = GatewayConfig::load_from(&p)
                .expect_err("posture in a config file must be refused, not ignored");
            assert!(err.contains("not valid config"), "unexpected: {err}");
            std::fs::remove_dir_all(p.parent().unwrap()).ok();
        }
    }

    /// The KEK has a custody ladder precisely so it is not sitting in a readable file in the
    /// Permaura home. A `vault_passphrase` key would be that file. The *path* form stays allowed.
    #[test]
    fn the_vault_key_itself_cannot_be_set_from_the_config_file() {
        let p = write("secret.toml", r#"vault_passphrase = "hunter2""#);
        let err = GatewayConfig::load_from(&p).expect_err("an inline vault key must be refused");
        assert!(err.contains("not valid config"), "unexpected: {err}");

        let p2 = write("secret-path.toml", r#"vault_passphrase_file = "/run/secrets/kek""#);
        let c = GatewayConfig::load_from(&p2).unwrap().unwrap();
        assert_eq!(c.vault_passphrase_file.as_deref(), Some("/run/secrets/kek"));
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// A typo must not read as "unset". Left to serde's default this would parse fine, apply
    /// nothing, and leave the gateway on loopback with its resource server off and no complaint:
    /// the exact silent failure the file exists to end.
    #[test]
    fn a_misspelled_key_is_refused_rather_than_silently_dropped() {
        let p = write("typo.toml", r#"public_utl = "https://gw.example.com""#);
        let err = GatewayConfig::load_from(&p).expect_err("a typo must not parse");
        assert!(err.contains("not valid config"), "unexpected: {err}");
        assert!(err.contains("did you mean `public_url`"), "the message must name the real key: {err}");
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// The bug this pair of tests exists for: a 1.3.26 gateway wrote `[[announce]]` into the home a
    /// 1.3.17 binary shared, and that binary rejected the WHOLE file. The CLI then ran with every
    /// setting dropped and a gateway refused to boot. A key from the future is ordinary, because the
    /// product writes this file as well as the operator.
    #[test]
    fn a_key_from_a_newer_version_is_skipped_and_the_rest_of_the_file_still_applies() {
        let p = write(
            "future.toml",
            "addr = \"0.0.0.0:7376\"\nstore_path = \"/var/lib/permaura/gateway.db\"\n\n[[flywheel]]\nwhat = \"a thing this version never heard of\"\n",
        );
        let (config, unknown) = GatewayConfig::load_reporting_unknown(&p)
            .expect("a key from the future is not an error")
            .expect("the file exists");
        assert_eq!(config.addr.as_deref(), Some("0.0.0.0:7376"), "the settings it understands still apply");
        assert_eq!(config.store_path.as_deref(), Some("/var/lib/permaura/gateway.db"));
        assert_eq!(unknown, vec!["flywheel".to_string()], "and it says what it skipped");
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// The real shape of it, verbatim from a real machine.
    #[test]
    fn the_announce_table_an_older_binary_met_no_longer_costs_it_the_file() {
        let p = write(
            "announce-only.toml",
            "[[announce]]\ngateway_id = \"gw_synthetic\"\nannounce_secret = \"gwa_synthetic\"\n",
        );
        let (config, unknown) = GatewayConfig::load_reporting_unknown(&p).unwrap().unwrap();
        assert!(unknown.is_empty(), "this binary knows announce: {unknown:?}");
        assert_eq!(config.announce_links().len(), 1);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// A field missing from `KNOWN_KEYS` would be stripped before the strict parse and read as unset,
    /// which is the very failure this file exists to end. Every key round-trips instead.
    #[test]
    fn every_field_is_a_known_key() {
        let body = r#"
addr = "127.0.0.1:7376"
public_url = "https://gw.example.com"
owner_sub = "user_owner"
owner_sub_replaces_env = "user_before"
as_issuer = "https://permaura.com/api/auth"
as_jwks = "https://permaura.com/api/auth/jwks"
allowed_hosts = ["gw.example.com"]
store_path = "/tmp/store.db"
vault_passphrase_file = "/run/secrets/kek"
vault_custody = "file"
webhook_url = "https://hooks.example.com/permaura"
announce_secret = "gwa_synthetic"
gateway_id = "gw_synthetic"

[[announce]]
gateway_id = "gw_synthetic"
announce_secret = "gwa_synthetic"
"#;
        let p = write("all-keys.toml", body);
        let (config, unknown) = GatewayConfig::load_reporting_unknown(&p).unwrap().unwrap();
        assert!(unknown.is_empty(), "a real field read as unknown: {unknown:?}");
        assert_eq!(config.addr.as_deref(), Some("127.0.0.1:7376"));
        assert_eq!(config.public_url.as_deref(), Some("https://gw.example.com"));
        assert_eq!(config.owner_sub.as_deref(), Some("user_owner"));
        assert_eq!(config.owner_sub_replaces_env.as_deref(), Some("user_before"));
        assert_eq!(config.as_issuer.as_deref(), Some("https://permaura.com/api/auth"));
        assert_eq!(config.as_jwks.as_deref(), Some("https://permaura.com/api/auth/jwks"));
        assert_eq!(config.store_path.as_deref(), Some("/tmp/store.db"));
        assert_eq!(config.vault_passphrase_file.as_deref(), Some("/run/secrets/kek"));
        assert_eq!(config.webhook_url.as_deref(), Some("https://hooks.example.com/permaura"));
        assert_eq!(config.announce_links().len(), 1);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// The environment outranks the file: a supervisor that injects a value must not be overridden
    /// by a config file left on the box. Drives `apply` directly with a key nothing else uses.
    ///
    /// The one exception is an owner a check-in re-pin wrote over exactly the environment's value, with no app supervising the gateway.
    #[test]
    fn the_environment_outranks_the_file() {
        std::env::set_var("PERMAURA_OWNER_SUB", "from-the-supervisor");
        let applied = GatewayConfig {
            owner_sub: Some("from-the-file".into()),
            ..Default::default()
        }
        .apply();
        assert!(!applied.contains(&"PERMAURA_OWNER_SUB"), "the file must not overwrite the env");
        assert_eq!(std::env::var("PERMAURA_OWNER_SUB").unwrap(), "from-the-supervisor");

        let re_pinned = GatewayConfig {
            owner_sub: Some("user_new".into()),
            owner_sub_replaces_env: Some("from-the-supervisor".into()),
            ..Default::default()
        };
        std::env::set_var("PERMAURA_SUPERVISED_BY_APP", "1");
        assert!(!re_pinned.apply().contains(&"PERMAURA_OWNER_SUB"), "a supervising app's pin is never outranked");
        assert_eq!(std::env::var("PERMAURA_OWNER_SUB").unwrap(), "from-the-supervisor");
        std::env::remove_var("PERMAURA_SUPERVISED_BY_APP");
        assert!(re_pinned.apply().contains(&"PERMAURA_OWNER_SUB"), "a VPS's gateway.env line the re-pin replaced is");
        assert_eq!(std::env::var("PERMAURA_OWNER_SUB").unwrap(), "user_new");
        std::env::remove_var("PERMAURA_OWNER_SUB");
    }

    /// The re-pinned owner outranks only the exact environment value it was written over, never under a supervising app, and the record is written beside `owner_sub` and dropped when the environment sets nothing.
    #[test]
    fn a_re_pinned_owner_outranks_only_the_environment_value_it_replaced() {
        let re_pinned = GatewayConfig {
            owner_sub: Some("user_new".into()),
            owner_sub_replaces_env: Some("user_old".into()),
            ..Default::default()
        };
        assert!(re_pinned.owner_outranks_environment(Some("user_old"), false));
        assert!(re_pinned.owner_outranks_environment(Some(" user_old "), false));
        assert!(!re_pinned.owner_outranks_environment(Some("user_old"), true), "a supervising app's pin");
        assert!(!re_pinned.owner_outranks_environment(Some("user_chosen"), false), "an environment the operator changed since");
        assert!(!re_pinned.owner_outranks_environment(None, false));
        let unrecorded = GatewayConfig { owner_sub: Some("user_new".into()), ..Default::default() };
        assert!(!unrecorded.owner_outranks_environment(Some("user_old"), false), "an owner_sub the operator wrote by hand");
        let emptied = GatewayConfig { owner_sub: Some(" ".into()), owner_sub_replaces_env: Some("user_old".into()), ..Default::default() };
        assert!(!emptied.owner_outranks_environment(Some("user_old"), false));

        let p = write("replaces.toml", "# vps\npublic_url = \"https://gw.acme.example\"\n");
        write_owner_sub(&p, "user_new", Some("user_old")).unwrap();
        let c = GatewayConfig::load_from(&p).unwrap().unwrap();
        assert_eq!((c.owner_sub.as_deref(), c.owner_sub_replaces_env.as_deref()), (Some("user_new"), Some("user_old")));
        assert!(std::fs::read_to_string(&p).unwrap().contains("# vps"));
        write_owner_sub(&p, "user_newer", None).unwrap();
        let c = GatewayConfig::load_from(&p).unwrap().unwrap();
        assert_eq!((c.owner_sub.as_deref(), c.owner_sub_replaces_env.as_deref()), (Some("user_newer"), None));
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// The 1.3.25 single form is what still travels through the environment, so both halves have to
    /// become the variables [`crate::announce::Config::from_env`] reads.
    #[test]
    fn the_announce_credentials_are_read_from_the_file_as_a_pair() {
        let p = write(
            "announce.toml",
            r#"
gateway_id = "gw_abc123"
announce_secret = "gwa_0123456789abcdefghijklmnopqrstuvwxyzABCD"
"#,
        );
        let c = GatewayConfig::load_from(&p).unwrap().unwrap();
        assert_eq!(c.gateway_id.as_deref(), Some("gw_abc123"));
        let pairs = c.env_pairs();
        let var = |key: &str| pairs.iter().find(|(k, _)| *k == key).and_then(|(_, v)| v.clone());
        assert_eq!(var("PERMAURA_GATEWAY_ID").as_deref(), Some("gw_abc123"));
        assert_eq!(
            var("PERMAURA_ANNOUNCE_SECRET").as_deref(),
            Some("gwa_0123456789abcdefghijklmnopqrstuvwxyzABCD")
        );
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// The writer edits a file the operator owns and has commented, so it must touch only its own
    /// keys, leave something this gateway can boot from, and be able to take them out again.
    #[test]
    fn announce_links_are_written_beside_the_operators_settings_and_removed_cleanly() {
        let p = write(
            "writer.toml",
            "# my box\naddr = \"0.0.0.0:7376\" # behind caddy\nwebhook_url = \"https://ntfy.sh/x\"\n",
        );
        let link = |id: &str, secret: &str| AnnounceLink {
            gateway_id: id.into(),
            announce_secret: secret.into(),
        };
        write_announce(&p, &[link("gw_first", "gwa_first_secret_first_secret_first_secret")]).unwrap();
        write_announce(
            &p,
            &[
                link("gw_first", "gwa_rotated_secret_rotated_secret_rotated"),
                link("gw_second", "gwa_second_secret_second_secret_second_x"),
            ],
        )
        .unwrap();

        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(raw.contains("# my box") && raw.contains("# behind caddy"), "comments lost: {raw}");
        assert!(!raw.contains("gwa_first_secret"), "a rotation left the old value");
        let c = GatewayConfig::load_from(&p).unwrap().unwrap();
        assert_eq!(c.addr.as_deref(), Some("0.0.0.0:7376"));
        assert_eq!(c.webhook_url.as_deref(), Some("https://ntfy.sh/x"));
        let links = c.announce_links();
        assert_eq!(links.len(), 2);
        assert_eq!(links[0].gateway_id, "gw_first");
        assert_eq!(links[1].announce_secret, "gwa_second_secret_second_secret_second_x");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "a file holding a secret must be owner-only");
        }

        write_announce(&p, &[]).unwrap();
        let c = GatewayConfig::load_from(&p).unwrap().unwrap();
        assert!(c.announce_links().is_empty());
        assert_eq!(c.addr.as_deref(), Some("0.0.0.0:7376"));
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// The owner a check-in names replaces `owner_sub` and nothing else, in a file with the other remote-access keys and in one that has none yet.
    #[test]
    fn the_owner_a_check_in_names_is_written_beside_the_other_remote_access_keys() {
        let p = write(
            "owner.toml",
            "# my vps\npublic_url = \"https://acme.permaura.app\" # managed\nowner_sub = \"user_old\"\n\n[[announce]]\ngateway_id = \"gw_one\"\nannounce_secret = \"gwa_0123456789abcdefghijklmnopqrstuv\"\n",
        );
        write_owner_sub(&p, "user_new", None).unwrap();
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(raw.contains("# my vps") && raw.contains("# managed"), "comments lost: {raw}");
        assert!(!raw.contains("user_old"));
        let c = GatewayConfig::load_from(&p).unwrap().unwrap();
        assert_eq!(c.owner_sub.as_deref(), Some("user_new"));
        assert_eq!(c.public_url.as_deref(), Some("https://acme.permaura.app"));
        assert_eq!(c.announce_links().len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        }

        let absent = p.parent().unwrap().join("fresh.toml");
        write_owner_sub(&absent, "user_new", None).unwrap();
        assert_eq!(GatewayConfig::load_from(&absent).unwrap().unwrap().owner_sub.as_deref(), Some("user_new"));
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// A check-in's owner re-pin and a `PUT /v1/announce` each read, edit and write the whole file. Racing, either could read before the other wrote and put back what the other changed, losing a link or the new owner at the next restart. Run side by side many times, both survive every time.
    #[test]
    fn an_owner_write_and_a_links_write_side_by_side_both_land() {
        let p = write("race.toml", "public_url = \"https://acme.permaura.app\"\nowner_sub = \"user_old\"\n");
        for round in 0..40 {
            let owner = format!("user_round{round}");
            let links: Vec<AnnounceLink> = (0..=round % 3)
                .map(|n| AnnounceLink {
                    gateway_id: format!("gw_{round}_{n}"),
                    announce_secret: format!("gwa_{round:02}{n}0123456789abcdefghijklmnopqrstuvwxyz"),
                })
                .collect();
            std::thread::scope(|scope| {
                scope.spawn(|| write_owner_sub(&p, &owner, None).unwrap());
                scope.spawn(|| write_announce(&p, &links).unwrap());
            });
            let c = GatewayConfig::load_from(&p).unwrap().unwrap();
            assert_eq!(c.owner_sub.as_deref(), Some(owner.as_str()), "round {round}: the owner was lost");
            assert_eq!(c.announce_links().len(), links.len(), "round {round}: a link was lost");
        }
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// A file written by gateway 1.3.25 states its one link in two top-level keys. It has to keep
    /// working, and the next write has to replace it rather than leave the file saying it twice.
    #[test]
    fn the_single_link_form_from_1_3_25_still_reads_and_is_migrated_on_write() {
        let p = write(
            "legacy.toml",
            "gateway_id = \"gw_old\"\nannounce_secret = \"gwa_legacy_secret_legacy_secret_legacyy\"\n",
        );
        let c = GatewayConfig::load_from(&p).unwrap().unwrap();
        let links = c.announce_links();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].gateway_id, "gw_old");

        write_announce(&p, &links).unwrap();
        let raw = std::fs::read_to_string(&p).unwrap();
        assert!(raw.contains("[[announce]]"), "the list form is what a write leaves: {raw}");
        assert!(!raw.starts_with("gateway_id"), "the old top-level key survived: {raw}");
        let after = GatewayConfig::load_from(&p).unwrap().unwrap();
        assert_eq!(after.announce_links(), links);
        assert_eq!(after.gateway_id, None);
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    /// A file that does not parse is left alone rather than overwritten with only the two new keys,
    /// which would silently discard whatever the operator had in it.
    #[test]
    fn an_unreadable_file_is_refused_rather_than_replaced() {
        let p = write("broken.toml", "addr = \"unterminated\n");
        let err = write_announce(
            &p,
            &[AnnounceLink {
                gateway_id: "gw_1".into(),
                announce_secret: "gwa_secret_secret_secret_secret_secret_x".into(),
            }],
        )
        .expect_err("a broken file must not be rewritten");
        assert!(err.contains("not valid config"), "unexpected: {err}");
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "addr = \"unterminated\n");
        std::fs::remove_dir_all(p.parent().unwrap()).ok();
    }

    #[test]
    fn a_missing_file_is_created_holding_only_the_credentials() {
        let dir = std::env::temp_dir().join(format!("permaura-cfg-new-{}", std::process::id()));
        let p = dir.join("config.toml");
        write_announce(
            &p,
            &[AnnounceLink {
                gateway_id: "gw_1".into(),
                announce_secret: "gwa_secret_secret_secret_secret_secret_x".into(),
            }],
        )
        .unwrap();
        let c = GatewayConfig::load_from(&p).unwrap().unwrap();
        assert_eq!(c.announce_links()[0].gateway_id, "gw_1");
        assert_eq!(c.addr, None);
        std::fs::remove_dir_all(dir).ok();
    }

    /// ...and fills in what the environment left unset, which is the whole point.
    #[test]
    fn the_file_fills_in_what_the_environment_did_not_set() {
        std::env::remove_var("PERMAURA_AS_JWKS");
        let applied = GatewayConfig {
            as_jwks: Some("https://example.test/jwks".into()),
            ..Default::default()
        }
        .apply();
        assert!(applied.contains(&"PERMAURA_AS_JWKS"));
        assert_eq!(std::env::var("PERMAURA_AS_JWKS").unwrap(), "https://example.test/jwks");
        std::env::remove_var("PERMAURA_AS_JWKS");
    }
}
