//! Schema-version gate and ordered migration runner for the SQLite store.
//!
//! The desktop app auto-swaps the gateway binary under users (binupdate), so a new binary
//! routinely opens a `gateway.db` written by an older one, and after a rollback an older
//! binary can meet a newer DB. Before this gate the schema was `CREATE TABLE IF NOT EXISTS`
//! on every boot and every change had to stay serde-additive by convention. Now the DB
//! carries its schema version and boot runs the pending steps in order, each in its own
//! transaction. A DB stamped *newer* than the binary understands is refused outright: fail
//! closed beats guessing at a schema from the future.
//!
//! Adding a migration means appending a step at the next version to [`MIGRATIONS`] and bumping
//! [`SCHEMA_VERSION`]; a test asserts the list ends there.
//!
//! Steps must be idempotent-safe to retry (a failed step rolls back and re-runs on next boot)
//! and may rewrite the JSON blobs freely: the whole point is that non-additive serde changes
//! get an explicit upgrade path instead of breaking installs.
//!
//! The version is stamped in `PRAGMA user_version`. The hosted worker runs this same store, kept
//! durable by snapshotting to object storage, so it migrates through exactly this path.

#[cfg(feature = "sqlite")]
use rusqlite::Connection;

use crate::error::GatewayError;

/// The schema version this binary writes. Must equal the last entry of [`MIGRATIONS`] (enforced by
/// test). A fresh DB is created directly at this version; `0` means a DB from before the gate
/// existed.
pub const SCHEMA_VERSION: i32 = 9;

/// The new column and JSON for one existing session row, or `None` when it is already done.
///
/// Idempotent on the row rather than on the version stamp, so a half-finished run and a re-run both
/// land in the same place: a row is done when its JSON carries no bearer, which is what
/// `session_at_rest` leaves behind.
pub(crate) fn rehash_session_row(stored: &str, data: &str) -> Option<(String, String)> {
    let mut session: crate::store::Session = serde_json::from_str(data).ok()?;
    if session.token.starts_with(crate::store::SESSION_HASH_PREFIX) {
        return None;
    }
    let hash = crate::store::session_token_hash(&session.token);
    // Recomputed from the JSON, not the column: an earlier run may have stopped between the two.
    let _ = stored;
    session.token = hash.clone();
    let scrubbed = serde_json::to_string(&session).ok()?;
    Some((hash, scrubbed))
}

/// The SQLite half of the same rewrite.
fn hash_session_tokens_sqlite(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let rows: Vec<(String, String, String)> = {
        let mut stmt = conn.prepare("SELECT id, token, data FROM sessions")?;
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        mapped.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (id, stored, data) in rows {
        let Some((hash, scrubbed)) = rehash_session_row(&stored, &data) else {
            continue;
        };
        conn.execute(
            "UPDATE sessions SET token = ?1, data = ?2 WHERE id = ?3",
            rusqlite::params![hash, scrubbed, id],
        )?;
    }
    Ok(())
}

/// The new key and JSON for one existing enrolment code row, or `None` when it is already done. Decided by the JSON, as [`rehash_session_row`] is, so a re-run leaves a rewritten row alone.
pub(crate) fn rehash_enrolment_code_row(data: &str) -> Option<(String, String)> {
    let code: crate::store::EnrolmentCode = serde_json::from_str(data).ok()?;
    if code.code.starts_with(crate::store::SESSION_HASH_PREFIX) {
        return None;
    }
    let code = crate::store::enrolment_code_at_rest(&code);
    let scrubbed = serde_json::to_string(&code).ok()?;
    Some((code.code, scrubbed))
}

/// v9: enrolment codes keyed by their digest, so a redeemed code (the bearer of the session it opened) is no longer readable from the store.
fn hash_enrolment_codes_sqlite(conn: &rusqlite::Connection) -> rusqlite::Result<()> {
    let rows: Vec<(String, String)> = {
        let mut stmt = conn.prepare("SELECT code, data FROM enrolment_codes")?;
        let mapped = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        mapped.collect::<rusqlite::Result<Vec<_>>>()?
    };
    for (stored, data) in rows {
        let Some((hash, scrubbed)) = rehash_enrolment_code_row(&data) else {
            continue;
        };
        conn.execute(
            "UPDATE enrolment_codes SET code = ?1, data = ?2 WHERE code = ?3",
            rusqlite::params![hash, scrubbed, stored],
        )?;
    }
    Ok(())
}

/// The opening words of the "this store was written by a newer gateway" refusal. Exported because
/// another repo matches on them: the desktop supervisor (`src-tauri/src/supervisor.rs`) scans a
/// crashed gateway's own output for this substring to recognise a failure that no restart can fix.
/// That substring is the only signal binaries ALREADY IN THE FIELD give it (the 1.1.0 sidecar that
/// first hit this predates [`EXIT_STORE_SCHEMA_TOO_NEW`]), so the coupling is real whether or not it
/// is written down. Reword the advice that follows freely; changing these first words silently
/// turns a terminal failure back into an infinite respawn loop over there, which is why a test pins
/// them.
pub const SCHEMA_TOO_NEW_PREFIX: &str = "gateway store is schema v";

/// The exit code a gateway uses when it refuses to open a store written by a newer binary, distinct
/// from the generic `1` so a supervisor can stop retrying on the code alone without reading any
/// text. The desktop supervisor pins the same number; changing it needs both repos.
pub const EXIT_STORE_SCHEMA_TOO_NEW: i32 = 78;

/// The exit code a worker uses when object storage tells it another instance owns the store. Not a
/// failure to retry in place: the instance is stale by definition, and Cloud Run's replacement boots
/// and restores the newer snapshot. Kept beside the schema code so both store exits are one lookup.
pub const EXIT_STORE_STALE: i32 = 75;

/// The exit code `permaura start` uses when another live process holds the self-run store: for the
/// whole of [`crate::store::lock::STORE_LOCK_WAIT`]; at once when that process is this home's gateway
/// already serving the address this start would bind; or, in a running gateway, when an audit append
/// meets a seq another writer already recorded. Retrying at once meets the same holder; a supervisor
/// can tell it from a crash by the code alone.
pub const EXIT_STORE_HELD: i32 = 73;

/// The exit code `permaura start` uses when the store holds a signed audit chain and its
/// `gateway.db.auditkey` is gone. No restart fixes it: the owner restores the key file, or runs
/// `permaura audit rekey --yes`. A supervisor can tell it from a crash by the code alone.
pub const EXIT_AUDIT_KEY_MISSING: i32 = 74;

/// Compose the refusal, so the two stores cannot drift apart on the part another process matches.
/// `advice` is per-store and free to say whatever suits that deployment; everything before it is
/// the machine-readable contract.
pub(crate) fn schema_too_new(current: i32, target: i32, advice: &str) -> String {
    format!(
        "{SCHEMA_TOO_NEW_PREFIX}{current} but this binary only supports up to v{target}. Refusing to open a store written by a newer gateway. {advice}"
    )
}

/// What to tell someone whose *local* store is ahead of this binary. The usual cause is two gateway
/// versions sharing one machine's store rather than the rollback the wording used to guess at: the
/// desktop app runs the gateway bundled inside the `.app` while `npx -y permaura start` installs a
/// separate one under `~/.permaura/bin`, and both open the same file.
///
/// The restore hint is looked up rather than composed, because a composed one was wrong twice over.
/// A backup is named for the version the store was at BEFORE the migration that wrote it, which is
/// not this binary's ceiling; and it exists only if a migration actually ran here, which it need not
/// have (a store created fresh by the newer gateway has no earlier state and no backup). Sending
/// someone to restore a file that was never written is worse than saying nothing.
#[cfg(feature = "sqlite")]
fn sqlite_schema_advice(db_path: Option<&str>, target: i32) -> String {
    let Some(path) = db_path else {
        return "Run or install the newest gateway you have.".to_string();
    };
    // A self-run store has no record outside itself (no checkpoint, no reconciliation), so whatever a restore drops, revocations included, nothing brings back or flags.
    const AFTER_RESTORE: &str = " That includes revocations: a session or device key revoked, or a recovery code spent, since then works again, so after restoring revoke every session and agent you no longer trust, and check the paired devices, before anything else connects.";
    let restore = match restorable_backup(path, target) {
        // The exact pre-migration copy: a store at this binary's ceiling, which it opens, losing everything the newer gateway wrote since the migration.
        Some((v, backup)) if v == target => format!(
            " To go back instead, restore {backup}, the copy saved before this store was migrated past what this gateway understands. Restoring it gives up everything written since that migration.{AFTER_RESTORE}"
        ),
        // An older copy. It still opens, since this binary migrates it forward, but describing it
        // with the sentence above would claim it was saved at a moment it was not, and quietly cost
        // every change written since. Observed: a store that reached v4 three weeks earlier was
        // offered `backup-v3` as though it were the copy from just before the v5 migration.
        Some((v, backup)) => format!(
            " There is no copy of it from just before that migration. The newest one here is {backup}, saved while the store was still at v{v}, so restoring it gives up everything written since.{AFTER_RESTORE}"
        ),
        None => " There is no pre-migration copy of it here, so going back is not an option on this machine.".to_string(),
    };
    format!(
        "Usually two gateway versions share one store on this machine: the Permaura app's bundled gateway and the `npx -y permaura start` install both open {path}. A downgraded gateway does it too. Run or install the newest gateway you have and it will open this store.{restore}"
    )
}

/// The newest pre-migration copy of `db_path` that THIS binary could still open, if one is there.
///
/// Backups are written as `{db_path}.backup-v{version-before-the-migration}`, so the directory is
/// scanned rather than a name guessed. Anything stamped above this binary's ceiling is skipped: it
/// would refuse that copy for exactly the reason it refused the live store.
#[cfg(feature = "sqlite")]
fn restorable_backup(db_path: &str, target: i32) -> Option<(i32, String)> {
    let path = std::path::Path::new(db_path);
    let prefix = format!("{}.backup-v", path.file_name()?.to_str()?);
    let mut best: Option<(i32, std::path::PathBuf)> = None;
    for entry in std::fs::read_dir(path.parent()?).ok()?.flatten() {
        let name = entry.file_name();
        let Some(version) = name
            .to_str()
            .and_then(|n| n.strip_prefix(&prefix))
            .and_then(|v| v.parse::<i32>().ok())
        else {
            continue;
        };
        if version <= target && best.as_ref().is_none_or(|(best, _)| version > *best) {
            best = Some((version, entry.path()));
        }
    }
    best.map(|(v, p)| (v, p.to_string_lossy().into_owned()))
}

/// One ordered schema step. `up` receives a connection already inside the migration's
/// transaction; returning an error rolls the whole step back and leaves `user_version`
/// at the previous value.
#[cfg(feature = "sqlite")]
pub struct Migration {
    /// The `user_version` this step upgrades the DB *to*.
    pub version: i32,
    /// Short human label for logs and errors.
    pub description: &'static str,
    /// The step itself. Runs inside the migration's transaction.
    pub up: fn(&Connection) -> rusqlite::Result<()>,
}

/// v1: the pre-gate JSON-blob schema, verbatim. `IF NOT EXISTS` makes it double as the
/// adoption step for legacy DBs that already have these tables at `user_version = 0`.
#[cfg(feature = "sqlite")]
const BASELINE_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, token TEXT NOT NULL, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS connections (id TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS policies (id TEXT PRIMARY KEY, connection_id TEXT NOT NULL, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS grants (grant_id TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS secrets (id TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS capabilities (id TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS enrolment_codes (code TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS connector_manifests (id TEXT PRIMARY KEY, data TEXT NOT NULL);
    CREATE TABLE IF NOT EXISTS audit_events (seq INTEGER PRIMARY KEY, data TEXT NOT NULL);
"#;

/// v2: per-secret custody records, so which layer holds a secret is a store row an operator can
/// change at runtime rather than an environment variable that needs a redeploy.
#[cfg(feature = "sqlite")]
const SECRET_CUSTODY_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS secret_custody (secret_id TEXT PRIMARY KEY, data TEXT NOT NULL);
"#;

/// v3: a key/value table the hosted store has had since its baseline. SQLite needs it so the
/// dev-KEK re-seal sweep can record that it ran in the same place on both stores.
#[cfg(feature = "sqlite")]
const GATEWAY_META_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS gateway_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"#;

/// v4: the replay cache behind single-use tokens. Keyed on `(scope, jti)` so the *database* decides
/// which claim was first: a hosted worker can be several instances at once, and anything a process
/// holds in memory is single-use per instance rather than single-use. `expires_at_ms` exists only so
/// spent claims can be pruned once the token they guard is dead.
#[cfg(feature = "sqlite")]
const ONE_TIME_CLAIMS_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS one_time_claims (scope TEXT NOT NULL, jti TEXT NOT NULL, expires_at_ms INTEGER NOT NULL, PRIMARY KEY (scope, jti));
    CREATE INDEX IF NOT EXISTS idx_one_time_claims_exp ON one_time_claims(expires_at_ms);
"#;

/// v6: the audit boundary record, which states where the hot window starts.
///
/// `INSERT OR IGNORE` of the genesis boundary, which is what every store already means: base seq 0,
/// genesis hash, epoch 0, nothing archived. O(1) on purpose, because no row moves and nothing is
/// pruned here; the batched export that actually moves events belongs to the archive writer.
///
/// It is written unsigned, because the migration runs before the audit signing key has been
/// resolved (the key lives in `gateway_meta`, in a table a migration creates). Only the genesis
/// boundary may be unsigned, and the store seals it under its own key on the first open, so a
/// boundary that ever names a base is signed from the moment it names one.
#[cfg(feature = "sqlite")]
fn insert_genesis_audit_boundary(conn: &Connection) -> rusqlite::Result<()> {
    let value = serde_json::to_string(&permaura_core::audit::AuditBoundary::genesis())
        .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
    conn.execute(
        "INSERT OR IGNORE INTO gateway_meta (key, value) VALUES (?1, ?2)",
        rusqlite::params![crate::store::sqlite::AUDIT_BOUNDARY_META, value],
    )?;
    Ok(())
}

/// v7: the materialised grant budget counter.
///
/// `AuditUsage` was an authorization decision computed by scanning the audit history, so the first
/// prune would silently reset a spent `Period::Total` budget to zero used and widen a grant the
/// owner believes is exhausted. The counter has to exist, and be
/// correct, before anything can be pruned.
///
/// `period_start` is the charge's own millisecond rather than the start of a tumbling window, which
/// is what lets a read be identical to the scan it replaces rather than merely close: a grant's
/// window slides with the clock and its boundary falls wherever the read happens to land. A fold
/// past [`crate::store::GRANT_USAGE_DETAIL_MS`] keeps the table proportional to the live windows.
#[cfg(feature = "sqlite")]
const GRANT_USAGE_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS grant_usage (
      grant_id      TEXT NOT NULL,
      agent_id      TEXT NOT NULL,
      period_start  INTEGER NOT NULL,
      count         INTEGER NOT NULL,
      PRIMARY KEY (grant_id, agent_id, period_start)
    );
    CREATE INDEX IF NOT EXISTS idx_grant_usage_period ON grant_usage(period_start);
"#;

/// v8: the free-text explanation of a failed call, kept beside the audit chain rather than in it so it
/// can be purged and can age out. See [`crate::store::CallDiagnostic`].
#[cfg(feature = "sqlite")]
const CALL_DIAGNOSTICS_SQL: &str = r#"
    CREATE TABLE IF NOT EXISTS call_diagnostics (audit_seq INTEGER PRIMARY KEY, recorded_at INTEGER NOT NULL, data TEXT NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_call_diagnostics_recorded ON call_diagnostics(recorded_at);
"#;

/// How many audit rows the backfill reads at once.
///
/// Bounded because the store this runs against may hold a quarter of a million events and the whole
/// point of the archive is that a gateway never has to materialise all of them at once. The counts
/// it accumulates are proportional to the distinct `(grant, agent, millisecond)` triples, not to the
/// history, so the batch bounds the peak.
#[cfg(feature = "sqlite")]
const BACKFILL_BATCH: usize = 5_000;

/// v7: count every charge already in the chain, once, while the whole history is still present.
///
/// This is the only chance to do it cheaply. After the archive writer lands, a rebuild has to walk
/// object storage; before it lands, every event a `Period::Total` grant has ever been charged for is
/// still a row in this database.
#[cfg(feature = "sqlite")]
fn backfill_grant_usage(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(GRANT_USAGE_SQL)?;
    let mut after: i64 = -1;
    loop {
        let batch: Vec<(i64, String)> = {
            let mut stmt = conn.prepare(
                "SELECT seq, data FROM audit_events WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2",
            )?;
            let rows = stmt.query_map(rusqlite::params![after, BACKFILL_BATCH as i64], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        if batch.is_empty() {
            return Ok(());
        }
        for (seq, data) in &batch {
            after = *seq;
            let event: permaura_core::AuditEvent = serde_json::from_str(data).map_err(|e| {
                rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(format!(
                    "audit event {seq} is not readable, so the grant budget it charges cannot be counted: {e}"
                ))))
            })?;
            let Some(grant_id) = crate::store::charged_grant(&event) else { continue };
            crate::store::sqlite::file_grant_charge(
                conn,
                grant_id,
                crate::store::charge_agent(&event.payload),
                event.timestamp,
            )
            .map_err(|e| {
                rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::other(
                    e.to_string(),
                )))
            })?;
        }
    }
}

/// Every schema step ever shipped, strictly ascending by version. Append-only.
#[cfg(feature = "sqlite")]
pub const MIGRATIONS: &[Migration] = &[
    Migration {
        version: 1,
        description: "baseline JSON-blob schema",
        up: |conn| conn.execute_batch(BASELINE_SQL),
    },
    Migration {
        version: 2,
        description: "per-secret custody records",
        up: |conn| conn.execute_batch(SECRET_CUSTODY_SQL),
    },
    Migration {
        version: 3,
        description: "gateway meta table, for parity with the hosted store",
        up: |conn| conn.execute_batch(GATEWAY_META_SQL),
    },
    Migration {
        version: 4,
        description: "one-time claim table, so a single-use token cannot be replayed",
        up: |conn| conn.execute_batch(ONE_TIME_CLAIMS_SQL),
    },
    Migration {
        version: 5,
        description: "hash session bearers at rest, so a database read is no longer a bearer read",
        up: hash_session_tokens_sqlite,
    },
    Migration {
        version: 6,
        description: "audit boundary record, so the hot window can start somewhere other than seq 0",
        up: insert_genesis_audit_boundary,
    },
    Migration {
        version: 7,
        description: "materialised grant budget counter, so a prune cannot widen a spent grant",
        up: backfill_grant_usage,
    },
    Migration {
        version: 8,
        description: "call diagnostics, so a failed call's error text lives outside the signed chain",
        up: |conn| conn.execute_batch(CALL_DIAGNOSTICS_SQL),
    },
    Migration {
        version: 9,
        description: "hash enrolment codes at rest, so a redeemed code read from the store is not its session's bearer",
        up: hash_enrolment_codes_sqlite,
    },
];

#[cfg(feature = "sqlite")]
fn map<E: std::fmt::Display>(e: E) -> GatewayError {
    GatewayError::Internal(format!("sqlite migration error: {e}"))
}

/// Read the DB's stamped schema version.
#[cfg(feature = "sqlite")]
pub fn user_version(conn: &Connection) -> Result<i32, GatewayError> {
    conn.query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(map)
}

/// Bring the DB at `conn` up to [`SCHEMA_VERSION`]. `db_path` is the on-disk file for the
/// backup step: `None` for `:memory:` (nothing to back up). Once the store has been at
/// [`CODES_HASHED_AT`] for [`PRE_HASH_BACKUP_RETENTION`], the copies from before it are removed.
#[cfg(feature = "sqlite")]
pub fn run(conn: &Connection, db_path: Option<&str>) -> Result<(), GatewayError> {
    run_list(conn, MIGRATIONS, db_path)?;
    if let Some(path) = db_path {
        prune_pre_hash_backups(path, user_version(conn)?, std::time::SystemTime::now());
    }
    Ok(())
}

/// The first schema version whose store keeps no enrolment code in plaintext. Every pre-migration copy from below it does, and a redeemed code is still its agent's bearer.
pub const CODES_HASHED_AT: i32 = 9;

/// How long the copies from below [`CODES_HASHED_AT`] are kept once the store has reached it: the window in which going back to an older binary by restoring one is supported.
pub const PRE_HASH_BACKUP_RETENTION: std::time::Duration = std::time::Duration::from_secs(7 * 24 * 60 * 60);

/// Remove every `{db_path}.backup-v{n}` with `n` below [`CODES_HASHED_AT`] once the newest of them, the copy the migration that reached it wrote, is [`PRE_HASH_BACKUP_RETENTION`] old. Logs one line for each copy removed, and returns them.
#[cfg(feature = "sqlite")]
fn prune_pre_hash_backups(db_path: &str, version: i32, now: std::time::SystemTime) -> Vec<String> {
    if version < CODES_HASHED_AT {
        return Vec::new();
    }
    let path = std::path::Path::new(db_path);
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else { return Vec::new() };
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => std::path::Path::new("."),
    };
    let prefix = format!("{name}.backup-v");
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    let mut before: Vec<(i32, std::path::PathBuf)> = entries
        .flatten()
        .filter_map(|e| {
            let v = e.file_name().to_str()?.strip_prefix(&prefix)?.parse::<i32>().ok()?;
            (v < CODES_HASHED_AT).then(|| (v, e.path()))
        })
        .collect();
    let Some((_, newest)) = before.iter().max_by_key(|(v, _)| *v) else { return Vec::new() };
    let Ok(written) = std::fs::metadata(newest).and_then(|m| m.modified()) else { return Vec::new() };
    if now.duration_since(written).unwrap_or_default() < PRE_HASH_BACKUP_RETENTION {
        return Vec::new();
    }
    before.sort();
    let mut removed = Vec::new();
    for (from_version, backup) in before {
        let backup = backup.to_string_lossy().into_owned();
        match std::fs::remove_file(&backup) {
            Ok(()) => {
                tracing::info!(
                    backup = %backup,
                    from_version,
                    retention_days = PRE_HASH_BACKUP_RETENTION.as_secs() / 86_400,
                    "removed a store backup from before enrolment codes were hashed: it held them in plaintext, and the rollback window since the store reached schema v9 has passed"
                );
                removed.push(backup);
            }
            Err(e) => tracing::warn!(backup = %backup, error = %e, "could not remove a store backup that holds enrolment codes in plaintext"),
        }
    }
    removed
}

#[cfg(feature = "sqlite")]
fn run_list(conn: &Connection, migrations: &[Migration], db_path: Option<&str>) -> Result<(), GatewayError> {
    for pair in migrations.windows(2) {
        if pair[1].version <= pair[0].version {
            return Err(GatewayError::Internal(format!(
                "migration list is not strictly ascending (v{} then v{})",
                pair[0].version, pair[1].version
            )));
        }
    }
    let target = migrations.last().map(|m| m.version).unwrap_or(0);
    let current = user_version(conn)?;
    if current > target {
        return Err(GatewayError::SchemaTooNew(schema_too_new(
            current,
            target,
            &sqlite_schema_advice(db_path, target),
        )));
    }
    if current == target {
        return Ok(());
    }

    // Back the file up before the first write, but only when there is an existing schema to
    // lose. A fresh `Connection::open` file has no tables and backing it up would just shadow
    // the real pre-migration copy on a later upgrade.
    let mut backup: Option<String> = None;
    if let Some(path) = db_path {
        if has_tables(conn)? {
            let backup_path = format!("{path}.backup-v{current}");
            // An empty file is a copy that never started, not a pre-migration state worth keeping.
            if std::fs::metadata(&backup_path).is_ok_and(|m| m.len() == 0) {
                let _ = std::fs::remove_file(&backup_path);
            }
            if std::path::Path::new(&backup_path).exists() {
                // A copy from an earlier (failed) attempt IS the pristine pre-migration state:
                // the failed step rolled back, so the live DB still matches it. Keep it.
                tracing::warn!(backup = %backup_path, "pre-migration backup already exists: keeping it");
            } else {
                // Created empty and owner-only first, so the copy is never readable by anyone else, not even before the tightening below; `VACUUM INTO` writes into an empty file.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&backup_path).map_err(|e| {
                        GatewayError::Internal(format!("pre-migration backup to {backup_path} could not be created: {e}: not migrating without a backup"))
                    })?;
                }
                conn.execute("VACUUM INTO ?1", [&backup_path]).map_err(|e| {
                    let _ = std::fs::remove_file(&backup_path);
                    GatewayError::Internal(format!("pre-migration backup to {backup_path} failed: {e}: not migrating without a backup"))
                })?;
                tracing::info!(backup = %backup_path, from_version = current, "backed up gateway store before migration");
            }
            // `VACUUM INTO` creates the copy itself, so it lands at whatever the umask allows, 0644 on
            // a default install. The copy is a whole second store: the same sealed credentials, the same
            // KDF salt, the same audit chain. Leaving it world-readable would hand back exactly what
            // tightening the live store took away, and it would keep doing so for the life of the file.
            super::sqlite::restrict_to_owner(&backup_path);
            backup = Some(backup_path);
        }
    }

    for m in migrations.iter().filter(|m| m.version > current) {
        let tx = conn.unchecked_transaction().map_err(map)?;
        (m.up)(&tx).map_err(|e| {
            let note = backup.as_deref().map(|b| format!(": pre-migration backup at {b}")).unwrap_or_default();
            GatewayError::Internal(format!(
                "schema migration v{} ({}) failed and was rolled back: {e}{note}",
                m.version, m.description
            ))
        })?;
        tx.pragma_update(None, "user_version", m.version).map_err(map)?;
        tx.commit().map_err(map)?;
        tracing::info!(version = m.version, description = m.description, "applied gateway store migration");
    }
    Ok(())
}

#[cfg(feature = "sqlite")]
fn has_tables(conn: &Connection) -> Result<bool, GatewayError> {
    conn.query_row(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table')",
        [],
        |r| r.get(0),
    )
    .map_err(map)
}

#[cfg(all(test, feature = "sqlite"))]
mod tests {
    use super::*;

    /// A unique-per-test temp DB path, pre-cleaned along with its sidecars.
    fn temp_db(tag: &str) -> String {
        let path = std::env::temp_dir()
            .join(format!("permaura-mig-{tag}-{}.db", std::process::id()))
            .to_string_lossy()
            .into_owned();
        cleanup(&path);
        path
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}.auditkey"));
        // Up to and including the synthetic step the runner tests append, so a bumped
        // SCHEMA_VERSION does not start leaving backups behind in the temp dir.
        for v in 0..=SCHEMA_VERSION + 1 {
            let _ = std::fs::remove_file(format!("{path}.backup-v{v}"));
        }
    }

    fn table_exists(conn: &Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
            [name],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn migration_list_is_strictly_ascending_and_ends_at_schema_version() {
        assert!(!MIGRATIONS.is_empty());
        for pair in MIGRATIONS.windows(2) {
            assert!(pair[1].version > pair[0].version);
        }
        assert_eq!(MIGRATIONS.last().unwrap().version, SCHEMA_VERSION);
    }

    #[test]
    fn fresh_create_stamps_latest_version_and_rerun_is_a_noop_without_backup() {
        let path = temp_db("fresh");
        let conn = Connection::open(&path).unwrap();
        run(&conn, Some(&path)).unwrap();
        assert_eq!(user_version(&conn).unwrap(), SCHEMA_VERSION);
        assert!(table_exists(&conn, "agents"));
        assert!(!std::path::Path::new(&format!("{path}.backup-v0")).exists(), "fresh create must not back up an empty file");

        // Re-run (a normal reboot): no error, no version change, still no backup.
        run(&conn, Some(&path)).unwrap();
        assert_eq!(user_version(&conn).unwrap(), SCHEMA_VERSION);
        assert!(!std::path::Path::new(&format!("{path}.backup-v0")).exists());
        cleanup(&path);
    }

    #[test]
    fn legacy_v0_database_is_adopted_with_backup_and_data_intact() {
        let path = temp_db("legacy");
        // Simulate an install from before the gate: baseline tables, data, user_version 0.
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(BASELINE_SQL).unwrap();
            conn.execute(
                "INSERT INTO agents (id, data) VALUES ('codex-cli', '{\"id\":\"codex-cli\",\"name\":\"Codex CLI\"}')",
                [],
            )
            .unwrap();
            assert_eq!(user_version(&conn).unwrap(), 0);
        }

        // Open through the real store so the whole boot path (migrate → audit restore) runs.
        let store = crate::store::sqlite::SqliteStore::open(&path).unwrap();
        use crate::store::Store;
        assert!(store.get_agent("codex-cli").unwrap().is_some(), "legacy rows must survive adoption");
        drop(store);

        let conn = Connection::open(&path).unwrap();
        assert_eq!(user_version(&conn).unwrap(), SCHEMA_VERSION);
        assert!(std::path::Path::new(&format!("{path}.backup-v0")).exists(), "adopting a legacy DB must leave a backup");
        cleanup(&path);
    }

    /// The real list plus one synthetic step, so the runner's behaviour is exercised against
    /// whatever [`SCHEMA_VERSION`] currently is rather than a version baked into the test.
    fn with_extra_step(up: fn(&Connection) -> rusqlite::Result<()>) -> Vec<Migration> {
        let mut list: Vec<Migration> = MIGRATIONS.iter().map(Migration::clone_for_test).collect();
        list.push(Migration { version: SCHEMA_VERSION + 1, description: "test step", up });
        list
    }

    #[test]
    fn a_next_version_migration_applies_backs_up_and_reruns_as_noop() {
        let next = with_extra_step(|conn| {
            conn.execute_batch("CREATE TABLE widgets (id TEXT PRIMARY KEY, data TEXT NOT NULL)")
        });

        let path = temp_db("next");
        let conn = Connection::open(&path).unwrap();
        run(&conn, Some(&path)).unwrap();
        conn.execute("INSERT INTO agents (id, data) VALUES ('a1', '{}')", []).unwrap();

        run_list(&conn, &next, Some(&path)).unwrap();
        assert_eq!(user_version(&conn).unwrap(), SCHEMA_VERSION + 1);
        assert!(table_exists(&conn, "widgets"));
        let agents: i64 = conn.query_row("SELECT count(*) FROM agents", [], |r| r.get(0)).unwrap();
        assert_eq!(agents, 1, "existing rows must survive the upgrade");
        let backup = format!("{path}.backup-v{SCHEMA_VERSION}");
        assert!(std::path::Path::new(&backup).exists());

        // The backup is the pre-migration DB: the shipped version, no widgets, with the agent row.
        let bconn = Connection::open(&backup).unwrap();
        assert_eq!(user_version(&bconn).unwrap(), SCHEMA_VERSION);
        assert!(!table_exists(&bconn, "widgets"));

        run_list(&conn, &next, Some(&path)).unwrap();
        assert_eq!(user_version(&conn).unwrap(), SCHEMA_VERSION + 1);
        assert!(
            !std::path::Path::new(&format!("{path}.backup-v{}", SCHEMA_VERSION + 1)).exists(),
            "a no-op re-run must not create a backup"
        );
        cleanup(&path);
    }

    /// The pre-migration copy is a whole second store (same sealed credentials, same KDF salt, same
    /// audit chain), and `VACUUM INTO` creates it under the process umask, so it landed 0644 while the
    /// store it was copied from was being tightened to 0600 on every open.
    #[cfg(unix)]
    #[test]
    fn the_pre_migration_backup_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let mode = |p: &str| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;

        let next = with_extra_step(|conn| conn.execute_batch("CREATE TABLE widgets (id TEXT PRIMARY KEY)"));

        let path = temp_db("backup-mode");
        let conn = Connection::open(&path).unwrap();
        run(&conn, Some(&path)).unwrap();
        conn.execute("INSERT INTO agents (id, data) VALUES ('a1', '{}')", []).unwrap();

        run_list(&conn, &next, Some(&path)).unwrap();
        let backup = format!("{path}.backup-v{SCHEMA_VERSION}");
        assert_eq!(mode(&backup), 0o600, "a fresh pre-migration backup must be owner-only");

        // A leftover from an earlier attempt is kept rather than overwritten, so it has to be tightened
        // on the way past too: the stores already on disk were copied under the old behaviour and
        // nothing else ever comes back for them.
        std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o644)).unwrap();
        let further = with_extra_step(|conn| conn.execute_batch("CREATE TABLE gadgets (id TEXT PRIMARY KEY)"));
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "user_version", SCHEMA_VERSION).unwrap();
        run_list(&conn, &further, Some(&path)).unwrap();
        assert_eq!(mode(&backup), 0o600, "an existing backup must be tightened, not left as it was found");

        cleanup(&path);
    }

    fn age(path: &str, by: std::time::Duration) {
        let file = std::fs::File::options().write(true).open(path).unwrap();
        file.set_modified(std::time::SystemTime::now() - by).unwrap();
    }

    const DAY: std::time::Duration = std::time::Duration::from_secs(86_400);

    /// Every copy from before enrolment codes were hashed holds them in plaintext, and a redeemed code is its agent's bearer. Once the store has been at v9 for the retention window (measured from the copy the migration that reached it wrote), a boot removes them all and keeps every later copy.
    #[test]
    fn pre_hash_backups_are_removed_once_the_v9_store_is_seven_days_old() {
        assert_eq!(PRE_HASH_BACKUP_RETENTION, 7 * DAY);
        let path = temp_db("prune-pre-hash");
        let conn = Connection::open(&path).unwrap();
        run(&conn, Some(&path)).unwrap();
        for v in [4, CODES_HASHED_AT - 1, CODES_HASHED_AT] {
            std::fs::write(format!("{path}.backup-v{v}"), b"a store copy").unwrap();
        }
        let exists = |v: i32| std::path::Path::new(&format!("{path}.backup-v{v}")).exists();
        age(&format!("{path}.backup-v4"), 90 * DAY);

        age(&format!("{path}.backup-v{}", CODES_HASHED_AT - 1), 6 * DAY);
        run(&conn, Some(&path)).unwrap();
        assert!(exists(4) && exists(CODES_HASHED_AT - 1), "inside the window the rollback copies stay");
        assert!(
            prune_pre_hash_backups(&path, CODES_HASHED_AT - 1, std::time::SystemTime::now() + 30 * DAY).is_empty(),
            "a store below v9 still holds plaintext codes itself, so its copies are not the exposure"
        );

        age(&format!("{path}.backup-v{}", CODES_HASHED_AT - 1), 7 * DAY + std::time::Duration::from_secs(1));
        let logs = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || Writer(writer.clone()))
            .with_ansi(false)
            .finish();
        tracing::subscriber::with_default(subscriber, || run(&conn, Some(&path)).unwrap());
        assert!(!exists(4) && !exists(CODES_HASHED_AT - 1), "both pre-hash copies are gone");
        assert!(exists(CODES_HASHED_AT), "a copy from v9 on holds no plaintext code and stays");
        let text = String::from_utf8(logs.lock().unwrap().clone()).unwrap();
        assert_eq!(text.lines().filter(|l| l.contains("removed a store backup")).count(), 2, "one line per copy: {text}");
        cleanup(&path);
    }

    struct Writer(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Writer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The v9 migration's copy is owner-only from the moment it exists, and an empty leftover from a copy that never started is not kept as the pre-migration state.
    #[cfg(unix)]
    #[test]
    fn the_copy_before_hashing_is_written_owner_only_and_an_empty_leftover_is_redone() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_db("v8-backup");
        let conn = Connection::open(&path).unwrap();
        let before: Vec<Migration> = MIGRATIONS.iter().filter(|m| m.version < CODES_HASHED_AT).map(|m| m.clone_for_test()).collect();
        run_list(&conn, &before, Some(&path)).unwrap();
        conn.execute("INSERT INTO agents (id, data) VALUES ('a1', '{}')", []).unwrap();
        let backup = format!("{path}.backup-v{}", CODES_HASHED_AT - 1);
        std::fs::write(&backup, b"").unwrap();
        std::fs::set_permissions(&backup, std::fs::Permissions::from_mode(0o644)).unwrap();

        run(&conn, Some(&path)).unwrap();
        assert_eq!(user_version(&conn).unwrap(), SCHEMA_VERSION);
        assert_eq!(std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777, 0o600);
        let copy = Connection::open(&backup).unwrap();
        assert_eq!(user_version(&copy).unwrap(), CODES_HASHED_AT - 1, "the empty leftover was replaced by a real copy");
        let agents: i64 = copy.query_row("SELECT COUNT(*) FROM agents", [], |r| r.get(0)).unwrap();
        assert_eq!(agents, 1);
        cleanup(&path);
    }

    /// The custody table the router reads must actually exist on a fresh DB and after adopting a
    /// pre-gate one: a missing table would fail every custody lookup closed at runtime.
    #[test]
    fn the_secret_custody_table_exists_after_migrating_from_any_version() {
        let fresh = temp_db("custody-fresh");
        let conn = Connection::open(&fresh).unwrap();
        run(&conn, Some(&fresh)).unwrap();
        assert!(table_exists(&conn, "secret_custody"));
        cleanup(&fresh);

        let legacy = temp_db("custody-legacy");
        let conn = Connection::open(&legacy).unwrap();
        conn.execute_batch(BASELINE_SQL).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        run(&conn, Some(&legacy)).unwrap();
        assert!(table_exists(&conn, "secret_custody"));
        cleanup(&legacy);
    }

    /// The boundary row is what the audit chain's base is read out of, so a store that came from
    /// before it existed has to acquire one, and it has to say what that store already meant.
    #[test]
    fn the_audit_boundary_row_exists_after_migrating_from_any_version() {
        let genesis = serde_json::to_string(&permaura_core::audit::AuditBoundary::genesis()).unwrap();
        let read = |conn: &Connection| -> Option<String> {
            conn.query_row(
                "SELECT value FROM gateway_meta WHERE key = 'audit_boundary'",
                [],
                |r| r.get(0),
            )
            .ok()
        };

        let fresh = temp_db("boundary-fresh");
        let conn = Connection::open(&fresh).unwrap();
        run(&conn, Some(&fresh)).unwrap();
        assert_eq!(read(&conn).as_deref(), Some(genesis.as_str()));
        cleanup(&fresh);

        let legacy = temp_db("boundary-legacy");
        let conn = Connection::open(&legacy).unwrap();
        conn.execute_batch(BASELINE_SQL).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        run(&conn, Some(&legacy)).unwrap();
        assert_eq!(read(&conn).as_deref(), Some(genesis.as_str()));
        cleanup(&legacy);
    }

    /// The replay cache has to exist before the first pairing ticket is presented, on a fresh DB and
    /// on one adopted from any earlier version: a missing table would fail every claim closed, and
    /// closed here means no device can be paired at all.
    #[test]
    fn the_one_time_claims_table_exists_after_migrating_from_any_version() {
        let fresh = temp_db("claims-fresh");
        let conn = Connection::open(&fresh).unwrap();
        run(&conn, Some(&fresh)).unwrap();
        assert!(table_exists(&conn, "one_time_claims"));
        cleanup(&fresh);

        let legacy = temp_db("claims-legacy");
        let conn = Connection::open(&legacy).unwrap();
        conn.execute_batch(BASELINE_SQL).unwrap();
        conn.pragma_update(None, "user_version", 1).unwrap();
        run(&conn, Some(&legacy)).unwrap();
        assert!(table_exists(&conn, "one_time_claims"));
        cleanup(&legacy);
    }

    #[test]
    fn a_db_from_a_newer_binary_fails_closed() {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", 99).unwrap();
        let err = run(&conn, None).unwrap_err();
        assert!(
            matches!(err, GatewayError::SchemaTooNew(_)),
            "the refusal must be its own variant, not Internal: the binary selects its exit code from the type: {err:?}"
        );
        assert!(format!("{err}").contains("Refusing to open"), "got: {err}");
    }

    /// The desktop supervisor (`permaura-desktop`, `src-tauri/src/supervisor.rs`) matches this exact
    /// opening in a crashed gateway's output to recognise a failure no restart can fix. Rewording it
    /// there is invisible from here, so the coupling is pinned as a test rather than left to a
    /// comment: if this fails, that repo's `SCHEMA_TOO_NEW_MARKER` has to change in the same release.
    #[test]
    fn the_schema_too_new_message_keeps_the_prefix_the_supervisor_matches() {
        let msg = schema_too_new(3, 1, "x");
        assert!(msg.starts_with(SCHEMA_TOO_NEW_PREFIX), "got: {msg}");
        assert!(msg.contains("schema v3"), "got: {msg}");
        assert!(msg.contains("up to v1"), "got: {msg}");
        assert!(msg.ends_with('x'), "the advice must be the tail, so it can be reworded freely: {msg}");
    }

    /// The advice may only name a backup that is really there, and it is named for the version the
    /// store was at BEFORE the migration that wrote it, not for this binary's ceiling. Composing
    /// `.backup-v{target}` was wrong on both counts and sent people hunting for a file that need
    /// never have existed.
    #[test]
    fn the_local_advice_names_the_backup_that_is_actually_on_disk() {
        let db = temp_db("advice-names");
        std::fs::write(&db, b"live store").unwrap();
        // The store was at v2 when the newer gateway migrated it, so that is the copy on disk.
        std::fs::write(format!("{db}.backup-v2"), b"pre-migration").unwrap();

        let advice = sqlite_schema_advice(Some(&db), 4);
        assert!(advice.contains(&format!("{db}.backup-v2")), "got: {advice}");
        assert!(!advice.contains("backup-v4"), "the ceiling is not a filename: {advice}");
        assert!(
            advice.contains("npx -y permaura start"),
            "the usual cause is two gateways, not a rollback: {advice}"
        );
        cleanup(&db);
    }

    /// Naming a backup is not the same as claiming when it was taken. Observed 2026-08-31: a store
    /// that had reached v4 three weeks earlier was offered `backup-v3` described as "the copy saved
    /// before this store was migrated past what this gateway understands". It was not; it predated
    /// the ceiling by a whole version, and restoring it would have silently dropped three weeks.
    /// The older copy is still worth offering, so say which it is and what it costs.
    #[test]
    fn an_older_backup_is_offered_without_pretending_it_is_the_pre_migration_copy() {
        let db = temp_db("advice-older");
        std::fs::write(&db, b"live store").unwrap();
        std::fs::write(format!("{db}.backup-v2"), b"older copy").unwrap();

        let advice = sqlite_schema_advice(Some(&db), 4);
        assert!(advice.contains(&format!("{db}.backup-v2")), "it must still be offered: {advice}");
        assert!(
            advice.contains("still at v2"),
            "the advice must say which moment the copy is from: {advice}"
        );
        assert!(
            advice.contains("gives up everything written since"),
            "the cost of restoring an older copy must be stated: {advice}"
        );
        assert!(
            !advice.contains("the copy saved before this store was migrated past"),
            "that sentence is only true of a copy at this binary's ceiling: {advice}"
        );
        cleanup(&db);
    }

    /// The exact pre-migration copy is described as that, and also as what restoring it costs: everything the newer gateway wrote since the migration, revocations included, since a self-run store has no record outside itself to restore them from. Self-run has no reconciliation, so the advice is the only place an owner learns that a revoked session's bearer and a lost device work again.
    #[test]
    fn the_backup_at_this_binarys_ceiling_is_described_as_the_pre_migration_copy() {
        let db = temp_db("advice-exact");
        std::fs::write(&db, b"live store").unwrap();
        std::fs::write(format!("{db}.backup-v4"), b"pre-migration").unwrap();

        let advice = sqlite_schema_advice(Some(&db), 4);
        assert!(advice.contains(&format!("{db}.backup-v4")), "got: {advice}");
        assert!(
            advice.contains("the copy saved before this store was migrated past"),
            "got: {advice}"
        );
        assert!(advice.contains("gives up everything written since"), "the cost of restoring it must be stated: {advice}");
        assert!(advice.contains("revocations"), "revocations are what restoring undoes silently: {advice}");
        assert!(advice.contains("revoke"), "and what to do after: {advice}");
        cleanup(&db);
    }

    /// A store the newer gateway created from scratch never had a migration run on it, so no backup
    /// was ever written. Promising one is a dead end.
    #[test]
    fn the_local_advice_promises_nothing_when_no_backup_was_written() {
        let db = temp_db("advice-none");
        std::fs::write(&db, b"live store").unwrap();
        let advice = sqlite_schema_advice(Some(&db), 4);
        assert!(!advice.contains(".backup-v"), "got: {advice}");
        assert!(advice.contains("going back is not an option"), "got: {advice}");
        cleanup(&db);
    }

    /// A copy stamped ABOVE this binary's ceiling would be refused for exactly the reason the live
    /// store was, so offering it just repeats the failure.
    #[test]
    fn a_backup_this_binary_could_not_open_is_never_offered() {
        let db = temp_db("advice-toonew");
        std::fs::write(&db, b"live store").unwrap();
        std::fs::write(format!("{db}.backup-v9"), b"still from the future").unwrap();
        std::fs::write(format!("{db}.backup-v1"), b"readable").unwrap();

        let advice = sqlite_schema_advice(Some(&db), 4);
        assert!(advice.contains(&format!("{db}.backup-v1")), "got: {advice}");
        assert!(!advice.contains("backup-v9"), "got: {advice}");
        // Out of `cleanup`'s range on purpose (it stops at SCHEMA_VERSION + 1), so remove it here.
        let _ = std::fs::remove_file(format!("{db}.backup-v9"));
        cleanup(&db);
    }

    #[test]
    fn the_in_memory_advice_has_no_file_to_offer_at_all() {
        let in_memory = sqlite_schema_advice(None, 1);
        assert!(!in_memory.contains("backup"), "got: {in_memory}");
        assert!(!in_memory.contains("restore"), "got: {in_memory}");
    }

    /// No em-dashes and British English in anything a user reads (house style), on both stores and
    /// in both shapes of the local advice.
    #[test]
    fn the_refusal_reads_as_product_copy() {
        let db = temp_db("advice-copy");
        std::fs::write(&db, b"live store").unwrap();
        let without_backup = sqlite_schema_advice(Some(&db), 4);
        std::fs::write(format!("{db}.backup-v2"), b"pre-migration").unwrap();
        let with_backup = sqlite_schema_advice(Some(&db), 4);
        for msg in [
            schema_too_new(3, 1, &with_backup),
            schema_too_new(3, 1, &without_backup),
            schema_too_new(3, 1, "Run or install the newest gateway you have."),
        ] {
            assert!(!msg.contains('\u{2014}'), "em-dash in user-facing copy: {msg}");
        }
        cleanup(&db);
    }

    #[test]
    fn failed_migration_rolls_back_schema_version_and_changes() {
        let broken = with_extra_step(|conn| {
            conn.execute_batch("CREATE TABLE half_done (id TEXT)")?;
            conn.execute_batch("THIS IS NOT SQL")
        });

        let path = temp_db("rollback");
        let conn = Connection::open(&path).unwrap();
        run(&conn, Some(&path)).unwrap();
        conn.execute("INSERT INTO agents (id, data) VALUES ('a1', '{}')", []).unwrap();

        let err = run_list(&conn, &broken, Some(&path)).unwrap_err();
        assert!(format!("{err}").contains("rolled back"), "got: {err}");
        assert_eq!(
            user_version(&conn).unwrap(),
            SCHEMA_VERSION,
            "version must not advance past a failed step"
        );
        assert!(!table_exists(&conn, "half_done"), "partial work must roll back");
        let agents: i64 = conn.query_row("SELECT count(*) FROM agents", [], |r| r.get(0)).unwrap();
        assert_eq!(agents, 1);
        assert!(
            std::path::Path::new(&format!("{path}.backup-v{SCHEMA_VERSION}")).exists(),
            "backup is taken before the attempt"
        );

        // Retry after the failure: the existing backup is kept (it still matches the rolled-back DB).
        let err2 = run_list(&conn, &broken, Some(&path)).unwrap_err();
        assert!(format!("{err2}").contains("rolled back"));
        cleanup(&path);
    }

    impl Migration {
        /// Tests compose ad-hoc lists starting from the real baseline; `fn` pointers copy fine.
        fn clone_for_test(&self) -> Migration {
            Migration { version: self.version, description: self.description, up: self.up }
        }
    }
}

#[cfg(test)]
mod session_hash_tests {
    use super::*;
    use crate::store::{session_token_hash, Session, SessionRole, Store};

    fn sess(token: &str) -> Session {
        Session {
            class: Default::default(),
            opened_by: None,
            id: "sess_r9".into(),
            agent_id: "operator".into(),
            user_id: None,
            device_id: None,
            token: token.into(),
            role: SessionRole::Operator,
            created_at: 0,
            revoked: false,
            expires_at: None,
            last_used_at: None,
            actor: None,
        }
    }

    /// A database read must stop being a bearer read: neither the column nor the JSON may carry it.
    #[test]
    fn a_stored_row_holds_no_bearer() {
        let dir = std::env::temp_dir().join(format!("permaura-r9-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("g.db");
        let store = crate::store::sqlite::SqliteStore::open(path.to_str().unwrap()).expect("open");
        store.put_session(sess("pgt_bearer_that_must_not_persist")).unwrap();

        let raw = std::fs::read(&path).unwrap();
        let hay = String::from_utf8_lossy(&raw);
        assert!(
            !hay.contains("pgt_bearer_that_must_not_persist"),
            "the bearer is still somewhere in the database file"
        );
        assert!(hay.contains(&session_token_hash("pgt_bearer_that_must_not_persist")));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// And the bearer the client holds must still authenticate against the hash.
    #[test]
    fn the_original_bearer_still_looks_up() {
        let dir = std::env::temp_dir().join(format!("permaura-r9b-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let store = crate::store::sqlite::SqliteStore::open(dir.join("g.db").to_str().unwrap()).expect("open");
        store.put_session(sess("pgt_lookup_me")).unwrap();

        let found = store.session_by_token("pgt_lookup_me").unwrap().expect("must resolve");
        assert_eq!(found.id, "sess_r9");
        assert!(store.session_by_token("pgt_wrong").unwrap().is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The rewrite is decided per row, so running it twice changes nothing the second time.
    #[test]
    fn the_rewrite_is_a_no_op_the_second_time() {
        let plain = serde_json::to_string(&sess("pgt_legacy_row")).unwrap();
        let (hash, scrubbed) =
            rehash_session_row("pgt_legacy_row", &plain).expect("a legacy row must be rewritten");
        assert_eq!(hash, session_token_hash("pgt_legacy_row"));
        assert!(!scrubbed.contains("pgt_legacy_row"));

        assert!(
            rehash_session_row(&hash, &scrubbed).is_none(),
            "a row already rewritten must be left alone"
        );
    }

    /// The enrolment code rewrite is decided per row too, and lands on the key a lookup by the code computes.
    #[test]
    fn the_enrolment_code_rewrite_is_a_no_op_the_second_time() {
        let plain = serde_json::to_string(&crate::store::EnrolmentCode {
            code: "ENRL-LEGA-CY00-0000-0000".into(),
            label: None,
            created_at: 0,
            expires_at: 1,
            used: true,
        })
        .unwrap();
        let (hash, scrubbed) = rehash_enrolment_code_row(&plain).expect("a legacy row must be rewritten");
        assert_eq!(hash, crate::store::bearer_lookup_hash("ENRL-LEGA-CY00-0000-0000"));
        assert!(!scrubbed.contains("ENRL-LEGA-CY00-0000-0000"));
        assert!(rehash_enrolment_code_row(&scrubbed).is_none(), "a row already rewritten must be left alone");
    }
}
