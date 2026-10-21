//! Recovery authority: the second factor behind the two controls that switch the device-signed hold
//! off.
//!
//! Once a device is trusted, a vault export and every destructive mutation are held for that device's
//! signature. Two controls switch that hold off: lowering the approval floor, and revoking the last
//! trusted key (after which `any_device_trusted()` is false and nothing is held). Both used to need
//! nothing but the operator bearer over loopback, and `$PERMAURA_HOME/operator.token` is readable by
//! every process running as the owner, agents included. A gate and its own off-switch shared one
//! readable credential, so the gate held against nobody the product is for.
//!
//! Every route out of that state now needs an authority the bearer does not carry:
//!
//! - **A device signature.** The ordinary path: the control is held as an approval and a trusted
//!   device co-signs it.
//! - **Recovery codes.** Eight single-use codes are issued the moment the first device is trusted
//!   and shown once. Only Argon2id hashes are stored, so a process that reads the store gets nothing
//!   it can present. A code applies the control immediately.
//! - **The identity anchor**, on a gateway that is an OAuth resource server: a single-use
//!   [`crate::oauth::TicketPurpose::Recovery`] ticket permaura.com mints after a fresh
//!   re-authentication, presented in `X-Permaura-Pairing-Ticket`. This is the same anchor a hosted
//!   worker uses, made available to a self-run gateway that has a remote-access configuration and
//!   therefore an authorization server to re-authenticate at.
//!
//! **A gateway with no OAuth configuration has no third authority, and that is stated rather than
//! papered over.** Host-level recovery, `permaura approver reset --yes` with the gateway stopped, also
//! takes a recovery code while a device is trusted, because anything running as the owner can stop the
//! gateway. With the device and the codes both gone, `permaura uninstall --purge-data` starts over and
//! destroys every credential. Editing the store file directly is the conceded same-user residual, not
//! a defended boundary.
//!
//! **What used to be here and why it is gone.** A third route completed on its own after 24 hours,
//! on the argument that an attacker could not finish silently because every paired device would be
//! told. It could. `POST /v1/devices/enroll` took an operator bearer and a caller-chosen approver id,
//! and replaced that approver's push entry with one carrying no token, leaving the signing key
//! trusted and the notification gone; push delivery is best effort besides, and the registry did not
//! survive a restart. The timer then finished the job. A timer is not an authority: it grants, on its
//! own, exactly what the bearer could not obtain, so the bearer obtains it by waiting. The completion
//! path is deleted rather than repaired, because repairing notification delivery would still leave a
//! control whose authority is the passage of time.
//!
//! Hosted (Mode C) workers are unchanged. There the second factor is the authorization-server ticket
//! minted after a fresh re-authentication, and no recovery codes are issued.

use crate::error::GatewayError;
use crate::policy_guard::Mutation;
use crate::service::EnforcementService;
use crate::store::Store;
use argon2::{Algorithm, Argon2, Params, Version};
use serde::{Deserialize, Serialize};

/// How many codes one issue produces.
pub const RECOVERY_CODE_COUNT: usize = 8;

/// The header a recovery code is presented in.
pub const RECOVERY_CODE_HEADER: &str = "x-permaura-recovery-code";

/// The header a caller used to ask for the delayed path with. Kept only so the request can be
/// refused by name and pointed at a real route, rather than silently ignored and answered with a hold
/// the caller has no device to resolve.
pub const RECOVERY_INTENT_HEADER: &str = "x-permaura-recovery";

/// `gateway_meta` key holding the hashed codes.
pub const RECOVERY_CODES_META: &str = "recovery_codes";

/// `gateway_meta` key that held the one pending delayed recovery. Nothing writes it any more; it is
/// read once at boot so a record left by an older build is cancelled rather than left on the clock.
pub const RECOVERY_PENDING_META: &str = "recovery_pending";

/// The audit `authority` label for a change a recovery code authorised.
pub const AUTHORITY_RECOVERY_CODE: &str = "recovery_code";

/// The audit `authority` label for the boot-time cancellation of a delayed recovery an older build
/// queued. Nothing else uses it: no change is ever applied under this authority again.
pub const AUTHORITY_DELAYED_RECOVERY: &str = "delayed_recovery";

/// The audit `authority` label for a change a permaura.com recovery ticket authorised.
pub const AUTHORITY_RECOVERY_TICKET: &str = "recovery_ticket";

/// Random bytes per code: 160 bits, which encodes to exactly 32 base32 characters.
const CODE_BYTES: usize = 20;

/// Crockford base32: no I, L, O or U, so a code read aloud or typed from paper survives.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const CLAIM_SCOPE: &str = "recovery:code";

/// Same interactive Argon2id profile the vault KEK derivation uses.
const ARGON_MEM_KIB: u32 = 19 * 1024;
const ARGON_PASSES: u32 = 2;
const ARGON_LANES: u32 = 1;

#[derive(Serialize, Deserialize)]
struct StoredCode {
    salt: String,
    hash: String,
    #[serde(default)]
    used_at: Option<i64>,
}

#[derive(Serialize, Deserialize)]
struct StoredCodes {
    version: u32,
    issued_at: i64,
    codes: Vec<StoredCode>,
}

/// What `GET /v1/recovery` reports about the codes, never the codes themselves.
#[derive(Serialize)]
pub struct CodeStatus {
    /// When this set was issued (unix ms).
    pub issued_at: i64,
    /// Codes not yet spent.
    pub remaining: usize,
    /// Codes in the set.
    pub total: usize,
}

/// A delayed recovery an older build left on the clock. Nothing writes one any more; this type
/// exists so [`cancel_pending`] can read one back and say what it cancelled.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PendingRecovery {
    /// The device-signed approval the recovery was queued as; a device resolves it through that id.
    pub approval_id: String,
    /// The change that will apply when the clock runs out.
    pub mutation: Mutation,
    /// `mutation.summary()`, for callers that show the pending change.
    pub summary: String,
    /// When it was requested (unix ms).
    pub requested_at: i64,
    /// When it applies if nothing cancels it (unix ms).
    pub effective_at: i64,
}

pub(crate) fn hosted() -> bool {
    std::env::var("PERMAURA_HOSTED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 8);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn group(code: &str) -> String {
    code.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

/// Canonical form of a code as a person might have typed it: case-folded, separators dropped, the
/// Crockford look-alikes mapped. `None` when what remains is not a code at all.
pub fn normalize(presented: &str) -> Option<String> {
    let mut out = String::with_capacity(32);
    for ch in presented.chars() {
        let c = match ch.to_ascii_uppercase() {
            '-' | ' ' | '_' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        };
        if !ALPHABET.contains(&(c as u8)) {
            return None;
        }
        out.push(c);
    }
    (out.len() == CODE_BYTES * 8 / 5).then_some(out)
}

fn hash_code(normalized: &str, salt: &[u8]) -> Result<[u8; 32], GatewayError> {
    let params = Params::new(ARGON_MEM_KIB, ARGON_PASSES, ARGON_LANES, Some(32))
        .map_err(|e| GatewayError::Internal(format!("recovery code KDF parameters: {e}")))?;
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(normalized.as_bytes(), salt, &mut out)
        .map_err(|e| GatewayError::Internal(format!("recovery code KDF: {e}")))?;
    Ok(out)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn load_codes(store: &dyn Store) -> Result<Option<StoredCodes>, GatewayError> {
    match store.get_meta(RECOVERY_CODES_META)? {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => serde_json::from_str(&s).map(Some).map_err(|e| {
            GatewayError::Internal(format!("the stored recovery codes are not readable: {e}"))
        }),
    }
}

fn save_codes(store: &dyn Store, codes: &StoredCodes) -> Result<(), GatewayError> {
    let json = serde_json::to_string(codes)
        .map_err(|e| GatewayError::Internal(format!("recovery codes could not be encoded: {e}")))?;
    store.put_meta(RECOVERY_CODES_META, &json)
}

/// Mint a fresh set, replacing any earlier one, and return the plaintext exactly once.
pub fn issue(store: &dyn Store, now: i64) -> Result<Vec<String>, GatewayError> {
    use base64::Engine as _;
    use rand::RngCore as _;
    let mut rng = rand::rngs::OsRng;
    let mut plain = Vec::with_capacity(RECOVERY_CODE_COUNT);
    let mut stored = Vec::with_capacity(RECOVERY_CODE_COUNT);
    for _ in 0..RECOVERY_CODE_COUNT {
        let mut bytes = [0u8; CODE_BYTES];
        rng.fill_bytes(&mut bytes);
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        let code = encode(&bytes);
        let hash = hash_code(&code, &salt)?;
        stored.push(StoredCode {
            salt: base64::engine::general_purpose::STANDARD_NO_PAD.encode(salt),
            hash: base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash),
            used_at: None,
        });
        plain.push(group(&code));
    }
    save_codes(store, &StoredCodes { version: 1, issued_at: now, codes: stored })?;
    Ok(plain)
}

/// Forget every code. Called when the keyring empties, because the codes belong to the trust epoch
/// that just ended; the next first pairing issues new ones.
pub fn clear(store: &dyn Store) -> Result<(), GatewayError> {
    store.put_meta(RECOVERY_CODES_META, "")
}

/// How many codes remain, or `None` when none were ever issued (or the set was cleared).
pub fn status(store: &dyn Store) -> Result<Option<CodeStatus>, GatewayError> {
    Ok(load_codes(store)?.map(|c| CodeStatus {
        issued_at: c.issued_at,
        remaining: c.codes.iter().filter(|c| c.used_at.is_none()).count(),
        total: c.codes.len(),
    }))
}

/// Whether `presented` is one of this store's unspent recovery codes, without spending it: the check a
/// caller makes before it records what the code will authorize, so a record that fails costs no code.
/// [`consume`] is still what spends it, and it can still refuse (a restore's replay floor, a code spent
/// in between).
pub fn check(store: &dyn Store, presented: &str) -> Result<Option<usize>, GatewayError> {
    use base64::Engine as _;
    let Some(code) = normalize(presented) else { return Ok(None) };
    let Some(stored) = load_codes(store)? else { return Ok(None) };
    let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    for (index, entry) in stored.codes.iter().enumerate() {
        if entry.used_at.is_some() {
            continue;
        }
        let salt = engine
            .decode(&entry.salt)
            .map_err(|e| GatewayError::Internal(format!("stored recovery salt: {e}")))?;
        let want = engine
            .decode(&entry.hash)
            .map_err(|e| GatewayError::Internal(format!("stored recovery hash: {e}")))?;
        if ct_eq(&hash_code(&code, &salt)?, &want) {
            return Ok(Some(index));
        }
    }
    Ok(None)
}

/// Spend a code. `Ok(Some(index))` burns it; `Ok(None)` means unknown, already spent, malformed, or
/// no codes were ever issued. Single use is enforced in the store's one-time ledger, not in this
/// process, so two instances presenting the same code cannot both succeed.
pub fn consume(store: &dyn Store, presented: &str, now: i64) -> Result<Option<usize>, GatewayError> {
    use base64::Engine as _;
    let Some(code) = normalize(presented) else { return Ok(None) };
    let Some(mut stored) = load_codes(store)? else { return Ok(None) };
    let engine = base64::engine::general_purpose::STANDARD_NO_PAD;
    for (index, entry) in stored.codes.iter_mut().enumerate() {
        if entry.used_at.is_some() {
            continue;
        }
        let salt = engine
            .decode(&entry.salt)
            .map_err(|e| GatewayError::Internal(format!("stored recovery salt: {e}")))?;
        let want = engine
            .decode(&entry.hash)
            .map_err(|e| GatewayError::Internal(format!("stored recovery hash: {e}")))?;
        let got = hash_code(&code, &salt)?;
        if !ct_eq(&got, &want) {
            continue;
        }
        let jti = format!("{}:{index}", stored.issued_at);
        // The replay floor, immediately before the claim. A restore rolls the single-use ledger back
        // with the database, so a code set issued before the restore has every code unspent again,
        // including the ones that were used. `issued_at` is the set's own mint time, which is what
        // the jti above is already keyed by.
        crate::restore::refuse_if_replayed_across_a_restore(
            store,
            stored.issued_at,
            "recovery code",
        )?;
        if !store.claim_once(CLAIM_SCOPE, &jti, i64::MAX / 2)? {
            return Ok(None);
        }
        entry.used_at = Some(now);
        save_codes(store, &stored)?;
        return Ok(Some(index));
    }
    Ok(None)
}

/// The delayed recovery on the clock, if any.
pub fn pending(store: &dyn Store) -> Result<Option<PendingRecovery>, GatewayError> {
    match store.get_meta(RECOVERY_PENDING_META)? {
        None => Ok(None),
        Some(s) if s.trim().is_empty() => Ok(None),
        Some(s) => serde_json::from_str(&s).map(Some).map_err(|e| {
            GatewayError::Internal(format!("the pending recovery record is not readable: {e}"))
        }),
    }
}

fn clear_pending(store: &dyn Store) -> Result<(), GatewayError> {
    store.put_meta(RECOVERY_PENDING_META, "")
}

/// Cancel a delayed recovery an older build left on the clock, and record that it was cancelled.
///
/// Run once at boot. Nothing applies a pending record any more, so leaving one would be inert rather
/// than dangerous; it is cancelled anyway for two reasons. `GET /v1/recovery` would keep reporting a
/// change as pending that will never happen, and the approval it was queued as would sit in the
/// pending queue forever waiting for a signature that now decides nothing. The audit entry is the
/// point of doing it here rather than silently: an owner who requested a delayed recovery under the
/// old build and never saw it land is entitled to find out why from the chain.
///
/// `Ok(None)` when there is nothing to cancel, which is every boot after the first.
pub fn cancel_pending(
    service: &EnforcementService,
    now: i64,
) -> Result<Option<PendingRecovery>, GatewayError> {
    let store = service.store();
    let Some(record) = pending(store.as_ref())? else { return Ok(None) };
    if let Some(mut approval) = store.get_approval(&record.approval_id)? {
        // Claimed first, as every other closing of a hold is, so a resolution that arrives meanwhile fails at its claim rather than finishing over this denial; one this process is already running ends the row itself.
        let resolving = |id: &str| service.executions().is_resolving(id);
        if approval.status == "pending"
            && !resolving(&approval.id)
            && (store.claim_once("approval-resolution", &approval.id, i64::MAX)? || !resolving(&approval.id))
        {
            approval.status = "denied".into();
            store.put_approval(approval)?;
        }
    }
    clear_pending(store.as_ref())?;
    let mut detail = serde_json::Map::new();
    detail.insert("approval_id".into(), serde_json::json!(record.approval_id));
    detail.insert("summary".into(), serde_json::json!(record.summary));
    detail.insert("requested_at".into(), serde_json::json!(record.requested_at));
    detail.insert("effective_at".into(), serde_json::json!(record.effective_at));
    detail.insert("cancelled_at".into(), serde_json::json!(now));
    detail.insert(
        "reason".into(),
        serde_json::json!(
            "recovery that completes on a timer has been removed: a timer is not an authority. \
             Repeat the change with a device signature, a recovery code, or a permaura.com recovery \
             ticket."
        ),
    );
    service.audit_approver_pairing(
        "deny",
        "recovery-delayed",
        None,
        AUTHORITY_DELAYED_RECOVERY,
        serde_json::Value::Object(detail),
    )?;
    Ok(Some(record))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::MemoryStore;

    #[test]
    fn codes_are_grouped_and_normalise_back() {
        let code = encode(&[0xAB; CODE_BYTES]);
        assert_eq!(code.len(), 32);
        let shown = group(&code);
        assert_eq!(shown.matches('-').count(), 7);
        assert_eq!(normalize(&shown).as_deref(), Some(code.as_str()));
        assert_eq!(normalize(&shown.to_lowercase()).as_deref(), Some(code.as_str()));
        assert_eq!(normalize(&shown.replace('-', " ")).as_deref(), Some(code.as_str()));
    }

    #[test]
    fn look_alikes_map_and_junk_is_refused() {
        let with_look_alikes = "O1IL".repeat(8);
        assert_eq!(normalize(&with_look_alikes).as_deref(), Some("0111".repeat(8).as_str()));
        assert!(normalize("too-short").is_none());
        assert!(normalize(&"U".repeat(32)).is_none());
    }

    #[test]
    fn issue_then_consume_burns_each_code_once() {
        let store = MemoryStore::new();
        let codes = issue(&store, 1_000).unwrap();
        assert_eq!(codes.len(), RECOVERY_CODE_COUNT);
        assert_eq!(status(&store).unwrap().unwrap().remaining, RECOVERY_CODE_COUNT);

        assert_eq!(consume(&store, &codes[3], 2_000).unwrap(), Some(3));
        assert_eq!(consume(&store, &codes[3], 2_001).unwrap(), None, "a code is single use");
        assert_eq!(consume(&store, "not a code", 2_002).unwrap(), None);
        assert_eq!(consume(&store, &"A".repeat(32), 2_003).unwrap(), None);
        assert_eq!(status(&store).unwrap().unwrap().remaining, RECOVERY_CODE_COUNT - 1);

        clear(&store).unwrap();
        assert!(status(&store).unwrap().is_none());
        assert_eq!(consume(&store, &codes[0], 3_000).unwrap(), None, "cleared codes are dead");
    }

    #[test]
    fn stored_form_holds_no_plaintext() {
        let store = MemoryStore::new();
        let codes = issue(&store, 1).unwrap();
        let raw = store.get_meta(RECOVERY_CODES_META).unwrap().unwrap();
        for c in codes {
            assert!(!raw.contains(&c.replace('-', "")), "plaintext code found in the store");
        }
    }
}
