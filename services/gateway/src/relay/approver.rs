//! The worker's local approver keyring.
//!
//! The set of approver **device** public keys the worker trusts to sign an `ApprovalResult`. This
//! keyring is the anchor of the human-approval gate (the compensating control for a semi-trusted
//! control plane), so the security question is not what the keyring stores but how a key gets INTO
//! it, and that answer now differs by placement.
//!
//! On a local (loopback) or tunnelled gateway, pairing is reachable only from a client on the
//! gateway's own host, so a compromised CP can never make the worker trust a key it did not
//! enroll. It can still remove keys: where the gateway is an OAuth resource server, a permaura.com
//! `approver-revoke` or `recovery` ticket revokes a key from off the host, up to emptying the
//! keyring, which switches off the holds that need a trusted device.
//!
//! A hosted worker cannot offer that. There is no desktop app, CLI, or console on its host by
//! construction, so "the caller is on loopback" is not a property Mode C can ever have, and
//! positional trust has to be replaced rather than relaxed. Pairing there is anchored to identity
//! instead: an owner-scoped Operator session (the token's `sub` equal to `PERMAURA_OWNER_SUB`) plus
//! a single-use, key-bound, short-TTL step-up ticket that permaura.com mints only after a fresh
//! re-auth. That anchor sits on the control plane's side of the trust boundary, and it would be
//! dishonest to describe it otherwise: on a hosted worker the CP **can** cause a key to become
//! trusted.
//!
//! What bounds it is that the identity anchor enrols the **first** device only. Every device after
//! that must be co-signed by a device already in this keyring (hardware the control plane never
//! touches) through the ordinary held-approval quorum, and each enrolment emits an audit event.
//! The window does not close for good: an `approver-revoke` ticket that names the owner as actor,
//! or carries `remove_alone`, revokes a key at once, and emptying the keyring that way reopens
//! first-device enrolment. So a CP that can forge tickets can replace a hosted worker's whole
//! keyring, with an audit event at each step.
//!
//! Keys come from configuration at startup merged over whatever was persisted. Two persistence
//! shapes exist: [`ApproverKeyring::load`]/[`ApproverKeyring::save`] for the file a
//! `PERMAURA_APPROVER_KEYS_PATH` install names, and [`ApproverKeyring::to_json`]/
//! [`ApproverKeyring::from_json`] for the store row every other gateway, hosted or self-run, uses.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use permaura_relay::validate_pubkey;
use serde::{Deserialize, Serialize};

/// One enrolled approver device.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ApproverEntry {
    pubkey_b64: String,
    revoked: bool,
    /// The person this key approves for, so a two-person rule counts people rather than devices: the
    /// account the AS names as having stepped up to pair it on a hosted worker, or the person named at a
    /// self-run gateway's own host. `None` on a key paired before keys carried one, and on a pairing
    /// that named nobody.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    person: Option<String>,
}

/// The worker's locally-held set of trusted approver device keys, keyed by approver id (the
/// `approver` field of an `ApprovalResult`, e.g. `device:sam-iphone` or `user:sam`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ApproverKeyring {
    keys: HashMap<String, ApproverEntry>,
    /// Fingerprints of `PERMAURA_APPROVER_KEYS` keys an operator revoked, which [`Self::merge_env_str`] no longer trusts. Persisted with the keys because the variable is merged again at every refresh and every start, and without this a revoked device came back within seconds.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    revoked_env_keys: BTreeSet<String>,
}

/// The longest approver id a pairing may create.
pub const MAX_APPROVER_ID_LEN: usize = 128;

/// Whether a pairing may create `approver_id`: 1 to [`MAX_APPROVER_ID_LEN`] characters, starting with an ASCII letter or digit, then letters, digits and `_ - . : @`. Permaura.com addresses a key by its id as one URL path segment, so an id holding `/`, `\`, a control character or nothing but dots could be paired but never revoked from the console. Ids already in a keyring are not re-checked, since dropping a trusted key on load could empty the keyring.
pub fn approver_id_well_formed(approver_id: &str) -> bool {
    let mut chars = approver_id.chars();
    approver_id.len() <= MAX_APPROVER_ID_LEN
        && chars.next().is_some_and(|c| c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || "_-.:@".contains(c))
        && !RESERVED_APPROVER_IDS.contains(&approver_id)
}

/// The static path segments beside the two routes that take an approver id as their last segment, `DELETE /v1/approver-keys/:approver_id` and `DELETE /v1/devices/:id`. A key paired under one of them would have its revoke answered by the static route (a 405), so no pairing may create one; permaura.com refuses the same list.
pub const RESERVED_APPROVER_IDS: &[&str] = &["pair", "enroll", "push-token"];

impl ApproverKeyring {
    /// An empty keyring: every relayed approval fails closed until a device is enrolled.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enroll (or replace) an approver's device key. Returns `false` for a malformed key (which is
    /// never stored, a bad key would otherwise silently brick that approver).
    pub fn add(&mut self, approver_id: impl Into<String>, pubkey_b64: impl Into<String>) -> bool {
        self.add_for(approver_id, pubkey_b64, None)
    }

    /// [`Self::add`], binding the key to `person`. Re-adding the SAME live key with no person keeps the
    /// binding it already has, so a statically configured key merged over a paired one at startup does
    /// not quietly lose it; a different key, or one that was revoked, starts from `person` alone.
    pub fn add_for(
        &mut self,
        approver_id: impl Into<String>,
        pubkey_b64: impl Into<String>,
        person: Option<String>,
    ) -> bool {
        let pubkey = pubkey_b64.into();
        if !validate_pubkey(&pubkey) {
            return false;
        }
        let approver_id = approver_id.into();
        let person = person.or_else(|| {
            self.keys
                .get(&approver_id)
                .filter(|e| !e.revoked && e.pubkey_b64 == pubkey)
                .and_then(|e| e.person.clone())
        });
        self.keys.insert(approver_id, ApproverEntry { pubkey_b64: pubkey, revoked: false, person });
        true
    }

    /// The person a usable key approves for, or `None` when the key is unknown, revoked, or bound to
    /// nobody.
    pub fn person(&self, approver_id: &str) -> Option<&str> {
        self.keys
            .get(approver_id)
            .filter(|e| !e.revoked)
            .and_then(|e| e.person.as_deref())
    }

    /// Whether `approver_id` is a usable entry for `pubkey_b64` already bound to someone other than
    /// `person`: binding it would move that device to another person.
    pub fn bound_to_someone_else(&self, approver_id: &str, pubkey_b64: &str, person: &str) -> bool {
        self.keys.get(approver_id).is_some_and(|e| {
            !e.revoked && e.pubkey_b64 == pubkey_b64 && e.person.as_deref().is_some_and(|bound| bound != person)
        })
    }

    /// Whether binding `person` to `approver_id` could raise how many distinct people this keyring can
    /// put behind one approval: true when another usable key is bound to someone and none of them to
    /// `person`. A binding that cannot (the person is already here, or nobody else is bound, so every
    /// quorum this keyring can meet is still at most one person) changes nothing a co-signer decides.
    pub fn binding_adds_a_person(&self, approver_id: &str, person: &str) -> bool {
        let mut others = self
            .keys
            .iter()
            .filter(|(id, e)| id.as_str() != approver_id && !e.revoked)
            .filter_map(|(_, e)| e.person.as_deref())
            .peekable();
        others.peek().is_some() && others.all(|p| p != person)
    }

    /// The most distinct people the usable keys can put behind one approval, counted as a quorum counts
    /// them: each person once, and keys bound to nobody as one person only when no usable key is bound.
    ///
    /// A signing key signs an approval once whichever approver id it is listed under, so this pairs keys
    /// with people (a bipartite matching) rather than counting labels: it is never above what signatures
    /// can reach.
    pub fn reachable_people(&self) -> u8 {
        let mut people_of: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        let mut any_live = false;
        for e in self.keys.values().filter(|e| !e.revoked) {
            any_live = true;
            if let Some(person) = e.person.as_deref() {
                people_of.entry(e.pubkey_b64.as_str()).or_default().insert(person);
            }
        }
        let mut signed_by: BTreeMap<&str, &str> = BTreeMap::new();
        let matched = people_of
            .keys()
            .filter(|key| assign_key(key, &people_of, &mut signed_by, &mut BTreeSet::new()))
            .count();
        let n = if matched == 0 { usize::from(any_live) } else { matched };
        n.min(u8::MAX as usize) as u8
    }

    /// Revoke an approver (a lost/rotated device): its key no longer verifies anything. Reports
    /// whether this actually changed the keyring, so a caller that persists the whole keyring on
    /// every mutation can skip a write for an approver that was unknown or already revoked.
    pub fn revoke(&mut self, approver_id: &str) -> bool {
        match self.keys.get_mut(approver_id) {
            Some(e) if !e.revoked => {
                e.revoked = true;
                true
            }
            _ => false,
        }
    }

    /// The trusted public key for `approver_id`, or `None` if it is unknown **or revoked**. The
    /// worker verifies a device signature against THIS key, never against any key the frame
    /// carries, so a relay that swaps the frame's `approver_pubkey` gains nothing.
    pub fn trusted_key(&self, approver_id: &str) -> Option<&str> {
        self.keys
            .get(approver_id)
            .filter(|e| !e.revoked)
            .map(|e| e.pubkey_b64.as_str())
    }

    /// True when no usable approver key is enrolled: relayed high-risk capabilities then fail
    /// closed (no approval can ever be honored), which onboarding should surface.
    pub fn is_empty(&self) -> bool {
        self.keys.values().all(|e| e.revoked)
    }

    /// Every approver this keyring has ever held, revoked ones included, ordered by approver id.
    ///
    /// This is the keyring's own census, and it exists because the push-device registry is not one.
    /// A key reaches the keyring through pairing alone; a row reaches the device registry through
    /// `POST /v1/devices/enroll`, which a phone only calls once push registration succeeds and an
    /// Apple Watch never calls at all. Enumerating trust by walking the registry therefore hides
    /// exactly the keys with no device row, and a trusted key nobody can see is a trusted key
    /// nobody can revoke, which on a hosted worker with the sticky device-signed floor is a bricked
    /// tenant. The revocation surfaces must read trust from here.
    pub fn entries(&self) -> Vec<(&str, &str, bool)> {
        let mut out: Vec<(&str, &str, bool)> = self
            .keys
            .iter()
            .map(|(id, e)| (id.as_str(), e.pubkey_b64.as_str(), e.revoked))
            .collect();
        out.sort_by(|a, b| a.0.cmp(b.0));
        out
    }

    /// True once any approver device has ever been enrolled, revoked entries included. Drives the
    /// signed-approval requirement: revocation is reachable through the console/broker,
    /// so counting only usable keys would let a compromised control plane revoke its way back to
    /// the bearer-only approval path. Losing every device is recovered by pairing a new one.
    pub fn ever_enrolled(&self) -> bool {
        !self.keys.is_empty()
    }

    /// Parse the `PERMAURA_APPROVER_KEYS` form: comma-separated `approver_id|pubkey_b64` pairs
    /// (the `|` separator avoids the `:` inside an approver id like `device:phone`).
    pub fn from_env_str(s: &str) -> Self {
        let mut kr = Self::new();
        kr.merge_env_str(s);
        kr
    }

    /// Merge `PERMAURA_APPROVER_KEYS`-form pairs into this keyring: statically provisioned keys
    /// trusted on top of any persisted/paired ones. An optional third field, `approver_id|pubkey_b64|person`,
    /// binds the key to a person.
    ///
    /// A key revoked through [`Self::revoke_provisioned`] is skipped, so it stays revoked until the variable names a different key.
    pub fn merge_env_str(&mut self, s: &str) {
        for (id, pk, person) in env_pairs(s) {
            if self.revoked_env_keys.contains(&crate::service::key_fingerprint(pk)) {
                continue;
            }
            self.add_for(id, pk, person.map(str::to_string));
        }
    }

    /// Whether `env`, in the `PERMAURA_APPROVER_KEYS` form, provisions `pubkey_b64` under `approver_id`.
    pub fn env_provisions(env: &str, approver_id: &str, pubkey_b64: &str) -> bool {
        env_pairs(env).any(|(id, pk, _)| id == approver_id && pk == pubkey_b64)
    }

    /// [`Self::revoke`], and when `env` provisions the key `approver_id` holds, a tombstone for that key so the next merge of `env` does not trust it again. Reports whether anything changed.
    pub fn revoke_provisioned(&mut self, approver_id: &str, env: Option<&str>) -> bool {
        let tombstone = self
            .keys
            .get(approver_id)
            .filter(|e| env.is_some_and(|env| Self::env_provisions(env, approver_id, &e.pubkey_b64)))
            .map(|e| crate::service::key_fingerprint(&e.pubkey_b64));
        let revoked = self.revoke(approver_id);
        let tombstoned = tombstone.is_some_and(|fp| self.revoked_env_keys.insert(fp));
        revoked || tombstoned
    }

    /// Load a persisted keyring from `path` (JSON written by [`Self::save`]). A missing file is a fresh gateway with nothing paired yet. A file that exists but cannot be read or parsed is an error, never an empty keyring: an empty keyring drops the approval floor to bearer-only, so treating a damaged file as first-run would turn a truncated write into a silently unprotected gateway.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::new()),
            Err(e) => return Err(e),
        };
        serde_json::from_slice(&bytes).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("{} is not a readable approver keyring: {e}", path.display()),
            )
        })
    }

    /// Persist the keyring to `path` (JSON), creating parent directories. Worker-local by design:
    /// this file is the durable record of keys the operator paired out-of-band, and the control
    /// plane never sees it. Written through a temp file and rename so a crash mid-write leaves the previous keyring intact rather than a truncated file.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
        permaura_core::secret_file::replace_secret_file(path, &json)
    }

    /// Serialise the keyring for a store row instead of a file, the only durable custody a hosted
    /// worker has, since its filesystem is ephemeral and it may run as several instances that must
    /// agree on which devices are trusted. Same JSON shape as [`Self::save`], so a keyring moves
    /// between the two sites without a migration.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse a keyring previously produced by [`Self::to_json`]. Returns `None` (not an empty
    /// keyring) when the stored JSON is malformed, so the caller can distinguish "nothing paired
    /// yet" from "the persisted row is unreadable". Collapsing the two would drop every trusted
    /// device on a corrupt read and, because the device-signed floor keys off `ever_enrolled`,
    /// silently demote a worker back to bearer-only approvals. The caller must fail closed on
    /// `None` rather than continue with an empty keyring.
    pub fn from_json(s: &str) -> Option<Self> {
        serde_json::from_str(s).ok()
    }
}

/// How far a signing key stands from the person who asked for a held change, least independent first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Independence {
    /// Bound to the requester, or listed under an approver id that names them or their device.
    Requester,
    /// Bound to nobody, so it cannot be shown to be the requester's or anyone else's.
    Unattributed,
    /// Bound to a person other than the requester.
    Independent,
}

impl ApproverKeyring {
    /// How independent of `requester` the key `approver_id` signs with, `None` for an unknown or revoked
    /// approver. Read across every usable entry that key is listed under, because a key signs once
    /// whichever id it uses: a key the requester holds under one id is theirs under every other.
    pub fn independence(&self, approver_id: &str, requester: &crate::store::HoldRequester) -> Option<Independence> {
        self.trusted_key(approver_id).map(|key| self.key_independence(key, requester))
    }

    /// The most independent of `requester` any usable key is: whether someone other than them could
    /// confirm their change, and how sure the keyring can be of it.
    pub fn most_independent(&self, requester: &crate::store::HoldRequester) -> Option<Independence> {
        self.keys
            .values()
            .filter(|e| !e.revoked)
            .map(|e| self.key_independence(&e.pubkey_b64, requester))
            .max()
    }

    /// Whether the key `approver_id` signs with is bound to `person` by the keyring itself: the person recorded when it was paired, read across every usable entry that key is listed under, and never the shape of an id it is listed under, which the pairing client chose.
    pub fn bound_to(&self, approver_id: &str, person: &str) -> bool {
        self.trusted_key(approver_id).is_some_and(|key| {
            self.keys.values().any(|e| !e.revoked && e.pubkey_b64 == key && e.person.as_deref() == Some(person))
        })
    }

    fn key_independence(&self, key: &str, requester: &crate::store::HoldRequester) -> Independence {
        let mut bound = false;
        for (id, e) in self.keys.iter().filter(|(_, e)| !e.revoked && e.pubkey_b64 == key) {
            let names_person = requester
                .person
                .as_deref()
                .is_some_and(|p| e.person.as_deref() == Some(p) || *id == format!("user:{p}"));
            let names_device = requester.device_id.as_deref().is_some_and(|d| *id == format!("device:{d}"));
            if names_person || names_device {
                return Independence::Requester;
            }
            bound |= e.person.is_some();
        }
        if bound {
            Independence::Independent
        } else {
            Independence::Unattributed
        }
    }
}

/// The `approver_id|pubkey_b64[|person]` pairs of a `PERMAURA_APPROVER_KEYS` value, trimmed, with an empty person read as none.
fn env_pairs(s: &str) -> impl Iterator<Item = (&str, &str, Option<&str>)> {
    s.split(',').map(str::trim).filter(|p| !p.is_empty()).filter_map(|pair| {
        let (id, rest) = pair.split_once('|')?;
        let (pk, person) = match rest.split_once('|') {
            Some((pk, person)) => (pk, Some(person.trim()).filter(|p| !p.is_empty())),
            None => (rest, None),
        };
        Some((id.trim(), pk.trim(), person))
    })
}

/// One augmenting-path step of [`ApproverKeyring::reachable_people`]: give `key` a person no other key
/// has taken, moving an earlier key to another of its people where that frees one.
fn assign_key<'a>(
    key: &'a str,
    people_of: &BTreeMap<&'a str, BTreeSet<&'a str>>,
    signed_by: &mut BTreeMap<&'a str, &'a str>,
    seen: &mut BTreeSet<&'a str>,
) -> bool {
    for &person in &people_of[key] {
        if !seen.insert(person) {
            continue;
        }
        let free = match signed_by.get(person).copied() {
            None => true,
            Some(other) => assign_key(other, people_of, signed_by, seen),
        };
        if free {
            signed_by.insert(person, key);
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;

    fn pubkey(seed: u8) -> String {
        STANDARD.encode(SigningKey::from_bytes(&[seed; 32]).verifying_key().to_bytes())
    }

    #[test]
    fn an_approver_id_a_url_segment_can_carry_is_well_formed_and_nothing_else() {
        for ok in ["device:3f9a0c1b2d4e", "user:user_2abc", "device:approver", "a", "phone.1@home", &"a".repeat(MAX_APPROVER_ID_LEN)] {
            assert!(approver_id_well_formed(ok), "{ok}");
        }
        for bad in ["", ".", "..", "device:a/b", "device:a\\b", "../v1", "device:\u{7}", "device:\n", "device: x", "-lead", ":lead", "device:\u{fc}", &"a".repeat(MAX_APPROVER_ID_LEN + 1)] {
            assert!(!approver_id_well_formed(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_static_sibling_of_a_revoke_route_is_not_an_approver_id() {
        for reserved in RESERVED_APPROVER_IDS {
            assert!(!approver_id_well_formed(reserved), "{reserved}");
        }
        for near in ["pairing", "enroll2", "push-tokens", "device:pair", "Pair"] {
            assert!(approver_id_well_formed(near), "{near}");
        }
    }

    /// Every static route beside a revoke route that takes an approver id is in the reserved list, so a route added there later cannot collide unnoticed.
    #[test]
    fn the_reserved_list_names_every_static_sibling_of_a_revoke_route() {
        let routes = include_str!("../lib.rs");
        for prefix in ["\"/v1/approver-keys/", "\"/v1/devices/"] {
            for rest in routes.split(prefix).skip(1) {
                let segment = rest.split('"').next().unwrap_or_default();
                if segment.starts_with(':') || segment.contains('/') {
                    continue;
                }
                assert!(RESERVED_APPROVER_IDS.contains(&segment), "{prefix}{segment} is a static sibling the reserved list does not name");
            }
        }
    }

    #[test]
    fn add_trust_revoke() {
        let mut kr = ApproverKeyring::new();
        assert!(kr.is_empty());
        assert!(!kr.ever_enrolled());
        assert!(kr.add("device:phone", pubkey(1)));
        assert_eq!(kr.trusted_key("device:phone"), Some(pubkey(1).as_str()));
        assert!(!kr.is_empty());
        assert!(kr.ever_enrolled());
        assert_eq!(kr.trusted_key("device:unknown"), None);
        assert!(kr.revoke("device:phone"));
        assert!(!kr.revoke("device:phone"), "a second revocation changes nothing to persist");
        assert!(!kr.revoke("device:never-seen"), "an unknown approver changes nothing to persist");
        assert_eq!(kr.trusted_key("device:phone"), None, "a revoked key must not verify");
        assert!(kr.is_empty());
        assert!(kr.ever_enrolled(), "revoking every device must not read as never-enrolled");
    }

    #[test]
    fn rejects_malformed_key() {
        let mut kr = ApproverKeyring::new();
        assert!(!kr.add("device:phone", "not-base64!!"));
        assert_eq!(kr.trusted_key("device:phone"), None);
    }

    #[test]
    fn json_round_trip_preserves_trust_and_revocation() {
        let mut kr = ApproverKeyring::new();
        assert!(kr.add("device:phone", pubkey(4)));
        assert!(kr.add("device:watch", pubkey(5)));
        kr.revoke("device:watch");
        let back = ApproverKeyring::from_json(&kr.to_json().unwrap()).expect("valid json parses");
        assert_eq!(back.trusted_key("device:phone"), Some(pubkey(4).as_str()));
        assert_eq!(back.trusted_key("device:watch"), None, "revocation must survive the round trip");
        assert!(back.ever_enrolled(), "a revoked device must still read as ever-enrolled");
    }

    #[test]
    fn corrupt_json_is_distinguishable_from_an_empty_keyring() {
        assert!(ApproverKeyring::from_json("{not json").is_none());
        assert!(ApproverKeyring::from_json("{\"keys\":{}}").is_some());
    }

    #[test]
    fn a_person_binding_survives_a_same_key_re_add_and_the_round_trip_but_not_a_new_key() {
        let mut kr = ApproverKeyring::new();
        assert!(kr.add_for("device:phone", pubkey(6), Some("user_sam".into())));
        assert!(kr.add("device:phone", pubkey(6)), "the same key configured again");
        assert_eq!(kr.person("device:phone"), Some("user_sam"));
        assert!(kr.add_for("device:watch", pubkey(8), Some("user_sam".into())));
        let back = ApproverKeyring::from_json(&kr.to_json().unwrap()).expect("valid json parses");
        assert_eq!(back.person("device:watch"), Some("user_sam"));
        assert!(kr.add("device:phone", pubkey(7)));
        assert_eq!(kr.person("device:phone"), None, "a different key is a different device and starts unbound");
        kr.revoke("device:watch");
        assert_eq!(kr.person("device:watch"), None, "a revoked key approves for nobody");
        assert!(kr.add("device:watch", pubkey(8)));
        assert_eq!(kr.person("device:watch"), None, "re-trusting a revoked key does not revive its old binding");

        let env = ApproverKeyring::from_env_str(&format!("device:a|{}|user_omar , device:b|{}", pubkey(9), pubkey(10)));
        assert_eq!(env.person("device:a"), Some("user_omar"));
        assert_eq!(env.person("device:b"), None);

        let before = format!(r#"{{"keys":{{"device:old":{{"pubkey_b64":"{}","revoked":false}}}}}}"#, pubkey(11));
        let old = ApproverKeyring::from_json(&before).expect("a keyring persisted before persons parses");
        assert_eq!(old.trusted_key("device:old"), Some(pubkey(11).as_str()));
        assert_eq!(old.person("device:old"), None);
    }

    /// Only a binding that could put a NEW person behind an approval needs a co-signer: the first person
    /// bound anywhere, or one already bound to another key, leaves every quorum where it was.
    #[test]
    fn a_binding_adds_a_person_only_beside_someone_else() {
        let mut kr = ApproverKeyring::new();
        assert!(kr.add("device:old-phone", pubkey(12)));
        assert!(kr.add("device:old-watch", pubkey(13)));
        assert!(!kr.binding_adds_a_person("device:old-phone", "user_sam"), "nobody else is bound");
        assert!(kr.add_for("device:old-phone", pubkey(12), Some("user_sam".into())));
        assert!(!kr.binding_adds_a_person("device:old-watch", "user_sam"), "the same person");
        assert!(kr.binding_adds_a_person("device:old-watch", "user_omar"), "a second person");
        assert!(!kr.binding_adds_a_person("device:old-phone", "user_omar"), "its own binding is not another person");
        kr.revoke("device:old-phone");
        assert!(!kr.binding_adds_a_person("device:old-watch", "user_omar"), "a revoked key binds nobody");
    }

    #[test]
    fn reachable_people_counts_as_a_quorum_does() {
        let mut kr = ApproverKeyring::new();
        assert_eq!(kr.reachable_people(), 0);
        assert!(kr.add("device:old", pubkey(14)));
        assert_eq!(kr.reachable_people(), 1, "keys bound to nobody are one person");
        assert!(kr.add_for("device:phone", pubkey(15), Some("user_sam".into())));
        assert!(kr.add_for("device:watch", pubkey(16), Some("user_sam".into())));
        assert_eq!(kr.reachable_people(), 1, "beside a bound key the unbound one adds nobody");
        assert!(kr.add_for("device:omar", pubkey(17), Some("user_omar".into())));
        assert_eq!(kr.reachable_people(), 2);
        kr.revoke("device:omar");
        assert_eq!(kr.reachable_people(), 1, "a revoked key reaches nobody");
    }

    /// One signing key signs an approval once whichever approver id it is listed under, so two person
    /// labels on one key reach one person, and a key carrying several labels reaches only the people the
    /// other keys leave it.
    #[test]
    fn reachable_people_counts_each_signing_key_once() {
        let mut kr = ApproverKeyring::new();
        assert!(kr.add_for("device:a", pubkey(20), Some("A".into())));
        assert!(kr.add_for("device:b", pubkey(20), Some("B".into())));
        assert_eq!(kr.reachable_people(), 1, "two labels on one signing key cannot both sign");
        assert!(kr.add_for("device:c", pubkey(21), Some("B".into())));
        assert_eq!(kr.reachable_people(), 2, "a second key can be the other person");

        let mut kr = ApproverKeyring::new();
        for (id, person) in [("device:k1-a", "A"), ("device:k1-b", "B"), ("device:k1-c", "C")] {
            assert!(kr.add_for(id, pubkey(22), Some(person.into())));
        }
        assert!(kr.add_for("device:k2", pubkey(23), Some("A".into())));
        assert!(kr.add_for("device:k3", pubkey(24), Some("A".into())));
        assert_eq!(kr.reachable_people(), 2, "three keys, but two of them can only be A");
    }

    /// A key is the requester's under every id it is listed under, a key bound to nobody is neither theirs
    /// nor provably someone else's, and the keyring answers who could confirm instead of them.
    #[test]
    fn independence_reads_every_id_a_key_is_listed_under() {
        let me = crate::store::HoldRequester { person: Some("priya".into()), device_id: Some("laptop".into()), ..Default::default() };
        let mut kr = ApproverKeyring::new();
        assert!(kr.add_for("device:phone", pubkey(30), Some("priya".into())));
        assert!(kr.add_for("device:alias", pubkey(30), None));
        assert!(kr.add("device:laptop", pubkey(31)));
        assert!(kr.add("user:priya", pubkey(32)));
        assert!(kr.add("device:legacy", pubkey(33)));
        assert_eq!(kr.independence("device:alias", &me), Some(Independence::Requester), "the same key as her phone");
        assert_eq!(kr.independence("device:laptop", &me), Some(Independence::Requester), "the requesting device");
        assert_eq!(kr.independence("user:priya", &me), Some(Independence::Requester), "an id that names her");
        assert_eq!(kr.independence("device:legacy", &me), Some(Independence::Unattributed));
        assert_eq!(kr.most_independent(&me), Some(Independence::Unattributed));
        assert!(kr.add_for("device:owner", pubkey(34), Some("sam".into())));
        assert_eq!(kr.independence("device:owner", &me), Some(Independence::Independent));
        assert_eq!(kr.most_independent(&me), Some(Independence::Independent));
        assert!(kr.revoke("device:owner"));
        assert_eq!(kr.independence("device:owner", &me), None, "a revoked key confirms nothing");
        assert_eq!(kr.most_independent(&me), Some(Independence::Unattributed));
    }

    #[test]
    fn parses_env_form_with_colon_in_id() {
        let s = format!("device:sam-iphone|{} , user:sam|{}", pubkey(2), pubkey(3));
        let kr = ApproverKeyring::from_env_str(&s);
        assert_eq!(kr.trusted_key("device:sam-iphone"), Some(pubkey(2).as_str()));
        assert_eq!(kr.trusted_key("user:sam"), Some(pubkey(3).as_str()));
    }

    /// The variable is merged again over the persisted keyring at every refresh and start, so a revoked provisioned key needs a tombstone that survives the round trip and that only a different key gets past.
    #[test]
    fn a_revoked_provisioned_key_survives_the_next_merge_until_the_key_changes() {
        let env = format!("device:phone|{},device:watch|{}", pubkey(40), pubkey(41));
        let mut kr = ApproverKeyring::from_env_str(&env);
        assert!(kr.revoke_provisioned("device:phone", Some(&env)));
        assert!(!kr.revoke_provisioned("device:phone", Some(&env)), "a second revocation changes nothing");

        let mut reloaded = ApproverKeyring::from_json(&kr.to_json().unwrap()).unwrap();
        reloaded.merge_env_str(&env);
        assert_eq!(reloaded.trusted_key("device:phone"), None, "the merge trusted the revoked key again");
        assert_eq!(reloaded.trusted_key("device:watch"), Some(pubkey(41).as_str()));

        reloaded.merge_env_str(&format!("device:phone|{},device:watch|{}", pubkey(42), pubkey(41)));
        assert_eq!(reloaded.trusted_key("device:phone"), Some(pubkey(42).as_str()), "a different key is trusted");
    }

    /// A paired key is revoked as before and leaves no tombstone, so pairing that key again is not refused by a variable that never named it.
    #[test]
    fn a_revoked_paired_key_leaves_no_tombstone() {
        let env = format!("device:watch|{}", pubkey(44));
        let mut kr = ApproverKeyring::from_env_str(&env);
        assert!(kr.add("device:phone", pubkey(43)));
        assert!(kr.revoke_provisioned("device:phone", Some(&env)));
        assert!(!kr.to_json().unwrap().contains("revoked_env_keys"), "nothing to persist for a paired key");
        assert!(ApproverKeyring::env_provisions(&env, "device:watch", &pubkey(44)));
        assert!(!ApproverKeyring::env_provisions(&env, "device:phone", &pubkey(43)));
    }
}
