//! The enumeration seam: every `secret_id` this gateway knows about, and which custody layer holds
//! each one.
//!
//! Nothing else in the gateway can answer that question. `Store::list_secret_ids` sees only the rows
//! sealed locally; `Store::list_secret_custody` sees only the ones deliberately enrolled elsewhere;
//! and a connection or capability can name a `secret_id` that appears in neither, which is a real,
//! findable state, not a theoretical one (a credential written on one host and the store copied to
//! another, an enrolment half-applied, a hand-edited row).
//!
//! Anything that has to reason about *all* the secrets (vault export above all) needs the union,
//! and needs to be able to tell the three apart. [`SecretLocation::Unresolvable`] is a first-class
//! outcome here. The vault export leaves such references out of the bundle rather than failing, and
//! does not call [`SecretInventory::ensure_all_resolvable`].
//!
//! Staged credentials ([`STAGING_SECRET_PREFIX`]) are excluded throughout: they are sealed blobs
//! parked for a device-signed approval that never arrived, belong to no connection, and would show
//! up as unresolvable noise.
//!
//! A row gateway 1.3.46 parked under `sec_staging_` sits in the namespace connection slots are derived in, so it is listed like any other secret; the hold that parked it carries no digest, is refused at approval, and releases it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::GatewayError;
use crate::store::{CustodyKind, Store};

/// The id prefix a credential change gets while it is parked awaiting a device-signed approval
/// (minted by the `POST /v1/connections/:id/credential` hold path). Such a row is a sealed blob with
/// no owner: it is not a connection's live credential, and if the approval is never resolved it is
/// simply garbage. Never part of the inventory.
///
/// The colon is the marker: a derived slot is `sec_<connection id>` and can never start `sec:`, so no connection, however it is named, derives a staged row's id, and every staging refusal keys on this prefix alone.
pub const STAGING_SECRET_PREFIX: &str = "sec:staging:";

/// A fresh staged id for a credential change about to be parked.
pub fn mint_staging_secret_id() -> String {
    format!("{STAGING_SECRET_PREFIX}{}", crate::service::short_id())
}

/// Whether `secret_id` is a staged credential (see [`STAGING_SECRET_PREFIX`]).
pub fn is_staging_secret_id(secret_id: &str) -> bool {
    secret_id.starts_with(STAGING_SECRET_PREFIX)
}

/// Refuse a write to, or a binding of, a staged credential from any route but the held change that parked it. The device signs a digest of the staged bytes, so a row anything else could rewrite would let a second caller choose what the device's approval promotes.
pub fn refuse_staging_secret_id(what: &str, secret_id: &str) -> Result<(), GatewayError> {
    if !is_staging_secret_id(secret_id) {
        return Ok(());
    }
    Err(GatewayError::Denied(format!(
        "{what} '{secret_id}' is a credential change parked for a device signature: only the held change that staged it can promote or discard it"
    )))
}

/// Hex SHA-256 over a staged credential's sealed envelope, the value a `credential_promote` hold binds and its promotion checks.
pub fn staged_digest(sealed: &permaura_core::SealedSecret) -> String {
    let bytes = serde_json::to_vec(sealed).unwrap_or_default();
    permaura_core::audit::sha256_hex(&bytes)
}

/// The bytes a secret row takes as stored: its JSON as the SQLite store writes it and every hosted upload carries it, sealed envelope and metadata both. What the staged-bytes bound counts, so a payload moved from the value into the labels is counted too.
pub fn secret_row_bytes(id: &str, sealed: &permaura_core::SealedSecret, metadata: &permaura_core::SecretMetadata) -> usize {
    #[derive(Serialize)]
    struct Row<'a> {
        id: &'a str,
        sealed: &'a permaura_core::SealedSecret,
        metadata: &'a permaura_core::SecretMetadata,
    }
    json_bytes(&Row { id, sealed, metadata })
}

/// The bytes a secret's metadata takes as stored, the figure [`crate::limits::LimitsConfig::secret_metadata_bytes`] bounds.
pub fn secret_metadata_bytes(metadata: &permaura_core::SecretMetadata) -> usize {
    json_bytes(metadata)
}

/// Refuse metadata a caller hands in for `secret_id` past `limit` stored bytes, before anything is sealed, staged or written.
pub fn refuse_oversized_secret_metadata(
    secret_id: &str,
    metadata: &permaura_core::SecretMetadata,
    limit: usize,
) -> Result<(), GatewayError> {
    let bytes = secret_metadata_bytes(metadata);
    if bytes <= limit {
        return Ok(());
    }
    Err(GatewayError::BadRequest(format!(
        "the labels and other metadata of secret '{secret_id}' take {bytes} bytes, more than the {limit} bytes one secret's metadata may; labels are short tags such as \"production\" or \"billing\", so shorten or drop some"
    )))
}

fn json_bytes<T: Serialize + ?Sized>(value: &T) -> usize {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.saturating_add(buf.len());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    // Serializing these types cannot fail: every map key is a string and nothing is a custom serializer.
    let _ = serde_json::to_writer(&mut count, value);
    count.0
}

/// Where a secret's bytes actually are, from the gateway's point of view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretLocation {
    /// A sealed row in this gateway's own store. A vault export also carries Infisical and KMS
    /// secrets, resolved to plaintext through their custodian at export time.
    LocalVault,
    /// Held by Infisical; this gateway holds only the credentials to fetch it at call time.
    Infisical,
    /// Held as a KMS-wrapped ciphertext; only the CMK can turn it back into plaintext.
    Kms,
    /// Named by a connection or capability, but present in neither the local vault nor any custody
    /// record, so the gateway cannot resolve it. The vault export leaves it out of the bundle; a
    /// caller that needs every secret can refuse with [`SecretInventory::ensure_all_resolvable`].
    Unresolvable,
}

impl SecretLocation {
    /// The wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            SecretLocation::LocalVault => "local_vault",
            SecretLocation::Infisical => "infisical",
            SecretLocation::Kms => "kms",
            SecretLocation::Unresolvable => "unresolvable",
        }
    }

    /// True when this gateway holds the bytes itself.
    pub fn is_local(self) -> bool {
        matches!(self, SecretLocation::LocalVault)
    }

    /// True when an external custodian holds the bytes.
    pub fn is_external(self) -> bool {
        matches!(self, SecretLocation::Infisical | SecretLocation::Kms)
    }

    /// True when the gateway cannot say where the bytes are.
    pub fn is_unresolvable(self) -> bool {
        matches!(self, SecretLocation::Unresolvable)
    }

    fn from_custody(kind: CustodyKind) -> Self {
        match kind {
            CustodyKind::LocalVault => SecretLocation::LocalVault,
            CustodyKind::Infisical => SecretLocation::Infisical,
            CustodyKind::Kms => SecretLocation::Kms,
        }
    }
}

/// What names a secret. Kept precise so an "I cannot resolve this" error can say which object is
/// broken rather than just quoting an id.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretReference {
    /// A connection whose `secret_id` is this secret.
    Connection(String),
    /// A capability whose `secret_id` is this secret.
    Capability(String),
}

/// One secret in the inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretInventoryEntry {
    /// The secret id.
    pub secret_id: String,
    /// Which layer holds it.
    pub location: SecretLocation,
    /// Unix-ms the custody record was written, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrolled_at: Option<i64>,
    /// The connections and capabilities that name it, sorted. Empty for an orphan: a sealed row or
    /// custody record nothing points at any more.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub referenced_by: Vec<SecretReference>,
}

impl SecretInventoryEntry {
    /// True when nothing references this secret, a leftover worth reporting, never an error.
    pub fn is_orphan(&self) -> bool {
        self.referenced_by.is_empty()
    }
}

/// Every secret this gateway knows about, sorted by id so two runs over the same store are
/// byte-identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretInventory {
    /// The entries, ascending by `secret_id`.
    pub entries: Vec<SecretInventoryEntry>,
}

impl SecretInventory {
    /// Secrets whose bytes this gateway holds in its own store. An export carries these and,
    /// resolved through their custodian, the external ones too.
    pub fn local(&self) -> impl Iterator<Item = &SecretInventoryEntry> {
        self.entries.iter().filter(|e| e.location.is_local())
    }

    /// Secrets an external custodian holds. A vault export resolves each one through its custodian
    /// and carries its plaintext, which the destination re-seals into its local vault; the custody
    /// arrangement does not travel.
    pub fn external(&self) -> impl Iterator<Item = &SecretInventoryEntry> {
        self.entries.iter().filter(|e| e.location.is_external())
    }

    /// Secrets referenced but not resolvable anywhere.
    pub fn unresolvable(&self) -> impl Iterator<Item = &SecretInventoryEntry> {
        self.entries.iter().filter(|e| e.location.is_unresolvable())
    }

    /// Look one up.
    pub fn get(&self, secret_id: &str) -> Option<&SecretInventoryEntry> {
        self.entries.iter().find(|e| e.secret_id == secret_id)
    }

    /// Error unless every secret in the inventory can be accounted for.
    ///
    /// The guard for anything that must be complete or not happen at all, so a broken reference
    /// surfaces as a refusal naming the id and what points at it. Nothing in the gateway calls it
    /// today: the vault export skips unresolvable references instead (see
    /// [`crate::vault_bundle::enumerate_secret_ids`]).
    pub fn ensure_all_resolvable(&self) -> Result<(), GatewayError> {
        let broken: Vec<String> = self
            .unresolvable()
            .map(|e| {
                let refs: Vec<String> = e
                    .referenced_by
                    .iter()
                    .map(|r| match r {
                        SecretReference::Connection(id) => format!("connection {id}"),
                        SecretReference::Capability(id) => format!("capability {id}"),
                    })
                    .collect();
                format!("'{}' (referenced by {})", e.secret_id, refs.join(", "))
            })
            .collect();
        if broken.is_empty() {
            return Ok(());
        }
        Err(GatewayError::Internal(format!(
            "{} secret(s) are referenced but held nowhere this gateway can reach: {}",
            broken.len(),
            broken.join("; ")
        )))
    }
}

/// Build the inventory: the union of the local sealed rows, the custody records, and every
/// `secret_id` a connection or capability names, minus empty ids and staged credentials.
///
/// A custody record wins over the presence of a local row, because that is the ordering
/// [`crate::backend::CustodyRouter`] resolves by; the two only overlap mid-enrolment.
pub fn secret_inventory(store: &dyn Store) -> Result<SecretInventory, GatewayError> {
    let mut located: BTreeMap<String, (SecretLocation, Option<i64>)> = BTreeMap::new();

    for id in store.list_secret_ids()? {
        if is_inventoried(&id) {
            located.insert(id, (SecretLocation::LocalVault, None));
        }
    }
    for custody in store.list_secret_custody()? {
        if is_inventoried(&custody.secret_id) {
            located.insert(
                custody.secret_id,
                (SecretLocation::from_custody(custody.kind), Some(custody.enrolled_at)),
            );
        }
    }

    let mut references: BTreeMap<String, Vec<SecretReference>> = BTreeMap::new();
    let mut note = |id: &str, reference: SecretReference| {
        if is_inventoried(id) {
            references.entry(id.to_string()).or_default().push(reference);
        }
    };
    for connection in store.list_connections()? {
        note(&connection.secret_id, SecretReference::Connection(connection.id.clone()));
    }
    for capability in store.list_capabilities()? {
        note(&capability.secret_id, SecretReference::Capability(capability.id.clone()));
    }

    for id in references.keys() {
        located
            .entry(id.clone())
            .or_insert((SecretLocation::Unresolvable, None));
    }

    let entries = located
        .into_iter()
        .map(|(secret_id, (location, enrolled_at))| {
            let mut referenced_by = references.remove(&secret_id).unwrap_or_default();
            referenced_by.sort();
            SecretInventoryEntry { secret_id, location, enrolled_at, referenced_by }
        })
        .collect();
    Ok(SecretInventory { entries })
}

/// Whether an id belongs in the inventory at all: non-empty (the "no credential yet" placeholder on
/// a connection) and not a staged credential.
fn is_inventoried(secret_id: &str) -> bool {
    !secret_id.is_empty() && !is_staging_secret_id(secret_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::MemoryStore;
    use crate::store::SecretCustody;
    use permaura_core::{seal, Cipher, Connection, SecretMetadata, SecretRecord};

    fn store() -> MemoryStore {
        MemoryStore::new()
    }

    #[test]
    fn a_rows_counted_bytes_are_its_stored_json() {
        let sealed = seal(Cipher::Aes256Gcm, b"kek", b"value").unwrap();
        let metadata = SecretMetadata { labels: vec!["production".into(), "A".repeat(500)], ..Default::default() };
        let record = SecretRecord { id: mint_staging_secret_id(), sealed, metadata };
        assert_eq!(
            secret_row_bytes(&record.id, &record.sealed, &record.metadata),
            serde_json::to_string(&record).unwrap().len()
        );
        assert_eq!(secret_metadata_bytes(&record.metadata), serde_json::to_string(&record.metadata).unwrap().len());
    }

    fn seal_secret(store: &MemoryStore, id: &str) {
        let sealed = seal(Cipher::Aes256Gcm, b"kek", b"value").unwrap();
        store
            .put_secret(SecretRecord { id: id.into(), sealed, metadata: SecretMetadata::default() })
            .unwrap();
    }

    fn connection(id: &str, secret_id: &str) -> Connection {
        Connection {
            id: id.into(),
            connector: "generic-http".into(),
            name: id.into(),
            label: id.into(),
            secret_id: secret_id.into(),
            capabilities: Vec::new(),
            disabled_capabilities: Vec::new(),
            disabled: false,
            allowed_hosts: Vec::new(),
            created_at: 0,
            redact_fields: Vec::new(),
            source: None,
            made_from: None,
        }
    }

    fn capability(id: &str, secret_id: &str) -> crate::connectors::Capability {
        crate::connectors::Capability {
            id: id.into(),
            description: "test".into(),
            risk: permaura_core::RiskTier::Low,
            action: permaura_core::Action::Read,
            requires_approval: false,
            resource: "conn".into(),
            secret_id: secret_id.into(),
            kind: crate::connectors::CapabilityKind::Http,
            command: None,
            http: None,
            ssh: None,
        }
    }

    #[test]
    fn the_inventory_is_the_union_of_every_layer() {
        let store = store();
        seal_secret(&store, "sec_local");
        store.put_secret_custody(SecretCustody::kms("sec_kms", b"ct".to_vec(), "cmk", 7)).unwrap();
        store
            .put_secret_custody(SecretCustody::infisical("sec_inf", Some("REMOTE".into()), 9))
            .unwrap();
        store.put_connection(connection("conn_a", "sec_local")).unwrap();
        store.put_capability(capability("cap.a", "sec_kms")).unwrap();

        let inv = secret_inventory(&store).unwrap();
        let ids: Vec<&str> = inv.entries.iter().map(|e| e.secret_id.as_str()).collect();
        assert_eq!(ids, ["sec_inf", "sec_kms", "sec_local"], "sorted union of all layers");

        assert_eq!(inv.get("sec_local").unwrap().location, SecretLocation::LocalVault);
        assert_eq!(inv.get("sec_kms").unwrap().location, SecretLocation::Kms);
        assert_eq!(inv.get("sec_inf").unwrap().location, SecretLocation::Infisical);
        assert_eq!(inv.get("sec_kms").unwrap().enrolled_at, Some(7));
        assert_eq!(inv.local().count(), 1);
        assert_eq!(inv.external().count(), 2);
        inv.ensure_all_resolvable().unwrap();
    }

    #[test]
    fn a_referenced_but_missing_secret_is_unresolvable_and_fails_loudly() {
        let store = store();
        store.put_connection(connection("conn_a", "sec_gone")).unwrap();
        store.put_capability(capability("cap.a", "sec_gone")).unwrap();

        let inv = secret_inventory(&store).unwrap();
        let entry = inv.get("sec_gone").unwrap();
        assert_eq!(entry.location, SecretLocation::Unresolvable);
        assert_eq!(
            entry.referenced_by,
            vec![
                SecretReference::Connection("conn_a".into()),
                SecretReference::Capability("cap.a".into()),
            ]
        );

        let err = inv.ensure_all_resolvable().unwrap_err();
        let rendered = format!("{err}");
        assert!(rendered.contains("sec_gone"), "the error must name the id: {rendered}");
        assert!(rendered.contains("connection conn_a"), "and what points at it: {rendered}");
    }

    /// A connection with no credential yet carries `secret_id: ""`. That is not a missing secret.
    #[test]
    fn the_empty_secret_id_is_never_an_entry() {
        let store = store();
        store.put_connection(connection("conn_new", "")).unwrap();
        let inv = secret_inventory(&store).unwrap();
        assert!(inv.entries.is_empty(), "an unconfigured connection contributes nothing");
        inv.ensure_all_resolvable().unwrap();
    }

    /// Staged credentials are sealed rows awaiting an approval that may never come. They are not
    /// part of the gateway's secret set and must not make an export look incomplete.
    #[test]
    fn staged_credentials_are_excluded_from_every_source() {
        let store = store();
        let parked = mint_staging_secret_id();
        let enrolled = mint_staging_secret_id();
        let referenced = mint_staging_secret_id();
        seal_secret(&store, &parked);
        store
            .put_secret_custody(SecretCustody::kms(&enrolled, b"ct".to_vec(), "cmk", 1))
            .unwrap();
        store.put_connection(connection("conn_a", &referenced)).unwrap();
        store.put_capability(capability("cap.a", &referenced)).unwrap();
        seal_secret(&store, "sec_real");

        let inv = secret_inventory(&store).unwrap();
        let ids: Vec<&str> = inv.entries.iter().map(|e| e.secret_id.as_str()).collect();
        assert_eq!(ids, ["sec_real"], "only the real secret survives");
        inv.ensure_all_resolvable().unwrap();
    }

    /// Every slot a connection named `staging_<anything>` derives is an ordinary credential, the exact shape gateway 1.3.46 minted for a parked change included: only the marker a hold mints now is staged.
    #[test]
    fn a_slot_a_connection_derives_is_never_staged() {
        assert!(is_staging_secret_id(&mint_staging_secret_id()));
        let legacy_shape = format!("sec_staging_{}", "0f".repeat(16));
        for ordinary in ["sec_staging_api_example_com", "sec_staging_", "staged_0f0f", legacy_shape.as_str(), "sec_sec:staging:x"] {
            assert!(!is_staging_secret_id(ordinary), "{ordinary}");
        }
        let store = store();
        for id in ["staging_api_example_com", &legacy_shape["sec_".len()..]] {
            let slot = format!("sec_{id}");
            store.put_connection(connection(id, &slot)).unwrap();
            seal_secret(&store, &slot);
        }
        let inv = secret_inventory(&store).unwrap();
        let ids: Vec<&str> = inv.entries.iter().map(|e| e.secret_id.as_str()).collect();
        assert_eq!(ids, [legacy_shape.as_str(), "sec_staging_api_example_com"]);
    }

    /// Mid-enrolment both a sealed row and a custody record exist. The router resolves through
    /// custody, so the inventory must agree, otherwise an export would copy a stale local copy and
    /// call it the secret.
    #[test]
    fn a_custody_record_wins_over_a_leftover_local_row() {
        let store = store();
        seal_secret(&store, "sec_moving");
        store
            .put_secret_custody(SecretCustody::kms("sec_moving", b"ct".to_vec(), "cmk", 3))
            .unwrap();

        let inv = secret_inventory(&store).unwrap();
        assert_eq!(inv.get("sec_moving").unwrap().location, SecretLocation::Kms);
        assert_eq!(inv.local().count(), 0);
    }

    #[test]
    fn a_secret_nothing_references_is_reported_as_an_orphan_not_an_error() {
        let store = store();
        seal_secret(&store, "sec_orphan");
        let inv = secret_inventory(&store).unwrap();
        assert!(inv.get("sec_orphan").unwrap().is_orphan());
        inv.ensure_all_resolvable().unwrap();
    }
}
