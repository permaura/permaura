//! The vault bundle's **payload**: what a gateway puts inside the sealed envelope, and what it does
//! with one on the way back in.
//!
//! [`permaura_core::bundle`] owns the envelope (sealing, the KDF, tamper-evidence). This module owns
//! the domain half: which entities travel, how a bundle is previewed without writing anything, and
//! how it is applied idempotently.
//!
//! ## What travels, and what deliberately does not
//!
//! Connections, policies, grants, **capabilities** and secret values travel. Capabilities are not
//! optional: `Connection.capabilities` holds ids only, and the enforcement loop resolves a capability
//! from its own table before any policy runs, so a bundle without them restores a gateway that looks
//! correct in the console and can do nothing.
//!
//! Excluded, each for its own reason:
//!
//! - **sessions**: per-gateway bearer state that means nothing on another gateway (tokens are stored
//!   as digests, so the rows are not bearers themselves); agents re-enrol on the destination.
//! - **enrolment codes**: bearer-equivalent; redeeming one mints a session.
//! - **approvals**: in-flight state that means nothing on a different gateway.
//! - **agents**: carried as preview metadata only. Writing agent rows is unsafe: `AgentStatus`
//!   defaults to `Approved`, so an omitted field reads as approved rather than pending.
//! - **the audit chain**: importing it would break its hash linkage, and a half-imported chain is
//!   worse than none.
//! - **approver device keys**: they live in gateway meta (or the file `PERMAURA_APPROVER_KEYS_PATH`
//!   names), which the bundle does not carry, and trusting a key takes a pairing with a possession
//!   proof (once a device is trusted, its co-signature or a recovery authority), which an import
//!   cannot supply.
//!
//! ## Command and SSH capabilities
//!
//! A bundle is a file someone can send you. A `CapabilityKind::Command` capability names a program
//! the gateway will run as its own OS user, and no other write path in the product can create one, so
//! import is the first. It is therefore gated behind an explicit opt-in *and* refused outright when
//! the destination is a hosted worker, where the program would execute inside Permaura's own
//! container rather than the operator's machine.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use permaura_core::{Connection, ConnectionSource, Grant, Policy, SecretMetadata};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::backend::SecretBackend;
use crate::connectors::{Capability, CapabilityKind, CommandSpec, HttpSpec, SshSpec};
use crate::error::GatewayError;
use crate::store::Store;

/// Secret ids with this prefix are credentials staged for a device-signed hold that was never
/// resolved. They are not live custody and must never be exported.
pub use crate::secret_inventory::STAGING_SECRET_PREFIX;

/// A secret's plaintext on its way into or out of a bundle.
///
/// Base64 on the wire, zeroized on drop. The value only ever exists in the clear inside the sealed
/// payload, so this type exists to bound how long it lives in this process rather than to protect the
/// artefact (the envelope does that). Its base64 is written from and read into buffers of exactly the
/// right size that are wiped too, so neither direction leaves an encoded copy behind; see
/// [`seal_payload`] and [`open_payload`] for the rest of the path.
#[derive(Clone, PartialEq, Eq)]
pub struct SecretValue(Zeroizing<Vec<u8>>);

impl zeroize::ZeroizeOnDrop for SecretValue {}

impl SecretValue {
    /// Wrap plaintext bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        SecretValue(Zeroizing::new(bytes))
    }

    /// Borrow the plaintext.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Never renders the value, so a payload can be `{:?}`-logged by accident without leaking.
impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretValue(<redacted>)")
    }
}

impl Serialize for SecretValue {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let engine = base64::engine::general_purpose::STANDARD;
        let len = base64::encoded_len(self.0.len(), true).ok_or_else(|| serde::ser::Error::custom("a secret too large to encode"))?;
        let mut encoded = Zeroizing::new(vec![0u8; len]);
        let written = engine.encode_slice(&*self.0, &mut encoded).map_err(serde::ser::Error::custom)?;
        s.serialize_str(std::str::from_utf8(&encoded[..written]).map_err(serde::ser::Error::custom)?)
    }
}

impl<'de> Deserialize<'de> for SecretValue {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Base64;
        impl<'de> serde::de::Visitor<'de> for Base64 {
            type Value = SecretValue;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a base64 secret value")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<SecretValue, E> {
                let mut decoded = Zeroizing::new(vec![0u8; base64::decoded_len_estimate(v.len())]);
                let written = base64::engine::general_purpose::STANDARD
                    .decode_slice(v.as_bytes(), &mut decoded)
                    .map_err(E::custom)?;
                decoded.truncate(written);
                Ok(SecretValue(decoded))
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<SecretValue, E> {
                let v = Zeroizing::new(v);
                self.visit_str(&v)
            }
        }
        d.deserialize_string(Base64)
    }
}

impl permaura_core::TypedPayload for BundlePayload {}

/// Seal `payload` into a bundle under `passphrase` at the export's KDF cost: serialized straight into
/// the sealing buffer, never through a `serde_json::Value`, so no credential in it is left in a string
/// nothing wipes.
pub fn seal_payload(
    passphrase: &[u8],
    payload: &BundlePayload,
    created_at_ms: i64,
    source: permaura_core::BundleSource,
) -> Result<permaura_core::VaultBundle, GatewayError> {
    Ok(permaura_core::seal_bundle(passphrase, payload, created_at_ms, source)?)
}

/// Open a bundle and read its payload straight from the wiped plaintext, never through a
/// `serde_json::Value`.
pub fn open_payload(bundle: &permaura_core::VaultBundle, passphrase: &[u8]) -> Result<BundlePayload, OpenPayloadError> {
    let opened = permaura_core::open_bundle(bundle, passphrase).map_err(OpenPayloadError::Open)?;
    opened.payload().map_err(|e| OpenPayloadError::Unreadable(e.to_string()))
}

/// Why [`open_payload`] failed, kept apart so each caller words a wrong passphrase its own way.
#[derive(Debug)]
pub enum OpenPayloadError {
    /// The envelope did not open: [`permaura_core::open_bundle`]'s error.
    Open(permaura_core::PermauraError),
    /// The envelope opened and the payload is not one this build reads, with the parser's reason.
    Unreadable(String),
}

/// One secret in a bundle: its id, its non-secret metadata, and its resolved plaintext.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleSecret {
    /// The secret id capabilities and connections refer to.
    pub id: String,
    /// Non-secret metadata, carried so risk classification and execution limits survive the move.
    pub metadata: SecretMetadata,
    /// Which custody layer it was resolved from on the source gateway. Informational: the
    /// destination re-seals everything into its own local vault.
    pub custody: String,
    /// The plaintext.
    pub value: SecretValue,
}

/// Serializable mirror of [`Capability`], which has no serde derives of its own.
///
/// Mirrors the private `CapabilityWire` the SQLite store keeps, so the JSON shape matches what that
/// store already persists. Consolidating the two into one shared type is a worthwhile follow-up; it
/// is not done here to avoid colliding with concurrent work in the store layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityRecord {
    /// Capability id, e.g. `braintree.transactions.search`.
    pub id: String,
    /// Human description.
    pub description: String,
    /// Risk tier.
    pub risk: permaura_core::RiskTier,
    /// Read/write classification.
    pub action: permaura_core::Action,
    /// Whether an invoke needs human approval.
    pub requires_approval: bool,
    /// The connection id this capability belongs to.
    pub resource: String,
    /// The secret it resolves at invoke time.
    pub secret_id: String,
    /// Which transport backs it.
    #[serde(default)]
    pub kind: CapabilityKind,
    /// Command transport spec, when `kind` is Command.
    #[serde(default)]
    pub command: Option<CommandSpec>,
    /// HTTP transport spec, when `kind` is Http.
    #[serde(default)]
    pub http: Option<HttpSpec>,
    /// SSH transport spec, when `kind` is Ssh.
    #[serde(default)]
    pub ssh: Option<SshSpec>,
}

impl From<&Capability> for CapabilityRecord {
    fn from(c: &Capability) -> Self {
        CapabilityRecord {
            id: c.id.clone(),
            description: c.description.clone(),
            risk: c.risk,
            action: c.action,
            requires_approval: c.requires_approval,
            resource: c.resource.clone(),
            secret_id: c.secret_id.clone(),
            kind: c.kind,
            command: c.command.clone(),
            http: c.http.clone(),
            ssh: c.ssh.clone(),
        }
    }
}

impl From<CapabilityRecord> for Capability {
    fn from(w: CapabilityRecord) -> Self {
        Capability {
            id: w.id,
            description: w.description,
            risk: w.risk,
            action: w.action,
            requires_approval: w.requires_approval,
            resource: w.resource,
            secret_id: w.secret_id,
            kind: w.kind,
            command: w.command,
            http: w.http,
            ssh: w.ssh,
        }
    }
}

/// One agent on the source gateway. Carried so the preview can name the agents that do not exist
/// here; never written on import.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRef {
    /// The agent's id on the source gateway.
    pub id: String,
    /// Display name on the source gateway.
    pub name: String,
}

/// Everything inside the sealed envelope.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BundlePayload {
    /// Connections, serialized whole. Partial connection records lose enforcement-bearing fields
    /// (`disabled`, `disabled_capabilities`, `allowed_hosts`), two of which fail OPEN when absent.
    /// `redact_fields` would be a third, so an import re-derives it rather than trusting its absence;
    /// see [`with_catalog_redaction`].
    #[serde(default)]
    pub connections: Vec<Connection>,
    /// Policies, whole.
    #[serde(default)]
    pub policies: Vec<Policy>,
    /// Grants, whole.
    #[serde(default)]
    pub grants: Vec<Grant>,
    /// Capability definitions. Without these an imported connection is inert.
    #[serde(default)]
    pub capabilities: Vec<CapabilityRecord>,
    /// Resolved secret values.
    #[serde(default)]
    pub secrets: Vec<BundleSecret>,
    /// Every agent on the source gateway (id and display name), so the preview can name the ones
    /// that do not exist here. Preview metadata only.
    #[serde(default)]
    pub agents: Vec<AgentRef>,
    /// What was deliberately left out, and why, so the artefact is self-describing.
    #[serde(default)]
    pub excluded: BTreeMap<String, String>,
}

/// The reasons recorded in [`BundlePayload::excluded`], so a customer reading the file can see that
/// the omissions are choices rather than gaps.
fn exclusion_notes() -> BTreeMap<String, String> {
    [
        ("sessions", "sessions are per-gateway bearer state; agents re-enrol on the destination"),
        ("enrolment_codes", "bearer-equivalent: redeeming one mints a session"),
        ("approvals", "in-flight state that does not transfer"),
        ("audit_events", "importing the chain would break its hash linkage"),
        ("approver_keys", "trust roots are never written by an import"),
        ("agent_records", "listed for preview only; agents re-enrol on the destination"),
        // Everything below travels nowhere and used to say nothing, which is the worse failure: the
        // first two make the destination LESS protected than the source, and an operator who is not
        // told simply does not know to restore them.
        (
            "approval_floor",
            "policy lives in gateway meta, which the bundle does not carry: the destination starts at its own floor, which may be lower: re-set it after importing",
        ),
        (
            "secret_custody",
            "an externally-held secret (KMS, Infisical) is RESOLVED to plaintext on export and lands as an ordinary local vault row: the value works, the custody arrangement does not travel: re-enrol it",
        ),
        (
            "connector_manifests",
            "installed connector manifests live outside the bundle; re-install them on the destination",
        ),
        (
            "device_registrations",
            "push/device registrations are per-gateway; notifications will not reach anyone until devices re-register",
        ),
        (
            "broker_pause",
            "the pause switch lives in gateway meta, which the bundle does not carry: the destination keeps its own pause state, so pause it again after importing if the source was paused",
        ),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect()
}

/// True if `secret_id` is exportable at all.
pub fn is_exportable_secret(secret_id: &str) -> bool {
    !secret_id.is_empty() && !crate::secret_inventory::is_staging_secret_id(secret_id)
}

/// Every secret id an export must carry, deduplicated and with staging ids removed.
///
/// Delegates to [`crate::secret_inventory::secret_inventory`], which is the authoritative seam: it
/// unions the local sealed rows, the per-secret custody records, and every `Connection.secret_id`
/// and `Capability.secret_id`. Using `Store::list_secret_ids` alone (the obvious implementation)
/// sees only the local rows and so omits every externally-enrolled secret, which is the exact silent
/// incompleteness a bundle exists to prevent.
///
/// Only ids some custodian actually holds are returned. A reference that nothing can resolve is a
/// legitimate state (a connection whose credential was revoked still names its old `secret_id`),
/// so it is left out of the bundle rather than failing the export. [`dangling_secret_references`]
/// can list such ids, but the export route does not call it, so nothing in its response or audit
/// record names them. The hard failure belongs one step later: an id that IS held but could not be
/// resolved (KMS unreachable, Infisical down) must stop the export, because that is the
/// silent-incompleteness case.
///
/// This returns ids only. Callers needing to distinguish local from external custody should use
/// `secret_inventory` directly.
pub fn enumerate_secret_ids(store: &dyn Store) -> Result<BTreeSet<String>, GatewayError> {
    let inventory = crate::secret_inventory::secret_inventory(store)?;
    Ok(inventory
        .entries
        .into_iter()
        .filter(|e| !e.location.is_unresolvable())
        .map(|e| e.secret_id)
        .collect())
}

/// Secret ids referenced by a connection or capability that no custodian holds.
///
/// Not an error: the connection travels in the bundle as a definition without a credential, and the
/// operator re-adds one after import. The export route does not call this, so neither its response
/// nor its audit record names these ids.
pub fn dangling_secret_references(store: &dyn Store) -> Result<Vec<String>, GatewayError> {
    Ok(crate::secret_inventory::secret_inventory(store)?
        .unresolvable()
        .map(|e| e.secret_id.clone())
        .collect())
}

/// What a bundle would do to this gateway, computed without writing anything.
///
/// Deliberately carries no secret value: it is rendered in a browser and, on a hosted destination,
/// travels back through the permaura.com proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportManifest {
    /// Unix-millisecond time the bundle was produced.
    pub created_at_ms: i64,
    /// The exporting gateway's id, as it described itself.
    pub source_gateway_id: String,
    /// `hosted` or `self-run`, as the exporter described itself.
    pub source_mode: String,
    /// How many of each entity the bundle carries.
    pub counts: BTreeMap<String, usize>,
    /// One row per connection, with whether it already exists here.
    pub connections: Vec<ManifestConnection>,
    /// Ids that already exist on this gateway, by entity.
    pub conflicts: BTreeMap<String, Vec<String>>,
    /// Capabilities that would run a program on this machine. Empty in the normal case.
    pub command_capabilities: Vec<RiskyCapability>,
    /// Capabilities that would open an SSH session to a host named in the bundle.
    pub ssh_capabilities: Vec<RiskyCapability>,
    /// Agent ids the bundle lists that do not exist here; grants naming them would be inert.
    pub missing_agents: Vec<String>,
    /// What the bundle records as deliberately omitted.
    pub excluded: BTreeMap<String, String>,
    /// Why importing it from where this preview was asked would be refused (see
    /// [`broker_import_refusals`]). Empty when it would apply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub broker_refusals: Vec<String>,
    /// Capabilities whose posture the import raises to the floor this gateway gives their shape ([`raise_to_floor`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raised: Vec<String>,
}

/// One connection row in a preview.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestConnection {
    /// Connection id.
    pub id: String,
    /// Connector family.
    pub connector: String,
    /// Operator-chosen name.
    pub name: String,
    /// How many capabilities travel with it.
    pub capability_count: usize,
    /// Whether an id-identical connection already exists here.
    pub conflict: bool,
    /// Whether the source had it paused. Surfaced because importing it live would be a security
    /// regression the operator did not ask for.
    pub disabled: bool,
    /// The redaction list the import will store on it: the bundle's own, or, for a bundle that
    /// carries none, the one re-derived from this gateway's catalog.
    #[serde(default)]
    pub redact_fields: Vec<String>,
    /// Where a discovered connection's capabilities came from, as the source recorded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<ConnectionSource>,
}

/// A capability whose transport can act outside the gateway's HTTP egress screening.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskyCapability {
    /// Capability id.
    pub id: String,
    /// The connection it belongs to.
    pub connection_id: String,
    /// The program to be run, or the SSH host to be reached. Shown so the operator can judge it.
    pub target: String,
}

/// How to resolve an id that already exists on the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum OnConflict {
    /// Leave what is here; do not write the bundle's version. The default, so an import can never
    /// silently overwrite.
    #[default]
    Skip,
    /// Overwrite with the bundle's version. Only ever set by an explicit operator action.
    Replace,
}

/// Import options.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ImportOptions {
    /// What to do about ids that already exist here.
    #[serde(default)]
    pub on_conflict: OnConflict,
    /// Whether to write capabilities that run a local program. Off unless the operator opted in.
    #[serde(default)]
    pub allow_command_capabilities: bool,
    /// True when this gateway is a hosted worker. Command capabilities are refused outright then,
    /// regardless of the opt-in, because the program would run inside Permaura's own container.
    #[serde(default)]
    pub hosted: bool,
    /// The revocation state this gateway runs under, which judges the origin an imported connection claims. Set by the caller, never by a request body.
    #[serde(skip)]
    pub revocation: Option<std::sync::Arc<crate::manifest::Revocation>>,
}

/// What an import actually wrote.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImportOutcome {
    /// Entities written, by kind.
    pub written: BTreeMap<String, usize>,
    /// Entities left alone because they already existed and the operator chose skip.
    pub skipped: BTreeMap<String, usize>,
    /// Capabilities refused, with the reason.
    pub refused: Vec<String>,
    /// Capabilities written with a posture raised to the floor this gateway gives their shape ([`raise_to_floor`]).
    #[serde(default)]
    pub raised: Vec<String>,
}

fn bump(map: &mut BTreeMap<String, usize>, key: &str) {
    *map.entry(key.to_string()).or_insert(0) += 1;
}

/// A bundled connection as an import will write it.
///
/// A bundle from a gateway that predates `Connection::redact_fields` carries no list, and importing
/// that as "redact nothing" would fail open the moment the destination lacks the manifest. So an
/// empty list is re-derived from this gateway's catalog manifest for the connection's connector. An
/// empty list and an absent one are the same bytes on the wire (the field is skipped when empty), so
/// both take this path; for a list that was genuinely empty at the source it can only add redaction,
/// which the per-call union would apply anyway while the manifest is installed. `source` needs no
/// such help: a bundle without it imports `None`, which is what every non-discovered connection has.
fn with_catalog_redaction(
    store: &dyn Store,
    mut c: Connection,
    revocation: Option<&crate::manifest::Revocation>,
) -> Result<Connection, GatewayError> {
    if c.redact_fields.is_empty() {
        c.redact_fields = crate::presets::manifest_redact_fields(store, &c.connector)?;
    }
    c.made_from = imported_origin(&c, revocation);
    Ok(c)
}

/// What an imported connection keeps of the origin its bundle claims: only an installed origin this gateway's own list refuses. A claim can then only tighten what the connection may do, never loosen it; anything else is judged by what is installed here, as a connection that records no origin is.
fn imported_origin(c: &Connection, revocation: Option<&crate::manifest::Revocation>) -> Option<permaura_core::CatalogOrigin> {
    match (&c.made_from, revocation) {
        (Some(origin @ permaura_core::CatalogOrigin::Installed { version, key_id: Some(key) }), Some(revocation))
            if revocation.refuses_origin(&c.connector, *version, Some(key)).is_some() =>
        {
            Some(origin.clone())
        }
        _ => None,
    }
}

/// Build the payload for an export.
///
/// `resolved` is the plaintext for each exportable secret id, produced by the caller through
/// `SecretBackend::resolve` so this function stays free of custody concerns and testable without a
/// backend. The caller must pass an entry for **every** id from [`enumerate_secret_ids`]; a missing
/// one is an error rather than an omission, because a quietly partial bundle is the failure mode this
/// whole feature exists to prevent.
pub fn build_payload(
    store: &dyn Store,
    resolved: Vec<(String, String, SecretValue)>,
) -> Result<BundlePayload, GatewayError> {
    let required = enumerate_secret_ids(store)?;
    let provided: BTreeSet<String> = resolved.iter().map(|(id, _, _)| id.clone()).collect();
    let missing: Vec<&String> = required.difference(&provided).collect();
    if !missing.is_empty() {
        return Err(GatewayError::Internal(format!(
            "refusing to export a partial bundle: {} secret(s) could not be resolved ({}). \
             A bundle that silently omits credentials is worse than no bundle.",
            missing.len(),
            missing.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
        )));
    }

    let secret_meta: BTreeMap<String, SecretMetadata> = store
        .list_secret_ids()?
        .into_iter()
        .filter_map(|id| store.get_secret(&id).ok().flatten().map(|r| (r.id, r.metadata)))
        .collect();

    let grants = store.list_grants()?;
    let agents = store
        .list_agents()?
        .into_iter()
        .map(|a| AgentRef { id: a.id, name: a.name })
        .collect();

    Ok(BundlePayload {
        connections: store.list_connections()?,
        policies: store.list_policies()?,
        grants,
        capabilities: store.list_capabilities()?.iter().map(CapabilityRecord::from).collect(),
        secrets: resolved
            .into_iter()
            .map(|(id, custody, value)| BundleSecret {
                metadata: secret_meta.get(&id).cloned().unwrap_or_default(),
                id,
                custody,
                value,
            })
            .collect(),
        agents,
        excluded: exclusion_notes(),
    })
}

/// Describe what `payload` would do to `store`, writing nothing.
pub fn preview(
    store: &dyn Store,
    payload: &BundlePayload,
    created_at_ms: i64,
    source_gateway_id: String,
    source_mode: String,
) -> Result<ImportManifest, GatewayError> {
    let existing_connections: BTreeSet<String> =
        store.list_connections()?.into_iter().map(|c| c.id).collect();
    let existing_policies: BTreeSet<String> =
        store.list_policies()?.into_iter().map(|p| p.id).collect();
    let existing_grants: BTreeSet<String> =
        store.list_grants()?.into_iter().map(|g| g.grant_id).collect();
    let existing_secrets: BTreeSet<String> = store.list_secret_ids()?.into_iter().collect();
    let existing_caps: BTreeSet<String> =
        store.list_capabilities()?.into_iter().map(|c| c.id).collect();
    let existing_agents: BTreeSet<String> =
        store.list_agents()?.into_iter().map(|a| a.id).collect();

    let caps_by_connection = |cid: &str| {
        payload.capabilities.iter().filter(|c| c.resource == cid).count()
    };

    let connections = payload
        .connections
        .iter()
        .map(|c| {
            let c = with_catalog_redaction(store, c.clone(), None)?;
            Ok(ManifestConnection {
                capability_count: caps_by_connection(&c.id),
                conflict: existing_connections.contains(&c.id),
                disabled: c.disabled,
                id: c.id,
                connector: c.connector,
                name: c.name,
                redact_fields: c.redact_fields,
                source: c.source,
            })
        })
        .collect::<Result<Vec<_>, GatewayError>>()?;

    let mut conflicts = BTreeMap::new();
    let collect = |ids: Vec<String>| -> Vec<String> { ids };
    conflicts.insert(
        "connections".into(),
        collect(payload.connections.iter().filter(|c| existing_connections.contains(&c.id)).map(|c| c.id.clone()).collect()),
    );
    conflicts.insert(
        "policies".into(),
        collect(payload.policies.iter().filter(|p| existing_policies.contains(&p.id)).map(|p| p.id.clone()).collect()),
    );
    conflicts.insert(
        "grants".into(),
        collect(payload.grants.iter().filter(|g| existing_grants.contains(&g.grant_id)).map(|g| g.grant_id.clone()).collect()),
    );
    conflicts.insert(
        "secrets".into(),
        collect(payload.secrets.iter().filter(|s| existing_secrets.contains(&s.id)).map(|s| s.id.clone()).collect()),
    );
    conflicts.insert(
        "capabilities".into(),
        collect(payload.capabilities.iter().filter(|c| existing_caps.contains(&c.id)).map(|c| c.id.clone()).collect()),
    );

    let command_capabilities = payload
        .capabilities
        .iter()
        .filter(|c| matches!(c.kind, CapabilityKind::Command))
        .map(|c| RiskyCapability {
            id: c.id.clone(),
            connection_id: c.resource.clone(),
            target: c.command.as_ref().map(|s| s.program.clone()).unwrap_or_default(),
        })
        .collect();

    let ssh_capabilities = payload
        .capabilities
        .iter()
        .filter(|c| matches!(c.kind, CapabilityKind::Ssh))
        .map(|c| RiskyCapability {
            id: c.id.clone(),
            connection_id: c.resource.clone(),
            target: c.ssh.as_ref().map(|s| s.target.host.clone()).unwrap_or_default(),
        })
        .collect();

    let bundled_agents: BTreeSet<String> = payload.agents.iter().map(|a| a.id.clone()).collect();
    let mut missing_agents: Vec<String> = bundled_agents
        .into_iter()
        .filter(|id| !existing_agents.contains(id))
        .collect();
    missing_agents.sort();

    let counts = [
        ("connections", payload.connections.len()),
        ("policies", payload.policies.len()),
        ("grants", payload.grants.len()),
        ("capabilities", payload.capabilities.len()),
        ("secrets", payload.secrets.len()),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v))
    .collect();

    Ok(ImportManifest {
        created_at_ms,
        source_gateway_id,
        source_mode,
        counts,
        connections,
        conflicts,
        command_capabilities,
        ssh_capabilities,
        missing_agents,
        excluded: payload.excluded.clone(),
        broker_refusals: Vec::new(),
        raised: raise_to_floor(store, &payload.connections, &mut payload.capabilities.clone())?,
    })
}

/// One bundle key derivation (a seal or an open) at a time in this process. Each costs 256 MiB of
/// Argon2 memory and a hosted worker has 512 MiB, so two at once could end the worker and every call in
/// flight on it. The routes wait for it and give up with a 429.
pub static BUNDLE_KDF: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(1);

/// Why `payload` may not be applied on the strength of a bearer alone, for an import that arrived over
/// the broker while this gateway requires a device signature for control-plane changes. Empty when the
/// import only adds new, self-contained definitions and credentials.
///
/// Every sibling write (a policy, a grant, a credential, a connection patch) is held for a device
/// signature in that situation, and an import is the one write that can do what they do in bulk: point
/// an existing capability at a new host while it keeps its sealed credential, attach a new capability to
/// a credential that is already here, or add the policies and grants that decide who may act. So an
/// import is accepted only when nothing it writes replaces or reaches into what is already here, and it
/// carries no policy or grant. Those are recreated from the console afterwards, where a device signs.
/// Ids the import would skip are ignored, because a skipped entity is never written.
/// An id `custody` holds externally counts as already here, as in [`credential_reach_refusals`]: this branch also serves a gateway whose every device was revoked, and its sticky enrolment must not cost it the no-trusted-device protection.
pub fn broker_import_refusals(
    store: &dyn Store,
    custody: &dyn SecretBackend,
    payload: &BundlePayload,
    on_conflict: OnConflict,
) -> Result<Vec<String>, GatewayError> {
    import_refusals(store, custody, payload, on_conflict, true)
}

/// The part of [`broker_import_refusals`] that moves a credential already here: replacing a connection
/// or capability, or attaching a new one to a connection or credential this gateway holds. Applied to
/// a loopback import once a device is trusted, where a policy or grant write is the operator's as it
/// is through every other loopback route, but a credential's destination is not.
///
/// An id the payload names also counts as already here when `custody` holds it externally ([`SecretBackend::holds_externally`]).
/// A legacy env enrolment or a dynamic secret has neither a local row nor a custody record, and once the connection that used it is deleted nothing here names it, yet it still resolves.
pub fn credential_reach_refusals(
    store: &dyn Store,
    custody: &dyn SecretBackend,
    payload: &BundlePayload,
    on_conflict: OnConflict,
) -> Result<Vec<String>, GatewayError> {
    import_refusals(store, custody, payload, on_conflict, false)
}

fn import_refusals(
    store: &dyn Store,
    custody: &dyn SecretBackend,
    payload: &BundlePayload,
    on_conflict: OnConflict,
    who_may_act: bool,
) -> Result<Vec<String>, GatewayError> {
    let replace = on_conflict == OnConflict::Replace;
    let existing_connections: BTreeSet<String> =
        store.list_connections()?.into_iter().map(|c| c.id).collect();
    let existing_caps: BTreeSet<String> =
        store.list_capabilities()?.into_iter().map(|c| c.id).collect();
    let existing_policies: BTreeSet<String> =
        store.list_policies()?.into_iter().map(|p| p.id).collect();
    let existing_grants: BTreeSet<String> =
        store.list_grants()?.into_iter().map(|g| g.grant_id).collect();
    // A secret a connection or capability names is live custody even when no local row holds it.
    let mut existing_secrets: BTreeSet<String> = crate::secret_inventory::secret_inventory(store)?
        .entries
        .into_iter()
        .map(|e| e.secret_id)
        .chain(store.list_secret_ids()?)
        .collect();
    let named: Vec<String> = payload
        .connections
        .iter()
        .map(connection_slot)
        .chain(payload.capabilities.iter().map(|c| c.secret_id.clone()))
        .collect();
    for id in named {
        if !id.is_empty() && !existing_secrets.contains(&id) && custody.holds_externally(&id)? {
            existing_secrets.insert(id);
        }
    }

    let mut refusals = Vec::new();
    let mut note = |what: &str, ids: Vec<String>| {
        if !ids.is_empty() {
            refusals.push(format!("{what}: {}", ids.join(", ")));
        }
    };

    if replace {
        let mut replaced: Vec<String> = Vec::new();
        replaced.extend(payload.connections.iter().filter(|c| existing_connections.contains(&c.id)).map(|c| format!("connection {}", c.id)));
        replaced.extend(payload.capabilities.iter().filter(|c| existing_caps.contains(&c.id)).map(|c| format!("capability {}", c.id)));
        if who_may_act {
            replaced.extend(payload.secrets.iter().filter(|s| existing_secrets.contains(&s.id)).map(|s| format!("secret {}", s.id)));
        }
        note("it would replace what is already here", replaced);
    }

    // The connections this import adds, the only ones its other entities may attach to.
    let fresh_connections: BTreeSet<&str> = payload
        .connections
        .iter()
        .filter(|c| !existing_connections.contains(&c.id))
        .map(|c| c.id.as_str())
        .collect();
    let written_caps = payload.capabilities.iter().filter(|c| replace || !existing_caps.contains(&c.id));
    let mut reaching = Vec::new();
    for cap in written_caps {
        if !fresh_connections.contains(cap.resource.as_str()) {
            reaching.push(format!("capability {} on connection {}", cap.id, cap.resource));
        }
        if existing_secrets.contains(&cap.secret_id) {
            reaching.push(format!("capability {} using secret {}", cap.id, cap.secret_id));
        }
    }
    for c in payload.connections.iter().filter(|c| fresh_connections.contains(c.id.as_str())) {
        let slot = connection_slot(c);
        if existing_secrets.contains(&slot) {
            reaching.push(format!("connection {} using secret {slot}", c.id));
        }
    }
    note("it would attach new definitions to connections or credentials already here", reaching);
    if !who_may_act {
        return Ok(refusals);
    }

    let policies: Vec<String> = payload
        .policies
        .iter()
        .filter(|p| replace || !existing_policies.contains(&p.id))
        .map(|p| p.id.clone())
        .collect();
    note("it carries policies, which change who may act", policies);
    let grants: Vec<String> = payload
        .grants
        .iter()
        .filter(|g| replace || !existing_grants.contains(&g.grant_id))
        .map(|g| g.grant_id.clone())
        .collect();
    note("it carries grants, which change who may act", grants);
    Ok(refusals)
}

/// The slot an imported connection reaches: its `secret_id`, or when it names none, the one its first credential write and a re-sync derive.
fn connection_slot(c: &Connection) -> String {
    if c.secret_id.is_empty() {
        crate::rest::derived_secret_slot(&c.id)
    } else {
        c.secret_id.clone()
    }
}

/// Everything [`apply`] refuses, checked before anything is written or held. `store` is read for the
/// connections already here, which a bundle's capability may attach to.
pub fn validate(store: &dyn Store, payload: &BundlePayload, opts: &ImportOptions) -> Result<(), GatewayError> {
    refuse_a_family_elsewhere(store, payload)?;
    for s in &payload.secrets {
        crate::secret_inventory::refuse_staging_secret_id("secret", &s.id)?;
    }
    for c in &payload.connections {
        crate::rest::refuse_reserved_id("connection", &c.id)?;
        crate::secret_inventory::refuse_staging_secret_id("the secret bound by connection", &connection_slot(c))?;
    }
    for cap in &payload.capabilities {
        let shape_matches = match cap.kind {
            CapabilityKind::Http => cap.command.is_none() && cap.ssh.is_none(),
            CapabilityKind::Command => cap.command.is_some() && cap.http.is_none() && cap.ssh.is_none(),
            CapabilityKind::Ssh => cap.ssh.is_some() && cap.http.is_none() && cap.command.is_none(),
        };
        if !shape_matches {
            return Err(GatewayError::BadRequest(format!("capability '{}' has a transport spec that does not match its kind", cap.id)));
        }
        if let Some(why) = cap.http.as_ref().and_then(crate::connectors::method_override_refusal) {
            return Err(GatewayError::BadRequest(format!("capability '{}' is refused: {why}", cap.id)));
        }
        crate::rest::refuse_reserved_id("capability", &cap.id)?;
        crate::rest::refuse_reserved_id("connection", &cap.resource)?;
        crate::secret_inventory::refuse_staging_secret_id("the secret bound by capability", &cap.secret_id)?;
        if let Some(host) = cap.ssh.as_ref().map(|s| s.target.host.as_str()).filter(|_| opts.hosted) {
            crate::connectors::screen_host(host).map_err(|e| {
                GatewayError::Denied(format!(
                    "capability '{}' opens SSH sessions to '{host}', and a hosted gateway opens them to public addresses only ({e})",
                    cap.id
                ))
            })?;
        }
        if matches!(cap.kind, CapabilityKind::Command) {
            if opts.hosted {
                return Err(GatewayError::Denied(format!(
                    "capability '{}' runs a local program, which is never accepted on a hosted \
                     worker: the program would execute inside Permaura's own container. Import this \
                     bundle into a self-run gateway instead.",
                    cap.id
                )));
            }
            if !opts.allow_command_capabilities {
                return Err(GatewayError::Denied(format!(
                    "capability '{}' runs a local program on this machine. Re-run with the \
                     command-capability opt-in if that is what you intend.",
                    cap.id
                )));
            }
        }
    }
    Ok(())
}

/// Refuse a bundle that would point a connection of a family the gateway pins to a fixed host
/// (GitHub, Braintree, Vercel, fal) at any other host, as `POST /v1/connections`, a preset and a
/// manifest install already do: a bundle is a file someone can send you, and it may carry a capability
/// for a connection it brings or for one already here. Both are read, since whether the import writes
/// the bundle's connection over the one here depends on its conflict mode.
fn refuse_a_family_elsewhere(store: &dyn Store, payload: &BundlePayload) -> Result<(), GatewayError> {
    for cap in &payload.capabilities {
        let Some(http) = &cap.http else { continue };
        let mut families: Vec<String> =
            payload.connections.iter().filter(|c| c.id == cap.resource).map(|c| c.connector.clone()).collect();
        families.extend(store.get_connection(&cap.resource)?.map(|c| c.connector));
        let imported = crate::connectors::shown_host(&http.base_url);
        for family in families {
            let pinned = crate::connectors::family_hosts(&family);
            if pinned.is_empty() || crate::connectors::on_family_host(&family, &http.base_url) {
                continue;
            }
            return Err(GatewayError::BadRequest(format!(
                "capability '{}' is on '{}', a '{family}' connection the gateway sends to {} only, and it would send that credential to {} instead",
                cap.id,
                cap.resource,
                pinned.join(", "),
                imported.as_deref().unwrap_or("a host it does not name")
            )));
        }
    }
    Ok(())
}

/// Raise every bundled capability whose posture is below the floor this gateway gives its shape, and
/// return their ids. A bundle is a file someone can send you, and a capability's risk is the one part
/// of its posture a policy it also carries cannot lower, so a bundle may raise it and never lower it,
/// as an unsigned manifest may ([`crate::presets::held_to_shape`]). The floor is a built-in connector's
/// own definition of the same action for a capability with no pinned shape, the line of a manifest
/// Permaura vouches for that pins the same method and path, and otherwise what the method and path
/// give. A command or SSH capability has no such floor and keeps what it carries.
pub fn raise_to_floor(store: &dyn Store, connections: &[Connection], capabilities: &mut [CapabilityRecord]) -> Result<Vec<String>, GatewayError> {
    let mut raised = Vec::new();
    for cap in capabilities.iter_mut() {
        // The owner's own decision on the source gateway is theirs to make again here, not the file's.
        if let Some(http) = cap.http.as_mut() {
            http.owner_posture = None;
        }
        let mut sources: Vec<Connection> = connections.iter().filter(|c| c.id == cap.resource).cloned().collect();
        sources.extend(store.get_connection(&cap.resource)?);
        let connectors: Vec<String> = sources.iter().map(|c| c.connector.clone()).collect();
        let action_id = cap.id.split_once('.').map_or(cap.id.as_str(), |(_, action)| action).to_string();
        let declared = (cap.action, cap.risk, cap.requires_approval);
        let mut held = declared;
        match (cap.kind, &cap.http) {
            (CapabilityKind::Http, Some(http)) => {
                let vouched = connectors.iter().find_map(|connector| {
                    vouched_preset(store, connector).ok().flatten().and_then(|p| p.vouched_posture(&action_id, http.method, &http.base_url, &http.path))
                });
                held = match vouched {
                    Some(floor) => crate::presets::held_to_vouched(floor, held),
                    // The method's floor still holds below the namespace, so an operation word in the namespace raises nothing and a write declared a read is raised.
                    None if !sources.is_empty() && sources.iter().all(|c| c.connector == "wordpress") => {
                        let stored: Capability = cap.clone().into();
                        sources.iter().fold(held, |posture, c| {
                            let namespaces = c.source.as_ref().map(|s| s.namespaces.as_slice()).unwrap_or_default();
                            let below = crate::wordpress::below_namespace(&http.path, namespaces);
                            let posture = crate::presets::held_to_shape(http.method, below, &action_id, posture);
                            crate::wordpress::stored_floor(&c.id, &stored, namespaces)
                                .map_or(posture, |floor| crate::presets::held_to_vouched(floor, posture))
                        })
                    }
                    None => crate::presets::held_to_shape(http.method, &http.path, &action_id, held),
                };
            }
            (CapabilityKind::Http, None) => {
                // Dispatch shapes it as the first built-in family it finds, and as the generic proxy otherwise.
                let families = connectors.iter().map(String::as_str).chain([cap.id.split('.').next().unwrap_or_default(), "generic-http"]);
                let built_in = families
                    .flat_map(|family| crate::rest::connector_capabilities(family, "r", "s"))
                    .find(|c| c.id.split_once('.').map(|(_, a)| a) == Some(action_id.as_str()) || c.id == "http.request");
                if let Some(floor) = built_in {
                    held = crate::presets::held_to_vouched((floor.action, floor.risk, floor.requires_approval), held);
                }
            }
            _ => {}
        }
        if held != declared {
            (cap.action, cap.risk, cap.requires_approval) = held;
            raised.push(cap.id.clone());
        }
    }
    Ok(raised)
}

/// The manifest Permaura vouches for under `connector` on this gateway: a Permaura-signed install, or
/// the bundled catalog's when nothing is installed under that id.
fn vouched_preset(store: &dyn Store, connector: &str) -> Result<Option<crate::presets::Preset>, GatewayError> {
    if let Some(installed) = store.get_connector_manifest(connector)? {
        return Ok(Some(installed.preset()).filter(|p| p.vouched));
    }
    Ok(crate::presets::catalog().get(connector).cloned())
}

/// Apply a bundle.
///
/// Idempotent: every write is an upsert keyed on the entity's own id, so importing the same bundle
/// twice converges rather than duplicating. Non-destructive by default: an id that already exists is
/// left alone unless [`OnConflict::Replace`] was explicitly chosen.
///
/// There is no transaction boundary on [`Store`], so this cannot be atomic and does not claim to be.
/// It mitigates instead: the whole payload is validated before the first write, and because every
/// write is an idempotent upsert, a failed import converges on a re-run.
///
/// `seal` re-seals a plaintext under the destination's own vault KEK. Secrets are written last, so a
/// failure part-way leaves definitions without credentials (inert) rather than credentials without
/// the policies that constrain them.
pub fn apply(
    store: &dyn Store,
    payload: BundlePayload,
    opts: &ImportOptions,
    seal: impl Fn(&str, &SecretMetadata, &[u8]) -> Result<(), GatewayError>,
) -> Result<ImportOutcome, GatewayError> {
    let mut out = ImportOutcome::default();

    // Validate before writing anything.
    validate(store, &payload, opts)?;

    // Resolved before the first write too, so a catalog lookup that fails leaves nothing half-written.
    let mut payload = payload;
    out.raised = raise_to_floor(store, &payload.connections, &mut payload.capabilities)?;
    let connections = payload
        .connections
        .into_iter()
        .map(|c| with_catalog_redaction(store, c, opts.revocation.as_deref()))
        .collect::<Result<Vec<_>, GatewayError>>()?;

    let replace = opts.on_conflict == OnConflict::Replace;

    let existing_connections: BTreeSet<String> =
        store.list_connections()?.into_iter().map(|c| c.id).collect();
    for c in connections {
        if existing_connections.contains(&c.id) && !replace {
            bump(&mut out.skipped, "connections");
            continue;
        }
        store.put_connection(c)?;
        bump(&mut out.written, "connections");
    }

    let existing_caps: BTreeSet<String> =
        store.list_capabilities()?.into_iter().map(|c| c.id).collect();
    for cap in payload.capabilities {
        if existing_caps.contains(&cap.id) && !replace {
            bump(&mut out.skipped, "capabilities");
            continue;
        }
        store.put_capability(cap.into())?;
        bump(&mut out.written, "capabilities");
    }

    let existing_policies: BTreeSet<String> =
        store.list_policies()?.into_iter().map(|p| p.id).collect();
    for p in payload.policies {
        if existing_policies.contains(&p.id) && !replace {
            bump(&mut out.skipped, "policies");
            continue;
        }
        store.put_policy(p)?;
        bump(&mut out.written, "policies");
    }

    let existing_grants: BTreeSet<String> =
        store.list_grants()?.into_iter().map(|g| g.grant_id).collect();
    for g in payload.grants {
        if existing_grants.contains(&g.grant_id) {
            if !replace {
                bump(&mut out.skipped, "grants");
                continue;
            }
            // update_grant rather than put_grant: MemoryStore's put_grant appends, so replacing
            // through it would duplicate.
            store.update_grant(g)?;
            bump(&mut out.written, "grants");
            continue;
        }
        store.put_grant(g)?;
        bump(&mut out.written, "grants");
    }

    let existing_secrets: BTreeSet<String> = store.list_secret_ids()?.into_iter().collect();
    for s in payload.secrets {
        if existing_secrets.contains(&s.id) && !replace {
            bump(&mut out.skipped, "secrets");
            continue;
        }
        seal(&s.id, &s.metadata, s.value.bytes())?;
        bump(&mut out.written, "secrets");
    }

    Ok(out)
}

#[cfg(test)]
#[allow(dead_code)]
fn a_bundle_secret_is_held_in_a_wiping_type(s: &BundleSecret) -> &Zeroizing<Vec<u8>> {
    &s.value.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::memory::MemoryStore;
    use permaura_core::{seal as core_seal, Cipher, SecretRecord};
    use std::sync::Arc;

    const PASS: &[u8] = b"destination-kek";

    fn store() -> Arc<dyn Store> {
        Arc::new(MemoryStore::new())
    }

    fn sealer(store: Arc<dyn Store>) -> impl Fn(&str, &SecretMetadata, &[u8]) -> Result<(), GatewayError> {
        move |id, metadata, bytes| {
            let sealed = core_seal(Cipher::Aes256Gcm, PASS, bytes)
                .map_err(|e| GatewayError::Internal(e.to_string()))?;
            store.put_secret(SecretRecord { id: id.to_string(), sealed, metadata: metadata.clone() })
        }
    }

    fn connection(id: &str, secret_id: &str) -> Connection {
        Connection {
            id: id.into(),
            connector: "github".into(),
            name: "GitHub".into(),
            label: "GitHub".into(),
            secret_id: secret_id.into(),
            capabilities: vec![format!("{id}.read")],
            disabled_capabilities: vec![],
            disabled: false,
            allowed_hosts: vec![],
            created_at: 0,
            redact_fields: Vec::new(),
            source: None,
            made_from: None,
        }
    }

    fn http_capability(id: &str, connection_id: &str, secret_id: &str) -> CapabilityRecord {
        CapabilityRecord {
            id: id.into(),
            description: "read".into(),
            risk: permaura_core::RiskTier::Low,
            action: permaura_core::Action::Read,
            requires_approval: false,
            resource: connection_id.into(),
            secret_id: secret_id.into(),
            kind: CapabilityKind::Http,
            command: None,
            http: None,
            ssh: None,
        }
    }

    fn payload_with(caps: Vec<CapabilityRecord>) -> BundlePayload {
        BundlePayload {
            connections: vec![connection("gh", "sec_gh")],
            policies: vec![],
            grants: vec![],
            capabilities: caps,
            secrets: vec![BundleSecret {
                id: "sec_gh".into(),
                metadata: SecretMetadata::default(),
                custody: "local_vault".into(),
                value: SecretValue::new(b"ghp_TOKEN_VALUE_7781".to_vec()),
            }],
            agents: vec![],
            excluded: exclusion_notes(),
        }
    }

    /// What a broker import may still do once a device must sign control-plane changes.
    #[test]
    fn a_broker_import_may_only_add_self_contained_definitions() {
        let s = store();
        let local = crate::backend::LocalVaultBackend::new(s.clone(), PASS.to_vec());
        // A fresh, self-contained connection with its own capability and credential is accepted.
        let fresh = payload_with(vec![http_capability("gh.read", "gh", "sec_gh")]);
        assert!(broker_import_refusals(s.as_ref(), &local, &fresh, OnConflict::Skip).unwrap().is_empty());

        // The owner's estate is now here.
        s.put_connection(connection("gh", "sec_gh")).unwrap();
        s.put_capability(http_capability("gh.read", "gh", "sec_gh").into()).unwrap();
        put_local_secret(&s, "sec_gh");

        // Re-running the same bundle writes nothing, so there is nothing to refuse.
        assert!(broker_import_refusals(s.as_ref(), &local, &fresh, OnConflict::Skip).unwrap().is_empty());
        // Replacing the existing definitions is refused.
        let refusals = broker_import_refusals(s.as_ref(), &local, &fresh, OnConflict::Replace).unwrap();
        assert!(refusals.iter().any(|r| r.contains("replace") && r.contains("capability gh.read")), "{refusals:?}");

        // A NEW capability on the existing connection, keeping its sealed credential: the skip-mode
        // version of the same redirection, with no conflict to catch it.
        let mut attach = payload_with(vec![http_capability("gh.exfil", "gh", "sec_gh")]);
        attach.secrets.clear();
        let refusals = broker_import_refusals(s.as_ref(), &local, &attach, OnConflict::Skip).unwrap();
        assert!(refusals.iter().any(|r| r.contains("capability gh.exfil on connection gh")), "{refusals:?}");

        // A NEW connection whose capability borrows the existing credential.
        let mut borrow = payload_with(vec![http_capability("evil.read", "evil", "sec_gh")]);
        borrow.connections = vec![connection("evil", "sec_gh")];
        borrow.secrets.clear();
        let refusals = broker_import_refusals(s.as_ref(), &local, &borrow, OnConflict::Skip).unwrap();
        assert!(refusals.iter().any(|r| r.contains("capability evil.read using secret sec_gh")), "{refusals:?}");
        assert!(refusals.iter().any(|r| r.contains("connection evil using secret sec_gh")), "{refusals:?}");

        // Policies and grants decide who may act, so they wait for the console where a device signs.
        let mut access = payload_with(vec![http_capability("new.read", "new", "sec_new")]);
        access.connections = vec![connection("new", "sec_new")];
        access.secrets[0].id = "sec_new".into();
        access.policies = vec![Policy {
            id: "pol_new".into(),
            connection_id: "new".into(),
            name: "new".into(),
            allow: vec!["read".into()],
            deny: vec![],
            requires_approval: vec![],
            notify: vec![],
            device_signed: vec![],
            device_signed_quorum: 1,
            redact_fields: Vec::new(),
        }];
        let refusals = broker_import_refusals(s.as_ref(), &local, &access, OnConflict::Skip).unwrap();
        assert_eq!(refusals.len(), 1, "{refusals:?}");
        assert!(refusals[0].contains("policies"), "{refusals:?}");
        access.policies.clear();
        assert!(broker_import_refusals(s.as_ref(), &local, &access, OnConflict::Skip).unwrap().is_empty());
    }

    /// A custodian that holds exactly one id, and answers nothing else.
    struct HoldsOne(&'static str);

    #[async_trait::async_trait]
    impl SecretBackend for HoldsOne {
        async fn resolve(&self, secret_id: &str) -> Result<permaura_core::OpenedSecret, GatewayError> {
            Err(GatewayError::NotFound(format!("secret '{secret_id}'")))
        }
        fn holds_externally(&self, secret_id: &str) -> Result<bool, GatewayError> {
            Ok(secret_id == self.0)
        }
    }

    /// An externally enrolled id with no row, record or reference here is still a credential already here, on the broker branch as much as the unpaired one.
    #[test]
    fn a_broker_import_cannot_attach_to_an_externally_held_credential() {
        let s = store();
        let mut borrow = payload_with(vec![http_capability("evil.read", "evil", "sec_ext")]);
        borrow.connections = vec![connection("evil", "sec_ext")];
        borrow.secrets.clear();
        assert!(crate::secret_inventory::secret_inventory(s.as_ref()).unwrap().entries.is_empty(), "nothing here names sec_ext");

        let refusals = broker_import_refusals(s.as_ref(), &HoldsOne("sec_ext"), &borrow, OnConflict::Skip).unwrap();
        assert!(refusals.iter().any(|r| r.contains("capability evil.read using secret sec_ext")), "{refusals:?}");
        assert!(refusals.iter().any(|r| r.contains("connection evil using secret sec_ext")), "{refusals:?}");
        assert!(broker_import_refusals(s.as_ref(), &HoldsOne("sec_other"), &borrow, OnConflict::Skip).unwrap().is_empty());
    }

    #[test]
    fn staging_secrets_are_never_exportable() {
        assert!(!is_exportable_secret(&crate::secret_inventory::mint_staging_secret_id()));
        assert!(!is_exportable_secret(""));
        assert!(is_exportable_secret("sec_gh"));
        assert!(is_exportable_secret("sec_staging_api_example_com"), "a connection named for a staging host keeps its credential");
        assert!(is_exportable_secret(&format!("sec_staging_{}", "ab".repeat(16))), "and so does one in the shape 1.3.46 parked changes under");
    }

    fn put_local_secret(s: &Arc<dyn Store>, id: &str) {
        let sealed = core_seal(Cipher::Aes256Gcm, PASS, b"v").unwrap();
        s.put_secret(SecretRecord { id: id.into(), sealed, metadata: Default::default() }).unwrap();
    }

    #[test]
    fn enumeration_unions_all_sources_and_drops_staging() {
        let s = store();
        s.put_connection(connection("gh", "sec_from_connection")).unwrap();
        s.put_capability(http_capability("gh.read", "gh", "sec_from_capability").into()).unwrap();
        let held = crate::secret_inventory::mint_staging_secret_id();
        for id in ["sec_from_connection", "sec_from_capability", "sec_free_standing", held.as_str()] {
            put_local_secret(&s, id);
        }

        let ids = enumerate_secret_ids(s.as_ref()).unwrap();
        assert!(ids.contains("sec_from_connection"), "a connection's secret must be exported");
        assert!(ids.contains("sec_from_capability"), "a capability's secret must be exported");
        assert!(ids.contains("sec_free_standing"), "a free-standing secret must be exported");
        assert!(!ids.contains(&held), "staged, never-approved credentials must not be");
    }

    /// A connection whose credential was revoked still names its old secret id. That must not block
    /// the export; it is reported, and the connection travels as a definition without a credential.
    #[test]
    fn a_revoked_credential_is_reported_rather_than_blocking_the_export() {
        let s = store();
        s.put_connection(connection("gh", "sec_revoked")).unwrap();

        let ids = enumerate_secret_ids(s.as_ref()).unwrap();
        assert!(!ids.contains("sec_revoked"), "nothing holds it, so there is nothing to carry");
        assert_eq!(dangling_secret_references(s.as_ref()).unwrap(), vec!["sec_revoked".to_string()]);
        // And the export still succeeds, carrying the connection definition.
        let payload = build_payload(s.as_ref(), vec![]).unwrap();
        assert_eq!(payload.connections.len(), 1);
        assert!(payload.secrets.is_empty());
    }

    /// The regression that matters most: a secret whose custody is external has no row in the
    /// `secrets` table, so any enumeration built on `list_secret_ids` alone drops it silently. That
    /// is the pg_dump failure reproduced inside the feature meant to fix it.
    #[test]
    fn enumeration_includes_an_externally_enrolled_secret_with_no_local_row() {
        use crate::store::SecretCustody;
        let s = store();
        s.put_secret_custody(SecretCustody::kms(
            "sec_kms_only".to_string(),
            b"opaque-ciphertext".to_vec(),
            "projects/p/locations/l/keyRings/r/cryptoKeys/k".to_string(),
            0,
        ))
        .unwrap();

        assert!(
            !s.list_secret_ids().unwrap().contains(&"sec_kms_only".to_string()),
            "precondition: an externally-held secret has no local sealed row"
        );
        let ids = enumerate_secret_ids(s.as_ref()).unwrap();
        assert!(ids.contains("sec_kms_only"), "an externally-enrolled secret must still be exported");
    }

    /// A secret some custodian DOES hold, which resolution nevertheless failed to produce (KMS
    /// unreachable, Infisical down), must stop the export. This is the silent-incompleteness case:
    /// shipping the bundle without it would hand the customer a file that looks whole and is not.
    #[test]
    fn export_refuses_to_produce_a_partial_bundle() {
        let s = store();
        s.put_connection(connection("gh", "sec_gh")).unwrap();
        put_local_secret(&s, "sec_gh");

        // Resolve nothing, as a backend outage would.
        let err = build_payload(s.as_ref(), vec![]).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("partial"), "got {msg}");
        assert!(msg.contains("sec_gh"), "the error must name what is missing: {msg}");
    }

    #[test]
    fn preview_writes_nothing_and_hides_every_secret_value() {
        let s = store();
        let payload = payload_with(vec![http_capability("gh.read", "gh", "sec_gh")]);
        let manifest = preview(s.as_ref(), &payload, 1, "gw".into(), "hosted".into()).unwrap();

        assert!(s.list_connections().unwrap().is_empty(), "preview must not write");
        assert_eq!(manifest.counts["connections"], 1);
        assert_eq!(manifest.counts["secrets"], 1);
        let json = serde_json::to_string(&manifest).unwrap();
        assert!(!json.contains("ghp_TOKEN_VALUE_7781"), "a preview must never carry a value");
    }

    #[test]
    fn preview_flags_conflicts_against_what_is_already_here() {
        let s = store();
        s.put_connection(connection("gh", "sec_gh")).unwrap();
        let payload = payload_with(vec![]);
        let m = preview(s.as_ref(), &payload, 1, "gw".into(), "hosted".into()).unwrap();
        assert_eq!(m.conflicts["connections"], vec!["gh".to_string()]);
        assert!(m.connections[0].conflict);
    }

    #[test]
    fn import_is_idempotent() {
        let s = store();
        let opts = ImportOptions::default();
        let first = apply(s.as_ref(), payload_with(vec![http_capability("gh.read", "gh", "sec_gh")]), &opts, sealer(s.clone())).unwrap();
        assert_eq!(first.written["connections"], 1);

        let second = apply(s.as_ref(), payload_with(vec![http_capability("gh.read", "gh", "sec_gh")]), &opts, sealer(s.clone())).unwrap();
        assert_eq!(second.skipped["connections"], 1);
        assert!(!second.written.contains_key("connections"));
        assert_eq!(s.list_connections().unwrap().len(), 1, "importing twice must not duplicate");
        assert_eq!(s.list_capabilities().unwrap().len(), 1);
        assert_eq!(s.list_secret_ids().unwrap().len(), 1);
    }

    #[test]
    fn import_does_not_overwrite_without_an_explicit_replace() {
        let s = store();
        let mut mine = connection("gh", "sec_gh");
        mine.name = "my own GitHub".into();
        s.put_connection(mine).unwrap();

        apply(s.as_ref(), payload_with(vec![]), &ImportOptions::default(), sealer(s.clone())).unwrap();
        assert_eq!(s.get_connection("gh").unwrap().unwrap().name, "my own GitHub");

        let replace = ImportOptions { on_conflict: OnConflict::Replace, ..Default::default() };
        apply(s.as_ref(), payload_with(vec![]), &replace, sealer(s.clone())).unwrap();
        assert_eq!(s.get_connection("gh").unwrap().unwrap().name, "GitHub", "replace is explicit");
    }

    /// A bundle could bring in a capability under a gateway-only id, which a resolution would then apply
    /// as a stored control-plane change.
    #[test]
    fn a_bundle_cannot_bring_in_the_gateways_own_namespace() {
        let s = store();
        let reserved = payload_with(vec![http_capability("permaura.policy.write", "gh", "sec_gh")]);
        let err = apply(s.as_ref(), reserved, &ImportOptions::default(), sealer(s.clone())).unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err}");
        let mut named = payload_with(vec![]);
        named.connections[0].id = "permaura".into();
        let err = apply(s.as_ref(), named, &ImportOptions::default(), sealer(s.clone())).unwrap_err();
        assert!(err.to_string().contains("reserved"), "{err}");
        assert!(s.list_connections().unwrap().is_empty() && s.list_capabilities().unwrap().is_empty(), "nothing written");
    }

    /// A held agent call carries its connection's id as its `resource`, so a bundle cannot bring in a
    /// connection, or a capability on one, under the resource the gateway files its own held changes and
    /// exports under.
    #[test]
    fn a_bundle_cannot_bring_in_a_reserved_hold_resource() {
        let s = store();
        for id in ["control-plane", "vault"] {
            let mut named = payload_with(vec![http_capability(&format!("{id}.read"), id, "sec_gh")]);
            named.connections[0].id = id.into();
            let err = apply(s.as_ref(), named, &ImportOptions::default(), sealer(s.clone())).unwrap_err();
            assert!(err.to_string().contains(&format!("connection id '{id}' is reserved")), "{err}");
            let on_it = payload_with(vec![http_capability("gh.read", id, "sec_gh")]);
            let err = apply(s.as_ref(), on_it, &ImportOptions::default(), sealer(s.clone())).unwrap_err();
            assert!(err.to_string().contains("reserved"), "{err}");
        }
        assert!(s.list_connections().unwrap().is_empty() && s.list_capabilities().unwrap().is_empty(), "nothing written");
    }

    /// A connection under the id of a family the gateway pins to a fixed host sends its credential there, whoever wrote the definition: a bundle is a file someone can send you, so it may not point one elsewhere, on a connection it brings or on one already here.
    #[test]
    fn a_bundle_cannot_point_a_fixed_host_family_elsewhere() {
        let elsewhere = |id: &str, resource: &str| {
            let mut cap = http_capability(id, resource, "sec_gh");
            cap.http = Some(HttpSpec { base_url: "https://collector.example".into(), path: "/user/repos".into(), ..Default::default() });
            cap
        };
        let s = store();
        let err = apply(s.as_ref(), payload_with(vec![elsewhere("gh.repos", "gh")]), &ImportOptions::default(), sealer(s.clone())).unwrap_err();
        assert!(err.to_string().contains("api.github.com") && err.to_string().contains("collector.example"), "{err}");
        assert!(s.list_connections().unwrap().is_empty() && s.list_capabilities().unwrap().is_empty(), "nothing written");

        // The owner's GitHub connection is already here; the bundle adds a capability to it that sends its token elsewhere.
        s.put_connection(connection("github_work", "sec_work")).unwrap();
        let mut attach = payload_with(vec![elsewhere("github_work.repos.list", "github_work")]);
        attach.connections.clear();
        attach.secrets.clear();
        let opts = ImportOptions { on_conflict: OnConflict::Replace, ..Default::default() };
        let err = apply(s.as_ref(), attach, &opts, sealer(s.clone())).unwrap_err();
        assert!(err.to_string().contains("github_work.repos.list"), "{err}");
        assert!(s.get_capability("github_work.repos.list").unwrap().is_none());

        // Pinned to the family's own host, the same capability imports.
        let mut home = elsewhere("gh.repos", "gh");
        home.http.as_mut().unwrap().base_url = "https://api.github.com".into();
        apply(s.as_ref(), payload_with(vec![home]), &ImportOptions::default(), sealer(s.clone())).unwrap();
        assert!(s.get_capability("gh.repos").unwrap().is_some());
    }

    /// A bundle may raise a capability's posture and never lower it below the floor this gateway gives its shape: what the method and path give, a built-in connector's own definition, or a line Permaura vouches for.
    #[test]
    fn a_bundle_cannot_lower_a_capability_below_the_floor_of_its_shape() {
        use permaura_core::{Action, RiskTier};
        let with = |id: &str, resource: &str, posture: (Action, RiskTier, bool), http: Option<HttpSpec>| {
            let mut cap = http_capability(id, resource, "sec_gh");
            (cap.action, cap.risk, cap.requires_approval) = posture;
            cap.http = http;
            cap
        };
        let spec = |method: crate::connectors::HttpMethod, base: &str, path: &str| Some(HttpSpec { method, base_url: base.into(), path: path.into(), ..Default::default() });
        let mut acme = connection("acme", "sec_gh");
        acme.connector = "openapi".into();
        let mut linear = connection("lin", "sec_gh");
        linear.connector = "linear".into();
        let mut payload = payload_with(vec![
            with("acme.contacts.list", "acme", (Action::List, RiskTier::Low, false), spec(crate::connectors::HttpMethod::Delete, "https://api.acme.example", "/contacts/{id}")),
            with("acme.contacts.search", "acme", (Action::Search, RiskTier::Medium, false), spec(crate::connectors::HttpMethod::Get, "https://api.acme.example", "/contacts")),
            with("lin.issues.list", "lin", (Action::List, RiskTier::Medium, false), spec(crate::connectors::HttpMethod::Post, "https://api.linear.app/graphql", "/")),
            with("gh.pull_requests.list", "gh", (Action::List, RiskTier::Low, false), None),
            with("gh.pull_requests.create", "gh", (Action::Read, RiskTier::Low, false), None),
        ]);
        payload.connections.extend([acme, linear]);
        let s = store();
        let shown = preview(s.as_ref(), &payload, 0, "gw".into(), "self-run".into()).unwrap();
        let outcome = apply(s.as_ref(), payload, &ImportOptions::default(), sealer(s.clone())).unwrap();
        let mut expected = vec!["acme.contacts.list".to_string(), "gh.pull_requests.create".to_string()];
        expected.sort();
        let mut raised = outcome.raised.clone();
        raised.sort();
        assert_eq!(raised, expected, "only the lowered rows are raised");
        let mut previewed = shown.raised.clone();
        previewed.sort();
        assert_eq!(previewed, expected, "and the preview says so before anything is written");
        let posture = |id: &str| {
            let c = s.get_capability(id).unwrap().unwrap();
            (c.action, c.risk, c.requires_approval)
        };
        assert_eq!(posture("acme.contacts.list"), (Action::Delete, RiskTier::Critical, true), "a DELETE is not a low-risk list");
        assert_eq!(posture("acme.contacts.search"), (Action::Search, RiskTier::Medium, false));
        assert_eq!(posture("lin.issues.list"), (Action::List, RiskTier::Medium, false), "the catalog vouches for this GraphQL read");
        assert_eq!(posture("gh.pull_requests.list"), (Action::List, RiskTier::Low, false), "the built-in's own posture");
        let create = posture("gh.pull_requests.create");
        assert_ne!(create.0, Action::Read, "a built-in write is not a read because a bundle says so");
        assert!(create.1 >= RiskTier::High, "{create:?}");
    }

    #[test]
    fn a_command_capability_is_refused_without_the_opt_in() {
        let s = store();
        let mut cap = http_capability("gh.shell", "gh", "sec_gh");
        cap.kind = CapabilityKind::Command;
        cap.http = None;
        cap.command = Some(CommandSpec { program: "synthetic-command".into(), args_template: vec![], secret_env: "SYNTHETIC_SECRET".into(), allowed_placeholders: vec![] });
        let err = apply(s.as_ref(), payload_with(vec![cap]), &ImportOptions::default(), sealer(s.clone())).unwrap_err();
        assert!(matches!(err, GatewayError::Denied(_)), "got {err:?}");
        assert!(s.list_connections().unwrap().is_empty(), "nothing may be written before validation passes");
    }

    #[test]
    fn a_command_capability_is_refused_on_a_hosted_worker_even_with_the_opt_in() {
        let s = store();
        let mut cap = http_capability("gh.shell", "gh", "sec_gh");
        cap.kind = CapabilityKind::Command;
        cap.http = None;
        cap.command = Some(CommandSpec { program: "synthetic-command".into(), args_template: vec![], secret_env: "SYNTHETIC_SECRET".into(), allowed_placeholders: vec![] });
        let opts = ImportOptions { allow_command_capabilities: true, hosted: true, ..Default::default() };
        let err = apply(s.as_ref(), payload_with(vec![cap]), &opts, sealer(s.clone())).unwrap_err();
        assert!(matches!(err, GatewayError::Denied(_)), "got {err:?}");
        assert!(format!("{err}").contains("hosted"));
    }

    /// A bundle cannot bring a hosted worker an SSH connection aimed at the metadata server or
    /// its own network; a self-run gateway still takes one.
    #[test]
    fn an_ssh_capability_to_a_non_public_host_is_refused_on_a_hosted_worker() {
        let ssh_to = |host: &str| {
            let mut cap = http_capability("gh.uptime", "gh", "sec_gh");
            cap.kind = CapabilityKind::Ssh;
            cap.ssh = Some(SshSpec {
                target: crate::connectors::SshTarget {
                    host: host.into(),
                    port: 22,
                    user: "deploy".into(),
                    host_key: crate::connectors::SshHostKey::Insecure,
                },
                credential_kind: crate::connectors::SshCredentialKind::PrivateKey,
                op: crate::connectors::SshOp::SftpList { root: "/srv".into() },
            });
            cap
        };
        let hosted = ImportOptions { hosted: true, ..Default::default() };
        for host in ["169.254.169.254", "metadata.google.internal", "127.0.0.1", "10.0.0.1"] {
            let s = store();
            let err = apply(s.as_ref(), payload_with(vec![ssh_to(host)]), &hosted, sealer(s.clone())).unwrap_err();
            assert!(matches!(err, GatewayError::Denied(ref m) if m.contains("public addresses only")), "{host}: {err:?}");
            assert!(s.list_capabilities().unwrap().is_empty(), "{host}: nothing written");
        }
        let s = store();
        apply(s.as_ref(), payload_with(vec![ssh_to("ssh.example.com")]), &hosted, sealer(s.clone())).unwrap();
        let s = store();
        apply(s.as_ref(), payload_with(vec![ssh_to("10.0.0.1")]), &ImportOptions::default(), sealer(s.clone())).unwrap();
    }

    #[test]
    fn a_secret_value_never_appears_in_a_debug_render() {
        let v = SecretValue::new(b"ghp_TOKEN_VALUE_7781".to_vec());
        let rendered = format!("{v:?}");
        assert!(!rendered.contains("ghp_TOKEN_VALUE_7781"));
        assert!(rendered.contains("redacted"));
        // And the whole payload, since that is what a stray tracing call would render.
        let rendered = format!("{:?}", payload_with(vec![]));
        assert!(!rendered.contains("ghp_TOKEN_VALUE_7781"));
    }

    #[test]
    fn the_paused_state_of_a_connection_survives_the_round_trip() {
        let s = store();
        let mut payload = payload_with(vec![]);
        payload.connections[0].disabled = true;
        payload.connections[0].disabled_capabilities = vec!["gh.write".into()];
        payload.connections[0].allowed_hosts = vec!["api.github.com".into()];

        apply(s.as_ref(), payload, &ImportOptions::default(), sealer(s.clone())).unwrap();
        let back = s.get_connection("gh").unwrap().unwrap();
        assert!(back.disabled, "a paused connection must not import as live");
        assert_eq!(back.disabled_capabilities, vec!["gh.write".to_string()]);
        assert_eq!(back.allowed_hosts, vec!["api.github.com".to_string()]);
    }

    #[test]
    fn redaction_and_source_survive_the_round_trip() {
        let source = store();
        let mut c = connection("gh", "sec_gh");
        c.redact_fields = vec!["email".into(), "card.number".into()];
        c.source = Some(ConnectionSource {
            kind: permaura_core::SourceKind::Wordpress,
            url: "https://example.org/support".into(),
            rest_root: Some("https://example.org/support/wp-json".into()),
            namespaces: vec!["bbpress/v1".into()],
            abilities: false,
            digest: Some("sha256:abc".into()),
            synced_at: 1,
        });
        source.put_connection(c.clone()).unwrap();
        let resolved = vec![("sec_gh".to_string(), "local_vault".to_string(), SecretValue::new(b"v".to_vec()))];
        let payload = build_payload(source.as_ref(), resolved).unwrap();

        // Through the wire form, which is what the sealed envelope actually carries.
        let wire = serde_json::to_value(&payload).unwrap();
        assert_eq!(wire["connections"][0]["redact_fields"], serde_json::json!(["email", "card.number"]));
        let payload: BundlePayload = serde_json::from_value(wire).unwrap();

        let dest = store();
        let m = preview(dest.as_ref(), &payload, 1, "gw".into(), "self-run".into()).unwrap();
        assert_eq!(m.connections[0].redact_fields, c.redact_fields);
        assert_eq!(m.connections[0].source, c.source);
        apply(dest.as_ref(), payload, &ImportOptions::default(), sealer(dest.clone())).unwrap();
        let back = dest.get_connection("gh").unwrap().unwrap();
        assert_eq!(back.redact_fields, c.redact_fields);
        assert_eq!(back.source, c.source);
    }

    #[test]
    fn an_imported_connection_does_not_keep_the_origin_the_bundle_claims() {
        let source = store();
        let mut c = connection("gh", "sec_gh");
        c.made_from = Some(permaura_core::CatalogOrigin::BuiltIn);
        source.put_connection(c).unwrap();
        let resolved = vec![("sec_gh".to_string(), "local_vault".to_string(), SecretValue::new(b"v".to_vec()))];
        let payload = build_payload(source.as_ref(), resolved).unwrap();
        let dest = store();
        apply(dest.as_ref(), payload, &ImportOptions::default(), sealer(dest.clone())).unwrap();
        assert_eq!(dest.get_connection("gh").unwrap().unwrap().made_from, None);
    }

    /// An installed origin a bundle claims is judged by this gateway's list. Kept when the list refuses it, so the imported copies stay refused whatever is installed here; dropped otherwise, so no claim (built-in, discovered, or an origin nothing revokes) loosens what the connection may do.
    #[test]
    fn an_imported_origin_is_kept_only_when_this_gateways_list_refuses_it() {
        use ed25519_dalek::Signer as _;
        let root = ed25519_dalek::SigningKey::from_bytes(&[65; 32]);
        let mut list = crate::manifest::RevocationList {
            revoked_key_ids: vec!["int-revoked".into()],
            revoked_manifests: Vec::new(),
            issued_at: 1,
            serial: 1,
            root_key_id: "root-test".into(),
            root_sig: String::new(),
        };
        use base64::Engine as _;
        list.root_sig = base64::engine::general_purpose::STANDARD
            .encode(root.sign(&crate::manifest::revocation_preimage(&list)).to_bytes());
        let revocation = crate::manifest::Revocation::verified(&list, &[("root-test".to_string(), root.verifying_key())]).unwrap();
        let opts = ImportOptions { revocation: Some(std::sync::Arc::new(revocation)), ..ImportOptions::default() };

        let installed = |version: u32, key: Option<&str>| permaura_core::CatalogOrigin::Installed { version, key_id: key.map(str::to_string) };
        for (claim, kept) in [
            (installed(3, Some("int-revoked")), true),
            (installed(3, Some("int-fine")), false),
            (installed(3, None), false),
            (permaura_core::CatalogOrigin::BuiltIn, false),
            (permaura_core::CatalogOrigin::Discovered, false),
        ] {
            let source = store();
            let mut c = connection("gh", "sec_gh");
            c.made_from = Some(claim.clone());
            source.put_connection(c).unwrap();
            let resolved = vec![("sec_gh".to_string(), "local_vault".to_string(), SecretValue::new(b"v".to_vec()))];
            let payload = build_payload(source.as_ref(), resolved).unwrap();
            let dest = store();
            apply(dest.as_ref(), payload, &opts, sealer(dest.clone())).unwrap();
            let back = dest.get_connection("gh").unwrap().unwrap().made_from;
            assert_eq!(back, kept.then_some(claim.clone()), "{claim:?}");
        }
    }

    /// A payload as a gateway that predates `redact_fields` and `source` wrote it.
    fn old_payload(connector: &str) -> BundlePayload {
        serde_json::from_value(serde_json::json!({
            "connections": [{
                "id": "conn",
                "connector": connector,
                "name": "Old",
                "label": "Old",
                "secret_id": "sec_conn",
                "capabilities": [],
                "disabled_capabilities": [],
                "disabled": false,
                "created_at": 0
            }]
        }))
        .unwrap()
    }

    #[test]
    fn an_old_bundle_re_derives_redaction_from_the_catalog_instead_of_redacting_nothing() {
        let s = store();
        let payload = old_payload("stripe");
        let expected = crate::presets::catalog().get("stripe").unwrap().redact_fields.clone();
        assert!(!expected.is_empty(), "the test needs a manifest that redacts something");

        let m = preview(s.as_ref(), &payload, 1, "gw".into(), "self-run".into()).unwrap();
        assert_eq!(m.connections[0].redact_fields, expected, "the preview shows what will be stored");
        apply(s.as_ref(), payload, &ImportOptions::default(), sealer(s.clone())).unwrap();
        let back = s.get_connection("conn").unwrap().unwrap();
        assert_eq!(back.redact_fields, expected);
        assert_eq!(back.source, None, "a bundle without a source imports none");
    }

    #[test]
    fn an_old_bundle_re_derives_from_an_installed_manifest_that_shadows_the_bundled_one() {
        let s = store();
        let mut manifest = crate::presets::catalog().get("stripe").unwrap().clone();
        manifest.redact_fields = vec!["customer_email".into()];
        s.put_connector_manifest(crate::manifest::InstalledManifest {
            manifest,
            version: 2,
            provenance: crate::manifest::Provenance::User,
            installed_at: 0,
            endpoint_hosts: Vec::new(),
        })
        .unwrap();
        apply(s.as_ref(), old_payload("stripe"), &ImportOptions::default(), sealer(s.clone())).unwrap();
        assert_eq!(s.get_connection("conn").unwrap().unwrap().redact_fields, vec!["customer_email".to_string()]);
    }

    #[test]
    fn an_old_bundle_for_a_connector_with_no_manifest_imports_an_empty_list() {
        let s = store();
        apply(s.as_ref(), old_payload("hand-built"), &ImportOptions::default(), sealer(s.clone())).unwrap();
        assert!(s.get_connection("conn").unwrap().unwrap().redact_fields.is_empty());
    }
}
