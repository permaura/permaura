//! Stored capabilities held to the posture floor after the fact.
//!
//! The floor a governed party's document gets (an unsigned manifest's lines, a WordPress site's routes
//! and ability annotations, a vault bundle) is applied where a capability is derived. A capability
//! stored by an earlier gateway, or by an import that ran before the manifest that vouches for it was
//! installed, keeps whatever it was stored with until something looks again. This module looks again:
//! once at every start, for rows the current rules would raise, and after a Permaura-signed install,
//! for rows a vault import raised from the posture that manifest now vouches for. A posture the owner
//! set themselves ([`crate::connectors::OwnerPosture`]) stays while the floor it replaced still holds.

use permaura_core::{Action, AuditPayload, Connection, RiskTier};

use crate::connectors::Capability;
use crate::error::GatewayError;
use crate::store::Store;

/// The audit action of the start-up pass that raised stored capabilities to the floor.
pub const FLOOR_ACTION: &str = "permaura.capability.posture.floor";

/// The capabilities of `connection`, a connection of a family the gateway pins to fixed hosts, whose
/// pinned spec would send that family's credential to another host. Every call through one is refused
/// at dispatch (`pinned_host`); a connection made before the family rule held at create can carry one.
pub fn pinned_elsewhere(store: &dyn Store, connection: &Connection) -> Result<Vec<String>, GatewayError> {
    if crate::connectors::family_hosts(&connection.connector).is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for id in &connection.capabilities {
        let Some(cap) = store.get_capability(id)? else { continue };
        if cap.http.as_ref().is_some_and(|h| !crate::connectors::on_family_host(&connection.connector, &h.base_url)) {
            out.push(cap.id);
        }
    }
    Ok(out)
}

/// Say at start-up which connections would have every call through such a capability refused, so an
/// owner reading the log learns to add them again as an import under their own id.
pub fn log_pinned_elsewhere(store: &dyn Store) {
    let Ok(connections) = store.list_connections() else { return };
    for connection in connections {
        if let Ok(caps) = pinned_elsewhere(store, &connection) {
            if !caps.is_empty() {
                tracing::warn!(
                    connection = %connection.id,
                    connector = %connection.connector,
                    capabilities = %caps.join(", "),
                    "connection sends a '{}' credential to a host outside {}: every call through these capabilities is refused; add the connection again as an OpenAPI import or a connector manifest under an id of its own",
                    connection.connector,
                    crate::connectors::family_hosts(&connection.connector).join(", ")
                );
            }
        }
    }
}

/// One stored capability whose posture a pass changed.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Moved {
    /// The capability id.
    pub capability: String,
    /// Its connection.
    pub connection: String,
    /// Action, risk and approval before.
    pub from: (Action, RiskTier, bool),
    /// Action, risk and approval after.
    pub to: (Action, RiskTier, bool),
    /// Whether the pass also switched it off, because it is now High or above and was on.
    pub switched_off: bool,
}

/// The floor the current rules give a stored capability its source does not vouch for, or `None`
/// when its source is one the gateway vouches for, or it has no pinned shape: a line of an installed
/// unsigned manifest, a WordPress route or ability.
fn stored_floor(store: &dyn Store, connection: &Connection, cap: &Capability) -> Result<Option<(Action, RiskTier, bool)>, GatewayError> {
    let Some(http) = cap.http.as_ref() else { return Ok(None) };
    let action_id = cap.id.strip_prefix(&format!("{}.", connection.id)).unwrap_or(&cap.id);
    if connection.connector == "wordpress" {
        let namespaces = connection.source.as_ref().map(|s| s.namespaces.as_slice()).unwrap_or_default();
        return Ok(crate::wordpress::stored_floor(&connection.id, cap, namespaces));
    }
    let unsigned = store
        .get_connector_manifest(&connection.connector)?
        .is_some_and(|m| matches!(m.provenance, crate::manifest::Provenance::User));
    if !unsigned {
        return Ok(None);
    }
    Ok(Some(crate::presets::held_to_shape(http.method, &http.path, action_id, (cap.action, cap.risk, cap.requires_approval))))
}

/// Raise every stored capability whose posture is below the floor the current rules give its
/// unvouched source, except one whose owner-set posture that floor would not raise (the floor it replaced still holds); an owner-set posture the floor would raise is dropped and the capability re-floored. Switch off any that this makes High or above and that were on, and record the
/// pass in the audit chain. Idempotent: a second run moves nothing. Returns what moved.
pub fn refloor_stored(store: &dyn Store) -> Result<Vec<Moved>, GatewayError> {
    let mut moved = Vec::new();
    for mut connection in store.list_connections()? {
        let mut switched = false;
        for id in connection.capabilities.clone() {
            let Some(mut cap) = store.get_capability(&id)? else { continue };
            let Some(floor) = stored_floor(store, &connection, &cap)? else { continue };
            let mut cleared = false;
            if let Some(owner) = cap.http.as_ref().and_then(|h| h.owner_posture) {
                let original = (owner.from_action, owner.from_risk, owner.from_requires_approval);
                if crate::presets::held_to_vouched(floor, original) == original {
                    continue;
                }
                cap.http.as_mut().unwrap().owner_posture = None;
                cleared = true;
            }
            let from = (cap.action, cap.risk, cap.requires_approval);
            let to = crate::presets::held_to_vouched(floor, from);
            if to == from {
                // Every start runs this, and on a hosted worker each write uploads the whole store.
                if cleared {
                    store.put_capability(cap)?;
                }
                continue;
            }
            let switched_off = to.1 >= RiskTier::High && from.1 < RiskTier::High && !connection.disabled_capabilities.contains(&id);
            if switched_off {
                connection.disabled_capabilities.push(id.clone());
                switched = true;
            }
            (cap.action, cap.risk, cap.requires_approval) = to;
            store.put_capability(cap)?;
            moved.push(Moved { capability: id, connection: connection.id.clone(), from, to, switched_off });
        }
        if switched {
            store.put_connection(connection)?;
        }
    }
    if !moved.is_empty() {
        record(store, FLOOR_ACTION, &moved)?;
        store.put_meta("last_posture_floor_pass", &serde_json::to_string(&moved).map_err(|e| GatewayError::Internal(e.to_string()))?)?;
    }
    Ok(moved)
}

/// After a Permaura-signed manifest for `preset` is installed, return each capability on its
/// connections that a vault import raised from the posture this manifest vouches for (the bundle
/// carried no manifest, so the import held it to its shape) back to that posture. A capability matches
/// only when it is exactly a vouched line ([`crate::presets::Preset::vouched_posture`]) and carries
/// exactly what the shape floor would have raised that line to. It runs inside the install's own
/// change and returns what it moved as that change's `restored`, which the audit record carries while the install's
/// answer fits an audit event (a larger one keeps only its length and digest), so it appends nothing itself.
pub fn restore_vouched(store: &dyn Store, preset: &crate::presets::Preset) -> Result<Vec<Moved>, GatewayError> {
    let mut moved = Vec::new();
    if !preset.vouched {
        return Ok(moved);
    }
    for connection in store.list_connections()?.into_iter().filter(|c| c.connector == preset.id) {
        for id in &connection.capabilities {
            let Some(mut cap) = store.get_capability(id)? else { continue };
            let Some(http) = cap.http.as_ref().filter(|h| h.owner_posture.is_none()) else { continue };
            let action_id = id.strip_prefix(&format!("{}.", connection.id)).unwrap_or(id);
            let Some(vouched) = preset.vouched_posture(action_id, http.method, &http.base_url, &http.path) else { continue };
            let from = (cap.action, cap.risk, cap.requires_approval);
            let raised = crate::presets::held_to_shape(http.method, &http.path, action_id, vouched);
            if from == vouched || from != raised {
                continue;
            }
            (cap.action, cap.risk, cap.requires_approval) = vouched;
            store.put_capability(cap)?;
            moved.push(Moved { capability: id.clone(), connection: connection.id.clone(), from, to: vouched, switched_off: false });
        }
    }
    Ok(moved)
}

fn record(store: &dyn Store, action: &str, moved: &[Moved]) -> Result<(), GatewayError> {
    let mut payload = AuditPayload::new(action, crate::store::CONTROL_PLANE_RESOURCE, "recorded");
    payload.summary = serde_json::json!({ "capabilities": moved });
    store.append_audit(payload)?;
    Ok(())
}

/// The start-up passes: log connections whose family pin now refuses their calls, and raise stored
/// rows to the current floor. Neither pass is fatal: a failed re-floor is logged and the gateway still
/// enforces what it stored, and a store that cannot be listed skips the pinned-host warning without logging it.
pub fn at_start(store: &dyn Store) {
    log_pinned_elsewhere(store);
    match refloor_stored(store) {
        Ok(moved) if !moved.is_empty() => tracing::warn!(
            count = moved.len(),
            capabilities = %moved.iter().map(|m| m.capability.as_str()).collect::<Vec<_>>().join(", "),
            "raised stored capabilities to the posture floor the current rules give their sources; those now High or above were switched off and are listed in the audit chain"
        ),
        Ok(_) => {}
        Err(e) => tracing::warn!(error = %e, "could not hold stored capabilities to the posture floor"),
    }
}
