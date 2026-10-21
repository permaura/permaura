//! Canonical request hashing.
//!
//! [`request_hash`] binds an audited decision (and any approval) to the exact request
//! payload that produced it. It must be deterministic and independent of JSON key order so
//! the value is stable across processes and `serde_json` configurations: the relay worker
//! recomputes it and rejects a mismatch, so a control plane cannot redirect an approval onto
//! a different call. We therefore serialise `params` with **recursively sorted object keys**
//! rather than relying on `serde_json`'s map ordering.

use sha2::{Digest, Sha256};

/// Stable hash of a capability invocation: `SHA256(capability ‖ 0x00 ‖ canonical(params))`,
/// lowercase hex. `canonical` is compact JSON with every object's keys sorted lexicographically
/// at every depth, byte-identical to `serde_json::to_vec` when `preserve_order` is off, and
/// still order-independent if it is ever on.
pub fn request_hash(capability: &str, params: &serde_json::Value) -> String {
    let mut hasher = Sha256::new();
    hasher.update(capability.as_bytes());
    hasher.update(b"\0");
    let mut canon = Vec::new();
    write_canonical(params, &mut canon);
    hasher.update(&canon);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Write `value` as compact JSON with object keys sorted at every depth. Scalars are delegated
/// to `serde_json` so number/string formatting matches it exactly.
fn write_canonical(value: &serde_json::Value, out: &mut Vec<u8>) {
    match value {
        serde_json::Value::Object(map) => {
            out.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                // Key as a JSON string (delegated, so escaping matches serde_json exactly).
                out.extend_from_slice(serde_json::to_string(k).unwrap_or_default().as_bytes());
                out.push(b':');
                write_canonical(&map[*k], out);
            }
            out.push(b'}');
        }
        serde_json::Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        scalar => {
            // Null / Bool / Number / String: serde_json's compact form is already canonical.
            out.extend_from_slice(&serde_json::to_vec(scalar).unwrap_or_default());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn stable_and_key_order_independent() {
        let a = request_hash("transactions.search", &json!({"status":"failed","date":"2026-06-21"}));
        let b = request_hash("transactions.search", &json!({"date":"2026-06-21","status":"failed"}));
        assert_eq!(a, b, "key order must not change the hash");
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn different_params_differ() {
        assert_ne!(request_hash("x", &json!({"a":1})), request_hash("x", &json!({"a":2})));
    }

    #[test]
    fn different_capability_differs() {
        assert_ne!(request_hash("a", &json!({})), request_hash("b", &json!({})));
    }

    #[test]
    fn nested_objects_are_sorted_recursively() {
        let a = request_hash("c", &json!({"outer":{"z":1,"a":2},"k":[{"b":1,"a":2}]}));
        let b = request_hash("c", &json!({"k":[{"a":2,"b":1}],"outer":{"a":2,"z":1}}));
        assert_eq!(a, b);
    }

    #[test]
    fn matches_legacy_to_vec_when_preserve_order_off() {
        // With preserve_order off (workspace default), serde_json already sorts keys, so the
        // canonical form equals the legacy SHA256(cap ‖ 0 ‖ serde_json::to_vec(params)): no
        // change to existing audit hashes today.
        let params = json!({"b":2,"a":1,"c":[3,2,1]});
        let mut legacy = Sha256::new();
        legacy.update(b"cap");
        legacy.update(b"\0");
        legacy.update(serde_json::to_vec(&params).unwrap());
        let legacy_hex: String = legacy.finalize().iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(request_hash("cap", &params), legacy_hex);
    }
}
