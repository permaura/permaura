//! Response redaction.
//!
//! Before a connector result is handed back to an agent, the value of every object key
//! whose name matches a redaction target (case-insensitive) is replaced with a fixed
//! placeholder. This module operates on `serde_json::Value` and walks it recursively. It
//! matches names only: a secret or personal detail under a name the set does not carry, or
//! inside a string, passes through, and [`crate::scrub`] removes only the call's own injected
//! credential, by value.
//!
//! A bare entry (`email`) matches that key name anywhere in the response. The defaults are
//! exact names (`api_key`, `access_token`, `authorization`, `cookie`, `password`,
//! `card_number`, `cvv`, ...), so a variant such as `cardNumber` or `x-api-key` is not
//! matched unless a manifest, connection or policy adds it. An entry containing a dot is a path
//! suffix: `card.number` matches a `number` key only when the nearest enclosing object
//! key is `card`, so a connector can hide a card number without blanking every invoice
//! number. Arrays are transparent to paths: `{"card": [{"number": ..}]}` matches too.
//!
//! The set applied to a call is built by [`effective_redact_keys`], which starts from
//! [`default_redact_keys`] and can only add to it.

use std::collections::HashSet;

use serde_json::Value;

/// The placeholder substituted for redacted values.
pub const REDACTED: &str = "[redacted]";

/// A reasonable default set of field names to redact.
/// Manifests, connections and policies can add to it per call
/// through [`effective_redact_keys`]; nothing can remove a default.
pub fn default_redact_keys() -> Vec<String> {
    [
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "token",
        "authorization",
        "auth",
        "cookie",
        "set-cookie",
        "password",
        "secret",
        "private_key",
        "client_secret",
        "session_token",
        "card_number",
        "pan",
        "cvv",
        "cvc",
        "ssn",
        "database_url",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

/// The redaction set for one call: [`default_redact_keys`] followed by every entry in
/// `additions`, trimmed, lowercased and deduplicated, with blank entries dropped.
///
/// This is the only way the gateway builds a set, and it has no way to express a removal:
/// whatever a manifest, connection, policy or operator supplies is appended, so no input
/// can un-redact a default. An entry that looks like a negation (`-authorization`) is just
/// another key name that matches nothing.
pub fn effective_redact_keys<I, S>(additions: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<String> = Vec::new();
    let defaults = default_redact_keys();
    let entries = defaults
        .iter()
        .map(|d| d.to_ascii_lowercase())
        .chain(additions.into_iter().map(|a| a.as_ref().trim().to_ascii_lowercase()));
    for entry in entries {
        if !entry.is_empty() && seen.insert(entry.clone()) {
            out.push(entry);
        }
    }
    out
}

/// Redaction targets, normalized once per call.
pub(crate) struct Targets {
    /// Every entry, matched against a single key name. A dotted entry is here too, so a
    /// key literally named `card.number` is still caught.
    names: HashSet<String>,
    /// Dotted entries split into segments, matched against the tail of the key path.
    paths: Vec<Vec<String>>,
}

impl Targets {
    pub(crate) fn new(keys: &[String]) -> Self {
        let mut names = HashSet::new();
        let mut paths = Vec::new();
        for key in keys {
            let key = key.trim().to_ascii_lowercase();
            if key.is_empty() {
                continue;
            }
            if key.contains('.') {
                let segments: Vec<String> = key.split('.').map(str::to_string).collect();
                if segments.iter().all(|s| !s.is_empty()) {
                    paths.push(segments);
                }
            }
            names.insert(key);
        }
        Targets { names, paths }
    }

    /// `path` is the chain of object keys from the root to the key being tested, lowercased, with
    /// array levels left out.
    pub(crate) fn matches(&self, path: &[String]) -> bool {
        let Some(key) = path.last() else { return false };
        self.names.contains(key) || self.paths.iter().any(|p| path.ends_with(p))
    }
}

/// Recursively redact, in place, the value of every object key (case-insensitively)
/// matched by `keys`. A bare entry matches the key anywhere; a dotted entry matches
/// when it is a suffix of the chain of enclosing object keys (arrays are transparent).
/// Scalars are untouched unless their key matched at the parent level.
pub fn redact_in_place(value: &mut Value, keys: &[String]) {
    let targets = Targets::new(keys);
    let mut path = Vec::new();
    redact_inner(value, &targets, &mut path);
}

fn redact_inner(value: &mut Value, targets: &Targets, path: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                path.push(key.to_ascii_lowercase());
                if targets.matches(path) {
                    // Matched: replace the whole subtree with the placeholder.
                    *child = Value::String(REDACTED.to_string());
                } else {
                    redact_inner(child, targets, path);
                }
                path.pop();
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_inner(item, targets, path);
            }
        }
        _ => {}
    }
}

/// Non-mutating convenience: clone, redact, and return.
pub fn redact(mut value: Value, keys: &[String]) -> Value {
    redact_in_place(&mut value, keys);
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_top_level_keys() {
        let v = json!({ "id": "tx_1", "api_key": "sk_live_abc", "amount": 49.0 });
        let out = redact(v, &["api_key".into()]);
        assert_eq!(out["api_key"], REDACTED);
        assert_eq!(out["id"], "tx_1");
        assert_eq!(out["amount"], 49.0);
    }

    #[test]
    fn redaction_is_case_insensitive() {
        let v = json!({ "Authorization": "Bearer xyz", "CardNumber": "4111111111111111" });
        let out = redact(v, &["authorization".into(), "cardnumber".into()]);
        assert_eq!(out["Authorization"], REDACTED);
        assert_eq!(out["CardNumber"], REDACTED);
    }

    #[test]
    fn redacts_nested_and_arrayed_values() {
        let v = json!({
            "transactions": [
                { "id": "tx_1", "customer": { "email": "a@b.com", "cvv": "123" } },
                { "id": "tx_2", "customer": { "email": "c@d.com", "cvv": "456" } }
            ]
        });
        let out = redact(v, &["cvv".into(), "email".into()]);
        assert_eq!(out["transactions"][0]["customer"]["cvv"], REDACTED);
        assert_eq!(out["transactions"][0]["customer"]["email"], REDACTED);
        assert_eq!(out["transactions"][1]["customer"]["cvv"], REDACTED);
        assert_eq!(out["transactions"][0]["id"], "tx_1");
    }

    #[test]
    fn redacts_whole_subtree_when_key_matches() {
        let v = json!({ "credentials": { "user": "x", "pass": "y" } });
        let out = redact(v, &["credentials".into()]);
        assert_eq!(out["credentials"], REDACTED);
    }

    #[test]
    fn default_keys_catch_common_secrets() {
        let v = json!({ "access_token": "t", "password": "p", "safe": "ok" });
        let out = redact(v, &default_redact_keys());
        assert_eq!(out["access_token"], REDACTED);
        assert_eq!(out["password"], REDACTED);
        assert_eq!(out["safe"], "ok");
    }

    #[test]
    fn a_dotted_entry_matches_only_under_its_parent() {
        let v = json!({
            "number": "INV-0042",
            "card": { "number": "4242424242424242", "brand": "visa" },
            "invoice": { "number": "INV-0043" }
        });
        let out = redact(v, &["card.number".into()]);
        assert_eq!(out["card"]["number"], REDACTED);
        assert_eq!(out["card"]["brand"], "visa");
        assert_eq!(out["number"], "INV-0042", "a top-level number is not under card");
        assert_eq!(out["invoice"]["number"], "INV-0043", "another parent's number is untouched");
    }

    #[test]
    fn a_dotted_entry_looks_only_at_the_nearest_enclosing_key() {
        // `card.number` names the key directly inside `card`, not anything deeper under it.
        let v = json!({ "card": { "issuer": { "number": "1-800" } } });
        let out = redact(v, &["card.number".into()]);
        assert_eq!(out["card"]["issuer"]["number"], "1-800");
    }

    #[test]
    fn arrays_are_transparent_to_a_dotted_entry() {
        let v = json!({
            "card": [ { "number": "4111" }, { "number": "5555" } ],
            "data": [ { "card": { "number": "3782" } }, { "lines": [ { "number": 1 } ] } ]
        });
        let out = redact(v, &["card.number".into()]);
        assert_eq!(out["card"][0]["number"], REDACTED);
        assert_eq!(out["card"][1]["number"], REDACTED);
        assert_eq!(out["data"][0]["card"]["number"], REDACTED);
        assert_eq!(out["data"][1]["lines"][0]["number"], 1);
    }

    #[test]
    fn a_dotted_entry_is_case_insensitive_and_can_be_longer_than_two_segments() {
        let v = json!({
            "Billing": { "Address": { "Line1": "1 Main St", "city": "Leeds" } },
            "shipping": { "address": { "line1": "2 High St" } }
        });
        let out = redact(v, &["billing.address.line1".into()]);
        assert_eq!(out["Billing"]["Address"]["Line1"], REDACTED);
        assert_eq!(out["Billing"]["Address"]["city"], "Leeds");
        assert_eq!(out["shipping"]["address"]["line1"], "2 High St");
    }

    #[test]
    fn a_bare_entry_still_matches_anywhere_beside_a_dotted_one() {
        let v = json!({
            "email": "a@b.com",
            "customer": { "email": "c@d.com", "card": { "number": "4242" } },
            "number": "INV-1"
        });
        let out = redact(v, &["email".into(), "card.number".into()]);
        assert_eq!(out["email"], REDACTED);
        assert_eq!(out["customer"]["email"], REDACTED);
        assert_eq!(out["customer"]["card"]["number"], REDACTED);
        assert_eq!(out["number"], "INV-1");
    }

    #[test]
    fn a_key_literally_named_with_a_dot_is_still_caught() {
        let v = json!({ "card.number": "4242" });
        let out = redact(v, &["card.number".into()]);
        assert_eq!(out["card.number"], REDACTED);
    }

    #[test]
    fn the_effective_set_starts_from_every_default() {
        let set = effective_redact_keys(["Email", " card.number ", "email", ""]);
        for d in default_redact_keys() {
            assert!(set.contains(&d), "default '{d}' missing from the effective set");
        }
        assert_eq!(set.iter().filter(|k| *k == "email").count(), 1, "deduplicated case-insensitively");
        assert!(set.contains(&"card.number".to_string()), "trimmed");
        assert!(!set.contains(&String::new()), "blank entries dropped");
    }

    #[test]
    fn no_addition_can_un_redact_a_default() {
        // Whatever shape an addition takes, including ones that look like removals, the result is
        // a superset of the defaults and a response carrying credential keys stays redacted.
        let hostile = [
            "-authorization", "!authorization", "~client_secret", "authorization:false",
            "*", "", " ", ".", "authorization.", ".client_secret", "!", "none",
        ];
        let set = effective_redact_keys(hostile);
        let v = json!({
            "authorization": "Bearer live",
            "client_secret": "cs_live",
            "nested": { "Authorization": "Bearer x", "items": [ { "client_secret": "y" } ] }
        });
        let out = redact(v, &set);
        assert_eq!(out["authorization"], REDACTED);
        assert_eq!(out["client_secret"], REDACTED);
        assert_eq!(out["nested"]["Authorization"], REDACTED);
        assert_eq!(out["nested"]["items"][0]["client_secret"], REDACTED);
        for d in default_redact_keys() {
            assert!(set.contains(&d), "default '{d}' was removed by a hostile addition");
        }
    }
}
