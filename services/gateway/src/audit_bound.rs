//! What an audit summary keeps of text and values someone else chose. The chain's hot window is resident on a hosted worker and comes back whole with every restored snapshot, so a field an agent or a member sets is kept whole only while it is small, and otherwise cut, with its length and SHA-256 so the original can still be matched.

use std::borrow::Cow;

use serde::Serialize;
use serde_json::Value;

/// The longest string a summary keeps whole (1 KiB).
pub const TEXT_MAX: usize = 1024;

/// How much of a longer string a summary keeps (its first 256 bytes, to a character boundary).
pub const TEXT_KEPT: usize = 256;

/// The most a recorded value may take serialized before a summary keeps only its length and SHA-256 (8 KiB).
pub const VALUE_MAX: usize = 8 * 1024;

/// `text` when it is at most [`TEXT_MAX`] bytes; otherwise its first [`TEXT_KEPT`] bytes, its length and its SHA-256.
pub fn cut_text(text: &str) -> Cow<'_, str> {
    if text.len() <= TEXT_MAX {
        return Cow::Borrowed(text);
    }
    let mut end = TEXT_KEPT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Cow::Owned(format!(
        "{}... [cut from {} bytes, sha256 {}]",
        &text[..end],
        text.len(),
        permaura_core::audit::sha256_hex(text.as_bytes())
    ))
}

/// Every string in `value`, object keys included, cut by [`cut_text`]; `except` names top-level members already bounded where they were made, which are left as they are.
pub fn cut_strings(value: &mut Value, except: &[&str]) {
    match value {
        Value::Object(map) => {
            let long_keys = map.keys().any(|k| k.len() > TEXT_MAX);
            if long_keys {
                let entries = std::mem::take(map);
                for (key, mut member) in entries {
                    if !except.contains(&key.as_str()) {
                        cut_strings(&mut member, &[]);
                    }
                    map.insert(cut_text(&key).into_owned(), member);
                }
            } else {
                for (key, member) in map.iter_mut() {
                    if !except.contains(&key.as_str()) {
                        cut_strings(member, &[]);
                    }
                }
            }
        }
        Value::Array(items) => items.iter_mut().for_each(|item| cut_strings(item, &[])),
        Value::String(text) => {
            if let Cow::Owned(cut) = cut_text(text) {
                *text = cut;
            }
        }
        _ => {}
    }
}

/// `payload`'s action, resource and agent id cut by [`cut_text`], as every store appends it: the first two name a capability and its connection, whose ids a vault restore or an earlier version may have stored at any length, and an OAuth agent id carries a client id from the token verbatim.
pub fn cut_ids(payload: &mut permaura_core::AuditPayload) {
    let fields = [&mut payload.action, &mut payload.resource].into_iter().chain(payload.agent_id.as_mut());
    for field in fields {
        if let Cow::Owned(cut) = cut_text(field) {
            *field = cut;
        }
    }
}

/// `agent_id` as [`cut_ids`] seals it into the chain, which is the key grant usage is filed and read under, so a budget counted from the chain and one asked about by the caller's whole id agree.
pub fn agent_key(agent_id: &str) -> Cow<'_, str> {
    cut_text(agent_id)
}

/// `value` as a summary records it: whole, its long strings cut, while it serializes to at most [`VALUE_MAX`] bytes; otherwise only how long it was and its SHA-256.
pub fn recorded<T: Serialize + ?Sized>(value: &T) -> Value {
    let text = match serde_json::to_string(value) {
        Ok(text) => text,
        Err(_) => return Value::Null,
    };
    if text.len() > VALUE_MAX {
        return serde_json::json!({
            "omitted": format!("{} bytes, more than an audit event keeps", text.len()),
            "bytes": text.len(),
            "sha256": permaura_core::audit::sha256_hex(text.as_bytes()),
        });
    }
    let mut value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    cut_strings(&mut value, &[]);
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn short_text_is_kept_and_long_text_is_cut_with_its_length_and_digest() {
        assert!(matches!(cut_text("a reason"), Cow::Borrowed("a reason")));
        let long = "é".repeat(TEXT_MAX);
        let cut = cut_text(&long);
        assert!(cut.len() < TEXT_KEPT + 128, "{} bytes", cut.len());
        assert!(cut.starts_with(&"é".repeat(TEXT_KEPT / 2)));
        assert!(cut.contains(&format!("cut from {} bytes", long.len())));
        assert!(cut.contains(&permaura_core::audit::sha256_hex(long.as_bytes())));
    }

    #[test]
    fn every_string_is_cut_but_the_members_named_as_already_bounded() {
        let long = "x".repeat(2 * TEXT_MAX);
        let mut summary = json!({ "reason": long, "intent": long, "detail": [{ "host": long }], "ok": true });
        summary.as_object_mut().unwrap().insert(long.clone(), json!(1));
        cut_strings(&mut summary, &["intent"]);
        assert!(summary["reason"].as_str().unwrap().len() < TEXT_MAX);
        assert_eq!(summary["intent"].as_str().unwrap().len(), long.len(), "left as its maker bounded it");
        assert!(summary["detail"][0]["host"].as_str().unwrap().len() < TEXT_MAX);
        assert!(summary.as_object().unwrap().keys().all(|k| k.len() < TEXT_MAX));
        assert_eq!(summary["ok"], true);
    }

    #[test]
    fn a_long_action_resource_or_agent_id_is_cut_and_a_short_one_kept_whole() {
        let long = "c".repeat(200_000);
        let mut payload = permaura_core::AuditPayload::new(format!("conn.{long}"), long.clone(), "deny");
        payload.agent_id = Some("agent_demo".into());
        cut_ids(&mut payload);
        assert!(payload.action.len() < TEXT_KEPT + 128, "{} bytes", payload.action.len());
        assert!(payload.action.starts_with("conn.ccc"));
        assert!(payload.action.contains(&permaura_core::audit::sha256_hex(format!("conn.{long}").as_bytes())));
        assert!(payload.resource.contains(&format!("cut from {} bytes", long.len())));
        assert_eq!(payload.agent_id.as_deref(), Some("agent_demo"));

        let agent = format!("oauth:{long}");
        let mut oauth = permaura_core::AuditPayload::new("github.pull_requests.list", "github_work", "allow");
        oauth.agent_id = Some(agent.clone());
        cut_ids(&mut oauth);
        let kept = oauth.agent_id.as_deref().unwrap();
        assert!(kept.len() < TEXT_KEPT + 128, "{} bytes", kept.len());
        assert!(kept.starts_with("oauth:ccc"));
        assert!(kept.contains(&permaura_core::audit::sha256_hex(agent.as_bytes())));
        assert_eq!(agent_key(&agent), kept, "usage is keyed the way the chain records the agent");
        assert_eq!(agent_key(kept), kept, "a sealed id keys as itself");

        let mut short = permaura_core::AuditPayload::new("github.pull_requests.list", "github_work", "allow");
        let before = short.clone();
        cut_ids(&mut short);
        assert_eq!(short, before);
    }

    #[test]
    fn a_large_value_is_recorded_as_its_length_and_digest() {
        let small = json!({ "deny": ["refund", "sale"] });
        assert_eq!(recorded(&small), small);
        let large = json!({ "deny": vec!["transactions.refund"; 2_000] });
        let text = serde_json::to_string(&large).unwrap();
        let kept = recorded(&large);
        assert_eq!(kept["bytes"], text.len());
        assert_eq!(kept["sha256"], permaura_core::audit::sha256_hex(text.as_bytes()));
        assert!(serde_json::to_string(&kept).unwrap().len() < 256);
    }
}
