//! What an approver is shown about a held call, and the digest a device signs over it.
//!
//! The gateway renders a held call's parameters into [`DisplayRow`]s: redacted and escaped, so every
//! approval surface prints the same text and none of them ever receives a secret. It serves two
//! renderings. The compact one ([`ApprovalDisplay`], `params_display`) is capped for cards and lists
//! and says whether it is [`complete`](ApprovalDisplay::complete). The full one
//! ([`ApprovalDisplayFull`], `params_display_full`, on `GET /v1/approvals/:id` only) has no row,
//! depth or length cap, only a size ceiling, and is the one an approve binds: a device computes
//! [`approval_display_full_digest`] over the rows it showed, plus the call's capability, resource,
//! risk, description, message and the agent's stated intent, and puts it in
//! [`crate::approval_result_preimage_v3`]. The gateway recomputes it from the held row, so a broker
//! that shows one call while the device signs another is refused, and so is any approve of a call too
//! large to be shown whole.
//!
//! The digest is a length-prefixed byte layout rather than a hash of JSON, for the same reason the
//! signing preimages are: the phone (TypeScript), the watch (Swift) and the desktop (this crate)
//! must produce identical bytes, and JSON canonicalisation is where those drift.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The rendering version this crate produces and the only one a signer may accept.
pub const APPROVAL_DISPLAY_VERSION: u32 = 1;

/// The compact rendering's digest domain, the first field of its preimage.
pub const APPROVAL_DISPLAY_DOMAIN: &str = "permaura/approval-display/v1";

/// The full rendering's digest domain. Different from the compact one, so a digest of a capped
/// rendering can never stand in for the full one a v3 approve must bind.
pub const APPROVAL_DISPLAY_FULL_DOMAIN: &str = "permaura/approval-display-full/v1";

/// How a row's value was treated. A client that meets a state it does not know must refuse to sign:
/// it cannot show the approver what that row means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisplayState {
    /// The value as it will be sent, escaped.
    Shown,
    /// A secret-bearing value: `value` says it is set and how long it is, never what it is.
    Redacted,
    /// A value with secrets inside it, each replaced by `[redacted]` and the rest shown.
    Masked,
    /// A long string cut short: `value` carries the start and the full length. Compact only.
    Truncated,
    /// A container below the depth cap: `value` says how many fields or items it holds. Compact only.
    Collapsed,
}

impl DisplayState {
    /// The word this state is hashed and served as.
    pub fn as_str(self) -> &'static str {
        match self {
            DisplayState::Shown => "shown",
            DisplayState::Redacted => "redacted",
            DisplayState::Masked => "masked",
            DisplayState::Truncated => "truncated",
            DisplayState::Collapsed => "collapsed",
        }
    }

    /// Whether a row in this state stands for less than the whole value it renders.
    pub fn is_partial(self) -> bool {
        matches!(self, DisplayState::Truncated | DisplayState::Collapsed)
    }
}

/// One parameter as an approver sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisplayRow {
    /// Where the value sits in the call's parameters, e.g. `items[0].price_id`.
    pub path: String,
    /// How the value was treated.
    pub state: DisplayState,
    /// The text every surface prints for it.
    pub value: String,
}

/// The compact rendering, served as `params_display` on every approval read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDisplay {
    /// [`APPROVAL_DISPLAY_VERSION`].
    pub version: u32,
    /// The parameters, in a fixed order.
    pub rows: Vec<DisplayRow>,
    /// Further values that are not listed because the row cap was reached.
    pub omitted: u32,
    /// True when nothing was omitted, truncated or collapsed: the rows are the full rendering, and a
    /// card may offer Approve on them. Derived from `rows` and `omitted`, so not hashed.
    pub complete: bool,
    /// [`approval_display_digest`] as the gateway computed it.
    pub digest: String,
}

/// The full rendering, served as `params_display_full` on `GET /v1/approvals/:id`. Either the rows
/// and their digest, or `too_large` with the rendered size, in which case nothing can approve it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalDisplayFull {
    /// [`APPROVAL_DISPLAY_VERSION`].
    pub version: u32,
    /// Every parameter, uncapped. Absent when `too_large`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rows: Option<Vec<DisplayRow>>,
    /// [`approval_display_full_digest`] of `rows`. Absent when `too_large`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    /// The rendering passed the gateway's ceiling, so it is not served and a device can only deny.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub too_large: bool,
    /// Bytes of rendered text (paths and values), or the point at which rendering stopped.
    pub size: u64,
}

/// The approval fields an approver reads beside the parameters, all bound into the digest, as the
/// gateway serves them (already escaped). `None` and an empty string hash identically.
#[derive(Debug, Clone, Copy, Default)]
pub struct DisplayContext<'a> {
    /// The capability the call runs.
    pub capability: &'a str,
    /// The resource it acts on.
    pub resource: &'a str,
    /// The gateway's risk label for it.
    pub risk: &'a str,
    /// The gateway's one-sentence description of what runs, if any.
    pub action_description: Option<&'a str>,
    /// The gateway's message for the hold.
    pub message: &'a str,
    /// What the agent said the call is for: its claim, never the gateway's.
    pub intent: Option<&'a str>,
}

fn digest_with(domain: &str, ctx: &DisplayContext<'_>, rows: &[DisplayRow], omitted: u32) -> String {
    let mut buf = Vec::new();
    let mut put = |b: &[u8]| {
        buf.extend_from_slice(&(b.len() as u32).to_be_bytes());
        buf.extend_from_slice(b);
    };
    put(domain.as_bytes());
    put(ctx.capability.as_bytes());
    put(ctx.resource.as_bytes());
    put(ctx.risk.as_bytes());
    put(ctx.action_description.unwrap_or("").as_bytes());
    put(ctx.message.as_bytes());
    put(ctx.intent.unwrap_or("").as_bytes());
    put(&(rows.len() as u32).to_be_bytes());
    for row in rows {
        put(row.path.as_bytes());
        put(row.state.as_str().as_bytes());
        put(row.value.as_bytes());
    }
    put(&omitted.to_be_bytes());
    Sha256::digest(&buf).iter().map(|b| format!("{b:02x}")).collect()
}

/// Lowercase-hex SHA-256 over the length-prefixed compact preimage: `domain, capability, resource,
/// risk, action_description, message, intent, u32 row count, then per row path, state, value, then
/// u32 omitted`, each field a `u32` big-endian length and its bytes.
pub fn approval_display_digest(ctx: &DisplayContext<'_>, rows: &[DisplayRow], omitted: u32) -> String {
    digest_with(APPROVAL_DISPLAY_DOMAIN, ctx, rows, omitted)
}

/// The same layout under [`APPROVAL_DISPLAY_FULL_DOMAIN`] with `omitted` always 0: what a v3 approve binds.
pub fn approval_display_full_digest(ctx: &DisplayContext<'_>, rows: &[DisplayRow]) -> String {
    digest_with(APPROVAL_DISPLAY_FULL_DOMAIN, ctx, rows, 0)
}

fn context_of(approval: &serde_json::Value) -> DisplayContext<'_> {
    let text = |key: &str| approval.get(key).and_then(|v| v.as_str()).unwrap_or("");
    DisplayContext {
        capability: text("capability"),
        resource: text("resource"),
        risk: text("risk"),
        action_description: approval.get("action_description").and_then(|v| v.as_str()),
        message: text("message"),
        intent: approval.get("intent").and_then(|v| v.as_str()),
    }
}

const NOT_SENT: &str = "this gateway did not send the parameters the call would run with";

/// The compact digest of an approval exactly as a gateway served it. An `Err` means the approval
/// carries no compact rendering this crate can vouch for.
pub fn approval_display_digest_of(approval: &serde_json::Value) -> Result<String, String> {
    let display = compact_of(approval)?;
    Ok(display.digest)
}

fn compact_of(approval: &serde_json::Value) -> Result<ApprovalDisplay, String> {
    let display = approval.get("params_display").filter(|d| !d.is_null()).ok_or_else(|| NOT_SENT.to_string())?;
    let display: ApprovalDisplay = serde_json::from_value(display.clone())
        .map_err(|e| format!("the parameters this gateway sent cannot be read: {e}"))?;
    if display.version != APPROVAL_DISPLAY_VERSION {
        return Err(format!("the parameters this gateway sent are in a version this app cannot show ({})", display.version));
    }
    let digest = approval_display_digest(&context_of(approval), &display.rows, display.omitted);
    if digest != display.digest {
        return Err("the parameters this gateway sent do not match their own digest".into());
    }
    let complete = display.omitted == 0 && !display.rows.iter().any(|r| r.state.is_partial());
    if complete != display.complete {
        return Err("the parameters this gateway sent misstate whether they are complete".into());
    }
    Ok(display)
}

/// The full digest of an approval exactly as a gateway served it (`params_display_full`). An `Err`
/// means it cannot be approved on what was served: no full rendering, one too large to show, one in
/// a version or state this crate does not know, or rows that disagree with their own digest.
pub fn approval_display_full_digest_of(approval: &serde_json::Value) -> Result<String, String> {
    let full = approval.get("params_display_full").filter(|d| !d.is_null()).ok_or_else(|| NOT_SENT.to_string())?;
    let full: ApprovalDisplayFull = serde_json::from_value(full.clone())
        .map_err(|e| format!("the parameters this gateway sent cannot be read: {e}"))?;
    if full.version != APPROVAL_DISPLAY_VERSION {
        return Err(format!("the parameters this gateway sent are in a version this app cannot show ({})", full.version));
    }
    if full.too_large {
        return Err(format!(
            "this call's parameters are too large to show in full ({} bytes), so it can only be denied; change the policy rung for this action to allow such calls",
            full.size
        ));
    }
    let (Some(rows), Some(served)) = (full.rows, full.digest) else {
        return Err("the parameters this gateway sent cannot be read".into());
    };
    if rows.iter().any(|r| r.state.is_partial()) {
        return Err("the full parameters this gateway sent are not complete".into());
    }
    let digest = approval_display_full_digest(&context_of(approval), &rows);
    if digest != served {
        return Err("the parameters this gateway sent do not match their own digest".into());
    }
    Ok(digest)
}

/// The full digest of what a surface DISPLAYED for `approval`: its full rendering when it showed
/// one, else its compact rendering when that is complete (the same rows). `Err` when it showed less
/// than the whole call, which is never enough to approve.
pub fn approval_shown_full_digest(approval: &serde_json::Value) -> Result<String, String> {
    if approval.get("params_display_full").is_some_and(|f| !f.is_null()) {
        return approval_display_full_digest_of(approval);
    }
    let compact = compact_of(approval)?;
    if !compact.complete {
        return Err("only part of this call's parameters was shown; review all of them before approving".into());
    }
    Ok(approval_display_full_digest(&context_of(approval), &compact.rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn paddle_rows() -> Vec<DisplayRow> {
        vec![
            DisplayRow { path: "effective_from".into(), state: DisplayState::Shown, value: "\"immediately\"".into() },
            DisplayRow { path: "subscription_id".into(), state: DisplayState::Shown, value: "\"sub_01h8\"".into() },
        ]
    }

    fn paddle_ctx() -> DisplayContext<'static> {
        DisplayContext {
            capability: "paddle.subscriptions.cancel",
            resource: "paddle_live",
            risk: "high",
            action_description: Some("Cancel a subscription."),
            message: "Approve 'subscriptions.cancel' on 'paddle_live'?",
            intent: Some("Cancel at the end of the billing period."),
        }
    }

    /// Non-ASCII, emoji and escaped text, as a gateway renders them: the bytes are UTF-8 and the
    /// escapes are literal backslash sequences, so every implementation must hash exactly these.
    fn unicode_rows() -> Vec<DisplayRow> {
        vec![
            DisplayRow { path: "note".into(), state: DisplayState::Shown, value: "\"Café für 東京 🚀\"".into() },
            DisplayRow { path: "[\"naïve key\"]".into(), state: DisplayState::Masked, value: "\"p\\u{0430}ypal.com [redacted]\"".into() },
            DisplayRow { path: "token".into(), state: DisplayState::Redacted, value: "set, 12 characters".into() },
        ]
    }

    fn unicode_ctx() -> DisplayContext<'static> {
        DisplayContext {
            capability: "http.request",
            resource: "generic_http",
            risk: "unknown",
            action_description: None,
            message: "Approve 'request' on 'generic_http'?",
            intent: Some("Envoyer le reçu à José \\u{202e} 👍"),
        }
    }

    /// Frozen: the phone (`lib/__tests__/approvalDisplay.test.ts`), the watch
    /// (`scripts/watch/PreimageVectors.swift`), the desktop and the console assert these exact values.
    #[test]
    fn the_display_digests_are_frozen() {
        assert_eq!(
            approval_display_digest(&paddle_ctx(), &paddle_rows(), 0),
            "bd4f322abe9452c694a24da4664e9bdc846325f8446fca8ab0b31f19d257d505"
        );
        assert_eq!(
            approval_display_full_digest(&paddle_ctx(), &paddle_rows()),
            "e9492208421f5aae8489f144bc8e658217ae24d2d077fb286f71501ea2ff47ad"
        );
        let empty = DisplayContext { capability: "permaura.vault.export", ..Default::default() };
        assert_eq!(
            approval_display_digest(&empty, &[], 3),
            "07d31d32feecf0525c0b2e6fc220c9d3103c285dbda5f9ced5bd61501b4e1119"
        );
        assert_eq!(
            approval_display_full_digest(&unicode_ctx(), &unicode_rows()),
            "0f0665f3937a0ce8194fd1466aff198082684ed4f24c53435b7daededf2ddb4e"
        );
    }

    #[test]
    fn every_bound_field_changes_the_digest() {
        let base = approval_display_full_digest(&paddle_ctx(), &paddle_rows());
        assert_ne!(approval_display_digest(&paddle_ctx(), &paddle_rows(), 0), base, "the compact domain");
        let mut rows = paddle_rows();
        rows[0].value = "\"next_billing_period\"".into();
        assert_ne!(approval_display_full_digest(&paddle_ctx(), &rows), base, "a value");
        let mut rows = paddle_rows();
        rows[0].state = DisplayState::Masked;
        assert_ne!(approval_display_full_digest(&paddle_ctx(), &rows), base, "a state");
        let mut rows = paddle_rows();
        rows[0].path = "effective_from ".into();
        assert_ne!(approval_display_full_digest(&paddle_ctx(), &rows), base, "a path");
        assert_ne!(approval_display_full_digest(&paddle_ctx(), &paddle_rows()[..1]), base, "a dropped row");
        assert_ne!(
            approval_display_digest(&paddle_ctx(), &paddle_rows(), 1),
            approval_display_digest(&paddle_ctx(), &paddle_rows(), 0),
            "the omitted count"
        );
        for ctx in [
            DisplayContext { capability: "paddle.subscriptions.pause", ..paddle_ctx() },
            DisplayContext { resource: "paddle_sandbox", ..paddle_ctx() },
            DisplayContext { risk: "low", ..paddle_ctx() },
            DisplayContext { action_description: None, ..paddle_ctx() },
            DisplayContext { message: "Cancel immediately.", ..paddle_ctx() },
            DisplayContext { intent: Some("Cancel immediately."), ..paddle_ctx() },
            DisplayContext { intent: None, ..paddle_ctx() },
        ] {
            assert_ne!(approval_display_full_digest(&ctx, &paddle_rows()), base);
        }
    }

    #[test]
    fn the_length_prefix_stops_one_field_borrowing_from_the_next() {
        let a = vec![DisplayRow { path: "ab".into(), state: DisplayState::Shown, value: "c".into() }];
        let b = vec![DisplayRow { path: "a".into(), state: DisplayState::Shown, value: "bc".into() }];
        assert_ne!(approval_display_full_digest(&paddle_ctx(), &a), approval_display_full_digest(&paddle_ctx(), &b));
    }

    fn served(rows: Vec<DisplayRow>, omitted: u32, full: bool) -> serde_json::Value {
        let complete = omitted == 0 && !rows.iter().any(|r| r.state.is_partial());
        let mut a = json!({
            "capability": "paddle.subscriptions.cancel",
            "resource": "paddle_live",
            "risk": "high",
            "action_description": "Cancel a subscription.",
            "message": "Approve 'subscriptions.cancel' on 'paddle_live'?",
            "intent": "Cancel at the end of the billing period.",
            "params_display": {
                "version": 1,
                "rows": rows,
                "omitted": omitted,
                "complete": complete,
                "digest": approval_display_digest(&paddle_ctx(), &rows, omitted),
            },
        });
        if full {
            a["params_display_full"] = json!({
                "version": 1,
                "rows": paddle_rows(),
                "digest": approval_display_full_digest(&paddle_ctx(), &paddle_rows()),
                "size": 64,
            });
        }
        a
    }

    #[test]
    fn a_served_approval_yields_the_digests_its_rows_produce() {
        let a = served(paddle_rows(), 0, true);
        assert_eq!(approval_display_digest_of(&a), Ok(approval_display_digest(&paddle_ctx(), &paddle_rows(), 0)));
        let full = approval_display_full_digest(&paddle_ctx(), &paddle_rows());
        assert_eq!(approval_display_full_digest_of(&a), Ok(full.clone()));
        assert_eq!(approval_shown_full_digest(&a), Ok(full.clone()));
        let compact_only = served(paddle_rows(), 0, false);
        assert_eq!(approval_shown_full_digest(&compact_only), Ok(full), "a complete compact rendering is the whole call");
    }

    #[test]
    fn a_rendering_that_shows_less_than_the_whole_call_cannot_be_approved() {
        let mut cut = paddle_rows();
        cut[0].state = DisplayState::Truncated;
        assert!(approval_shown_full_digest(&served(cut, 0, false)).is_err(), "a truncated row");
        assert!(approval_shown_full_digest(&served(paddle_rows()[..1].to_vec(), 1, false)).is_err(), "an omitted row");
        let mut a = served(paddle_rows(), 0, false);
        a["params_display"]["complete"] = json!(false);
        assert!(approval_display_digest_of(&a).is_err(), "a complete flag that disagrees with the rows");
        let mut big = served(paddle_rows(), 0, false);
        big["params_display_full"] = json!({ "version": 1, "too_large": true, "size": 300_000 });
        let err = approval_display_full_digest_of(&big).unwrap_err();
        assert!(err.contains("too large") && err.contains("policy rung"), "{err}");
        assert!(approval_shown_full_digest(&big).is_err(), "a surface holding a too-large rendering showed nothing whole");
    }

    #[test]
    fn a_served_approval_that_cannot_be_shown_faithfully_is_refused() {
        let mut tampered = served(paddle_rows(), 0, true);
        tampered["params_display_full"]["rows"][0]["value"] = json!("\"next_billing_period\"");
        assert!(approval_display_full_digest_of(&tampered).is_err(), "rows that disagree with the served digest");

        let mut relabelled = served(paddle_rows(), 0, true);
        relabelled["intent"] = json!("Cancel immediately.");
        assert!(approval_display_full_digest_of(&relabelled).is_err(), "an intent that disagrees with the digest");

        let mut absent = served(paddle_rows(), 0, true);
        absent.as_object_mut().unwrap().remove("params_display_full");
        assert!(approval_display_full_digest_of(&absent).is_err(), "no full rendering at all");

        let mut later = served(paddle_rows(), 0, true);
        later["params_display_full"]["version"] = json!(2);
        assert!(approval_display_full_digest_of(&later).is_err(), "a version this build cannot show");

        let mut unknown = served(paddle_rows(), 0, true);
        unknown["params_display_full"]["rows"][0]["state"] = json!("summarised");
        assert!(approval_display_full_digest_of(&unknown).is_err(), "a row state this build cannot show");
    }
}
