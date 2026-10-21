//! Out-of-band approval notifications: a second, human-scale channel for the `approve` and
//! `notify` rungs, alongside the device push in [`crate::push`]. Slack, Discord, Buzz, and a
//! generic JSON webhook for everything else.
//!
//! An operator configures one or more channels and the gateway posts a short card when an action
//! is held for approval, or when a `notify`-rung action has already run. The card carries a
//! **deep link into the authenticated console**, never a way to act from chat: the decision is
//! still made on a surface that authenticates the human.
//!
//! SECURITY: three invariants, all enforced here rather than at the call sites so a future caller
//! cannot leak by omission, and shared by every channel so adding one cannot quietly opt out:
//!
//! 1. **`device_signed`-tier approvals are never posted.** That rung exists precisely because a
//!    channel the control plane (or a workspace/server admin, or anyone who has ever been in the
//!    channel) can observe is not a trustworthy approval surface. Device-signed stays device-only
//!    BY DESIGN. [`notify_approval`] drops those before a payload is ever built.
//! 2. **No parameters, results, or secrets.** The card carries the capability id, the connection
//!    id, the operator-authored approval message, the approval id, the captured risk grade, and a
//!    link to the console that names the workspace when the gateway knows it. Nothing derived from
//!    the agent's request body, and nothing that passed through the custody seam.
//!    [`AnnouncedApproval`] makes that a property of the type rather than a rule the payload builders
//!    must remember.
//! 3. **Nothing in the card can act.** No token, no signed link, no approval query string that a
//!    channel member could replay: the link lands on `/console/approvals`, which authenticates.
//!
//! Configuration is **environment-only** (`PERMAURA_SLACK_WEBHOOK_URL`,
//! `PERMAURA_DISCORD_WEBHOOK_URL`, `PERMAURA_WEBHOOK_URL`, `PERMAURA_BUZZ_*`), deliberately: a
//! webhook URL settable over REST would hand the broker an outbound-request primitive pointed at a
//! host of its choosing, and a settable Buzz key would be worse. The host operator who sets the env
//! already runs the process. `PERMAURA_WEBHOOK_URL` additionally has a `webhook_url` key in
//! `~/.permaura/config.toml` ([`crate::config`]), because the operator who most needs a generic
//! webhook is the one running the gateway by hand, for whom an env var lasts exactly as long as the
//! shell. Same authority, since writing that file means access to the gateway's own home.
//!
//! Buzz is not a webhook. The gateway signs as a Buzz identity and posts through the `buzz` CLI,
//! which means two things the webhook channels never had to think about: the worker now holds a
//! **private key** (give it its own identity, never a person's), and the gateway **spawns a child
//! process**. That child gets an explicit environment rather than an inherited one (the gateway's
//! own environment holds the vault passphrase and the operator token), and the message body goes
//! in on stdin, never argv, so approvals stay off the process table.
//!
//! Best-effort throughout: every failure is logged and swallowed, and the send is meant to be
//! `tokio::spawn`ed from the enforcement loop so it never delays the agent's response.

use std::time::Duration;

use crate::store::PendingApproval;

/// The approval tier that must never leave the device. See invariant 1 in the module docs.
const DEVICE_SIGNED_TIER: &str = "device_signed";

/// How long a webhook POST may take before it is abandoned. The send is detached, but an
/// unbounded hang would leak a task per held approval.
const POST_TIMEOUT: Duration = Duration::from_secs(10);

/// The console a deep link points at when `PERMAURA_CONSOLE_URL` is unset.
const DEFAULT_CONSOLE_URL: &str = "https://permaura.com";

/// Which chat service a channel speaks. They differ in payload shape, in what counts as success,
/// and (the part that matters) in how a hostile string turns into a working link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// Slack incoming webhook (Block Kit, mrkdwn).
    Slack,
    /// Discord incoming webhook (embeds, markdown).
    Discord,
    /// A Buzz community, reached through the `buzz` CLI. Not a webhook: the gateway signs as a
    /// Buzz identity, so this one carries a private key rather than a URL bearing a token.
    Buzz,
    /// Any endpoint that accepts a JSON POST: ntfy, Pushover, Home Assistant, a script behind a
    /// reverse proxy. The self-hosted answer to "how do I get told", and deliberately the plainest
    /// shape here: flat JSON with stable keys, no service's markup dialect, nothing to escape.
    ///
    /// It exists because a self-run operator's notification path should not depend on us. The
    /// chat channels post a card a human reads in a team channel; this one posts a fact a program
    /// consumes. Same three invariants as every other channel: a `device_signed` approval is
    /// never announced, no parameters or results are in the body, and nothing in it can act.
    Generic,
}

impl Channel {
    /// For logs. Never carries a webhook URL or a key.
    fn name(self) -> &'static str {
        match self {
            Channel::Slack => "slack",
            Channel::Discord => "discord",
            Channel::Buzz => "buzz",
            Channel::Generic => "webhook",
        }
    }
}

/// Whether an HTTP response status means the message landed. Slack answers `200 ok`; Discord
/// answers **204 No Content** for a webhook without `?wait=true`, so a naive `== 200` would log
/// every successful Discord post as a failure.
fn http_delivered(status: u16) -> bool {
    (200..300).contains(&status)
}

/// How a channel is actually reached. Two shapes, and the difference is not cosmetic: a webhook
/// URL is a bearer credential the gateway sends *to*, while Buzz is a **signing identity** the
/// gateway posts *as*.
#[derive(Debug, Clone)]
enum Transport {
    /// An incoming-webhook URL. Secret: never logged, never serialized, never returned over REST.
    Webhook { url: String },
    /// The `buzz` CLI, spawned with an explicit environment.
    Buzz {
        /// Community host, https only.
        relay_url: String,
        /// 64-hex agent secret. This signs everything the gateway posts, so it should be its own
        /// identity, never a person's.
        private_key: String,
        /// The channel UUID to post into.
        channel_id: String,
        /// NIP-OA attestation, when the relay requires one.
        auth_tag: Option<String>,
        /// Path to the binary; `buzz` on PATH by default.
        binary: String,
    },
}

/// Delivery settings for one channel, read from the environment at send time.
#[derive(Debug, Clone)]
pub struct ChannelConfig {
    /// Which service this channel speaks.
    channel: Channel,
    /// How to reach it.
    transport: Transport,
    /// Console origin the deep link is built against, no trailing slash.
    console_url: String,
    /// The workspace this gateway is enrolled into, when it knows. Present → the link routes
    /// through `/console/switch` so the operator lands in the right workspace rather than
    /// wherever their browser session last was.
    workspace_id: Option<String>,
}

impl ChannelConfig {
    /// Every configured channel, in a stable order. Empty (the default) means chat notifications
    /// are off and the whole path is a no-op.
    ///
    /// Read per-send rather than cached, matching how the approval floor reads its forcing env
    /// var, and so tests can drive it without a global.
    pub fn from_env() -> Vec<ChannelConfig> {
        let console = std::env::var("PERMAURA_CONSOLE_URL").ok();
        let workspace = std::env::var("PERMAURA_WORKSPACE_ID").ok();
        let mut out = Vec::new();
        for (channel, var) in [
            (Channel::Slack, "PERMAURA_SLACK_WEBHOOK_URL"),
            (Channel::Discord, "PERMAURA_DISCORD_WEBHOOK_URL"),
            (Channel::Generic, "PERMAURA_WEBHOOK_URL"),
        ] {
            if let Ok(url) = std::env::var(var) {
                if let Some(cfg) =
                    Self::webhook(channel, url, console.clone(), workspace.clone())
                {
                    out.push(cfg);
                }
            }
        }
        if let Some(cfg) = Self::buzz_from_env(console, workspace) {
            out.push(cfg);
        }
        out
    }

    /// Validate and assemble a webhook channel. Returns `None` for anything that is not a
    /// plausible https webhook: an `http://` URL would put the (secret) webhook path and the
    /// approval text on the wire in clear, and a non-URL is an operator typo worth refusing
    /// loudly at the first send.
    pub fn webhook(
        channel: Channel,
        webhook_url: String,
        console_url: Option<String>,
        workspace_id: Option<String>,
    ) -> Option<Self> {
        let url = webhook_url.trim().to_string();
        if url.is_empty() {
            return None;
        }
        if !url.starts_with("https://") {
            tracing::error!(
                channel = channel.name(),
                "webhook URL must be https://; notifications disabled for this channel"
            );
            return None;
        }
        Some(ChannelConfig {
            channel,
            transport: Transport::Webhook { url },
            console_url: normalise_console(console_url),
            workspace_id: normalise_workspace(workspace_id),
        })
    }

    /// Read `PERMAURA_BUZZ_*`. Namespaced rather than reusing the CLI's own `BUZZ_*` names so the
    /// gateway can never pick up an ambient key meant for something else on the same host; the
    /// `BUZZ_*` names are set explicitly on the child instead.
    fn buzz_from_env(console_url: Option<String>, workspace_id: Option<String>) -> Option<Self> {
        let any_set = ["PERMAURA_BUZZ_RELAY_URL", "PERMAURA_BUZZ_PRIVATE_KEY", "PERMAURA_BUZZ_CHANNEL"]
            .iter()
            .any(|k| std::env::var(k).is_ok_and(|v| !v.trim().is_empty()));
        let built = Self::buzz(
            std::env::var("PERMAURA_BUZZ_RELAY_URL").unwrap_or_default(),
            std::env::var("PERMAURA_BUZZ_PRIVATE_KEY").unwrap_or_default(),
            std::env::var("PERMAURA_BUZZ_CHANNEL").unwrap_or_default(),
            std::env::var("PERMAURA_BUZZ_AUTH_TAG").ok(),
            std::env::var("PERMAURA_BUZZ_BINARY").ok(),
            console_url,
            workspace_id,
        );
        // A half-configured channel is the footgun: approvals the operator believes are going to
        // Buzz would silently go nowhere. Say so once, loudly.
        if any_set && built.is_none() {
            tracing::error!(
                "PERMAURA_BUZZ_* is partially or invalidly configured: Buzz notifications disabled"
            );
        }
        built
    }

    /// Validate and assemble a Buzz channel.
    #[allow(clippy::too_many_arguments)]
    pub fn buzz(
        relay_url: String,
        private_key: String,
        channel_id: String,
        auth_tag: Option<String>,
        binary: Option<String>,
        console_url: Option<String>,
        workspace_id: Option<String>,
    ) -> Option<Self> {
        let relay_url = relay_url.trim().to_string();
        let private_key = private_key.trim().to_string();
        let channel_id = channel_id.trim().to_string();
        if relay_url.is_empty() || private_key.is_empty() || channel_id.is_empty() {
            return None;
        }
        if !relay_url.starts_with("https://") {
            tracing::error!("PERMAURA_BUZZ_RELAY_URL must be https://; Buzz notifications disabled");
            return None;
        }
        // A malformed key is a hard refusal, never a truncation or a retry: the key is the identity
        // everything is signed as, and half of one is not a smaller version of it.
        if private_key.len() != 64 || !private_key.chars().all(|c| c.is_ascii_hexdigit()) {
            tracing::error!(
                "PERMAURA_BUZZ_PRIVATE_KEY must be 64 hex characters; Buzz notifications disabled"
            );
            return None;
        }
        Some(ChannelConfig {
            channel: Channel::Buzz,
            transport: Transport::Buzz {
                relay_url,
                private_key,
                channel_id,
                auth_tag: auth_tag.map(|t| t.trim().to_string()).filter(|t| !t.is_empty()),
                binary: binary
                    .map(|b| b.trim().to_string())
                    .filter(|b| !b.is_empty())
                    .unwrap_or_else(|| "buzz".to_string()),
            },
            console_url: normalise_console(console_url),
            workspace_id: normalise_workspace(workspace_id),
        })
    }

    /// The console URL a card's link points at. Routed through `/console/switch` when the
    /// workspace is known so the operator lands in the workspace this gateway belongs to.
    pub fn approvals_link(&self) -> String {
        match &self.workspace_id {
            Some(ws) => format!(
                "{}/console/switch?ws={}&to=approvals",
                self.console_url,
                urlencode(ws)
            ),
            None => format!("{}/console/approvals", self.console_url),
        }
    }
}

/// The console origin every link this gateway hands a person is built against: `PERMAURA_CONSOLE_URL`
/// when set, else permaura.com. One answer, so an operator who repoints their console does not then
/// have to discover that some other surface kept the old one.
pub fn console_base() -> String {
    normalise_console(std::env::var("PERMAURA_CONSOLE_URL").ok())
}

fn normalise_console(console_url: Option<String>) -> String {
    console_url
        .map(|u| u.trim().trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| DEFAULT_CONSOLE_URL.to_string())
}

fn normalise_workspace(workspace_id: Option<String>) -> Option<String> {
    workspace_id.map(|w| w.trim().to_string()).filter(|w| !w.is_empty())
}

/// Percent-encode everything outside the unreserved set, so a workspace id can never break out of
/// the query string it is placed in.
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Escape Slack's three mrkdwn control characters. Without this a capability id or approval message
/// containing `<https://evil.example|Approve>` would render in the channel as a working link that
/// the gateway appears to have sent.
fn escape_slack(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

/// Backslash-escape Discord's markdown control characters.
///
/// The same attack as Slack's, in Discord's dialect: an embed description renders
/// `[Approve here](https://evil.example)` as a **masked link**, so `[`, `]`, `(` and `)` matter as
/// much as the emphasis characters. Pings are handled separately and belt-and-braces by
/// `allowed_mentions` on the payload, so an `@everyone` in a capability id renders as text and
/// notifies nobody.
fn escape_discord(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if matches!(c, '\\' | '*' | '_' | '~' | '`' | '|' | '>' | '#' | '[' | ']' | '(' | ')') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Cap a field so one pathological string cannot blow past a channel's block/embed limits and drop
/// the whole message. Truncates on a char boundary.
fn clamp(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{head}…")
}

/// The narrow projection of a held approval that the notifier is allowed to see: six strings (id,
/// capability, connection, message, rung and risk grade), and deliberately **not** `params` or
/// `result`. Built at the call site so the agent's request body
/// never crosses into the detached notification task at all: invariant 2 becomes a property of the
/// type rather than a rule a payload builder has to keep remembering.
#[derive(Debug, Clone)]
pub struct AnnouncedApproval {
    id: String,
    capability: String,
    resource: String,
    message: String,
    required_tier: String,
    risk: String,
}

impl From<&PendingApproval> for AnnouncedApproval {
    fn from(a: &PendingApproval) -> Self {
        AnnouncedApproval {
            id: a.id.clone(),
            capability: a.capability.clone(),
            resource: a.resource.clone(),
            message: a.message.clone(),
            required_tier: a.required_tier.clone(),
            risk: a.risk_label(),
        }
    }
}

/// What happened, in the two shapes worth telling a channel about.
#[derive(Debug, Clone)]
pub enum NotifyEvent {
    /// An `approve`-rung action is held and waiting for a human.
    ApprovalRequested {
        /// The approval id, shown so it can be correlated with the audit log.
        approval_id: String,
        /// The capability that was held (e.g. `stripe.refund`).
        capability: String,
        /// The connection it targeted.
        resource: String,
        /// The operator-authored approval message from the policy.
        message: String,
        /// The gateway's captured risk classification, or `unknown`. A tier name is public data:
        /// it says how bad the action is, never what it would touch, so it is the one piece of
        /// triage signal this projection can carry without widening what leaves the device.
        risk: String,
    },
    /// A `notify`-rung action executed unattended: after the fact, nothing to decide.
    Executed {
        /// The capability that ran.
        capability: String,
        /// The connection it ran against.
        resource: String,
    },
}

/// Whether a held approval may be announced in a channel at all.
///
/// `false` for the `device_signed` rung, by design: a device-signed decision is device-only.
/// Posting it would advertise a pending high-risk action on a channel that cannot resolve it, and
/// normalise chat as an approval surface for the one rung whose whole point is that it is not one.
/// Enforced here, at the module boundary, so no call site and no channel can leak by omission.
pub fn may_announce(approval: &AnnouncedApproval) -> bool {
    approval.required_tier != DEVICE_SIGNED_TIER
}

/// Build the webhook payload for an event on a given channel. Pure, so the wording and (the part
/// that matters) the escaping are testable without a network.
pub fn payload(cfg: &ChannelConfig, event: &NotifyEvent) -> serde_json::Value {
    match cfg.channel {
        Channel::Slack => slack_payload(cfg, event),
        Channel::Discord => discord_payload(cfg, event),
        // Buzz carries plain text, not JSON. See [`buzz_text`]. Rendered here too so a caller
        // that only knows about `payload` still gets something coherent rather than an empty body.
        Channel::Buzz => serde_json::json!({ "content": buzz_text(cfg, event) }),
        Channel::Generic => generic_payload(cfg, event),
    }
}

/// Flat JSON for a consumer that is a program rather than a chat client.
///
/// `title` and `message` are there because that pair is what ntfy, Pushover, Gotify and most of the
/// self-hosted notifiers read straight off a body, so the common case needs no transformation at
/// all. The structured fields sit alongside them for anything doing real routing, and the schema
/// is versioned, because this is the one channel whose consumer is somebody else's code and a
/// silent reshape would break it.
///
/// No markup, so nothing to escape: the chat channels have to worry about a policy's approval
/// message containing link syntax that renders as a fake button, and JSON string encoding makes
/// that a non-question here.
fn generic_payload(cfg: &ChannelConfig, event: &NotifyEvent) -> serde_json::Value {
    match event {
        NotifyEvent::ApprovalRequested { approval_id, capability, resource, message, risk } => {
            serde_json::json!({
                "schema": "permaura.notify.v1",
                "event": "approval_requested",
                "title": "Approval needed",
                "message": clamp(message, 500),
                "approval_id": clamp(approval_id, 64),
                "capability": clamp(capability, 120),
                "resource": clamp(resource, 120),
                // The captured grade, or `unknown`. A consumer routing on severity needs the same
                // string the chat cards show, not its own guess from the capability name.
                "risk": clamp(risk, 16),
                "url": cfg.approvals_link(),
            })
        }
        NotifyEvent::Executed { capability, resource } => serde_json::json!({
            "schema": "permaura.notify.v1",
            "event": "executed",
            // "Action executed", matching the other channels verbatim: an after-the-fact notice
            // must never read as a decision that is still open, and the shared invariant test
            // asserts that wording rather than trusting each channel to paraphrase it safely.
            "title": "Action executed",
            "message": format!(
                "{} ran on {}. No approval was required (notify rung).",
                clamp(capability, 120),
                clamp(resource, 120),
            ),
            "capability": clamp(capability, 120),
            "resource": clamp(resource, 120),
            "url": cfg.approvals_link(),
        }),
    }
}

/// Render an event as the plain-text body of a Buzz message.
///
/// No markup escaping: a Buzz message is text, and there is no inline-link syntax to smuggle a
/// fake button through. Mentions resolve by display name on Buzz, so an `@name` inside a policy's
/// approval message may notify somebody, noise rather than a security hole, and not worth
/// mangling operator-authored text over.
pub fn buzz_text(cfg: &ChannelConfig, event: &NotifyEvent) -> String {
    match event {
        NotifyEvent::ApprovalRequested { approval_id, capability, resource, message, risk } => format!(
            "Approval needed\n{}\n\nCapability: {}\nConnection: {}\nRisk: {}\nReview: {}\n\n{} · decide in the console: Permaura never accepts an approval from chat",
            clamp(message, 500),
            clamp(capability, 120),
            clamp(resource, 120),
            clamp(risk, 16),
            cfg.approvals_link(),
            clamp(approval_id, 64),
        ),
        NotifyEvent::Executed { capability, resource } => format!(
            "Action executed\n{} ran on {}. No approval was required (notify rung).\n\nConsole: {}",
            clamp(capability, 120),
            clamp(resource, 120),
            cfg.approvals_link(),
        ),
    }
}

fn slack_payload(cfg: &ChannelConfig, event: &NotifyEvent) -> serde_json::Value {
    match event {
        NotifyEvent::ApprovalRequested { approval_id, capability, resource, message, risk } => {
            serde_json::json!({
                "text": format!("Approval needed: {}", escape_slack(&clamp(capability, 120))),
                "blocks": [
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": format!("*Approval needed*\n{}", escape_slack(&clamp(message, 500))),
                        },
                    },
                    {
                        "type": "section",
                        "fields": [
                            { "type": "mrkdwn", "text": format!("*Capability*\n`{}`", escape_slack(&clamp(capability, 120))) },
                            { "type": "mrkdwn", "text": format!("*Connection*\n`{}`", escape_slack(&clamp(resource, 120))) },
                            { "type": "mrkdwn", "text": format!("*Risk*\n{}", escape_slack(&clamp(risk, 16))) },
                        ],
                    },
                    {
                        "type": "actions",
                        "elements": [
                            {
                                "type": "button",
                                "text": { "type": "plain_text", "text": "Review in console" },
                                "url": cfg.approvals_link(),
                                "style": "primary",
                            },
                        ],
                    },
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": format!(
                                    "`{}` · decide in the console: Permaura never accepts an approval from chat",
                                    escape_slack(&clamp(approval_id, 64)),
                                ),
                            },
                        ],
                    },
                ],
            })
        }
        NotifyEvent::Executed { capability, resource } => serde_json::json!({
            "text": format!(
                "Executed: {} on {}",
                escape_slack(&clamp(capability, 120)),
                escape_slack(&clamp(resource, 120))
            ),
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": format!(
                            "*Action executed*\n`{}` ran on `{}`. No approval was required (notify rung).",
                            escape_slack(&clamp(capability, 120)),
                            escape_slack(&clamp(resource, 120)),
                        ),
                    },
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": { "type": "plain_text", "text": "Open console" },
                            "url": cfg.approvals_link(),
                        },
                    ],
                },
            ],
        }),
    }
}

/// Brand green (`#25a777`) as a Discord embed colour, so a held approval is recognisable at a
/// glance in a busy channel.
const EMBED_COLOUR_PENDING: u32 = 0x25_a7_77;
/// A muted slate for the after-the-fact `notify` card: nothing is waiting on the reader.
const EMBED_COLOUR_EXECUTED: u32 = 0x64_74_8b;

/// Suppress every mention type. A capability id or approval message containing `@everyone` must
/// render as text and ping nobody; `users`/`roles` are pinned empty too so the intent survives a
/// reading of the docs where an empty `parse` alone falls back to defaults.
fn no_mentions() -> serde_json::Value {
    serde_json::json!({ "parse": [], "users": [], "roles": [], "replied_user": false })
}

fn discord_payload(cfg: &ChannelConfig, event: &NotifyEvent) -> serde_json::Value {
    match event {
        NotifyEvent::ApprovalRequested { approval_id, capability, resource, message, risk } => {
            serde_json::json!({
                "username": "Permaura",
                "allowed_mentions": no_mentions(),
                "embeds": [{
                    "title": "Approval needed",
                    // The embed title links to the console. A webhook that is not owned by an
                    // application cannot send a button component, so the link rides here instead.
                    "url": cfg.approvals_link(),
                    "color": EMBED_COLOUR_PENDING,
                    "description": escape_discord(&clamp(message, 500)),
                    "fields": [
                        { "name": "Capability", "value": format!("`{}`", escape_discord(&clamp(capability, 120))), "inline": true },
                        { "name": "Connection", "value": format!("`{}`", escape_discord(&clamp(resource, 120))), "inline": true },
                        { "name": "Risk", "value": escape_discord(&clamp(risk, 16)), "inline": true },
                    ],
                    "footer": {
                        "text": format!(
                            "{} · decide in the console: Permaura never accepts an approval from chat",
                            clamp(approval_id, 64),
                        ),
                    },
                }],
            })
        }
        NotifyEvent::Executed { capability, resource } => serde_json::json!({
            "username": "Permaura",
            "allowed_mentions": no_mentions(),
            "embeds": [{
                "title": "Action executed",
                "url": cfg.approvals_link(),
                "color": EMBED_COLOUR_EXECUTED,
                "description": format!(
                    "`{}` ran on `{}`. No approval was required (notify rung).",
                    escape_discord(&clamp(capability, 120)),
                    escape_discord(&clamp(resource, 120)),
                ),
            }],
        }),
    }
}

/// Post a held approval to every configured channel, unless [`may_announce`] refuses it or no
/// channel is configured. Detached and best-effort; call it with `tokio::spawn`.
pub async fn notify_approval(approval: AnnouncedApproval) {
    if !may_announce(&approval) {
        return;
    }
    let event = NotifyEvent::ApprovalRequested {
        approval_id: approval.id,
        capability: approval.capability,
        resource: approval.resource,
        message: approval.message,
        risk: approval.risk,
    };
    fan_out(&event).await;
}

/// Post an after-the-fact `notify`-rung execution. Detached and best-effort.
pub async fn notify_executed(capability: String, resource: String) {
    fan_out(&NotifyEvent::Executed { capability, resource }).await;
}

/// Send one event to every configured channel. Sequential on purpose: this already runs on a
/// detached task, and one slow channel delaying another is not worth the extra concurrency.
async fn fan_out(event: &NotifyEvent) {
    for cfg in ChannelConfig::from_env() {
        deliver(&cfg, event).await;
    }
}

/// Deliver one event on one channel. Never returns an error; never logs a URL or a key.
async fn deliver(cfg: &ChannelConfig, event: &NotifyEvent) {
    match &cfg.transport {
        Transport::Webhook { url } => post_webhook(cfg, url, &payload(cfg, event)).await,
        Transport::Buzz { .. } => post_buzz(cfg, &buzz_text(cfg, event)).await,
    }
}

/// POST a prepared payload to a channel's webhook.
async fn post_webhook(cfg: &ChannelConfig, url: &str, body: &serde_json::Value) {
    let client = match reqwest::Client::builder().timeout(POST_TIMEOUT).build() {
        Ok(client) => client,
        Err(e) => {
            tracing::warn!(channel = cfg.channel.name(), "notify: failed to build http client: {e}");
            return;
        }
    };
    match client
        .post(url)
        .header("content-type", "application/json")
        .json(body)
        .send()
        .await
    {
        Ok(resp) if http_delivered(resp.status().as_u16()) => {
            tracing::debug!(channel = cfg.channel.name(), "notify: notification sent")
        }
        Ok(resp) => tracing::warn!(
            channel = cfg.channel.name(),
            status = resp.status().as_u16(),
            "notify: webhook rejected the message"
        ),
        // A Slack or Discord webhook URL is itself the credential, and reqwest renders it into the error.
        Err(e) => tracing::warn!(
            channel = cfg.channel.name(),
            "notify: send failed (best-effort): {}",
            e.without_url()
        ),
    }
}

/// The argv for `buzz messages send`, split out so the two rules that matter are testable without
/// spawning anything.
///
/// `--content -` reads the body from **stdin**, always, even for a short message. Two reasons, both
/// load-bearing: a body beginning with `--` would otherwise be parsed as a flag, and argv is world
/// readable in `ps`, which would put every approval message on the process table.
fn buzz_args(channel_id: &str) -> Vec<String> {
    vec![
        "messages".into(),
        "send".into(),
        "--channel".into(),
        channel_id.into(),
        "--content".into(),
        "-".into(),
    ]
}

/// The child's environment, built explicitly rather than inherited.
///
/// This is the security-relevant half of the Buzz path. The gateway process holds the vault
/// passphrase, the operator token, and whatever vault-backend credentials the deployment
/// configured; inheriting its environment would hand all of them to a third-party binary on every
/// held approval. `PATH` is present only so a bare `buzz` resolves.
fn buzz_env(relay_url: &str, private_key: &str, auth_tag: Option<&str>) -> Vec<(String, String)> {
    let path = std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/usr/bin:/bin".into());
    let mut env = vec![
        ("PATH".to_string(), path),
        ("BUZZ_RELAY_URL".to_string(), relay_url.to_string()),
        ("BUZZ_PRIVATE_KEY".to_string(), private_key.to_string()),
    ];
    if let Some(tag) = auth_tag {
        env.push(("BUZZ_AUTH_TAG".to_string(), tag.to_string()));
    }
    env
}

/// Post to a Buzz community by spawning the `buzz` CLI. Best-effort like every other channel.
async fn post_buzz(cfg: &ChannelConfig, text: &str) {
    let Transport::Buzz { relay_url, private_key, channel_id, auth_tag, binary } = &cfg.transport
    else {
        return;
    };
    use tokio::io::AsyncWriteExt;

    let mut command = tokio::process::Command::new(binary);
    command
        .args(buzz_args(channel_id))
        .env_clear()
        .envs(buzz_env(relay_url, private_key, auth_tag.as_deref()))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // Without this a `buzz` that hangs outlives the timeout below as an orphan, one per held
        // approval, on a path that is supposed to cost nothing when it fails.
        .kill_on_drop(true);

    // The start counts against the same budget as the post, so a stuck start cannot hold this longer.
    let deadline = tokio::time::Instant::now() + POST_TIMEOUT;
    let mut child = match tokio::time::timeout_at(deadline, permaura_platform::child::spawn_tokio_dying_with_this_process(command)).await {
        Ok(Ok(child)) => child,
        Ok(Err(e)) => {
            // The usual cause is the binary not being on PATH. Say which, without echoing config.
            tracing::warn!(channel = "buzz", "notify: could not run the buzz CLI: {e}");
            return;
        }
        Err(_) => {
            tracing::warn!(channel = "buzz", "notify: the buzz CLI could not be started in time (best-effort); the approval is still in the console");
            return;
        }
    };
    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(text.as_bytes()).await {
            tracing::warn!(channel = "buzz", "notify: writing the message body failed: {e}");
            return;
        }
        drop(stdin);
    }

    match tokio::time::timeout_at(deadline, child.wait_with_output()).await {
        Ok(Ok(out)) if out.status.success() => {
            tracing::debug!(channel = "buzz", "notify: notification sent")
        }
        Ok(Ok(out)) => tracing::warn!(
            channel = "buzz",
            code = out.status.code(),
            "notify: the buzz CLI refused the message"
        ),
        Ok(Err(e)) => tracing::warn!(channel = "buzz", "notify: buzz CLI failed: {e}"),
        Err(_) => tracing::warn!(
            channel = "buzz",
            "notify: buzz CLI timed out (best-effort); the approval is still in the console"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(channel: Channel, workspace: Option<&str>) -> ChannelConfig {
        let url = match channel {
            Channel::Slack => "https://hooks.slack.com/services/T000/B000/xxx",
            Channel::Discord => "https://discord.com/api/webhooks/123/abc",
            Channel::Generic => "https://ntfy.example.com/permaura",
            Channel::Buzz => panic!("Buzz is not a webhook channel: use buzz_cfg()"),
        };
        ChannelConfig::webhook(
            channel,
            url.to_string(),
            Some("https://permaura.com".to_string()),
            workspace.map(|w| w.to_string()),
        )
        .expect("valid config")
    }

    fn approval(tier: &str) -> AnnouncedApproval {
        (&stored(tier)).into()
    }

    fn stored(tier: &str) -> PendingApproval {
        PendingApproval {
            id: "appr_abc123".into(),
            session_id: "sess_1".into(),
            capability: "stripe.refund".into(),
            resource: "conn_stripe".into(),
            message: "Refund $40 to customer 12".into(),
            status: "pending".into(),
            grant_id: None,
            policy_id: None,
            params: serde_json::json!({ "amount": 40, "card": "4242424242424242" }).into(),
            result: None,
            result_status: None,
            resolution_reason: None,
            created_at: 0,
            expires_at: None,
            risk: Some(permaura_core::RiskTier::Critical),
            action_description: Some("Refund a captured transaction.".into()),
            intent: None,
            required_tier: tier.into(),
            required_signatures: 1,
            signatures: Vec::new(),
            requested_by: None,
        }
    }

    fn requested() -> NotifyEvent {
        let a = approval("approve");
        NotifyEvent::ApprovalRequested {
            approval_id: a.id,
            capability: a.capability,
            resource: a.resource,
            message: a.message,
            risk: a.risk,
        }
    }

    /// The two webhook channels. Buzz has its own constructor and its own transport, so the
    /// shared-behaviour loops below cover it separately via [`buzz_cfg`].
    const CHANNELS: [Channel; 3] = [Channel::Slack, Channel::Discord, Channel::Generic];

    const KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn buzz_cfg(workspace: Option<&str>) -> ChannelConfig {
        ChannelConfig::buzz(
            "https://buzz.example.com".into(),
            KEY.into(),
            "chan-uuid-1".into(),
            None,
            None,
            Some("https://permaura.com".into()),
            workspace.map(|w| w.to_string()),
        )
        .expect("valid buzz config")
    }

    #[test]
    fn http_webhook_is_refused_on_every_channel() {
        for ch in CHANNELS {
            assert!(ChannelConfig::webhook(ch, "http://hooks.example/x".into(), None, None).is_none());
            assert!(ChannelConfig::webhook(ch, "   ".into(), None, None).is_none());
            assert!(ChannelConfig::webhook(ch, "https://hooks.example/x".into(), None, None).is_some());
        }
    }

    #[test]
    fn console_url_defaults_and_strips_trailing_slash() {
        let c = ChannelConfig::webhook(Channel::Discord, "https://h.example/x".into(), None, None).unwrap();
        assert_eq!(c.approvals_link(), "https://permaura.com/console/approvals");
        let c = ChannelConfig::webhook(
            Channel::Discord,
            "https://h.example/x".into(),
            Some("https://staging.permaura.com/".into()),
            None,
        )
        .unwrap();
        assert_eq!(c.approvals_link(), "https://staging.permaura.com/console/approvals");
    }

    #[test]
    fn workspace_routes_through_switch_and_is_encoded() {
        for ch in CHANNELS {
            assert_eq!(
                cfg(ch, Some("ws_1&to=evil")).approvals_link(),
                "https://permaura.com/console/switch?ws=ws_1%26to%3Devil&to=approvals"
            );
        }
    }

    #[test]
    fn no_channel_leaks_params_or_carries_anything_actionable() {
        for ch in CHANNELS {
            let body = payload(&cfg(ch, None), &requested()).to_string();
            assert!(body.contains("stripe.refund"), "{ch:?}");
            assert!(body.contains("appr_abc123"), "{ch:?}");
            // Invariant 2: nothing from `params` reaches the channel.
            assert!(!body.contains("4242424242424242"), "{ch:?}");
            // Invariant 3: the link authenticates; it carries no approval id to act on, no secret.
            assert!(body.contains("https://permaura.com/console/approvals"), "{ch:?}");
            assert!(!body.contains("hooks.slack.com"), "{ch:?}");
            assert!(!body.contains("discord.com/api/webhooks"), "{ch:?}");
        }
    }

    #[test]
    fn device_signed_approvals_are_never_announced() {
        assert!(!may_announce(&approval(DEVICE_SIGNED_TIER)));
        assert!(may_announce(&approval("approve")));
        // An unknown/legacy tier must not silently become device-only-exempt in either direction:
        // it is announceable, matching the `approve` default the store applies to old rows.
        assert!(may_announce(&approval("")));
    }

    #[test]
    fn slack_mrkdwn_injection_is_escaped() {
        let event = NotifyEvent::ApprovalRequested {
            approval_id: "appr_1".into(),
            capability: "evil<https://evil.example|click me>".into(),
            resource: "conn & co".into(),
            message: "<!channel> <https://evil.example|Approve here>".into(),
            risk: "critical".into(),
        };
        let body = payload(&cfg(Channel::Slack, None), &event).to_string();
        assert!(!body.contains("<https://evil.example|"));
        assert!(!body.contains("<!channel>"));
        assert!(body.contains("&lt;"));
        assert!(body.contains("&amp;"));
    }

    #[test]
    fn discord_masked_link_injection_is_escaped() {
        // Discord's dialect of the same attack: an embed description renders `[text](url)` as a
        // clickable masked link, so a hostile approval message could appear to be a Permaura
        // button pointing anywhere.
        let event = NotifyEvent::ApprovalRequested {
            approval_id: "appr_1".into(),
            capability: "evil*bold*".into(),
            resource: "conn".into(),
            message: "[Approve here](https://evil.example) and ||spoiler||".into(),
            risk: "critical".into(),
        };
        let json = payload(&cfg(Channel::Discord, None), &event);
        let description = json["embeds"][0]["description"].as_str().expect("description");
        assert!(!description.contains("[Approve here](https://evil.example)"));
        assert!(description.contains("\\[Approve here\\]\\(https://evil.example\\)"));
        assert!(description.contains("\\|\\|spoiler\\|\\|"));
        let capability = json["embeds"][0]["fields"][0]["value"].as_str().expect("capability");
        assert!(capability.contains("\\*bold\\*"));
    }

    #[test]
    fn discord_pings_nobody() {
        // Belt and braces on top of escaping: even if an `@everyone` survives as text, the payload
        // tells Discord to parse no mentions at all, so a gateway notification can never ping a
        // whole server.
        let event = NotifyEvent::ApprovalRequested {
            approval_id: "appr_1".into(),
            capability: "cap".into(),
            resource: "conn".into(),
            message: "@everyone @here <@&12345>".into(),
            risk: "critical".into(),
        };
        let json = payload(&cfg(Channel::Discord, None), &event);
        let allowed = &json["allowed_mentions"];
        assert_eq!(allowed["parse"].as_array().expect("parse").len(), 0);
        assert_eq!(allowed["users"].as_array().expect("users").len(), 0);
        assert_eq!(allowed["roles"].as_array().expect("roles").len(), 0);
    }

    #[test]
    fn the_generic_webhook_names_its_schema_and_keeps_the_ntfy_shape() {
        // The one channel whose consumer is somebody else's code, so the contract is the test: a
        // stable `schema`, and the title/message pair the self-hosted notifiers read straight off
        // a body. Reshaping either silently is what breaks a user's alerting at 3am.
        let json = payload(
            &cfg(Channel::Generic, None),
            &NotifyEvent::ApprovalRequested {
                approval_id: "appr_1".into(),
                capability: "stripe.refunds.create".into(),
                resource: "stripe".into(),
                message: "Refund £42".into(),
                risk: "critical".into(),
            },
        );
        assert_eq!(json["schema"], "permaura.notify.v1");
        assert_eq!(json["event"], "approval_requested");
        assert_eq!(json["title"], "Approval needed");
        assert_eq!(json["message"], "Refund £42");
        assert_eq!(json["approval_id"], "appr_1");
        assert_eq!(json["capability"], "stripe.refunds.create");
        assert_eq!(json["resource"], "stripe");
        // The captured grade, same string the chat cards carry, so a consumer routing on severity is
        // reading the gateway's classification rather than inventing one.
        assert_eq!(json["risk"], "critical");
    }

    #[test]
    fn a_generic_webhook_body_carries_no_markup_to_escape() {
        // Slack and Discord have to worry about a policy message that renders as a fake button.
        // JSON string encoding makes that a non-question here, and this asserts we did not
        // reintroduce the problem by formatting a body with markup in it.
        let json = payload(
            &cfg(Channel::Generic, None),
            &NotifyEvent::ApprovalRequested {
                approval_id: "appr_1".into(),
                capability: "c".into(),
                resource: "r".into(),
                message: "<https://evil.example|Approve now>".into(),
                risk: "critical".into(),
            },
        );
        // Verbatim: not rendered, not stripped, and not a link in any consumer of flat JSON.
        assert_eq!(json["message"], "<https://evil.example|Approve now>");
    }

    #[test]
    fn discord_204_counts_as_success() {
        // A webhook POST without `?wait=true` answers 204 No Content. A naive `== 200` would log
        // every successful Discord post as a rejection.
        assert!(http_delivered(204));
        assert!(http_delivered(200));
        assert!(!http_delivered(400));
        assert!(!http_delivered(404));
        assert!(http_delivered(200));
    }

    #[test]
    fn long_fields_are_clamped_on_every_channel() {
        for ch in CHANNELS {
            let event = NotifyEvent::ApprovalRequested {
                approval_id: "appr_1".into(),
                capability: "c".repeat(400),
                resource: "r".into(),
                message: "m".repeat(4000),
                risk: "critical".into(),
            };
            let body = payload(&cfg(ch, None), &event).to_string();
            assert!(!body.contains(&"c".repeat(200)), "{ch:?}");
            assert!(!body.contains(&"m".repeat(600)), "{ch:?}");
            assert!(body.contains('…'), "{ch:?}");
        }
    }

    #[test]
    fn discord_stays_inside_its_embed_limits() {
        // Title 256, description 4096, field name 256, field value 1024, footer 2048, and 6000
        // across the lot. The clamps are far under, but a future edit that loosens one should
        // trip here rather than in a channel.
        let event = NotifyEvent::ApprovalRequested {
            approval_id: "a".repeat(300),
            capability: "c".repeat(400),
            resource: "r".repeat(400),
            message: "m".repeat(9000),
            risk: "critical".into(),
        };
        let json = payload(&cfg(Channel::Discord, None), &event);
        let embed = &json["embeds"][0];
        let len = |v: &serde_json::Value| v.as_str().map(|s| s.chars().count()).unwrap_or(0);
        assert!(len(&embed["title"]) <= 256);
        assert!(len(&embed["description"]) <= 4096);
        assert!(len(&embed["footer"]["text"]) <= 2048);
        let mut total = len(&embed["title"]) + len(&embed["description"]) + len(&embed["footer"]["text"]);
        for field in embed["fields"].as_array().expect("fields") {
            assert!(len(&field["name"]) <= 256);
            assert!(len(&field["value"]) <= 1024);
            total += len(&field["name"]) + len(&field["value"]);
        }
        assert!(total <= 6000, "combined embed characters must stay under 6000, got {total}");
        assert!(json["embeds"].as_array().expect("embeds").len() <= 10);
    }

    #[test]
    fn approve_tier_builds_a_payload() {
        assert_eq!(
            payload(&cfg(Channel::Slack, None), &requested())["blocks"]
                .as_array()
                .expect("blocks")
                .len(),
            4
        );
        assert!(payload(&cfg(Channel::Discord, None), &requested())["embeds"][0]["url"].is_string());
    }

    // ── Buzz ────────────────────────────────────────────────────────────────

    #[test]
    fn buzz_needs_a_relay_a_key_and_a_channel() {
        let ok = |relay: &str, key: &str, chan: &str| {
            ChannelConfig::buzz(relay.into(), key.into(), chan.into(), None, None, None, None)
                .is_some()
        };
        assert!(ok("https://buzz.example.com", KEY, "chan"));
        // Each one missing disables the channel rather than half-configuring it.
        assert!(!ok("", KEY, "chan"));
        assert!(!ok("https://buzz.example.com", "", "chan"));
        assert!(!ok("https://buzz.example.com", KEY, ""));
        // http would put the message (and the relay handshake) in the clear.
        assert!(!ok("http://buzz.example.com", KEY, "chan"));
    }

    #[test]
    fn a_malformed_buzz_key_is_refused_not_trimmed() {
        // The key is the identity everything is signed as. Half of one is not a smaller version of
        // it, so anything that is not exactly 64 hex characters disables the channel.
        let bad = |key: &str| {
            ChannelConfig::buzz(
                "https://buzz.example.com".into(),
                key.into(),
                "chan".into(),
                None,
                None,
                None,
                None,
            )
            .is_none()
        };
        assert!(bad(&KEY[..63]), "too short");
        assert!(bad(&format!("{KEY}0")), "too long");
        assert!(bad(&"z".repeat(64)), "not hex");
        assert!(bad(&format!("{} ", &KEY[..63])), "hex with a space");
    }

    #[test]
    fn the_buzz_body_never_rides_in_argv() {
        // `--content -` means the body comes from stdin. argv is world-readable in `ps`, and a body
        // starting with `--` would otherwise be parsed as a flag, so the message must appear
        // nowhere in the arguments.
        let args = buzz_args("chan-uuid-1");
        assert_eq!(args, ["messages", "send", "--channel", "chan-uuid-1", "--content", "-"]);
        let text = buzz_text(&buzz_cfg(None), &requested());
        assert!(!args.iter().any(|a| a.contains("Refund")), "{args:?}");
        assert!(text.contains("Refund $40 to customer 12"));
    }

    #[test]
    fn the_buzz_child_gets_an_explicit_environment() {
        // The gateway process holds the vault passphrase, the operator token, and any vault-backend
        // credentials. Inheriting its environment would hand all of them to a third-party binary on
        // every held approval, so the child env is built from nothing but what buzz needs.
        let env = buzz_env("https://buzz.example.com", KEY, Some("tag"));
        let names: Vec<&str> = env.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(names, ["PATH", "BUZZ_RELAY_URL", "BUZZ_PRIVATE_KEY", "BUZZ_AUTH_TAG"]);
        // No auth tag → the variable is absent rather than empty, which the CLI treats differently.
        let untagged = buzz_env("https://buzz.example.com", KEY, None);
        assert!(!untagged.iter().any(|(k, _)| k == "BUZZ_AUTH_TAG"));
    }

    #[test]
    fn buzz_carries_no_params_and_nothing_actionable() {
        let text = buzz_text(&buzz_cfg(None), &requested());
        assert!(text.contains("stripe.refund"));
        assert!(text.contains("appr_abc123"));
        // Invariant 2 holds on this channel too.
        assert!(!text.contains("4242424242424242"));
        // Invariant 3: a console link that authenticates, and no key or relay in the body.
        assert!(text.contains("https://permaura.com/console/approvals"));
        assert!(!text.contains(KEY));
        assert!(!text.contains("buzz.example.com"));
    }

    #[test]
    fn buzz_respects_the_same_clamps() {
        let event = NotifyEvent::ApprovalRequested {
            approval_id: "appr_1".into(),
            capability: "c".repeat(400),
            resource: "r".into(),
            message: "m".repeat(4000),
            risk: "critical".into(),
        };
        let text = buzz_text(&buzz_cfg(None), &event);
        assert!(!text.contains(&"c".repeat(200)));
        assert!(!text.contains(&"m".repeat(600)));
        assert!(text.contains('…'));
    }

    #[test]
    fn buzz_uses_the_workspace_link_like_every_other_channel() {
        assert!(buzz_text(&buzz_cfg(Some("ws_9")), &requested())
            .contains("https://permaura.com/console/switch?ws=ws_9&to=approvals"));
    }

    #[test]
    fn a_device_signed_approval_reaches_no_channel_including_buzz() {
        // The gate is on the approval, before any channel is consulted, so a new transport cannot
        // opt out of invariant 1 by forgetting to check.
        assert!(!may_announce(&approval(DEVICE_SIGNED_TIER)));
    }

    #[test]
    fn executed_card_has_no_pending_language() {
        for ch in CHANNELS {
            let body = payload(
                &cfg(ch, None),
                &NotifyEvent::Executed {
                    capability: "github.push".into(),
                    resource: "conn_gh".into(),
                },
            )
            .to_string();
            assert!(body.contains("Action executed"), "{ch:?}");
            assert!(!body.contains("Approval needed"), "{ch:?}");
        }
    }
}
