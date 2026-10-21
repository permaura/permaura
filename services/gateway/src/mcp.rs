//! The MCP surface: `POST /mcp`, JSON-RPC 2.0, exposing eight fixed `permaura_*` tools
//! (`permaura_http_request` only where an `http.request` capability exists) and one tool per
//! capability the session may attempt, onto the same [`EnforcementService`] the REST endpoints use.
//!
//! Methods handled: `initialize`, `tools/list`, `tools/call`. There is deliberately no
//! `get_secret` / `get_api_key` / `export_token` tool.

use axum::extract::State;
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Value};

use permaura_core::ExecutionLocation;

use crate::service::InvokeOutcome;
use crate::store::Session;
use crate::AppState;

/// The fixed `permaura_*` MCP tools, as a `tools/list` payload. Each carries a `title` and
/// `annotations` (read-only / destructive / open-world hints), required by the Claude and
/// ChatGPT directories, and used by clients to decide when to confirm an action with the human.
fn tool_catalog() -> Value {
    json!({
        "tools": [
            {
                "name": "permaura_list_capabilities",
                "title": "List capabilities",
                "description": "List the capabilities this session may attempt. Never returns secrets.",
                "inputSchema": { "type": "object", "properties": {} },
                "annotations": ann(true, false, true, false)
            },
            {
                "name": "permaura_enroll",
                "title": "Enrol agent",
                "description": "Enrol this agent with the gateway using a one-time code from the operator's console. The agent appears as Pending until a human approves it; only then can it invoke. Returns a session token to use on subsequent calls.",
                "inputSchema": { "type": "object", "properties": {
                    "code": { "type": "string", "description": "The one-time enrolment code from the console." },
                    "name": { "type": "string", "description": "A human-friendly name for this agent." },
                    "agent_id": { "type": "string", "description": "Optional stable id; defaults to a slug of the name." }
                }, "required": ["code"], "additionalProperties": false },
                "annotations": ann(false, false, false, false)
            },
            {
                "name": "permaura_request_grant",
                "title": "Request a grant",
                "description": "Find out how this agent gets access to a connection's capability. Grants are created by a human in the console (policy → agent), so this returns guidance and records nothing: it does not self-grant, and the operator is not notified.",
                "inputSchema": { "type": "object", "properties": {
                    "connection": { "type": "string" },
                    "capabilities": { "type": "array", "items": { "type": "string" } }
                }, "required": ["connection"], "additionalProperties": false },
                "annotations": ann(false, false, true, false)
            },
            {
                "name": "permaura_invoke",
                "title": "Invoke a capability",
                "description": "Invoke a capability. Permaura checks policy, injects the real secret server-side, performs the action, and returns only the redacted result.",
                "inputSchema": { "type": "object", "properties": {
                    "capability": { "type": "string" },
                    "params": { "type": "object" },
                    "reason": { "type": "string" }
                }, "required": ["capability"], "additionalProperties": false },
                "annotations": ann(false, true, false, true)
            },
            {
                "name": "permaura_http_request",
                "title": "Make an HTTP request",
                "description": "Make a policy-gated generic HTTP request. The secret is injected server-side; the agent never sees it.",
                "inputSchema": { "type": "object", "properties": {
                    "method": { "type": "string" },
                    "url": { "type": "string", "description": "Absolute https URL on a host the connection allows; plain http is refused." },
                    "headers": { "type": "object" },
                    "body": {}
                }, "required": ["url"], "additionalProperties": false },
                "annotations": ann(false, true, false, true)
            },
            {
                "name": "permaura_get_approval_status",
                "title": "Check approval status",
                "description": "Poll the status of a pending approval by id.",
                "inputSchema": { "type": "object", "properties": { "approval_id": { "type": "string" } }, "required": ["approval_id"], "additionalProperties": false },
                "annotations": ann(true, false, true, false)
            },
            {
                "name": "permaura_explain_denial",
                "title": "Explain a denial",
                "description": "Explain why a capability would be denied for this session right now. Does not execute anything.",
                "inputSchema": { "type": "object", "properties": { "capability": { "type": "string" }, "params": { "type": "object" } }, "required": ["capability"], "additionalProperties": false },
                "annotations": ann(true, false, true, false)
            },
            {
                "name": "permaura_revoke_session",
                "title": "Revoke a session",
                "description": "Revoke a session immediately, so its bearer stops authenticating; with no session_id it revokes the caller's own session. The agent's grants are not changed.",
                "inputSchema": { "type": "object", "properties": { "session_id": { "type": "string" } }, "additionalProperties": false },
                "annotations": ann(false, true, true, false)
            }
        ]
    })
}

/// The refusal a fixed tool's arguments get: one its input schema does not list, a value of a type the schema does not allow (a mistyped value used to read as absent, so `session_id: 123` revoked the caller's own session), or arguments that are not an object.
/// A tool that reads no argument takes whatever it is sent, since nothing it ignores can change its answer and some clients add a placeholder argument to such a tool. A capability's own tool is checked against its pinned parameters in the dispatch instead.
fn undeclared_argument(name: &str, args: &Value) -> Option<RpcError> {
    let catalog = tool_catalog();
    let tool = catalog["tools"].as_array()?.iter().find(|t| t["name"] == name)?;
    let declared = tool["inputSchema"]["properties"].as_object()?;
    if declared.is_empty() {
        return None;
    }
    let given = match args {
        Value::Null => return None,
        Value::Object(given) => given,
        _ => return Some((-32602, format!("{name} takes its arguments as an object")).into()),
    };
    if let Some(unknown) = given.keys().find(|k| !declared.contains_key(k.as_str())) {
        let accepted = declared.keys().map(String::as_str).collect::<Vec<_>>().join(", ");
        return Some((-32602, format!("{name} has no argument '{unknown}' (it takes: {accepted})")).into());
    }
    let (argument, schema) = given.iter().filter(|(_, v)| !v.is_null()).find_map(|(k, v)| (!of_type(&declared[k], v)).then(|| (k, &declared[k])))?;
    let wanted = match (schema["type"].as_str(), schema["items"]["type"].as_str()) {
        (Some("array"), Some(item)) => format!("an array of {item}s"),
        (Some(ty), _) => format!("a {ty}"),
        (None, _) => "a value of another type".into(),
    };
    Some((-32602, format!("{name} takes '{argument}' as {wanted}")).into())
}

/// Whether `value` has the JSON type `schema` names (and, for an array, its items' type). A schema naming no type takes anything.
fn of_type(schema: &Value, value: &Value) -> bool {
    match schema["type"].as_str() {
        Some("string") => value.is_string(),
        Some("object") => value.is_object(),
        Some("boolean") => value.is_boolean(),
        Some("integer") => value.is_i64() || value.is_u64(),
        Some("number") => value.is_number(),
        Some("array") => value.as_array().is_some_and(|items| items.iter().all(|item| of_type(&schema["items"], item))),
        _ => true,
    }
}

/// The argument a capability tool takes the call's stated reason from. `reason` unless the capability reads a `reason` of its own (Stripe's refunds, Paddle's adjustments), which it then keeps; such a tool takes the stated reason as `permaura_reason`, and if that is the capability's too, takes none.
fn audit_reason_argument(pinned: Option<&crate::approval_display::PinnedParams>) -> Option<&'static str> {
    match pinned {
        Some(p) if p.accepted.contains("reason") => (!p.accepted.contains(AUDIT_REASON)).then_some(AUDIT_REASON),
        _ => Some("reason"),
    }
}

/// The argument name a capability tool takes the call's stated reason from when its capability has a `reason` of its own.
const AUDIT_REASON: &str = "permaura_reason";

/// The JSON-RPC code for a tenant under an execution hold, the transport equivalent of the REST
/// 423. Its own code rather than the catch-all `-32000` for the same reason 423 is not 503: the
/// condition is deliberate, it will not clear on retry, and a client that cannot tell it from an
/// ordinary failure will retry it forever.
const RPC_EXECUTION_HELD: i64 = -32005;

/// A JSON-RPC error: the code and message every tool failure carries, plus the structured `data` a
/// caller needs when the message alone is not actionable.
struct RpcError {
    code: i64,
    message: String,
    data: Option<Value>,
}

impl From<(i64, String)> for RpcError {
    fn from((code, message): (i64, String)) -> Self {
        RpcError { code, message, data: None }
    }
}

/// Render a gateway error for an MCP caller, keeping the facts a 423 carries over REST.
fn tool_error(e: crate::error::GatewayError) -> RpcError {
    if let crate::error::GatewayError::ExecutionHeld { hold_id, state, reason } = &e {
        return RpcError {
            code: RPC_EXECUTION_HELD,
            message: e.to_string(),
            data: Some(json!({ "hold_id": hold_id, "state": state, "reason": reason })),
        };
    }
    RpcError { code: -32000, message: e.to_string(), data: None }
}

/// JSON-RPC error object.
fn rpc_error(id: Value, error: RpcError) -> Json<Value> {
    let mut body = json!({ "code": error.code, "message": error.message });
    if let (Some(data), Some(object)) = (error.data, body.as_object_mut()) {
        object.insert("data".into(), data);
    }
    Json(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": body
    }))
}

/// The longest JSON-RPC id echoed in an answer to a body refused before it was parsed. An id is a number or a short string; anything longer is answered as `null`.
const REQUEST_ID_MAX_BYTES: usize = 256;

/// The `id` of a JSON-RPC request, or `null`, and its `method`, read from its body without building a tree of the rest of it.
fn request_envelope(body: &[u8]) -> (Value, Option<String>) {
    #[derive(serde::Deserialize)]
    struct Envelope<'a> {
        #[serde(borrow, default)]
        id: Option<&'a serde_json::value::RawValue>,
        #[serde(borrow, default)]
        method: Option<std::borrow::Cow<'a, str>>,
    }
    let Ok(envelope) = serde_json::from_slice::<Envelope>(body) else { return (Value::Null, None) };
    let id = envelope
        .id
        .filter(|id| id.get().len() <= REQUEST_ID_MAX_BYTES)
        .and_then(|id| serde_json::from_str(id.get()).ok())
        .unwrap_or(Value::Null);
    (id, envelope.method.map(std::borrow::Cow::into_owned))
}

fn rpc_result(id: Value, result: Value) -> Json<Value> {
    Json(json!({ "jsonrpc": "2.0", "id": id, "result": result }))
}

/// A tool's result: a small object the gateway built, or one holding a document (an execution's result) that is written into the response as the text it is held as.
enum ToolOut {
    Value(Value),
    /// A document and the view-growth room its result takes, kept until the response has been sent.
    Document(crate::memory::Assembled, crate::connectors::MemoryCharge),
}

impl From<Value> for ToolOut {
    fn from(value: Value) -> Self {
        ToolOut::Value(value)
    }
}

/// The largest result whose text block is pretty-printed. Indentation grows with depth, so a large deep result pretty-printed is many times its own size; above this the block is the result's compact text, which every client reads the same way.
const PRETTY_MAX_BYTES: usize = 256 * 1024;

/// A `tools/call` answer whose result holds a document: the MCP `content` text block and `structuredContent`, written around the document's text without a tree or a second copy of it.
fn tool_document_response(id: Value, doc: crate::memory::Assembled) -> axum::response::Response {
    use axum::body::Bytes;
    let pretty = (doc.len() <= PRETTY_MAX_BYTES)
        .then(|| permaura_core::json_stream::pretty_within(&doc.to_text(), 4 * PRETTY_MAX_BYTES))
        .flatten();
    let head = format!(
        r#"{{"jsonrpc":"2.0","id":{},"result":{{"content":[{{"type":"text","text":""#,
        serde_json::to_string(&id).unwrap_or_else(|_| "null".into())
    );
    let (text_len, text): (usize, Box<dyn Iterator<Item = Bytes> + Send>) = match pretty {
        Some(pretty) => {
            let quoted = serde_json::to_string(&pretty).unwrap_or_default();
            let inner = Bytes::from(quoted[1..quoted.len() - 1].to_string());
            (inner.len(), Box::new(std::iter::once(inner)))
        }
        None => (doc.escaped_len(), Box::new(doc.escaped())),
    };
    const MIDDLE: &[u8] = br#""}],"structuredContent":"#;
    const TAIL: &[u8] = b"}}";
    let len = head.len() + text_len + MIDDLE.len() + doc.len() + TAIL.len();
    let pieces = std::iter::once(Bytes::from(head))
        .chain(text)
        .chain(std::iter::once(Bytes::from_static(MIDDLE)))
        .chain(doc.into_pieces())
        .chain(std::iter::once(Bytes::from_static(TAIL)));
    crate::memory::streamed_response(axum::http::StatusCode::OK, len, pieces)
}

/// Wrap a tool result as MCP `content` (a single JSON text block) so any MCP client can
/// render it.
fn tool_content(value: Value) -> Value {
    json!({
        "content": [
            { "type": "text", "text": serde_json::to_string_pretty(&value).unwrap_or_default() }
        ],
        "structuredContent": value,
    })
}

/// Authenticate the MCP caller from the bearer header. Unlike REST, a gateway without a public URL allows an unauthenticated
/// `initialize` / `tools/list` (discovery), `permaura_enroll` (which takes a code) and `permaura_request_grant` (which returns
/// guidance); every other tool call requires a session. A gateway with a public URL requires a bearer on every request.
fn authed(state: &AppState, headers: &HeaderMap) -> Option<Session> {
    authenticated(state, headers)?.ok()
}

/// What authenticating the caller's bearer gave, or `None` when there is no bearer to try.
fn authenticated(state: &AppState, headers: &HeaderMap) -> Option<Result<Session, crate::error::GatewayError>> {
    let raw = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())?;
    let token = raw.strip_prefix("Bearer ").unwrap_or(raw).trim();
    if token.is_empty() {
        return None;
    }
    Some(state.service.authenticate(token))
}

/// The 401 that starts an MCP client's OAuth flow at permaura.com, or makes one holding a lapsed token refresh it: `WWW-Authenticate` names this gateway's protected-resource metadata. Once `permaura remote disable` has withdrawn the resource server it is a plain 401 saying so. Shared with admission control, which answers a tokenless or lapsed caller with it ahead of every bucket.
pub(crate) fn sign_in_challenge(oauth: &crate::oauth::OAuthRs, error: &str) -> axum::response::Response {
    use axum::response::IntoResponse;
    // A withdrawn resource server has nothing to sign in to: its metadata routes 404, so a challenge would only send the client round a discovery that fails.
    if oauth.is_withdrawn() {
        return (axum::http::StatusCode::UNAUTHORIZED, Json(json!({ "error": if error == "authorization required" { crate::oauth::REMOTE_ACCESS_OFF } else { error } }))).into_response();
    }
    let prm = format!("{}/.well-known/oauth-protected-resource/mcp", oauth.config().public_url);
    (
        axum::http::StatusCode::UNAUTHORIZED,
        [(axum::http::header::WWW_AUTHENTICATE, format!("Bearer resource_metadata=\"{prm}\""))],
        Json(json!({ "error": error })),
    )
        .into_response()
}

/// Whether `caller` may read or revoke the session `target_id`: an operator may act on any session, an
/// agent only on its own session or another agent-role session of the same agent. Anything else answers
/// as not found, so an agent cannot probe for ids.
fn may_act_on_session(
    store: &dyn crate::store::Store,
    caller: &Session,
    target_id: &str,
) -> Result<bool, crate::error::GatewayError> {
    if caller.role == crate::store::SessionRole::Operator || target_id == caller.id {
        return Ok(true);
    }
    if target_id.is_empty() {
        return Ok(false);
    }
    Ok(store
        .get_session(target_id)?
        .is_some_and(|s| s.role == crate::store::SessionRole::Agent && s.agent_id == caller.agent_id))
}

/// `POST /mcp`: the JSON-RPC entrypoint.
pub async fn handle(
    State(state): State<AppState>,
    axum::Extension(crate::rest::RemoteFlag(remote)): axum::Extension<crate::rest::RemoteFlag>,
    headers: HeaderMap,
    request: axum::extract::Request,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    // OAuth gate: when this gateway is an OAuth resource server, every /mcp request needs a valid
    // bearer; an unauthenticated request gets a 401 + WWW-Authenticate so the client starts the
    // OAuth flow at permaura.com. (Local gateways without a public URL keep open discovery.)
    // It reads only the headers and runs before the body is parsed, so a refused caller's body never becomes a tree.
    if let Some(oauth) = state.service.oauth() {
        // Authenticated once: a second attempt to tell the refusals apart cost a refused request a second redemption attempt.
        let refusal = match authenticated(&state, &headers) {
            Some(Ok(_)) => None,
            // A token that verifies but was not consented for an agent is told so (403): a 401 challenge would send the client round the sign-in it already completed.
            Some(Err(denied @ crate::error::GatewayError::Denied(_))) => Some(denied.into_response()),
            Some(Err(error)) => Some(sign_in_challenge(oauth, &error.to_string())),
            None => Some(sign_in_challenge(oauth, "authorization required")),
        };
        if let Some(refusal) = refusal {
            let limit = state.limits.config().body_exec_bytes;
            return crate::rest::refuse_after_draining(request, limit, refusal).await;
        }
    }
    // The body becomes a tree only under the worker's JSON memory budget, reserved with the body an execution writes from it; the parts of it a call needs are taken out of it, never cloned.
    let budget = state.service.memory().clone();
    let slot = request.extensions().get::<crate::limits::ExecutionSlot>().cloned();
    // A body over the one ceiling on an agent call's unpacked size is answered as a tool error, as every other refusal of a tool call is, carrying the request's id. The ceiling is for agent calls, so a request with another method is read as it was before it.
    let over_limit = |body: &[u8], over: crate::error::GatewayError| match request_envelope(body) {
        (_, Some(method)) if method != "tools/call" => None,
        (id, _) => Some(rpc_error(id, tool_error(over)).into_response()),
    };
    let (req, charge, unpacked) = match crate::memory::read_json_or::<crate::connectors::json_budget::MeteredValue, AppState>(
        &budget, request, &state, "/mcp", over_limit,
    )
    .await
    {
        Ok(read) => read,
        Err(refusal) => return refusal,
    };
    let mut req = req.0;

    let id = req.get_mut("id").map(Value::take).unwrap_or(Value::Null);
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("").to_string();

    let body: Json<Value> = match method.as_str() {
        "initialize" => rpc_result(
            id,
            json!({
                "protocolVersion": "2024-11-05",
                "serverInfo": { "name": "permaura-gateway", "version": env!("CARGO_PKG_VERSION") },
                "capabilities": { "tools": {} }
            }),
        ),
        "tools/list" => {
            // The seven fixed permaura.* tools, PLUS one dynamic tool per capability in the
            // catalog (e.g. `fal.image.generate`) so an agent sees each ability as a
            // first-class tool with its own input schema and calls it directly: no separate
            // discovery hop. Adding an integration grows this list; it never needs another MCP server.
            let mut tools = tool_catalog()["tools"].as_array().cloned().unwrap_or_default();
            // `permaura_http_request` maps onto the `http.request` capability, which only the demo
            // estate registers: a clean bootstrap registers none. Advertising it on a real install
            // hands the agent a tool that answers "not found: capability 'http.request'", which reads
            // like a transient failure and gets retried. Advertise it only where it resolves.
            let has_http_request = state
                .service
                .store()
                .list_capabilities()
                .map(|caps| caps.iter().any(|c| c.id == "http.request"))
                .unwrap_or(false);
            if !has_http_request {
                tools.retain(|t| t.get("name").and_then(|n| n.as_str()) != Some("permaura_http_request"));
            }
            // Scope the dynamic tools to what this session could actually attempt, for the same
            // reason the REST capability listing is scoped: a tool list is a description of
            // what you may call, and handing the whole catalogue to a session that can call none of
            // it is a map of the estate rather than a tool list. An operator drives the console and
            // gets everything; an agent gets what a grant actually points it at; an unauthenticated
            // caller (possible only on a local gateway, where open discovery is deliberate) gets
            // the fixed permaura_* tools, which is all it needs to enrol.
            let session = authed(&state, &headers);
            let visible = |c: &crate::connectors::Capability| match &session {
                Some(s) if s.role == crate::store::SessionRole::Operator => true,
                Some(s) => crate::rest::reachable_by_agent(&state.service, &s.agent_id, c).unwrap_or(false),
                None => false,
            };
            if let Ok(mut caps) = state.service.store().list_capabilities() {
                caps.sort_by(|a, b| a.id.cmp(&b.id));
                for c in caps.into_iter().filter(|c| visible(c)) {
                    let schema = dynamic_tool_input_schema(&c);
                    tools.push(json!({
                        "name": c.id,
                        "title": humanize_cap_id(&c.id),
                        "description": dynamic_tool_description(&c.description, c.risk),
                        "inputSchema": schema,
                        "annotations": capability_annotations(&c),
                    }));
                }
            }
            rpc_result(id, json!({ "tools": tools }))
        }
        "tools/call" => {
            let mut params = req.get_mut("params").map(Value::take).unwrap_or(Value::Null);
            drop(req);
            let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
            let args = params.get_mut("arguments").map(Value::take).unwrap_or_else(|| json!({}));
            drop(params);
            // Remote is this gateway's own judgement of the request, never something a tool call says.
            let location = if remote { ExecutionLocation::RemoteAllowed } else { ExecutionLocation::LocalOnly };
            match call_tool(&state, &headers, &name, args, location, Admitted { charge, unpacked, slot }).await {
                Ok(ToolOut::Value(result)) => rpc_result(id, tool_content(result)),
                Ok(ToolOut::Document(doc, room)) => {
                    let mut response = tool_document_response(id, doc);
                    crate::delivery::HoldWhileSending::attach(&mut response, room);
                    return response;
                }
                Err(error) => rpc_error(id, error),
            }
        }
        other => rpc_error(id, (-32601, format!("method not found: {other}")).into()),
    };
    body.into_response()
}

/// What reading a `tools/call` body under the JSON memory budget gave the call it carries: the room its params hold, their unpacked size and the execution slot it was admitted under.
struct Admitted {
    charge: crate::connectors::MemoryCharge,
    unpacked: u64,
    slot: Option<crate::limits::ExecutionSlot>,
}

/// Dispatch a single `tools/call`. Returns the structured tool result or a
/// `(json-rpc-code, message)` error.
async fn call_tool(
    state: &AppState,
    headers: &HeaderMap,
    name: &str,
    mut args: Value,
    location: ExecutionLocation,
    admitted: Admitted,
) -> Result<ToolOut, RpcError> {
    if let Some(refusal) = undeclared_argument(name, &args) {
        return Err(refusal);
    }
    let store = state.service.store();
    let Admitted { charge, unpacked, slot } = admitted;
    let charged = |value: Value| crate::memory::AgentParams::charged(value, charge.clone()).holding(slot.clone()).measured(unpacked);
    match name {
        "permaura_list_capabilities" => {
            // Scoped exactly as tools/list is: what this session may attempt, not the estate. It used
            // to answer any caller with the whole catalogue, so a Pending agent, or on a hosted worker
            // anyone holding a live enrolment code, could map every connection and capability before a
            // human had approved anything. Unauthenticated callers get the same refusal as every other
            // tool; discovery for them is tools/list, which already carries what an enrolment needs.
            let session = authed(state, headers)
                .ok_or_else(|| (-32001, "unauthorized: missing or invalid session".to_string()))?;
            let visible = |c: &crate::connectors::Capability| match session.role {
                crate::store::SessionRole::Operator => true,
                _ => crate::rest::reachable_by_agent(&state.service, &session.agent_id, c).unwrap_or(false),
            };
            let caps: Vec<_> = store
                .list_capabilities()
                .map_err(internal)?
                .into_iter()
                .filter(|c| visible(c))
                .map(|c| json!({ "id": c.id, "description": c.description, "risk": c.risk }))
                .collect();
            Ok(json!({ "capabilities": caps }).into())
        }
        "permaura_enroll" => {
            // Agent-initiated enrolment: redeem a one-time code → create a PENDING agent and
            // open a session for it. The agent cannot invoke anything until a human approves
            // it in the console. Proving its identity by connecting is what makes the record
            // real, but approval is still a separate, human step.
            let code = args
                .get("code")
                .and_then(|v| v.as_str())
                .ok_or_else(|| (-32602, "missing 'code'".to_string()))?;
            state.service.refuse_enrolment_if_agents_paused().map_err(tool_error)?;
            // The agents table keeps both for good; checked before the code is spent, so a refused call can be made again with it.
            for field in ["name", "agent_id"] {
                if args.get(field).and_then(|v| v.as_str()).is_some_and(|v| v.chars().count() > crate::rest::ENROLMENT_LABEL_MAX_CHARS) {
                    return Err((-32602, format!("'{field}' is longer than {} characters", crate::rest::ENROLMENT_LABEL_MAX_CHARS)).into());
                }
            }
            let now = crate::service::now_ms();
            let ticket = store
                .consume_enrolment_code(code, now)
                .map_err(internal)?
                .ok_or_else(|| (-32003, "enrolment code is invalid, used, or expired".to_string()))?;
            let name = args
                .get("name")
                .and_then(|v| v.as_str())
                .map(String::from)
                .or_else(|| ticket.label.clone())
                .unwrap_or_else(|| "Agent".to_string());
            let agent_id = args
                .get("agent_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| name.to_lowercase().replace(' ', "-"));
            // Refuse to enrol onto an existing agent id. put_agent is an upsert, so without this
            // guard a redeemed code could OVERWRITE an approved agent (even the operator) with a
            // Pending record, downgrading it to no-access. A self-enrolled agent must claim a
            // fresh id, never collide with an existing one.
            if store.get_agent(&agent_id).map_err(internal)?.is_some() {
                return Err((
                    -32002,
                    format!("agent id '{agent_id}' is already taken; choose another"),
                )
                    .into());
            }
            // The agent-initiated path, and the one a console can never see: this request reaches a
            // hosted worker's `/mcp` directly. Refused here rather than at the code, because the
            // code is the operator's invitation and the ceiling is the plan's answer to it.
            state
                .service
                .refuse_if_over_allowance(crate::allowances::Allowance::Agents, None)
                .map_err(tool_error)?;
            store
                .put_agent(crate::store::Agent {
                    id: agent_id.clone(),
                    name: name.clone(),
                    status: crate::store::AgentStatus::Pending,
                    enrolled_at: now,
                })
                .map_err(internal)?;
            // Pending is a gate, and a gate nobody is told about is a queue. Same two rungs as every
            // other hold; see `EnforcementService::announce_agent_pending`.
            state.service.announce_agent_pending(&agent_id, &name);
            // A code a remote request minted carries the console prefix, and so does the bearer it becomes here, exactly as the HTTP redeem keeps the code itself as the bearer: the agent stays remote on any transport. Only the full code redeems, so the prefix cannot be dropped to shed it.
            let prefix = if crate::is_console_token(code) { crate::CONSOLE_TOKEN_PREFIX } else { "" };
            let token = format!("{prefix}tok_{}", crate::service::short_id());
            let session = crate::store::Session {
                class: Default::default(),
                opened_by: None,
                id: format!("sess_{}", crate::service::short_id()),
                agent_id: agent_id.clone(),
                user_id: None,
                device_id: None,
                // An agent-scoped token: it may invoke (once approved) and enrol, but NEVER
                // mutate the console (approve itself, self-grant, write credentials, …).
                role: crate::store::SessionRole::Agent,
                token: token.clone(),
                created_at: now,
                revoked: false,
                expires_at: Some(now + crate::store::AGENT_SESSION_TTL_MS),
                last_used_at: None,
                actor: None,
            };
            // Recorded before the bearer is granted, as the code-as-bearer redemption is.
            state.service.grant_enrolled_session(&session, &ticket, "mcp_tool").map_err(internal)?;
            Ok(ToolOut::Value(json!({
                "agent_id": agent_id,
                "status": "pending",
                "token": token,
                "message": "Enrolled. You are PENDING approval: ask the operator to approve you in the Permaura console before invoking.",
            })))
        }
        "permaura_request_grant" => {
            // Grants are operator-created in the new model (a human binds a policy to an
            // agent). The agent cannot self-grant; surface guidance instead of minting access.
            let connection = args
                .get("connection")
                .and_then(|v| v.as_str())
                .unwrap_or("(unspecified)");
            let capabilities: Vec<String> = args
                .get("capabilities")
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
                .unwrap_or_default();
            Ok(ToolOut::Value(json!({
                "status": "needs_operator",
                "connection": connection,
                "requested_capabilities": capabilities,
                "message": "Access is granted by a human in the Permaura console (a policy on this connection, bound to your agent). Ask the operator to add a grant.",
            })))
        }
        "permaura_invoke" => {
            let session = authed(state, headers)
                .ok_or_else(|| (-32001, "unauthorized: missing or invalid session".to_string()))?;
            let capability = args
                .get("capability")
                .and_then(|v| v.as_str())
                .ok_or_else(|| (-32602, "missing 'capability'".to_string()))?;
            let capability = capability.to_string();
            let params = args.get_mut("params").map(Value::take).unwrap_or_else(|| json!({}));
            let reason = args.get("reason").and_then(|v| v.as_str()).map(str::to_string);
            drop(args);
            let outcome = state
                .service
                .invoke_admitted(&session, &capability, charged(params), reason.as_deref(), location)
                .await
                .map_err(tool_error)?;
            Ok(render_outcome(outcome))
        }
        "permaura_http_request" => {
            let session = authed(state, headers)
                .ok_or_else(|| (-32001, "unauthorized: missing or invalid session".to_string()))?;
            // The generic HTTP proxy maps onto the `http.request` capability; the agent's
            // method/url/headers/body are the params.
            let outcome = state
                .service
                .invoke_admitted(&session, "http.request", charged(args), Some("generic http_request"), location)
                .await
                .map_err(tool_error)?;
            Ok(render_outcome(outcome))
        }
        "permaura_get_approval_status" => {
            let caller = authed(state, headers)
                .ok_or_else(|| (-32001, "unauthorized: missing or invalid session".to_string()))?;
            let approval_id = args
                .get("approval_id")
                .and_then(|v| v.as_str())
                .ok_or_else(|| (-32602, "missing 'approval_id'".to_string()))?;
            let not_found = || (-32004, format!("approval '{approval_id}' not found"));
            // Without its params, which an agent polling for its result never reads and which may be several times the body it sent.
            let approval = store.get_approval_outcome(approval_id).map_err(internal)?.ok_or_else(not_found)?;
            // The result is the redacted output of another caller's held call, so only its own agent sees it.
            if !may_act_on_session(store.as_ref(), &caller, &approval.session_id).map_err(internal)? {
                return Err(not_found().into());
            }
            // Once approved, the held call has run: hand back its redacted result so the
            // agent collects what it was waiting on without ever seeing the secret.
            let head = json!({
                "approval_id": approval.id,
                "status": approval.status,
                "message": approval.message,
                "upstream_status": approval.result_status,
                "expires_at": approval.expires_at,
                "risk": approval.risk_label(),
                "action_description": approval.action_description,
            });
            let head = head.as_object().cloned().unwrap_or_default();
            // The result is written in as the text the row keeps; no tree of it is built to answer.
            let result = approval.result.unwrap_or_else(|| axum::body::Bytes::from_static(b"null"));
            Ok(ToolOut::Document(crate::memory::Assembled::object_bytes(head, "result", result), crate::connectors::MemoryCharge::none()))
        }
        "permaura_explain_denial" => {
            let session = authed(state, headers)
                .ok_or_else(|| (-32001, "unauthorized: missing or invalid session".to_string()))?;
            let capability = args
                .get("capability")
                .and_then(|v| v.as_str())
                .ok_or_else(|| (-32602, "missing 'capability'".to_string()))?;
            let capability = capability.to_string();
            let params = args.get_mut("params").map(Value::take).unwrap_or_else(|| json!({}));
            let decision = state
                .service
                .explain(&session, &capability, &params, location)
                .map_err(tool_error)?;
            Ok(json!({ "capability": capability, "decision": decision }).into())
        }
        "permaura_revoke_session" => {
            let caller = authed(state, headers)
                .ok_or_else(|| (-32001, "unauthorized: missing or invalid session".to_string()))?;
            // Default to revoking the caller's own session when none is named.
            let session_id =
                args.get("session_id").and_then(|v| v.as_str()).map(str::to_string).unwrap_or_else(|| caller.id.clone());
            if !may_act_on_session(store.as_ref(), &caller, &session_id).map_err(internal)? {
                return Err((-32004, format!("session '{session_id}' not found")).into());
            }
            let mut existed = false;
            store
                .change_with_record(&mut || {
                    existed = store.revoke_session(&session_id)?;
                    if existed {
                        let summary = json!({ "via": "mcp" });
                        state.service.audit_authority(crate::service::SESSION_REVOKE_ACTION, &session_id, &caller, summary)?;
                    }
                    Ok(())
                })
                .map_err(internal)?;
            if !existed {
                return Err((-32004, format!("session '{session_id}' not found")).into());
            }
            Ok(json!({ "session_id": session_id, "revoked": true }).into())
        }
        other => {
            // Dynamic per-capability tool: a tool named after a capability id (e.g.
            // `fal.image.generate`) is routed straight into the enforcement loop: same
            // policy check, secret injection, redaction and audit as `permaura.invoke`.
            if let Some(cap) = store.get_capability(other).map_err(internal)? {
                let session = authed(state, headers)
                    .ok_or_else(|| (-32001, "unauthorized: missing or invalid session".to_string()))?;
                let pinned = crate::approval_display::pinned_params(&cap);
                let audit = audit_reason_argument(pinned.as_ref());
                let mut params = args;
                let stated = audit.and_then(|name| params.as_object_mut().and_then(|o| o.remove(name)).map(|v| (name, v)));
                let reason = match stated {
                    Some((_, Value::String(text))) => Some(text),
                    Some((_, Value::Null)) | None => None,
                    Some((name, _)) => return Err((-32602, format!("{other} takes '{name}' as a string")).into()),
                };
                // A capability's own reason stays in its params for the upstream, and stands as the stated reason when no other was given.
                let reason = reason.or_else(|| {
                    pinned.as_ref().filter(|p| p.accepted.contains("reason")).and_then(|_| params.get("reason")?.as_str().map(String::from))
                });
                crate::approval_display::refuse_unpinned_params(&cap, &params).map_err(|e| match e {
                    crate::error::GatewayError::BadRequest(why) => RpcError::from((-32602, why)),
                    other => tool_error(other),
                })?;
                let outcome = state
                    .service
                    .invoke_admitted(&session, other, charged(params), reason.as_deref(), location)
                    .await
                    .map_err(tool_error)?;
                Ok(render_outcome(outcome))
            } else {
                Err((-32601, format!("unknown tool: {other}")).into())
            }
        }
    }
}

fn render_outcome(outcome: InvokeOutcome) -> ToolOut {
    match outcome {
        InvokeOutcome::Allowed { decision, result, status, room } => {
            let mut head = serde_json::Map::new();
            head.insert("decision".into(), json!(decision));
            head.insert("upstream_status".into(), json!(status));
            ToolOut::Document(crate::memory::Assembled::object(head, "result", result), room)
        }
        InvokeOutcome::RequiresApproval { decision, approval } => ToolOut::Value(json!({
            "decision": decision,
            "approval_id": approval.id,
            "status": approval.status,
            "message": approval.message,
            "expires_at": approval.expires_at,
            "risk": approval.risk_label(),
            "action_description": approval.action_description,
        })),
        InvokeOutcome::Denied { decision } => ToolOut::Value(json!({ "decision": decision })),
    }
}

fn internal(e: crate::error::GatewayError) -> RpcError {
    (-32603, e.to_string()).into()
}

/// Describe a dynamic capability tool: the capability's own description plus the broker
/// guarantee and its risk tier, so an agent has the context to choose it appropriately.
fn dynamic_tool_description(desc: &str, risk: permaura_core::RiskTier) -> String {
    let r = match serde_json::to_value(risk) {
        Ok(Value::String(s)) => s,
        _ => "unknown".to_string(),
    };
    format!("{desc}. Risk: {r}. Permaura injects the real credential and performs the call server-side: the secret is never exposed to you.")
}

/// The input schema for a dynamic capability tool. A capability with a pinned shape (an imported HTTP spec, an SSH operation) advertises exactly the parameters it reads, since its connector drops the rest; the built-in connectors without one keep a hand-written schema for their well-known capabilities, and anything else gets an open object.
fn dynamic_tool_input_schema(cap: &crate::connectors::Capability) -> Value {
    if let Some(pinned) = crate::approval_display::pinned_params(cap) {
        let audit = audit_reason_argument(Some(&pinned));
        let props = match &cap.ssh {
            Some(spec) => ssh_properties(spec, &pinned),
            None => pinned.accepted.iter().map(|name| (name.clone(), json!({}))).collect(),
        };
        return pinned_schema(props, &pinned.required, audit);
    }
    match cap.id.as_str() {
        "fal.image.generate" => json!({
            "type": "object",
            "properties": {
                "prompt": { "type": "string", "description": "The text prompt to generate an image from." },
                "image_size": { "type": "string", "description": "e.g. landscape_16_9, square_hd." },
                "num_images": { "type": "integer", "minimum": 1 }
            },
            "required": ["prompt"]
        }),
        "http.request" => json!({
            "type": "object",
            "properties": {
                "method": { "type": "string" },
                "url": { "type": "string", "description": "Absolute https URL on a host the connection allows; plain http is refused." },
                "headers": { "type": "object" },
                "body": {}
            },
            "required": ["url"]
        }),
        "github.pull_requests.create" => json!({
            "type": "object",
            "properties": {
                "repo": { "type": "string", "description": "owner/name" },
                "title": { "type": "string" },
                "head": { "type": "string" },
                "base": { "type": "string" },
                "body": { "type": "string" }
            },
            "required": ["repo", "title"]
        }),
        id if id.starts_with("braintree.transactions") => json!({
            "type": "object",
            "properties": {
                "transaction_id": { "type": "string" },
                "status": { "type": "string" }
            }
        }),
        _ => json!({
            "type": "object",
            "additionalProperties": true,
            "description": "Parameters forwarded to this capability's connector."
        }),
    }
}

/// The properties of an SSH capability's tool: the exec placeholders as strings, or the sftp path and content.
fn ssh_properties(spec: &crate::connectors::SshSpec, pinned: &crate::approval_display::PinnedParams) -> serde_json::Map<String, Value> {
    use crate::connectors::SshOp;
    let about = |name: &str| match (&spec.op, name) {
        (SshOp::Exec { .. }, _) => "",
        (SshOp::SftpList { .. }, "path") => "Optional sub-path under the connection's root.",
        (_, "path") => "File path relative to the connection's root.",
        (_, "content") => "File contents, base64-encoded.",
        _ => "",
    };
    pinned
        .accepted
        .iter()
        .map(|name| {
            let schema = match about(name) {
                "" => json!({ "type": "string" }),
                text => json!({ "type": "string", "description": text }),
            };
            (name.clone(), schema)
        })
        .collect()
}

/// Whether the Claude API takes `name` as an input-schema property key. It refuses a tool with any other key, and Claude clients send every tool with every request, so one such tool fails every turn of a session.
fn claude_property_key(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
}

/// A pinned capability tool's schema: the parameters it reads and the argument it takes the stated reason from, and nothing else. A parameter name the Claude API would refuse as a key (Microsoft Graph's `$top`, OData's `$filter`, JSON:API's `page[size]`) cannot be declared, so such a tool gets an open schema that names what it takes instead.
fn pinned_schema(mut props: serde_json::Map<String, Value>, required: &[String], audit: Option<&str>) -> Value {
    if !props.keys().all(|name| claude_property_key(name)) {
        let mut takes: Vec<String> = props.keys().cloned().collect();
        if let Some(audit) = audit {
            takes.push(format!("{audit} (why the call is made, for the audit trail)"));
        }
        let needs = if required.is_empty() { String::new() } else { format!(", and needs {}", required.join(", ")) };
        return json!({
            "type": "object",
            "additionalProperties": true,
            "description": format!("Takes {}{needs}. Some of these names cannot be declared as properties here, so they are listed; any other parameter is refused.", takes.join(", ")),
        });
    }
    if let Some(audit) = audit {
        if audit == AUDIT_REASON {
            if let Some(Value::Object(own)) = props.get_mut("reason") {
                own.insert(
                    "description".into(),
                    json!(format!("This capability's own reason, sent upstream. Recorded as why the call is made when {AUDIT_REASON} is not given.")),
                );
            }
        }
        props.insert(
            audit.into(),
            json!({ "type": "string", "description": "Why the call is made; recorded on the audit trail and shown on any approval." }),
        );
    }
    json!({
        "type": "object",
        "properties": Value::Object(props),
        "required": required,
        "additionalProperties": false,
    })
}

/// An MCP tool `annotations` object. The booleans are the safety hints the Claude and ChatGPT
/// directories require, and clients use them to decide when to confirm an action with the human:
/// `read_only` (no state change), `destructive` (irreversible), `idempotent` (repeat-safe),
/// `open_world` (reaches an external system).
fn ann(read_only: bool, destructive: bool, idempotent: bool, open_world: bool) -> Value {
    json!({
        "readOnlyHint": read_only,
        "destructiveHint": destructive,
        "idempotentHint": idempotent,
        "openWorldHint": open_world,
    })
}

/// Annotations for a dynamic per-capability tool. A client may skip its own confirmation for a
/// read-only tool, so `readOnlyHint` needs both a read action and a transport that only reads: a
/// pinned `GET`, a GraphQL query (the gateway refuses anything else on it), an SFTP read or listing,
/// or a built-in HTTP connector the gateway shapes itself; never a command. Risk never makes a tool read-only, because an
/// imported document can set it. A write that deletes, moves money or rotates a secret, sends a
/// `DELETE`, or is Critical is destructive. Every capability tool reaches an external system, so
/// `openWorldHint` is always true.
fn capability_annotations(c: &crate::connectors::Capability) -> Value {
    use crate::connectors::{CapabilityKind, GraphqlOperation, HttpMethod};
    use permaura_core::Action;
    let reads = matches!(c.action, Action::Read | Action::Search | Action::List);
    let transport_reads = match (c.kind, &c.http, &c.ssh) {
        (CapabilityKind::Http, Some(http), _) => {
            http.method == HttpMethod::Get || http.graphql.as_ref().is_some_and(|g| g.operation == GraphqlOperation::Query)
        }
        (CapabilityKind::Http, None, _) => true,
        // A command runs whatever program it names, so its action alone never makes it read-only.
        (CapabilityKind::Command, _, _) => false,
        (CapabilityKind::Ssh, _, Some(ssh)) => {
            matches!(ssh.op, crate::connectors::SshOp::SftpGet { .. } | crate::connectors::SshOp::SftpList { .. })
        }
        (CapabilityKind::Ssh, _, None) => false,
    };
    let read_only = reads && transport_reads;
    let destructive = !read_only
        && (matches!(c.action, Action::Delete | Action::Refund | Action::Charge | Action::RotateSecret)
            || c.http.as_ref().is_some_and(|h| h.method == HttpMethod::Delete)
            || c.risk == permaura_core::RiskTier::Critical);
    ann(read_only, destructive, false, true)
}

/// A human-readable title for a dynamic capability tool: `fal.image.generate` → `Fal image generate`.
fn humanize_cap_id(id: &str) -> String {
    let spaced = id.replace(['.', '_', '-'], " ");
    let mut chars = spaced.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => spaced,
    }
}
