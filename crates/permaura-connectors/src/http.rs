//! HTTP client abstraction for the connector layer.
//!
//! Connectors never touch `reqwest` directly: they build an [`HttpRequest`] and hand it to an [`HttpClient`]. In production that is [`ReqwestClient`] (rustls TLS, JSON); offline and in tests it is [`MockHttpClient`], which records every request and replays queued responses (falling through to a deterministic synthetic `200` so the whole enforcement runtime compiles and runs with zero network access). This is the seam that lets the request-shaping and redaction code be exercised end-to-end without ever reaching the internet.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use reqwest::header::{HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use serde::{Deserialize, Serialize};

use crate::json_budget::{MemoryCharge, MemoryPool};

/// HTTP methods a connector can issue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum HttpMethod {
    /// HTTP GET.
    #[default]
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
}

impl HttpMethod {
    /// The uppercase method name.
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Patch => "PATCH",
            HttpMethod::Delete => "DELETE",
        }
    }

    /// Parse a case-insensitive method name; defaults to GET for unknown input.
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "POST" => HttpMethod::Post,
            "PUT" => HttpMethod::Put,
            "PATCH" => HttpMethod::Patch,
            "DELETE" => HttpMethod::Delete,
            _ => HttpMethod::Get,
        }
    }
}

/// A fully-formed HTTP request, ready to send. Built by connectors after policy has authorized the call, with the secret placed where its auth scheme says. This struct is internal and never returned to an agent.
///
/// The injected credential sits in the URL, a header, the form or one of the encoded bodies. The URL, the header values and the form are wiped when the request drops; [`ReqwestClient`] encodes the form, and takes the encoded bodies, into buffers it hands to the HTTP stack that wipe themselves when the stack releases them. `Debug` prints the URL without its query and the header names without their values. The HTTP stack's own copies (reqwest's URL and header values, hyper's and rustls's write buffers) are out of reach.
#[derive(Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// The method.
    pub method: HttpMethod,
    /// The absolute URL.
    pub url: String,
    /// Request headers, including the injected `Authorization` header.
    pub headers: BTreeMap<String, String>,
    /// Optional JSON body.
    pub body: Option<serde_json::Value>,
    /// Optional `application/x-www-form-urlencoded` body, which takes precedence over `body`.
    ///
    /// Connector traffic is JSON, but OAuth is not: RFC 6749 §4.1.3 requires the token endpoint to
    /// take a form-encoded body, and Google, Xero, Slack, Dropbox and GitHub all reject a JSON one.
    /// Kept as a separate field rather than folding both into an enum so every existing call site
    /// and every `req.body` assertion stays untouched.
    pub form: Option<BTreeMap<String, String>>,
    /// A body already encoded as `application/x-www-form-urlencoded`, sent byte for byte, after `form`
    /// and before `body` in precedence. An imported capability with a form body style builds one,
    /// because a nested value in PHP bracket syntax (`metadata[order]=1042`) and its order do not fit
    /// in `form`'s flat sorted map.
    pub form_encoded: Option<String>,
    /// A JSON body already written as text, sent byte for byte, after `form` and `form_encoded` and before `body` in precedence. The connector builders write an agent's params here from the tree they borrow, so the request never holds a second tree of them.
    pub json_encoded: Option<String>,
    /// The request carries a credential the gateway injected. [`ReqwestClient`] then follows a redirect
    /// only on the first URL's host and never from https to http: on a cross-host hop reqwest strips only
    /// `Authorization` and cookies, so a key in any other header, the query (through `Referer`) or a body
    /// re-sent on a 307 would follow.
    pub credentialed: bool,
}

impl Drop for HttpRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.url.zeroize();
        self.headers.values_mut().for_each(Zeroize::zeroize);
        if let Some(form) = &mut self.form {
            form.values_mut().for_each(Zeroize::zeroize);
        }
        if let Some(text) = &mut self.form_encoded {
            text.zeroize();
        }
        if let Some(text) = &mut self.json_encoded {
            text.zeroize();
        }
    }
}

impl std::fmt::Debug for HttpRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRequest")
            .field("method", &self.method)
            .field("url", &crate::egress::scrub_url(&self.url))
            .field("headers", &self.headers.keys().collect::<Vec<_>>())
            .field("body", &self.body.is_some())
            .field("form", &self.form.as_ref().map(|form| form.keys().collect::<Vec<_>>()))
            .field("form_encoded", &self.form_encoded.as_ref().map(String::len))
            .field("json_encoded", &self.json_encoded.as_ref().map(String::len))
            .field("credentialed", &self.credentialed)
            .finish()
    }
}

impl HttpRequest {
    /// Start building a GET request to `url`.
    pub fn get(url: impl Into<String>) -> Self {
        HttpRequest {
            method: HttpMethod::Get,
            url: url.into(),
            headers: BTreeMap::new(),
            body: None,
            form: None,
            form_encoded: None,
            json_encoded: None,
            credentialed: false,
        }
    }

    /// Start building a POST request to `url`.
    pub fn post(url: impl Into<String>) -> Self {
        HttpRequest {
            method: HttpMethod::Post,
            url: url.into(),
            headers: BTreeMap::new(),
            body: None,
            form: None,
            form_encoded: None,
            json_encoded: None,
            credentialed: false,
        }
    }

    /// Construct a request with an explicit method.
    pub fn new(method: HttpMethod, url: impl Into<String>) -> Self {
        HttpRequest {
            method,
            url: url.into(),
            headers: BTreeMap::new(),
            body: None,
            form: None,
            form_encoded: None,
            json_encoded: None,
            credentialed: false,
        }
    }

    /// Add a header (builder style).
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.insert(name.into(), value.into());
        self
    }

    /// Attach a JSON body (builder style).
    pub fn json_body(mut self, body: serde_json::Value) -> Self {
        self.body = Some(body);
        self
    }

    /// Send `value` as the JSON body when it carries a credential: written into a buffer that leaves no
    /// copy behind as it grows, then moved, not copied, into [`HttpRequest::json_encoded`], which is wiped
    /// when the request drops, or handed to the HTTP stack by [`ReqwestClient`] in a buffer that wipes
    /// itself when the stack releases it.
    pub fn secret_json_body(mut self, value: &impl Serialize) -> serde_json::Result<Self> {
        let mut json = permaura_core::secret::to_json(value)?;
        let text = String::from_utf8(std::mem::take(&mut *json)).map_err(|e| {
            zeroize::Zeroize::zeroize(&mut e.into_bytes());
            serde_json::Error::io(std::io::Error::other("a JSON body that is not UTF-8"))
        })?;
        self.json_encoded = Some(text);
        Ok(self)
    }

    /// Send `fields` as an `application/x-www-form-urlencoded` body. Required by OAuth token
    /// endpoints, which reject JSON.
    pub fn form_body(mut self, fields: BTreeMap<String, String>) -> Self {
        self.form = Some(fields);
        self
    }

    /// Mark the request as carrying a gateway-injected credential (builder style). See
    /// [`HttpRequest::credentialed`].
    pub fn credentialed(mut self) -> Self {
        self.credentialed = true;
        self
    }

    /// The JSON body as a tree, whichever field holds it: for a test or a mock reading what a request would send.
    pub fn json(&self) -> Option<serde_json::Value> {
        match &self.json_encoded {
            Some(text) => serde_json::from_str(text).ok(),
            None => self.body.clone(),
        }
    }

    /// The hostname of the request URL, if it is an absolute http(s) URL whose host is unambiguous.
    /// Derived by [`crate::egress::parse_url`], the parser [`ReqwestClient`] dispatches with, so an
    /// `allowed_hosts` check on this value judges the host the request actually reaches.
    pub fn host(&self) -> Option<String> {
        crate::egress::url_host(&self.url)
    }
}

/// An HTTP response as seen by a connector.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HttpResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The parsed JSON body. `Null` if the body was empty or not JSON.
    pub body: serde_json::Value,
    /// The response headers that pass [`is_diagnostic_header`], lowercase, values capped at
    /// [`DIAGNOSTIC_HEADER_VALUE_MAX`]. Everything else the upstream sent is dropped in the client.
    pub headers: Vec<(String, String)>,
    /// The body as text, kept only for a non-2xx answer that was not JSON, so an error page can be
    /// reported to the operator without changing what the agent receives (`body` stays `Null`).
    pub text: Option<String>,
    /// The room `body`'s tree holds in the worker's [`MemoryPool`], given back when the last clone of this response is dropped. Holds nothing for a client with no pool, a mock, or a body that is not JSON.
    pub memory: MemoryCharge,
}

/// An upstream response whose body is left as the bytes that arrived, for a caller that never needs its structure: the agent's view of a response is a streaming pass over these bytes (`permaura_core::json_stream::agent_view`), so no tree of an upstream body is ever built for it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RawHttpResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The body as read, under the client's response cap.
    pub body: Vec<u8>,
    /// As [`HttpResponse::headers`].
    pub headers: Vec<(String, String)>,
}

/// An upstream response whose body is itself a credential (an OAuth token endpoint's answer, a secret a vault returns, a key a KMS unwraps): the bytes that arrived, in a buffer wiped when it drops.
pub struct SecretHttpResponse {
    /// The HTTP status code.
    pub status: u16,
    /// The body as read, under the client's response cap. [`ReqwestClient`] reads it into a buffer that wipes each block it outgrows, so no partial copy of this buffer is left behind; the chunks hyper received it in are the transport's own.
    pub body: zeroize::Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for SecretHttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretHttpResponse {{ status: {}, body: [redacted; {} bytes] }}", self.status, self.body.len())
    }
}

impl RawHttpResponse {
    /// True for 2xx statuses.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

}

/// The start of a body that is not JSON, as [`HttpResponse::text`] keeps it, or `None` when it is blank.
/// Only for a body that did not read as JSON: a JSON body reaches an operator only through its redacted view, since its raw text still holds every member redaction removed.
pub fn non_json_text(body: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(&body[..body.len().min(DIAGNOSTIC_TEXT_MAX)]).into_owned();
    Some(text).filter(|t| !t.trim().is_empty())
}

impl HttpResponse {
    /// Build a JSON response with a status code.
    pub fn json(status: u16, body: serde_json::Value) -> Self {
        HttpResponse { status, body, ..HttpResponse::default() }
    }

    /// True for 2xx statuses.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// The longest header value [`HttpResponse::headers`] keeps.
pub const DIAGNOSTIC_HEADER_VALUE_MAX: usize = 200;

/// The most headers [`HttpResponse::headers`] keeps from one response.
const DIAGNOSTIC_HEADER_COUNT_MAX: usize = 16;

/// The longest non-JSON error body [`HttpResponse::text`] keeps.
const DIAGNOSTIC_TEXT_MAX: usize = 2048;

/// Whether a response header is safe to record in the signed audit chain.
///
/// An allowlist, because the chain is permanent and a denylist fails open on the next header nobody
/// thought of: `set-cookie`, `location` (an OAuth redirect carries a code) and anything a vendor
/// invents are all left out. What is kept is what an operator needs to debug a connection: the
/// content type, the upstream's own request id to quote to its support, and rate-limit state. `link`
/// is kept because WordPress discovery reads its `rel="https://api.w.org/"` target; its value is URL
/// text the upstream chooses, so it is never chain-safe and only reaches the purgeable diagnostics.
pub fn is_diagnostic_header(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    matches!(
        name.as_str(),
        "content-type"
            | "content-length"
            | "retry-after"
            | "www-authenticate"
            | "link"
            | "x-request-id"
            | "request-id"
            | "x-github-request-id"
            | "x-amzn-requestid"
            | "x-amz-request-id"
            | "x-ms-request-id"
            | "x-vercel-id"
            | "cf-ray"
    ) || name.starts_with("x-ratelimit-")
        || name.starts_with("ratelimit")
        || name.starts_with("x-rate-limit-")
}

/// Whether an allowlisted header's value is structured enough to sign into the permanent audit chain:
/// a bare media type, a byte count, a delay in seconds, or a numeric rate-limit figure.
///
/// The name allowlist is not enough on its own, because the values are the upstream's to choose and
/// plenty of upstreams echo what the request carried: an `x-request-id`, or the `error_description`
/// inside a `www-authenticate`, can hold any text at all. Those go to the purgeable diagnostics row
/// instead.
pub fn is_chain_safe_header(name: &str, value: &str) -> bool {
    let name = name.to_ascii_lowercase();
    let digits = |v: &str| !v.is_empty() && v.len() <= 20 && v.bytes().all(|b| b.is_ascii_digit() || b == b'.');
    match name.as_str() {
        "content-type" => {
            let token = |t: &str| {
                !t.is_empty() && t.len() <= 64 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$&^_.+-".contains(&b))
            };
            matches!(value.split_once('/'), Some((kind, sub)) if token(kind) && token(sub))
        }
        "content-length" | "retry-after" => digits(value),
        _ if name.starts_with("x-ratelimit-") || name.starts_with("ratelimit") || name.starts_with("x-rate-limit-") => {
            digits(value)
        }
        _ => false,
    }
}

fn diagnostic_headers(headers: &reqwest::header::HeaderMap) -> Vec<(String, String)> {
    let mut kept: Vec<(String, String)> = headers
        .iter()
        .filter(|(name, _)| is_diagnostic_header(name.as_str()))
        .filter_map(|(name, value)| {
            let value = value.to_str().ok()?;
            let value = if name == reqwest::header::CONTENT_TYPE {
                value.split(';').next().unwrap_or_default().trim().to_ascii_lowercase()
            } else {
                value.trim().chars().take(DIAGNOSTIC_HEADER_VALUE_MAX).collect()
            };
            Some((name.as_str().to_ascii_lowercase(), value))
        })
        .collect();
    kept.sort();
    kept.truncate(DIAGNOSTIC_HEADER_COUNT_MAX);
    kept
}

/// The trait connectors depend on to perform upstream calls. Object-safe so a connector can hold `Arc<dyn HttpClient>`.
#[async_trait]
pub trait HttpClient: Send + Sync {
    /// Send `request` and return the response.
    async fn send(&self, request: HttpRequest) -> anyhow::Result<HttpResponse>;

    /// Send `request` and return the body as the bytes that arrived, unparsed, through the same egress screen and response cap as [`HttpClient::send`].
    ///
    /// This default rebuilds the bytes from what `send` returned (the JSON body written back out, or the text of a body that was not JSON), which is how [`MockHttpClient`] and test doubles answer it from their queued responses.
    /// [`ReqwestClient`] overrides it to read the body and stop.
    async fn send_raw(&self, request: HttpRequest) -> anyhow::Result<RawHttpResponse> {
        let resp = self.send(request).await?;
        let body = match (&resp.body, resp.text) {
            (serde_json::Value::Null, Some(text)) => text.into_bytes(),
            (body, _) => serde_json::to_vec(body)?,
        };
        Ok(RawHttpResponse { status: resp.status, body, headers: resp.headers })
    }

    /// Send `request` whose answer is a credential, and return the body in a buffer wiped when it drops, through the same egress screen and response cap as [`HttpClient::send`].
    ///
    /// This default wraps what [`HttpClient::send_raw`] returned, which is how [`MockHttpClient`] and test doubles answer it. [`ReqwestClient`] overrides it to read the body straight into a buffer that wipes each block it outgrows.
    async fn send_secret(&self, request: HttpRequest) -> anyhow::Result<SecretHttpResponse> {
        let raw = self.send_raw(request).await?;
        Ok(SecretHttpResponse { status: raw.status, body: zeroize::Zeroizing::new(raw.body) })
    }

    /// Send `request` and keep the whole body in [`HttpResponse::text`] whatever the status or content
    /// type, for a gateway-side read of a document such as a YAML OpenAPI specification.
    ///
    /// [`HttpClient::send`] keeps text only for a non-JSON error, because connector traffic is JSON and
    /// the agent only ever sees `body`. This default rebuilds the text from what `send` returned (the
    /// JSON body re-serialized when there is no text), which is how [`MockHttpClient`] answers it from
    /// its queued responses. [`ReqwestClient`] overrides it to return the raw bytes, through the same
    /// egress screen and response cap as `send`.
    async fn fetch_text(&self, request: HttpRequest) -> anyhow::Result<HttpResponse> {
        let mut resp = self.send(request).await?;
        if resp.text.is_none() && !resp.body.is_null() {
            resp.text = Some(resp.body.to_string());
        }
        Ok(resp)
    }
}

/// The most redirects a screened request follows, reqwest's own default.
const MAX_REDIRECTS: usize = 10;

/// A redirect policy that screens every hop the way [`HttpClient::send`] screens the first request.
///
/// The [`crate::egress::GuardedResolver`] only sees hostnames, so a `Location` naming an IP literal
/// (`http://10.0.0.5/`, `http://169.254.169.254/`) would otherwise be followed without any check.
fn screened_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        match crate::egress::screen_url(attempt.url().as_str()) {
            Ok(()) => attempt.follow(),
            Err(e) => attempt.error(e),
        }
    })
}

/// [`screened_redirects`] for a [`HttpRequest::credentialed`] request: every hop is also held to the
/// first URL's host and scheme by [`crate::egress::check_pinned_hop`].
fn pinned_redirects() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        let Some(first) = attempt.previous().first() else {
            return attempt.error("a redirect with no originating request");
        };
        let verdict = crate::egress::check_pinned_hop(first.as_str(), attempt.url().as_str())
            .and_then(|()| crate::egress::screen_url(attempt.url().as_str()));
        match verdict {
            Ok(()) => attempt.follow(),
            Err(e) => attempt.error(e),
        }
    })
}

/// The production HTTP client, backed by `reqwest` with rustls TLS and JSON support.
pub struct ReqwestClient {
    inner: reqwest::Client,
    /// The client a [`HttpRequest::credentialed`] request is sent with: [`pinned_redirects`] instead of
    /// [`screened_redirects`]. reqwest fixes the redirect policy per client, so it is a second client.
    pinned: reqwest::Client,
    /// When `true` (the default, [`new`]), every request is SSRF-screened and metadata headers are
    /// stripped, the posture for all connector/agent traffic. When `false` ([`new_infra`]), the
    /// screen is skipped for the gateway's OWN fixed infrastructure calls (Cloud KMS via the metadata
    /// server), which must reach hosts the connector guard deliberately blocks.
    screened: bool,
    /// The largest response body this client will read. See [`crate::caps`].
    max_response_bytes: u64,
    /// The pool a [`HttpClient::send`] body's tree is charged to when it has room at once. Never waited on: see [`ReqwestClient::with_memory`].
    memory: Option<Arc<MemoryPool>>,
    /// The most one [`HttpClient::send`] body's tree may take, with room in the pool or without.
    max_tree_bytes: u64,
    /// The one origin this client may send to, for [`ReqwestClient::for_configured_origin`]; `None` for every other client.
    origin_pin: Option<String>,
}

/// The most one response body's tree may take by default (64 MiB). The gateway gives its own client the figure in its limits; the clients a secret backend or the KMS custody path build for themselves read small, fixed documents.
pub const DEFAULT_MAX_TREE_BYTES: u64 = 64 * 1024 * 1024;

impl ReqwestClient {
    /// Build a client with sane defaults, including **request and connect timeouts**, so a hung
    /// or slow upstream (a stuck secret backend, a wedged API) can never block a worker's dispatch
    /// loop indefinitely. Without these, reqwest waits forever and one stuck call starves the
    /// worker's heartbeats until the relay drops it.
    ///
    /// The client also installs the [`crate::egress::GuardedResolver`], so every hostname target
    /// is re-screened against the private/metadata IP blocklist at the moment of connection: the
    /// addresses it returns are the ones connected to, closing the DNS-rebinding window.
    pub fn new() -> anyhow::Result<Self> {
        let build = |policy: reqwest::redirect::Policy| {
            reqwest::Client::builder()
                .user_agent("permaura/0.1")
                .connect_timeout(std::time::Duration::from_secs(10))
                .timeout(std::time::Duration::from_secs(30))
                .dns_resolver(Arc::new(crate::egress::GuardedResolver))
                // Through a proxy the target resolves at the proxy, out of the GuardedResolver's sight.
                .no_proxy()
                .redirect(policy)
                // A Referer carries the previous URL's query, where an ApiKeyQuery credential sits.
                .referer(false)
                .build()
        };
        Ok(ReqwestClient {
            inner: build(screened_redirects())?,
            pinned: build(pinned_redirects())?,
            screened: true,
            max_response_bytes: crate::caps::http_max_response_bytes(),
            memory: None,
            max_tree_bytes: DEFAULT_MAX_TREE_BYTES,
            origin_pin: None,
        })
    }

    /// An **unscreened** client for the gateway's OWN trusted infrastructure calls, specifically the
    /// Cloud KMS custody path, which must reach the Cloud Run / GCE metadata server
    /// (`metadata.google.internal`, a link-local address the connector egress guard deliberately
    /// blocks) to mint the workload's short-lived access token, and then `cloudkms.googleapis.com`.
    /// Both hosts are hardcoded in the KMS client and its only variable input (`PERMAURA_KMS_KEY_ID`)
    /// is an operator-set env value used as a URL *path*, never the host, so the SSRF screen provides
    /// no benefit here and only breaks token minting.
    ///
    /// **Never hand this client to connector or agent execution.** That path must keep the screened
    /// [`new`] client; this one exists solely for the gateway's own calls to fixed cloud endpoints.
    pub fn new_infra() -> anyhow::Result<Self> {
        let inner = reqwest::Client::builder()
            .user_agent("permaura/0.1")
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            // The workload token from the metadata server must not be handed to a proxy from the environment.
            .no_proxy()
            .build()?;
        Ok(ReqwestClient {
            pinned: inner.clone(),
            inner,
            screened: false,
            max_response_bytes: crate::caps::http_max_response_bytes(),
            memory: None,
            max_tree_bytes: DEFAULT_MAX_TREE_BYTES,
            origin_pin: None,
        })
    }

    /// A client for one service the operator configured by its address, such as a self-hosted secret store, which often sits on loopback or a private network the connector egress screen refuses by design. It reaches that origin wherever it is and nothing else: every request must be for `base_url`'s scheme, host and port, no redirect is followed, no proxy from the environment is used, and plain http is accepted only for a loopback base, so a credential never crosses a network in the clear.
    ///
    /// **Never hand this client to connector or agent execution.** Its exemption from the screen rests on the address being the operator's own configuration.
    pub fn for_configured_origin(base_url: &str) -> anyhow::Result<Self> {
        let (parsed, parts) = crate::egress::parse_checked(base_url.trim()).map_err(|e| anyhow::anyhow!("{e}"))?;
        anyhow::ensure!(
            parsed.username().is_empty() && parsed.password().is_none(),
            "the address of a configured service must not carry a user name or password"
        );
        let loopback = parts.host == "localhost"
            || parts.host.parse::<std::net::IpAddr>().is_ok_and(|ip| match ip {
                std::net::IpAddr::V4(v4) => v4.is_loopback(),
                std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback()),
            });
        anyhow::ensure!(
            parts.scheme == "https" || loopback,
            "the address of a configured service must be https unless it is on this machine"
        );
        let client = reqwest::Client::builder()
            .user_agent("permaura/0.1")
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .https_only(!loopback)
            .build()?;
        Ok(ReqwestClient {
            pinned: client.clone(),
            inner: client,
            screened: false,
            max_response_bytes: crate::caps::http_max_response_bytes(),
            memory: None,
            max_tree_bytes: DEFAULT_MAX_TREE_BYTES,
            origin_pin: Some(parsed.origin().ascii_serialization()),
        })
    }

    /// The connector client's redirect policies and error handling with the egress screen off, proxies
    /// off and a caller-chosen timeout, so another crate's integration test can drive it against its own
    /// loopback server (which the screen refuses by design). Only in tests and `test-support` builds.
    #[cfg(any(test, feature = "test-support"))]
    pub fn loopback_for_tests(timeout: std::time::Duration) -> Self {
        let build = |policy: reqwest::redirect::Policy| {
            reqwest::Client::builder()
                .user_agent("permaura/0.1")
                .connect_timeout(timeout)
                .timeout(timeout)
                .no_proxy()
                .redirect(policy)
                .referer(false)
                .build()
                .expect("a loopback test client builds")
        };
        ReqwestClient {
            inner: build(screened_redirects()),
            pinned: build(pinned_redirects()),
            screened: false,
            max_response_bytes: 64 * 1024,
            memory: None,
            max_tree_bytes: DEFAULT_MAX_TREE_BYTES,
            origin_pin: None,
        }
    }

    /// A client with an explicit response cap. The cap is normally read once per process from the
    /// environment, which a test cannot vary; this is how a test pins one.
    pub fn with_response_cap(mut self, max_response_bytes: u64) -> Self {
        self.max_response_bytes = max_response_bytes;
        self
    }

    /// Charge each [`HttpClient::send`] body's tree to `pool` when the pool has room for it at once.
    /// The pool is never waited on and never refuses a body: the request has been sent when its answer is read, and refusing it then loses what the upstream already committed (a refresh token an OAuth provider rotated, a single-use authorization code), so a tree with no room is built beside the pool, under the same [`ReqwestClient::with_max_tree_bytes`] ceiling.
    pub fn with_memory(mut self, pool: Arc<MemoryPool>) -> Self {
        self.memory = Some(pool);
        self
    }

    /// Hold each [`HttpClient::send`] body's tree to `max_tree_bytes`.
    pub fn with_max_tree_bytes(mut self, max_tree_bytes: u64) -> Self {
        self.max_tree_bytes = max_tree_bytes;
        self
    }

    /// The body's tree and the room it holds in the pool (none when the pool had no room at once), or `Null` and the start of the text for a body that is not JSON.
    /// A JSON body over the tree ceiling is an error and never `Null`: a caller reading `Null` as "nothing came back" would be told something false.
    fn parse_body(&self, buf: &[u8]) -> anyhow::Result<(serde_json::Value, Option<String>, MemoryCharge)> {
        let not_json = || (serde_json::Value::Null, non_json_text(buf), MemoryCharge::none());
        let estimate = crate::json_budget::estimate(buf);
        if estimate > self.max_tree_bytes {
            if serde_json::from_slice::<serde::de::IgnoredAny>(buf).is_err() {
                return Ok(not_json());
            }
            anyhow::bail!(
                "upstream response not read: its JSON would take about {estimate} bytes once parsed, over this client's {}-byte limit",
                self.max_tree_bytes
            );
        }
        let charge = self.memory.as_ref().and_then(|pool| pool.try_reserve(estimate)).unwrap_or_default();
        match crate::json_budget::value_from_slice(buf, estimate) {
            Ok(body) => Ok((body, None, charge)),
            Err(crate::json_budget::BuildError::Parse(_)) => Ok(not_json()),
            Err(over) => anyhow::bail!("upstream response not read: {over}"),
        }
    }
}

impl Default for ReqwestClient {
    fn default() -> Self {
        ReqwestClient::new().expect("reqwest client builds with default config")
    }
}

impl ReqwestClient {
    /// Screen, shape and send `request`, leaving the body unread so each caller reads it under the cap.
    async fn dispatch(&self, mut request: HttpRequest) -> anyhow::Result<reqwest::Response> {
        // Egress guard (defence in depth) for connector/agent traffic. Reject non-http(s) schemes and
        // IP-literal targets in disallowed ranges before any socket is opened (the resolver never sees
        // IP literals), and strip any agent-supplied `Metadata-Flavor` header. Hostname targets are
        // re-screened by the GuardedResolver after DNS resolution. Skipped only for the unscreened
        // infra client ([`ReqwestClient::new_infra`]), whose fixed KMS/metadata destinations the screen
        // would wrongly block, and which is never reachable from connector input.
        let mut target = if self.screened {
            let target = crate::egress::screened_url(&request.url)?;
            if request.credentialed && target.scheme() != "https" {
                return Err(crate::egress::EgressError::CredentialOverPlainHttp.into());
            }
            crate::egress::strip_metadata_headers(&mut request.headers);
            target
        } else {
            reqwest::Url::parse(&request.url)?
        };
        if let Some(pin) = &self.origin_pin {
            let origin = target.origin().ascii_serialization();
            anyhow::ensure!(origin == *pin, "egress refused: this client sends only to {pin}, not {origin}");
        }
        // reqwest sends URL userinfo as an `Authorization: Basic` ahead of any the request sets, and nothing here authenticates that way.
        let _ = target.set_username("");
        let _ = target.set_password(None);

        let method = match request.method {
            HttpMethod::Get => reqwest::Method::GET,
            HttpMethod::Post => reqwest::Method::POST,
            HttpMethod::Put => reqwest::Method::PUT,
            HttpMethod::Patch => reqwest::Method::PATCH,
            HttpMethod::Delete => reqwest::Method::DELETE,
        };
        let client = if request.credentialed { &self.pinned } else { &self.inner };
        let mut builder = client.request(method, target);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }
        let bodyless_write = request.form.is_none()
            && request.form_encoded.is_none()
            && request.json_encoded.is_none()
            && request.body.is_none()
            && matches!(
                request.method,
                HttpMethod::Post | HttpMethod::Put | HttpMethod::Patch
            );
        // Form takes precedence: a request carrying both is an OAuth-style call that also happens to
        // have a JSON body set, and the form encoding is the one the endpoint will accept.
        let typed = request.headers.keys().any(|name| name.eq_ignore_ascii_case("content-type"));
        if let Some(form) = &request.form {
            if !typed {
                builder = builder.header(CONTENT_TYPE, "application/x-www-form-urlencoded");
            }
            builder = builder.body(wiped_body(encode_form(form)));
        } else if let Some(encoded) = request.form_encoded.take() {
            if !typed {
                builder = builder.header(CONTENT_TYPE, "application/x-www-form-urlencoded");
            }
            builder = builder.body(wiped_body(zeroize::Zeroizing::new(encoded.into_bytes())));
        } else if let Some(encoded) = request.json_encoded.take() {
            if !typed {
                builder = builder.header(CONTENT_TYPE, "application/json");
            }
            builder = builder.body(wiped_body(zeroize::Zeroizing::new(encoded.into_bytes())));
        } else if let Some(body) = &request.body {
            builder = builder.json(body);
        }
        let mut outbound = builder.build().map_err(reqwest::Error::without_url)?;
        if bodyless_write {
            // hyper declares no length for an empty body, even an explicit one, and Google's front end refuses such a POST with 411 Length Required.
            outbound
                .headers_mut()
                .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
        }
        // reqwest renders the request URL into every send, timeout and refused-redirect error, and an
        // `ApiKeyQuery` credential sits in that URL's query.
        Ok(client.execute(outbound).await.map_err(reqwest::Error::without_url)?)
    }
}

/// A body for the HTTP stack over `bytes`, which are wiped when the stack drops its last reference to them,
/// rather than freed as they were.
fn wiped_body(bytes: zeroize::Zeroizing<Vec<u8>>) -> reqwest::Body {
    reqwest::Body::from(bytes::Bytes::from_owner(bytes))
}

/// `fields` as an `application/x-www-form-urlencoded` body, byte for byte as reqwest's `form` (serde_urlencoded)
/// writes it (letters, digits and `*-._` kept, a space as `+`, anything else as `%XX`), into a buffer of exactly
/// its length: a token endpoint's form holds the refresh token and the client secret, and the encoder reqwest uses
/// grows a `String` as it goes.
fn encode_form(fields: &BTreeMap<String, String>) -> zeroize::Zeroizing<Vec<u8>> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let kept = |b: u8| b.is_ascii_alphanumeric() || matches!(b, b'*' | b'-' | b'.' | b'_');
    let encoded_len = |s: &str| s.bytes().map(|b| if kept(b) || b == b' ' { 1 } else { 3 }).sum::<usize>();
    let total = fields.iter().map(|(k, v)| encoded_len(k) + 1 + encoded_len(v)).sum::<usize>() + fields.len().saturating_sub(1);
    let mut out = zeroize::Zeroizing::new(Vec::with_capacity(total));
    let push = |out: &mut Vec<u8>, s: &str| {
        for b in s.bytes() {
            if kept(b) {
                out.push(b);
            } else if b == b' ' {
                out.push(b'+');
            } else {
                out.extend_from_slice(&[b'%', HEX[usize::from(b >> 4)], HEX[usize::from(b & 15)]]);
            }
        }
    };
    for (i, (name, value)) in fields.iter().enumerate() {
        if i > 0 {
            out.push(b'&');
        }
        push(&mut out, name);
        out.push(b'=');
        push(&mut out, value);
    }
    out
}

/// The text of an [`HttpClient`] failure for an error a caller returns or logs: the whole cause chain,
/// with every URL in it reduced by [`crate::egress::scrub_url`].
///
/// [`ReqwestClient`] already strips the URL reqwest attaches, so this is the second layer: whatever an
/// implementation or a nested cause puts in its text, the query, fragment and userinfo where a
/// credential can sit never leave through here.
pub fn transport_error_text(err: &anyhow::Error) -> String {
    crate::egress::scrub_urls(&format!("{err:#}"))
}

#[async_trait]
impl HttpClient for ReqwestClient {
    async fn send(&self, request: HttpRequest) -> anyhow::Result<HttpResponse> {
        let resp = self.dispatch(request).await?;
        let status = resp.status().as_u16();
        let headers = diagnostic_headers(resp.headers());
        let buf = read_capped_bytes(resp, self.max_response_bytes).await?;
        // A body that is empty or is not JSON becomes `Null` rather than an error, as `json()` made it: plenty of upstreams answer 204 or `text/plain` on success.
        let (body, text, memory) = self.parse_body(&buf)?;
        let text = if (200..300).contains(&status) { None } else { text };
        Ok(HttpResponse { status, body, headers, text, memory })
    }

    async fn send_raw(&self, request: HttpRequest) -> anyhow::Result<RawHttpResponse> {
        let resp = self.dispatch(request).await?;
        let status = resp.status().as_u16();
        let headers = diagnostic_headers(resp.headers());
        let body = read_capped_bytes(resp, self.max_response_bytes).await?;
        Ok(RawHttpResponse { status, body, headers })
    }

    async fn send_secret(&self, request: HttpRequest) -> anyhow::Result<SecretHttpResponse> {
        let mut resp = self.dispatch(request).await?;
        let status = resp.status().as_u16();
        let cap = self.max_response_bytes;
        if resp.content_length().is_some_and(|declared| declared > cap) {
            anyhow::bail!("upstream response declared more than the {cap}-byte response cap");
        }
        let mut buf = permaura_core::WipingBuffer::with_capacity(resp.content_length().unwrap_or(4096).min(cap) as usize);
        while let Some(chunk) = resp.chunk().await.map_err(reqwest::Error::without_url)? {
            if buf.as_slice().len() as u64 + chunk.len() as u64 > cap {
                anyhow::bail!("upstream response exceeded the {cap}-byte response cap");
            }
            buf.extend_from_slice(&chunk);
        }
        Ok(SecretHttpResponse { status, body: buf.into_inner() })
    }

    async fn fetch_text(&self, request: HttpRequest) -> anyhow::Result<HttpResponse> {
        let resp = self.dispatch(request).await?;
        let status = resp.status().as_u16();
        let headers = diagnostic_headers(resp.headers());
        let buf = read_capped_bytes(resp, self.max_response_bytes).await?;
        // Every caller reads the text; a tree of the document here would be built and thrown away.
        let text = Some(String::from_utf8_lossy(&buf).into_owned());
        Ok(HttpResponse { status, body: serde_json::Value::Null, headers, text, memory: MemoryCharge::none() })
    }
}

/// Read an upstream response body with a running byte cap, and fail rather than truncate.
///
/// `Response::json()` buffers the whole body before it deserializes, so a capability whose upstream
/// answers with a very large document could end a 512 MiB worker on one call. Streaming with a cap
/// bounds that, and the refusal is an error rather than a short body because a truncated document
/// returned as if it were complete is a correctness failure the agent cannot detect: it would parse,
/// it would look plausible, and it would be missing records.
///
/// The error text carries sizes only. Nothing from the body reaches it, so it needs no redaction and
/// cannot leak the very secret material the response was fetched with.
async fn read_capped_bytes(mut resp: reqwest::Response, cap: u64) -> anyhow::Result<Vec<u8>> {
    // A declared length over the cap is refused before a single byte is read. An upstream that lies
    // about (or omits) its length is still caught by the running total below.
    if let Some(declared) = resp.content_length() {
        if declared > cap {
            anyhow::bail!(
                "upstream response declared {declared} bytes, over the {cap}-byte response cap"
            );
        }
    }
    // Sized once when the length is declared, so a body near the cap is not held twice while it grows.
    let mut buf: Vec<u8> = Vec::with_capacity(resp.content_length().unwrap_or(0).min(cap) as usize);
    while let Some(chunk) = resp.chunk().await.map_err(reqwest::Error::without_url)? {
        if buf.len() as u64 + chunk.len() as u64 > cap {
            anyhow::bail!("upstream response exceeded the {cap}-byte response cap");
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// A deterministic test/offline double. It records every request and replays queued responses in FIFO order; with no queued responses it returns a deterministic `200` echo of the request method + host so the runtime works end-to-end without a network.
#[derive(Clone, Default)]
pub struct MockHttpClient {
    requests: Arc<Mutex<Vec<HttpRequest>>>,
    responses: Arc<Mutex<Vec<HttpResponse>>>,
}

impl MockHttpClient {
    /// A mock that returns a deterministic synthetic response for every call.
    pub fn new() -> Self {
        MockHttpClient::default()
    }

    /// A mock pre-loaded with a single response.
    pub fn with_response(response: HttpResponse) -> Self {
        let m = MockHttpClient::default();
        m.responses.lock().unwrap().push(response);
        m
    }

    /// Queue another response (FIFO).
    pub fn push_response(&self, response: HttpResponse) {
        self.responses.lock().unwrap().push(response);
    }

    /// The requests captured so far, in order.
    pub fn requests(&self) -> Vec<HttpRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// The most recently captured request, if any.
    pub fn last_request(&self) -> Option<HttpRequest> {
        self.requests.lock().unwrap().last().cloned()
    }
}

#[async_trait]
impl HttpClient for MockHttpClient {
    async fn send(&self, request: HttpRequest) -> anyhow::Result<HttpResponse> {
        let synthetic = HttpResponse::json(
            200,
            serde_json::json!({
                "ok": true,
                "mocked": true,
                "method": request.method.as_str(),
                "host": request.host(),
            }),
        );
        self.requests.lock().unwrap().push(request);
        let mut responses = self.responses.lock().unwrap();
        if responses.is_empty() {
            Ok(synthetic)
        } else {
            Ok(responses.remove(0))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_parsing() {
        assert_eq!(
            HttpRequest::get("https://api.github.com/repos/x/y")
                .host()
                .as_deref(),
            Some("api.github.com")
        );
        assert_eq!(
            HttpRequest::get("https://user:pass@api.example.com:8443/path?q=1")
                .host()
                .as_deref(),
            Some("api.example.com")
        );
        assert_eq!(HttpRequest::get("not-a-url").host(), None);
        assert_eq!(HttpRequest::get("https://attacker.example\\@api.allowed.com/").host(), None);
    }

    /// A credentialed request is sent through the pinned client, so a hop to another host is refused
    /// before anything is sent there, while an uncredentialed one is not held to its host.
    #[tokio::test]
    async fn a_credentialed_request_is_not_redirected_to_another_host() {
        let redirect = "HTTP/1.1 307 Temporary Redirect\r\nlocation: https://attacker.example/collect\r\n\
                        content-length: 0\r\nconnection: close\r\n\r\n";
        let build = |policy| {
            reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_secs(2))
                .timeout(std::time::Duration::from_secs(5))
                .no_proxy()
                .redirect(policy)
                .build()
                .unwrap()
        };
        let client = ReqwestClient {
            inner: build(screened_redirects()),
            pinned: build(pinned_redirects()),
            screened: false,
            max_response_bytes: 64 * 1024,
            memory: None,
            max_tree_bytes: DEFAULT_MAX_TREE_BYTES,
            origin_pin: None,
        };
        let url = raw_server(redirect).await;
        let request = HttpRequest::get(url).header("X-Api-Key", "sk_live_secret").credentialed();
        let err = client.send(request).await.expect_err("the cross-host hop must be refused");
        let chain = format!("{err:#}");
        assert!(chain.contains("may not follow a redirect"), "refused by the pin, not by DNS: {chain}");
        assert!(chain.contains("attacker.example"), "{chain}");

        let url = raw_server(redirect).await;
        let err = client.send(HttpRequest::get(url)).await.err().map(|e| format!("{e:#}")).unwrap_or_default();
        assert!(!err.contains("may not follow a redirect"), "an uncredentialed request is not pinned: {err}");
    }

    /// The screened client refuses a backslash authority before a socket opens, so even a
    /// request that skipped the gateway's allowlist cannot reach the host `reqwest` would have read.
    #[tokio::test]
    async fn screened_client_refuses_a_backslash_authority() {
        let client = ReqwestClient::new().unwrap();
        let err = client
            .send(HttpRequest::get("https://attacker.example\\@api.allowed.com/v1/data").header("Authorization", "Bearer tok"))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("backslash"), "{err}");
    }

    #[test]
    fn only_structured_values_are_chain_safe() {
        assert!(is_chain_safe_header("content-type", "application/json"));
        assert!(is_chain_safe_header("Retry-After", "30"));
        assert!(is_chain_safe_header("x-ratelimit-remaining", "0"));
        assert!(is_chain_safe_header("x-ratelimit-reset", "1790000000.5"));
        assert!(!is_chain_safe_header("content-type", "text/html; charset=utf-8"), "parameters are stripped before this check");
        assert!(!is_chain_safe_header("retry-after", "Wed, 21 Oct 2026 07:28:00 GMT"));
        assert!(!is_chain_safe_header("x-request-id", "abc123"), "request ids are upstream-chosen text");
        assert!(!is_chain_safe_header("www-authenticate", "Bearer error=\"invalid_token\""));
        assert!(!is_chain_safe_header("ratelimit-policy", "100;w=60"));
        assert!(!is_chain_safe_header("x-ratelimit-remaining", "sk_live_123"));
        assert!(!is_chain_safe_header("link", "<https://example.com/wp-json/>; rel=\"https://api.w.org/\""));
    }

    /// A raw one-shot HTTP/1.1 server answering every connection with `response` verbatim.
    async fn raw_server(response: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut head_in = Vec::new();
            let mut byte = [0u8; 1];
            while !head_in.ends_with(b"\r\n\r\n") && head_in.len() < 8192 {
                match sock.read(&mut byte).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => head_in.push(byte[0]),
                }
            }
            let _ = sock.write_all(response.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
        format!("http://{addr}/")
    }

    /// The real client, not a mock: headers off the allowlist never leave it, and an error page's
    /// text is kept for the operator while the agent's body stays `Null`.
    #[tokio::test]
    async fn the_client_keeps_allowlisted_headers_and_an_error_pages_text() {
        let url = raw_server(
            "HTTP/1.1 401 Unauthorized\r\ncontent-type: text/html; charset=utf-8\r\nset-cookie: session=s3cret\r\n\
             x-request-id: req-42\r\ncontent-length: 17\r\nconnection: close\r\n\r\n<html>nope</html>",
        )
        .await;
        let resp = capped_loopback_client(64 * 1024).send(HttpRequest::get(url)).await.unwrap();
        assert_eq!(resp.status, 401);
        assert_eq!(resp.body, serde_json::Value::Null);
        assert_eq!(resp.text.as_deref(), Some("<html>nope</html>"));
        let names: Vec<&str> = resp.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"x-request-id") && names.contains(&"content-type"), "{names:?}");
        assert!(!names.contains(&"set-cookie"), "{names:?}");
        assert!(resp.headers.contains(&("content-type".into(), "text/html".into())), "parameters stripped: {:?}", resp.headers);
    }

    #[tokio::test]
    async fn a_successful_text_body_is_not_kept() {
        let url = raw_server(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\nconnection: close\r\n\r\nhello",
        )
        .await;
        let resp = capped_loopback_client(64 * 1024).send(HttpRequest::get(url)).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, serde_json::Value::Null, "unchanged for the agent");
        assert_eq!(resp.text, None, "only an error's text is kept");
    }

    #[tokio::test]
    async fn fetch_text_keeps_a_successful_documents_text() {
        let url = raw_server(
            "HTTP/1.1 200 OK\r\ncontent-type: application/yaml\r\ncontent-length: 14\r\nconnection: close\r\n\r\nopenapi: 3.0.3",
        )
        .await;
        let resp = capped_loopback_client(64 * 1024).fetch_text(HttpRequest::get(url)).await.unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.text.as_deref(), Some("openapi: 3.0.3"));
        assert_eq!(resp.body, serde_json::Value::Null, "the text is what is read");
    }

    #[tokio::test]
    async fn fetch_text_is_held_to_the_same_cap_and_screen_as_send() {
        let url = one_shot_server(200_000, false).await;
        let err = capped_loopback_client(64 * 1024)
            .fetch_text(HttpRequest::get(url))
            .await
            .expect_err("an oversize document is refused, not truncated");
        assert!(err.to_string().contains("exceeded"), "unexpected error: {err}");

        let err = ReqwestClient::new()
            .unwrap()
            .fetch_text(HttpRequest::get("http://169.254.169.254/openapi.json"))
            .await
            .expect_err("the metadata address is screened");
        assert!(err.to_string().contains("egress blocked"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn the_mock_answers_fetch_text_from_its_queue() {
        let mock = MockHttpClient::new();
        mock.push_response(HttpResponse::json(200, serde_json::json!({ "openapi": "3.1.0" })));
        mock.push_response(HttpResponse { status: 200, text: Some("openapi: 3.0.0".into()), ..HttpResponse::default() });
        let json = mock.fetch_text(HttpRequest::get("https://api.example.com/openapi.json")).await.unwrap();
        assert_eq!(json.text.as_deref(), Some(r#"{"openapi":"3.1.0"}"#));
        let yaml = mock.fetch_text(HttpRequest::get("https://api.example.com/openapi.yaml")).await.unwrap();
        assert_eq!(yaml.text.as_deref(), Some("openapi: 3.0.0"));
        assert_eq!(mock.requests().len(), 2, "every fetch is captured like a send");
    }

    #[test]
    fn only_allowlisted_headers_are_diagnostic() {
        for kept in ["Content-Type", "retry-after", "x-github-request-id", "X-RateLimit-Remaining", "ratelimit-policy", "cf-ray", "Link"] {
            assert!(is_diagnostic_header(kept), "{kept} should be kept");
        }
        for dropped in ["set-cookie", "location", "authorization", "x-api-key", "x-amz-security-token", "x-custom"] {
            assert!(!is_diagnostic_header(dropped), "{dropped} must never reach the chain");
        }
    }

    #[tokio::test]
    async fn reqwest_client_blocks_metadata_and_private_targets() {
        let client = ReqwestClient::new().unwrap();
        // Each of these is screened and rejected before any socket opens (literal IPs / bad
        // scheme never reach the network), so the test is deterministic and offline.
        for url in [
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
            "http://10.0.0.1/internal",
            "http://127.0.0.1:8080/",
            "http://[::1]/",
            "file:///etc/passwd",
        ] {
            let err = client
                .send(HttpRequest::get(url))
                .await
                .expect_err(&format!("{url} must be blocked"));
            assert!(
                err.to_string().contains("egress blocked"),
                "unexpected error for {url}: {err}"
            );
        }
    }

    #[test]
    fn the_infra_client_skips_the_screen_that_the_default_client_enforces() {
        // The connector client screens egress (blocks metadata/private targets); the infra client does
        // not, because the Cloud KMS custody path must reach metadata.google.internal to mint its
        // access token, a host the screen deliberately blocks for connector traffic.
        assert!(ReqwestClient::new().unwrap().screened, "connector client must screen egress");
        assert!(!ReqwestClient::new_infra().unwrap().screened, "infra/KMS client must not screen egress");
    }

    #[tokio::test]
    async fn mock_replays_then_synthesizes() {
        let mock = MockHttpClient::new();
        mock.push_response(HttpResponse::json(201, serde_json::json!({ "id": 1 })));
        let first = mock
            .send(HttpRequest::post("https://api.example.com/things"))
            .await
            .unwrap();
        assert_eq!(first.status, 201);
        // The next call falls through to the deterministic synthetic response.
        let second = mock
            .send(HttpRequest::get("https://api.example.com/things"))
            .await
            .unwrap();
        assert_eq!(second.status, 200);
        assert_eq!(second.body["mocked"], true);
        assert_eq!(mock.requests().len(), 2);
    }

    /// Serve one HTTP/1.1 response of `body_len` bytes on a loopback port and return its URL.
    /// `declare_length` picks which half of the cap is exercised: a `Content-Length` big enough to
    /// refuse before reading, or a read-to-EOF body that only the running total can catch.
    ///
    /// The request head is drained before anything is written back, and the socket is held open until
    /// the client closes: on Windows, closing a socket that still holds unread bytes in its receive
    /// queue is an abortive close, and the RST makes the client's stack discard the response it had
    /// already buffered, so the call fails with os error 10053 rather than returning a response. Linux
    /// and macOS hand the buffered response to the application regardless, which is why a server that
    /// never read its request passed everywhere except the Windows lane.
    async fn one_shot_server(body_len: usize, declare_length: bool) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();

            let mut head_in = Vec::new();
            let mut byte = [0u8; 1];
            while !head_in.ends_with(b"\r\n\r\n") && head_in.len() < 8192 {
                match sock.read(&mut byte).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => head_in.push(byte[0]),
                }
            }

            let head = if declare_length {
                format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {body_len}\r\n\r\n")
            } else {
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n".to_string()
            };
            let _ = sock.write_all(head.as_bytes()).await;
            // Valid JSON of the requested size: a quoted string of `body_len - 2` filler bytes.
            let mut body = Vec::with_capacity(body_len);
            body.push(b'"');
            body.resize(body_len.saturating_sub(1), b'Z');
            body.push(b'"');
            let _ = sock.write_all(&body).await;
            let _ = sock.flush().await;
            let _ = sock.shutdown().await;

            let mut sink = [0u8; 256];
            while let Ok(n) = sock.read(&mut sink).await {
                if n == 0 {
                    break;
                }
            }
        });
        format!("http://{addr}/")
    }

    /// Serves `body` once, with its length declared.
    async fn body_server(body: Vec<u8>) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut seen = Vec::new();
            let mut buf = [0u8; 4096];
            while !seen.windows(4).any(|w| w == b"\r\n\r\n") {
                match sock.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            let head = format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n", body.len());
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock.write_all(&body).await;
            let _ = sock.shutdown().await;
        });
        format!("http://{addr}/")
    }

    fn one_key_objects(size: usize) -> Vec<u8> {
        let mut body = b"[".to_vec();
        while body.len() + 9 < size {
            body.extend_from_slice(b"{\"a\":1},");
        }
        body.pop();
        body.push(b']');
        body
    }

    /// The body an agent receives is never parsed by the client; `send_raw` hands back the bytes as they arrived, under the same cap.
    #[tokio::test]
    async fn send_raw_returns_the_bytes_unparsed() {
        let body = one_key_objects(256 * 1024);
        let url = body_server(body.clone()).await;
        let raw = capped_loopback_client(1024 * 1024).send_raw(HttpRequest::get(url)).await.unwrap();
        assert_eq!(raw.status, 200);
        assert_eq!(raw.body, body);
        let url = body_server(body).await;
        let err = capped_loopback_client(64 * 1024).send_raw(HttpRequest::get(url)).await.expect_err("over the cap");
        assert!(err.to_string().contains("cap"), "{err}");
    }

    /// A document the client does parse (`send`) is built under a fixed ceiling, and one over it is an error, never a `Null` a caller would read as an empty answer; one that is not JSON is still `Null` with its text.
    /// The pool is never waited on and never refuses a body, since the request has been sent by then; a body is charged when the pool has room at once and built beside it when it has not, even behind a queued waiter.
    #[tokio::test]
    async fn send_never_refuses_a_body_for_pool_room_and_never_reads_a_refusal_as_null() {
        let small = serde_json::to_vec(&serde_json::json!({ "rows": [{ "id": 1 }, { "id": 2 }] })).unwrap();
        let pool = Arc::new(MemoryPool::new(16 * 1024 * 1024));
        let client = capped_loopback_client(1024 * 1024).with_memory(pool.clone()).with_max_tree_bytes(1024 * 1024);
        let resp = client.send(HttpRequest::get(body_server(small.clone()).await)).await.unwrap();
        assert_eq!(resp.body["rows"][1]["id"], 2);
        assert!(resp.memory.bytes() > 0, "the tree is charged while the response is held");
        assert!(pool.available_bytes() < pool.max_bytes());
        drop(resp);
        assert_eq!(pool.available_bytes(), pool.max_bytes());

        let held = pool.reserve(pool.max_bytes(), std::time::Duration::ZERO).await.unwrap();
        let resp = client.send(HttpRequest::get(body_server(small.clone()).await)).await.expect("a full pool refuses nothing");
        assert_eq!(resp.body["rows"][0]["id"], 1);
        assert_eq!(resp.memory.bytes(), 0, "built beside the pool, uncharged");
        drop((resp, held));

        // The probe's shape: 10 of 16 MiB held, a 10 MiB reservation queued behind it, and a token-sized answer read after the request went out.
        let held = pool.reserve(10 * 1024 * 1024, std::time::Duration::ZERO).await.unwrap();
        let waiter = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.reserve(10 * 1024 * 1024, std::time::Duration::from_secs(30)).await })
        };
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let token = serde_json::to_vec(&serde_json::json!({ "access_token": "at-SYNTHETIC", "refresh_token": "rt-ROTATED-SYNTHETIC" })).unwrap();
        let resp = tokio::time::timeout(std::time::Duration::from_secs(5), client.send(HttpRequest::get(body_server(token).await)))
            .await
            .expect("never waits on the queue")
            .expect("never refused behind a waiter");
        assert_eq!(resp.body["refresh_token"], "rt-ROTATED-SYNTHETIC");
        drop(held);
        assert!(waiter.await.unwrap().is_ok(), "the waiter still gets its room");

        let costly = one_key_objects(64 * 1024);
        assert!(crate::json_budget::estimate(&costly) > 1024 * 1024);
        let err = client.send(HttpRequest::get(body_server(costly).await)).await.expect_err("over the client's tree ceiling");
        assert!(err.to_string().contains("limit"), "{err}");

        let html = b"<html>not json</html>".to_vec();
        let resp = client.send(HttpRequest::get(body_server(html).await)).await.unwrap();
        assert_eq!(resp.body, serde_json::Value::Null, "not JSON reads as no document, as before");

        let unpooled = capped_loopback_client(2 * 1024 * 1024);
        let over = one_key_objects(1024 * 1024);
        assert!(crate::json_budget::estimate(&over) > DEFAULT_MAX_TREE_BYTES);
        let err = unpooled.send(HttpRequest::get(body_server(over).await)).await.expect_err("over the default ceiling");
        assert!(err.to_string().contains("limit"), "{err}");
    }

    /// Unscreened, because the connector client's egress screen blocks loopback by design, and with
    /// proxies off, because on Windows reqwest resolves a system proxy from the registry and nothing
    /// may stand between this test and its own loopback server.
    fn capped_loopback_client(cap: u64) -> ReqwestClient {
        let inner = reqwest::Client::builder()
            .user_agent("permaura/0.1")
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .no_proxy()
            .build()
            .unwrap();
        ReqwestClient { pinned: inner.clone(), inner, screened: false, max_response_bytes: cap, memory: None, max_tree_bytes: DEFAULT_MAX_TREE_BYTES, origin_pin: None }
    }

    #[tokio::test]
    async fn a_redirect_to_a_private_ip_literal_is_refused_before_it_connects() {
        let url = raw_server(
            "HTTP/1.1 302 Found\r\nlocation: http://169.254.169.254/latest/meta-data/\r\ncontent-length: 0\r\n\
             connection: close\r\n\r\n",
        )
        .await;
        // Unscreened for the first hop only, so the loopback test server is reachable; the redirect
        // policy under test is the one `ReqwestClient::new` installs.
        let inner = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(2))
            .timeout(std::time::Duration::from_secs(5))
            .no_proxy()
            .redirect(screened_redirects())
            .build()
            .unwrap();
        let client = ReqwestClient { pinned: inner.clone(), inner, screened: false, max_response_bytes: 64 * 1024, memory: None, max_tree_bytes: DEFAULT_MAX_TREE_BYTES, origin_pin: None };
        let err = client.send(HttpRequest::get(url)).await.expect_err("the metadata hop must be refused");
        let chain = format!("{err:#}");
        assert!(chain.contains("egress blocked"), "refused by the screen, not by a timeout: {chain}");
    }

    #[test]
    fn the_redirect_screen_admits_public_hosts_and_refuses_private_ones() {
        let policy_follows = |target: &str| crate::egress::screen_url(target).is_ok();
        assert!(policy_follows("https://example.com/wp-json/"));
        assert!(!policy_follows("http://10.0.0.5/"));
        assert!(!policy_follows("http://[::ffff:169.254.169.254]/"));
        assert!(!policy_follows("http://metadata.google.internal/"));
    }

    #[tokio::test]
    async fn an_oversize_declared_response_is_refused_before_it_is_read() {
        let url = one_shot_server(200_000, true).await;
        let err = capped_loopback_client(64 * 1024)
            .send(HttpRequest::get(url))
            .await
            .expect_err("a declared length over the cap is refused");
        let text = err.to_string();
        assert!(text.contains("declared"), "unexpected error: {text}");
        assert!(text.contains("response cap"), "unexpected error: {text}");
    }

    /// An upstream that declares no length is the case the `Content-Length` precheck cannot see, and
    /// is exactly how a hostile or misconfigured upstream would stream a worker to death.
    #[tokio::test]
    async fn an_undeclared_oversize_response_is_caught_by_the_running_total() {
        let url = one_shot_server(200_000, false).await;
        let err = capped_loopback_client(64 * 1024)
            .send(HttpRequest::get(url))
            .await
            .expect_err("an undeclared body over the cap is refused");
        let text = err.to_string();
        assert!(text.contains("exceeded"), "unexpected error: {text}");
        // Sizes only: nothing from the body, which may hold whatever the injected secret fetched.
        assert!(!text.contains("ZZ"), "body content leaked into the error: {text}");
    }

    #[tokio::test]
    async fn a_response_under_the_cap_is_returned_whole() {
        let url = one_shot_server(4_096, true).await;
        let resp = capped_loopback_client(64 * 1024)
            .send(HttpRequest::get(url))
            .await
            .expect("a small response succeeds");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body.as_str().map(|s| s.len()), Some(4_094));
    }

    /// Answer one request with `200 {}` and hand back its head, lowercased, plus whatever body its own
    /// `content-length` declared. The socket is held open until the client closes, as in [`one_shot_server`].
    async fn recording_server() -> (String, tokio::sync::oneshot::Receiver<(String, Vec<u8>)>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut head_in = Vec::new();
            let mut byte = [0u8; 1];
            while !head_in.ends_with(b"\r\n\r\n") && head_in.len() < 8192 {
                match sock.read(&mut byte).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => head_in.push(byte[0]),
                }
            }
            let head = String::from_utf8_lossy(&head_in).to_ascii_lowercase();
            let declared = declared_length(&head).and_then(|v| v.parse().ok());
            let mut body = vec![0u8; declared.unwrap_or(0)];
            if sock.read_exact(&mut body).await.is_err() {
                return;
            }
            let _ = tx.send((head, body));
            let reply =
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}";
            let _ = sock.write_all(reply.as_bytes()).await;
            let _ = sock.flush().await;
            let mut sink = [0u8; 256];
            while let Ok(n) = sock.read(&mut sink).await {
                if n == 0 {
                    break;
                }
            }
        });
        (format!("http://{addr}/users/me/messages/abc/trash"), rx)
    }

    fn declared_length(head: &str) -> Option<&str> {
        head.lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .map(str::trim)
    }

    /// The form is sent exactly as reqwest's own `form` would have written it, so moving the encoding here
    /// changed no token endpoint's request.
    #[test]
    fn a_form_encodes_byte_for_byte_as_reqwest_does() {
        let mut form = BTreeMap::new();
        form.insert("grant_type".to_string(), "refresh_token".to_string());
        form.insert("refresh_token".to_string(), "a+b/c=d&e%f~g*h-i.j_k l\u{e9}\u{2603}\"'<>".to_string());
        form.insert("client secret".to_string(), "".to_string());
        form.insert("scope".to_string(), "read write".to_string());
        let theirs = reqwest::Client::new().post("http://127.0.0.1/").form(&form).build().unwrap();
        let theirs = theirs.body().unwrap().as_bytes().unwrap().to_vec();
        assert_eq!(String::from_utf8(encode_form(&form).to_vec()).unwrap(), String::from_utf8(theirs).unwrap());
        assert!(encode_form(&BTreeMap::new()).is_empty());
    }

    async fn sent_head(request: HttpRequest) -> (String, Vec<u8>) {
        let (url, sent) = recording_server().await;
        let mut request = request;
        request.url = url;
        let resp = capped_loopback_client(64 * 1024)
            .send(request)
            .await
            .expect("the loopback server answers");
        assert_eq!(resp.status, 200);
        sent.await.expect("the server recorded the request")
    }

    /// On the wire, a generic-proxy request reaches its upstream with the URL's host, the one the
    /// allowlist judged, and exactly one credential, the vault's. Before the builder refused them, an
    /// agent's `Host` replaced the virtual host and an `authorization` in another case travelled beside
    /// the injected `Authorization`.
    #[tokio::test]
    async fn the_generic_proxy_sends_the_url_host_and_one_credential() {
        use crate::connector::{build_request_for, Capability, CapabilityKind};
        let cap = Capability {
            id: "http.request".into(),
            description: "proxy".into(),
            risk: permaura_core::RiskTier::High,
            action: permaura_core::Action::Execute,
            requires_approval: false,
            resource: "generic_http".into(),
            secret_id: "sec".into(),
            kind: CapabilityKind::Http,
            command: None,
            http: None,
            ssh: None,
        };
        let (url, sent) = recording_server().await;
        let parsed = reqwest::Url::parse(&url).unwrap();
        let authority = format!("{}:{}", parsed.host_str().unwrap(), parsed.port().unwrap());
        let spoofed = serde_json::json!({
            "url": url, "headers": { "Host": "internal.example", "authorization": "Bearer attacker", "Accept": "*/*" }
        });
        // A refusal is the repaired builder; a request is the builder of record, sent so the recorded
        // head shows what travelled.
        let request = match build_request_for("generic-http", &cap, &spoofed, b"vault") {
            Err(refusal) => {
                assert_eq!(refusal.code, "agent_header", "{}", refusal.reason);
                let plain = serde_json::json!({ "url": url, "headers": { "Accept": "*/*" } });
                build_request_for("generic-http", &cap, &plain, b"vault").unwrap()
            }
            Ok(request) => request,
        };
        let resp = capped_loopback_client(64 * 1024).send(request).await.expect("the loopback server answers");
        assert_eq!(resp.status, 200);
        let (head, _) = sent.await.expect("the server recorded the request");
        let hosts: Vec<&str> = head.lines().filter_map(|l| l.strip_prefix("host:")).map(str::trim).collect();
        assert_eq!(hosts, vec![authority.as_str()], "the wire carries the URL host only:\n{head}");
        let credentials: Vec<&str> =
            head.lines().filter_map(|l| l.strip_prefix("authorization:")).map(str::trim).collect();
        assert_eq!(credentials, vec!["bearer vault"], "one credential, the vault's:\n{head}");
    }

    /// On the wire, URL userinfo is refused by the builder, and a request that carries some
    /// anyway leaves the client with one credential, the vault's. reqwest turns userinfo into an
    /// `Authorization: Basic` sent ahead of the injected Bearer, and an upstream that reads the first
    /// header would run the call as whoever the agent named.
    #[tokio::test]
    async fn url_userinfo_never_travels_as_a_second_credential() {
        use crate::connector::{build_request_for, request_refusal, Capability, CapabilityKind};
        let cap = Capability {
            id: "http.request".into(),
            description: "proxy".into(),
            risk: permaura_core::RiskTier::High,
            action: permaura_core::Action::Execute,
            requires_approval: false,
            resource: "generic_http".into(),
            secret_id: "sec".into(),
            kind: CapabilityKind::Http,
            command: None,
            http: None,
            ssh: None,
        };
        let (url, sent) = recording_server().await;
        let authority = url.trim_start_matches("http://").split('/').next().unwrap().to_string();
        for userinfo in ["agent:pw@", "agent@", ":pw@", "agent%40x:p%3Aw@"] {
            let with_userinfo = url.replacen("http://", &format!("http://{userinfo}"), 1);
            let params = serde_json::json!({ "url": with_userinfo });
            let refusal = build_request_for("generic-http", &cap, &params, b"vault").expect_err(userinfo);
            assert_eq!(refusal.code, "userinfo", "{userinfo}: {}", refusal.reason);
            assert!(!refusal.reason.contains("pw"), "the refusal does not repeat the password: {}", refusal.reason);
            assert_eq!(request_refusal("generic-http", &cap, &params).map(|r| r.code), Some("userinfo"), "{userinfo}");
        }

        let request = HttpRequest::get(url.replacen("http://", "http://agent:pw@", 1))
            .header("Authorization", "Bearer vault")
            .credentialed();
        let resp = capped_loopback_client(64 * 1024).send(request).await.expect("the loopback server answers");
        assert_eq!(resp.status, 200);
        let (head, _) = sent.await.expect("the server recorded the request");
        let credentials: Vec<&str> =
            head.lines().filter_map(|l| l.strip_prefix("authorization:")).map(str::trim).collect();
        assert_eq!(credentials, vec!["bearer vault"], "one credential, the vault's:\n{head}");
        assert!(head.lines().any(|l| l.trim() == format!("host: {authority}")), "{head}");
    }

    /// The production client is the last line: a request carrying a credential never leaves it over
    /// plain http, whatever built the request, and it is refused before a socket is opened.
    #[tokio::test]
    async fn a_credentialed_request_over_plain_http_never_leaves_the_client() {
        let request = HttpRequest::get("http://api.probe.invalid/v1/me").header("Authorization", "Bearer tok").credentialed();
        let err = ReqwestClient::new().unwrap().send(request).await.expect_err("plain http with a credential is refused");
        let chain = format!("{err:#}");
        assert!(chain.contains("https only"), "refused by the scheme rule, not by the network: {chain}");
        assert!(!chain.contains("tok"), "the credential never appears in the error: {chain}");
    }

    /// Google's front end answers a POST that declares no length with `411 Length Required` before it
    /// looks at the token, which is how an approved `gmail.messages.trash` (path params only) failed.
    #[tokio::test]
    async fn a_bodyless_post_put_or_patch_declares_a_zero_length() {
        for method in [HttpMethod::Post, HttpMethod::Put, HttpMethod::Patch] {
            let (head, body) =
                sent_head(HttpRequest::new(method, "").header("Authorization", "Bearer tok")).await;
            assert!(
                head.starts_with(&format!("{} ", method.as_str().to_ascii_lowercase())),
                "{head}"
            );
            assert_eq!(declared_length(&head), Some("0"), "{head}");
            assert_eq!(head.matches("content-length:").count(), 1, "{head}");
            assert!(!head.contains("transfer-encoding:"), "{head}");
            assert!(body.is_empty());
        }
    }

    #[tokio::test]
    async fn a_bodyless_get_or_delete_still_declares_no_length() {
        for method in [HttpMethod::Get, HttpMethod::Delete] {
            let (head, _) = sent_head(HttpRequest::new(method, "")).await;
            assert!(
                head.starts_with(&format!("{} ", method.as_str().to_ascii_lowercase())),
                "{head}"
            );
            assert_eq!(declared_length(&head), None, "{head}");
            assert!(!head.contains("transfer-encoding:"), "{head}");
        }
    }

    /// The zero is only for a request with nothing to send: a JSON or form body keeps its real length,
    /// and a `Content-Length` already in the request's headers is replaced, never sent twice.
    #[tokio::test]
    async fn a_post_with_a_body_keeps_its_real_length() {
        let (head, body) =
            sent_head(HttpRequest::post("").json_body(serde_json::json!({ "a": 1 }))).await;
        assert_eq!(declared_length(&head), Some("7"), "{head}");
        assert_eq!(body, br#"{"a":1}"#);

        let form = BTreeMap::from([("grant_type".to_string(), "refresh_token".to_string())]);
        let (head, body) = sent_head(HttpRequest::post("").form_body(form)).await;
        assert_eq!(declared_length(&head), Some("24"), "{head}");
        assert_eq!(body, b"grant_type=refresh_token");

        let (head, _) = sent_head(HttpRequest::post("").header("Content-Length", "5")).await;
        assert_eq!(head.matches("content-length:").count(), 1, "{head}");
        assert_eq!(declared_length(&head), Some("0"), "{head}");

        // A body the builders wrote as text goes as written, typed JSON unless the request says otherwise.
        let mut written = HttpRequest::post("");
        written.json_encoded = Some(r#"{"a":1e15}"#.to_string());
        let (head, body) = sent_head(written).await;
        assert!(head.contains("content-type: application/json\r\n"), "{head}");
        assert_eq!(declared_length(&head), Some("10"), "{head}");
        assert_eq!(body, br#"{"a":1e15}"#);
        let mut typed = HttpRequest::post("").header("Content-Type", "application/vnd.api+json");
        typed.json_encoded = Some("[]".to_string());
        let (head, _) = sent_head(typed).await;
        assert_eq!(head.matches("content-type:").count(), 1, "{head}");
        assert!(head.contains("content-type: application/vnd.api+json\r\n"), "{head}");
    }

    /// Stripe's v1 API reads only `application/x-www-form-urlencoded` bodies, so a JSON refund reaches
    /// it with no parameters at all. A form-style capability sends the bracket syntax Stripe documents.
    #[tokio::test]
    async fn a_form_style_capability_sends_a_urlencoded_body_with_nested_values_in_brackets() {
        use crate::connector::{build_request, AuthScheme, BodyStyle, Capability, CapabilityKind, HttpSpec};
        let refund = Capability {
            id: "stripe.refunds.create".into(),
            description: "Refund a charge".into(),
            risk: permaura_core::RiskTier::Critical,
            action: permaura_core::Action::Refund,
            requires_approval: true,
            resource: "stripe".into(),
            secret_id: "sec_stripe".into(),
            kind: CapabilityKind::Http,
            command: None,
            http: Some(HttpSpec {
                method: HttpMethod::Post,
                base_url: "https://api.stripe.com/v1".into(),
                path: "/refunds".into(),
                body_params: vec!["charge".into(), "amount".into(), "reason".into(), "metadata".into()],
                auth: AuthScheme::Basic { key_as_username: true },
                static_headers: BTreeMap::from([("Stripe-Version".to_string(), "2024-06-20".to_string())]),
                body_style: BodyStyle::Form,
                ..Default::default()
            }),
            ssh: None,
        };
        let params = serde_json::json!({
            "charge": "ch_123",
            "amount": 1000,
            "reason": "requested_by_customer",
            "metadata": { "order": "1042", "note": "gift & wrap+1" },
            "undeclared": "never sent",
        });
        let (head, body) = sent_head(build_request(&refund, &params, b"sk_test_x").unwrap()).await;
        let expected: &[u8] = b"charge=ch_123&amount=1000&reason=requested_by_customer\
            &metadata[note]=gift%20%26%20wrap%2B1&metadata[order]=1042";
        assert_eq!(String::from_utf8_lossy(&body), String::from_utf8_lossy(expected));
        assert_eq!(head.matches("content-type:").count(), 1, "{head}");
        assert!(head.contains("content-type: application/x-www-form-urlencoded\r\n"), "{head}");
        assert_eq!(declared_length(&head), Some(expected.len().to_string().as_str()), "{head}");
        assert!(head.contains("stripe-version: 2024-06-20\r\n"), "{head}");

        let mut bare = HttpRequest::post("");
        bare.form_encoded = Some("a[b]=1".into());
        let (head, body) = sent_head(bare).await;
        assert!(head.contains("content-type: application/x-www-form-urlencoded\r\n"), "{head}");
        assert_eq!(body, b"a[b]=1");
    }
}
