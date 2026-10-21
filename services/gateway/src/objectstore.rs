//! A minimal object-storage seam: enough of Cloud Storage's JSON API to keep a single object
//! durable with generation preconditions, and nothing more.
//!
//! It exists for the hosted worker's [`PersistedSqliteStore`](crate::store::persisted), which keeps
//! its SQLite database in the instance's memory and its durable copy in a per-tenant bucket. The
//! generation number is the concurrency control: a conditional upload is how a worker discovers that
//! another instance owns the store, without a lock service or a second database.
//!
//! The trait is synchronous because [`Store`](crate::store::Store) is; implementations bridge to
//! async through [`crate::store::bridge`].

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::backend::GcpTokenSource;
use crate::error::GatewayError;
use crate::store::bridge::block_on;

/// What a conditional upload did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutOutcome {
    /// The upload won; the object is now at this generation.
    Stored(u64),
    /// The precondition failed: someone else wrote a newer generation.
    Conflict,
    /// Whether it was applied is not known here: the request went out and no response came back, or
    /// an attempt was answered (a 429 or a 5xx, which a server can return for a write it committed)
    /// and the same upload was sent again, so a 412 or a last error may follow this upload's own
    /// landing.
    ///
    /// Its own outcome rather than an error, because the two need opposite handling and telling them
    /// apart by reading a message is how this went wrong in the first place. An error means the
    /// write definitely did not land; this means it may have, and the caller has to find out before
    /// it says anything to anyone. The upload is never retried on this path: resending the same
    /// `ifGenerationMatch` after a write that did land comes back 412 and convinces the rightful
    /// owner it is stale.
    Uncertain,
}

/// An object's metadata, as the checkpoint job and the reconciler need it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ObjectHead {
    /// The live generation.
    pub generation: u64,
    /// The custom metadata the writer stamped. Empty means nothing was stamped, which a reader must
    /// treat as unknown and never as a default.
    pub metadata: BTreeMap<String, String>,
    /// Size of the stored bytes.
    pub size: u64,
    /// The store's own checksum of the bytes, where it computes one. Empty when it does not.
    pub crc32c: String,
}

/// Read and conditionally write single objects in a bucket.
pub trait ObjectStore: Send + Sync {
    /// The object's current generation, or `None` when it does not exist. An error means the store
    /// could not be reached, which callers must never treat as "empty".
    fn head(&self, name: &str) -> Result<Option<u64>, GatewayError>;

    /// The generation plus the stamped metadata, size and checksum.
    ///
    /// The expensive-to-be-wrong path: it is what decides whether an object this instance did not
    /// see acknowledged is its own write or another instance's, and that decision is the difference
    /// between carrying on and exiting. [`head`](Self::head) stays the cheap one for the fresh-read
    /// confirmation, which only needs to compare a number. Like `has_history`, no default
    /// implementation, so a store that cannot answer is a compile error rather than a silent guess.
    fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError>;

    /// Whether any version of `name` exists, live or noncurrent.
    ///
    /// It is how a store that was deleted is told apart from one that was never written: both answer
    /// `None` to [`head`](Self::head), and only one of them may be started fresh. An error means the
    /// store could not be reached and, like `head`, must never be read as "no history". Deliberately
    /// without a default implementation, so a store that cannot answer this is a compile error
    /// rather than a silent "no".
    fn has_history(&self, name: &str) -> Result<bool, GatewayError>;

    /// Fetch exactly the bytes of `generation`, so metadata read earlier and bytes read now cannot
    /// disagree.
    fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError>;

    /// Replace `name` only if its current generation is `expected` (0 meaning "must not exist"),
    /// stamping `metadata` on the new version.
    ///
    /// The metadata travels with the bytes and describes exactly them, which is what lets a reader
    /// that may not open the database say what is inside it. It is part of the durability contract
    /// rather than a convenience: if the metadata and the bytes can disagree, everything read from
    /// it downstream is worthless.
    fn put_if_generation(
        &self,
        name: &str,
        bytes: &[u8],
        expected: u64,
        metadata: &BTreeMap<String, String>,
    ) -> Result<PutOutcome, GatewayError>;

    /// Where this store writes, for log lines and error messages.
    fn describe(&self) -> String;
}

/// How many times a transient failure (429, 5xx, a dropped connection) is retried, and the waits
/// between attempts. Three retries at these delays keep a Cloud Storage blip well inside the
/// startup probe's budget while staying short enough that a mutation does not appear to hang.
const RETRY_BACKOFF_MS: [u64; 3] = [100, 400, 1600];

/// The least time one snapshot upload attempt is given before it counts as unanswered. A 3 MB
/// snapshot normally lands in 0.1 to 0.3 s, and every write waits on its upload.
pub(crate) const PUT_ATTEMPT_FLOOR: Duration = Duration::from_millis(2500);

/// The slowest rate an upload attempt may run at before it counts as unanswered, so a large store is
/// given time in proportion to its size rather than cut off mid-transfer.
const PUT_ATTEMPT_BYTES_PER_SEC: u64 = 8 * 1024 * 1024;

/// The bound on one metadata request: a few hundred bytes of JSON that normally answer in tens of
/// milliseconds.
const METADATA_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a connection may sit idle in the pool and still be reused. Short, because reuse only
/// pays inside a burst, and a connection that sat out a pause may have been dropped on the path
/// without this process noticing.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// The line every unanswered upload logs. The hosted stall alert counts it, so it is a wire format.
pub(crate) const UNANSWERED_UPLOAD_MESSAGE: &str = "the store upload produced no response, so whether it landed is not known here; resolving it against the object's own metadata rather than resending";

/// The metadata key a store snapshot stamps with a fresh 128-bit id per upload. Only an upload that
/// carries one can prove an object is its own by reading it back: without it, metadata and size are
/// facts another writer's object can share.
pub(crate) const UPLOAD_ID_KEY: &str = "pm-upload-id";

/// Logged when an upload attempt was answered with an error and sent again, and the outcome that came back cannot rule out the earlier attempt having landed.
const RESENT_UPLOAD_MESSAGE: &str = "the store upload was answered with an error and sent again, and an answered error does not prove the earlier attempt was not applied; resolving it against the object's own metadata";

/// How long one upload attempt of `bytes` may take before it is abandoned as unanswered.
pub(crate) fn put_attempt_timeout(bytes: usize) -> Duration {
    PUT_ATTEMPT_FLOOR + Duration::from_millis((bytes as u64).saturating_mul(1000) / PUT_ATTEMPT_BYTES_PER_SEC)
}

/// How one kind of request is bounded and retried.
#[derive(Clone, Copy)]
struct Attempts {
    /// The bound on each attempt, or `None` for the client's own (a restore download can be large).
    timeout: Option<Duration>,
    /// How many times a request that produced no response is sent again. Answered failures (429,
    /// 5xx) are retried on [`RETRY_BACKOFF_MS`] whatever this says.
    transport_retries: usize,
}

impl Attempts {
    const METADATA: Attempts = Attempts { timeout: Some(METADATA_ATTEMPT_TIMEOUT), transport_retries: 3 };
    /// The read that resolves an unanswered upload, on a write's own path: one fresh attempt after a
    /// lost answer, because the carrier comes back every 2 s and a write should not wait out four.
    const RESOLVING: Attempts = Attempts { timeout: Some(METADATA_ATTEMPT_TIMEOUT), transport_retries: 1 };
    const DOWNLOAD: Attempts = Attempts { timeout: None, transport_retries: 3 };
}

/// A transport error with the causes `reqwest` keeps behind its own message, which on its own says
/// only "error sending request for url (...)" and so cannot tell a timeout from a reset.
fn transport_detail(e: &reqwest::Error) -> String {
    let mut out = e.to_string();
    let mut source = std::error::Error::source(e);
    while let Some(cause) = source {
        out.push_str(": ");
        out.push_str(&cause.to_string());
        source = cause.source();
    }
    out
}

fn retryable(status: u16) -> bool {
    status == 429 || (500..600).contains(&status)
}

/// Why a request produced no usable response, and with it whether the request may have taken effect
/// anyway. Only the upload cares, and for it the distinction is the whole of section D: a request
/// that produced no answer at all may have been applied. An answer is not proof either way when it is
/// a 429 or a 5xx, so the upload also asks whether an answered attempt was sent again
/// ([`GcsObjectStore::send_noting_resends`]).
enum SendFailure {
    /// Nothing came back.
    Transport(GatewayError),
    /// The last attempt was answered, or the token could not be minted.
    Answered(GatewayError),
}

impl SendFailure {
    fn into_error(self) -> GatewayError {
        match self {
            SendFailure::Transport(e) | SendFailure::Answered(e) => e,
        }
    }
}

// ── Cloud Storage ────────────────────────────────────────────────────────────

/// Google Cloud Storage over the JSON API, authenticated by the workload's metadata-server token.
///
/// Its own `reqwest` client rather than the shared [`HttpClient`](crate::connectors::HttpClient):
/// that trait carries a parsed JSON body, and both halves of this API are opaque bytes. The client
/// is built unscreened for the same reason the KMS one is, and the only host it ever reaches is
/// `storage.googleapis.com`; the bucket name comes from provisioning and is percent-encoded into a
/// path segment, never into the host.
pub struct GcsObjectStore {
    /// Replaced whole after any request that produced no response, so the request after it can only
    /// go out on a connection opened after the failure.
    http: Mutex<reqwest::Client>,
    token: Arc<GcpTokenSource>,
    bucket: String,
    endpoint: String,
}

const GCS_ENDPOINT: &str = "https://storage.googleapis.com";

impl GcsObjectStore {
    /// Build a client for `bucket`, minting tokens through the process's shared source.
    pub(crate) fn new(bucket: impl Into<String>, token: Arc<GcpTokenSource>) -> Result<Self, GatewayError> {
        Ok(GcsObjectStore {
            http: Mutex::new(Self::client()?),
            token,
            bucket: bucket.into(),
            endpoint: GCS_ENDPOINT.to_string(),
        })
    }

    /// The same client against a stand-in for Cloud Storage, so a test can make it hang.
    #[cfg(test)]
    pub(crate) fn at_endpoint(
        endpoint: &str,
        bucket: impl Into<String>,
        token: Arc<GcpTokenSource>,
    ) -> Result<Self, GatewayError> {
        let mut store = Self::new(bucket, token)?;
        store.endpoint = endpoint.trim_end_matches('/').to_string();
        Ok(store)
    }

    fn client() -> Result<reqwest::Client, GatewayError> {
        reqwest::Client::builder()
            .user_agent("permaura/0.1")
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .pool_idle_timeout(POOL_IDLE_TIMEOUT)
            // One idle connection at most: a request sent before the previous one's connection is
            // back in the pool would otherwise be handed an older one that has sat idle far longer.
            .pool_max_idle_per_host(1)
            .build()
            .map_err(|e| GatewayError::Internal(format!("object store http client: {e}")))
    }

    fn http(&self) -> reqwest::Client {
        self.http.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Drop every pooled connection, so the next request opens a new one rather than riding a
    /// connection that may be the reason the last one went unanswered.
    fn discard_connections(&self) {
        match Self::client() {
            Ok(fresh) => *self.http.lock().unwrap_or_else(|p| p.into_inner()) = fresh,
            Err(e) => tracing::warn!(error = %e, "could not rebuild the object store client; keeping the current one"),
        }
    }

    /// Percent-encode a bucket or object name for a URL path segment. Object names may contain `/`,
    /// which has to be escaped or the API reads the rest as a different resource.
    fn seg(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
                _ => out.push_str(&format!("%{b:02X}")),
            }
        }
        out
    }

    /// Report a failed request once, here, where the operation, the object, the generation and the
    /// status are all known together, and hand back the error the caller returns.
    ///
    /// It is the only place that can: above this layer an object-store failure is either turned into
    /// a message and returned to a client, or tolerated deliberately, so a whole storage outage used
    /// to reach the operator as nothing but the status column on the request rows.
    fn fail(
        &self,
        op: &str,
        name: &str,
        generation: Option<u64>,
        status: Option<u16>,
        message: String,
    ) -> GatewayError {
        tracing::error!(
            op,
            bucket = %self.bucket,
            object = %name,
            generation,
            status,
            error = %message,
            "an object store request failed"
        );
        GatewayError::Internal(message)
    }

    /// Send `build()`'s request, retrying a transient status up to [`RETRY_BACKOFF_MS`] times.
    /// Returns the last response so the caller can branch on 404 or 412 itself.
    ///
    /// `attempts.transport_retries` says how often a request that never produced a response may be
    /// sent again. It is zero for the conditional upload, where a lost response is indistinguishable
    /// from a lost request: the server may already have applied the write, and resending the same
    /// `ifGenerationMatch` would then come back 412 and convince the rightful owner it is stale. The
    /// upload reports that case as [`PutOutcome::Uncertain`] and its caller resolves it against the
    /// object's own metadata before deciding anything.
    async fn send_with_retry(
        &self,
        what: &str,
        name: &str,
        attempts: Attempts,
        build: impl Fn(&reqwest::Client, &str) -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, SendFailure> {
        self.send_noting_resends(what, name, attempts, build, &mut false).await
    }

    /// [`Self::send_with_retry`], setting `resent` when an attempt the server answered was sent again.
    async fn send_noting_resends(
        &self,
        what: &str,
        name: &str,
        attempts: Attempts,
        build: impl Fn(&reqwest::Client, &str) -> reqwest::RequestBuilder,
        resent: &mut bool,
    ) -> Result<reqwest::Response, SendFailure> {
        let mut last: Option<String> = None;
        let mut refreshed = false;
        let mut unanswered = 0usize;
        for attempt in 0..=RETRY_BACKOFF_MS.len() {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_millis(RETRY_BACKOFF_MS[attempt - 1])).await;
            }
            let token = self.token.access_token().await.map_err(SendFailure::Answered)?;
            let mut request = build(&self.http(), token.expose());
            drop(token);
            if let Some(bound) = attempts.timeout {
                request = request.timeout(bound);
            }
            let started = Instant::now();
            match request.send().await {
                Ok(resp) => {
                    let status = resp.status().as_u16();
                    // One refresh, then the 401 is the answer: a standing authorization failure is an
                    // IAM binding to fix, and dressing it up as a retry exhaustion hides that.
                    if status == 401 && !refreshed {
                        refreshed = true;
                        self.token.clear();
                        last = Some("401".into());
                        *resent = true;
                        continue;
                    }
                    if retryable(status) && attempt < RETRY_BACKOFF_MS.len() {
                        last = Some(format!("{status}"));
                        *resent = true;
                        continue;
                    }
                    return Ok(resp);
                }
                Err(e) => {
                    self.discard_connections();
                    let detail = format!(
                        "{} ({} after {} ms)",
                        transport_detail(&e),
                        if e.is_timeout() { "timed out" } else { "no response" },
                        started.elapsed().as_millis()
                    );
                    unanswered += 1;
                    if unanswered > attempts.transport_retries || attempt == RETRY_BACKOFF_MS.len() {
                        let message = format!("object store {what} on gs://{}/{name}: {detail}", self.bucket);
                        return Err(SendFailure::Transport(self.fail(what, name, None, None, message)));
                    }
                    last = Some(detail);
                }
            }
        }
        let message = format!(
            "object store {what} on gs://{}/{name} failed after {} retries: {}",
            self.bucket,
            RETRY_BACKOFF_MS.len(),
            last.unwrap_or_default()
        );
        Err(SendFailure::Answered(self.fail(what, name, None, None, message)))
    }

    /// The JSON metadata part and the bytes, as one `multipart/related` body.
    ///
    /// `boundary` is 128 bits from the OS, so a delimiter cannot occur inside a database it is
    /// separating by accident, and the body is never scanned for one: on a snapshot-sized buffer
    /// that scan would cost real time on every upload to guard against something that does not
    /// happen.
    fn multipart_body(
        boundary: &str,
        name: &str,
        metadata: &BTreeMap<String, String>,
        bytes: &[u8],
    ) -> Result<Vec<u8>, GatewayError> {
        let resource = serde_json::to_vec(&serde_json::json!({ "name": name, "metadata": metadata }))
            .map_err(|e| GatewayError::Internal(format!("object store put: metadata part: {e}")))?;
        let mut body = Vec::with_capacity(bytes.len() + resource.len() + 256);
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Type: application/json; charset=UTF-8\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(&resource);
        body.extend_from_slice(
            format!("\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        Ok(body)
    }

    /// A delimiter no payload will contain.
    fn multipart_boundary() -> String {
        use rand::RngCore;
        let mut raw = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut raw);
        let mut out = String::with_capacity(41);
        out.push_str("permaura-");
        for b in raw {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }

    /// A decimal-string field, which is how Cloud Storage sends every number that does not fit a
    /// JSON one safely.
    fn decimal_field(body: &serde_json::Value, key: &str) -> u64 {
        body.get(key).and_then(|v| v.as_str()).and_then(|s| s.parse().ok()).unwrap_or(0)
    }

    /// The generation field of an object-metadata response. Cloud Storage sends it as a decimal
    /// **string**, because it does not fit a JSON number safely.
    fn generation_of(&self, op: &str, name: &str, body: &serde_json::Value) -> Result<u64, GatewayError> {
        body.get("generation")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                self.fail(op, name, None, None, "object store: response carried no generation".into())
            })?
            .parse::<u64>()
            .map_err(|e| {
                let message = format!("object store: unreadable generation: {e}");
                self.fail(op, name, None, None, message)
            })
    }

    /// Settle an upload that was answered with an error and sent again, by what the object now holds.
    ///
    /// An answered 429 or 5xx does not prove the write was not applied, so a 412 after a resend can be
    /// this upload's own earlier attempt, and so can a last error. Only for an upload that carries an
    /// [`UPLOAD_ID_KEY`]: the object is this upload's when it carries exactly the metadata sent with
    /// it, that fresh id included, at the size sent, and then this is the upload's own `Stored`. An object still at
    /// `expected` proves nothing was applied, and `unapplied` is then the answer; one moved to anything
    /// else is a real conflict. A read that fails proves nothing, so the outcome stays
    /// [`PutOutcome::Uncertain`] for the caller to resolve.
    async fn resolve_resent(
        &self,
        name: &str,
        bytes: &[u8],
        expected: u64,
        metadata: &BTreeMap<String, String>,
        unapplied: impl FnOnce() -> GatewayError,
    ) -> Result<PutOutcome, GatewayError> {
        match self.head_full_async(name).await {
            Ok(Some(head)) if head.generation != expected && head.metadata == *metadata && head.size == bytes.len() as u64 => {
                tracing::info!(object = %name, generation = head.generation, "this upload's own earlier attempt landed; its answer was an error");
                Ok(PutOutcome::Stored(head.generation))
            }
            Ok(head) if head.as_ref().map_or(0, |h| h.generation) == expected => Err(unapplied()),
            Ok(_) => Ok(PutOutcome::Conflict),
            Err(e) => {
                tracing::warn!(error = %e, object = %name, generation = expected, "the object could not be read back after a resent upload, so whether it landed is not known");
                Ok(PutOutcome::Uncertain)
            }
        }
    }

    /// [`ObjectStore::head_full`] for a caller already inside the runtime: the upload resolving its own resend.
    async fn head_full_async(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
        let url = format!("{}/storage/v1/b/{}/o/{}", self.endpoint, Self::seg(&self.bucket), Self::seg(name));
        let resp = self
            .send_with_retry("head", name, Attempts::RESOLVING, |http, token| http.get(&url).bearer_auth(token))
            .await
            .map_err(SendFailure::into_error)?;
        let status = resp.status().as_u16();
        if status == 404 {
            return Ok(None);
        }
        if status >= 400 {
            let message =
                format!("object store head gs://{}/{name} returned {status}", self.bucket);
            return Err(self.fail("head", name, None, Some(status), message));
        }
        let body: serde_json::Value = resp.json().await.map_err(|e| {
            let message = format!("object store head: unreadable body: {e}");
            self.fail("head", name, None, Some(status), message)
        })?;
        let metadata = body
            .get("metadata")
            .and_then(|v| v.as_object())
            .map(|map| {
                map.iter()
                    .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        Ok(Some(ObjectHead {
            generation: self.generation_of("head", name, &body)?,
            metadata,
            size: Self::decimal_field(&body, "size"),
            crc32c: body.get("crc32c").and_then(|v| v.as_str()).unwrap_or_default().to_string(),
        }))
    }
}

impl ObjectStore for GcsObjectStore {
    fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
        block_on(async {
            let url = format!("{}/storage/v1/b/{}/o/{}", self.endpoint, Self::seg(&self.bucket), Self::seg(name));
            let resp = self
                .send_with_retry("head", name, Attempts::METADATA, |http, token| http.get(&url).bearer_auth(token))
                .await
                .map_err(SendFailure::into_error)?;
            let status = resp.status().as_u16();
            if status == 404 {
                return Ok(None);
            }
            if status >= 400 {
                let message =
                    format!("object store head gs://{}/{name} returned {status}", self.bucket);
                return Err(self.fail("head", name, None, Some(status), message));
            }
            let body: serde_json::Value = resp.json().await.map_err(|e| {
                let message = format!("object store head: unreadable body: {e}");
                self.fail("head", name, None, Some(status), message)
            })?;
            Ok(Some(self.generation_of("head", name, &body)?))
        })
    }

    fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
        block_on(self.head_full_async(name))
    }

    fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
        block_on(async {
            let url = format!(
                "{}/storage/v1/b/{}/o?versions=true&prefix={}&fields=items(name,generation,timeDeleted)&maxResults=16",
                self.endpoint,
                Self::seg(&self.bucket),
                Self::seg(name)
            );
            let resp = self
                .send_with_retry("versions", name, Attempts::METADATA, |http, token| http.get(&url).bearer_auth(token))
                .await
                .map_err(SendFailure::into_error)?;
            let status = resp.status().as_u16();
            if status >= 400 {
                let message =
                    format!("object store versions gs://{}/{name} returned {status}", self.bucket);
                return Err(self.fail("versions", name, None, Some(status), message));
            }
            let body: serde_json::Value = resp.json().await.map_err(|e| {
                let message = format!("object store versions: unreadable body: {e}");
                self.fail("versions", name, None, Some(status), message)
            })?;
            // `prefix` is a prefix: a listing for `store.db` also returns `store.db.bak`, so only an
            // exact name counts. An empty listing comes back with no `items` field at all.
            Ok(body
                .get("items")
                .and_then(|v| v.as_array())
                .is_some_and(|items| {
                    items.iter().any(|item| item.get("name").and_then(|n| n.as_str()) == Some(name))
                }))
        })
    }

    fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
        block_on(async {
            let url = format!(
                "{}/storage/v1/b/{}/o/{}?alt=media&generation={generation}",
                self.endpoint,
                Self::seg(&self.bucket),
                Self::seg(name)
            );
            let resp = self
                .send_with_retry("get", name, Attempts::DOWNLOAD, |http, token| http.get(&url).bearer_auth(token))
                .await
                .map_err(SendFailure::into_error)?;
            let status = resp.status().as_u16();
            if status >= 400 {
                let message = format!(
                    "object store get gs://{}/{name}#{generation} returned {status}",
                    self.bucket
                );
                return Err(self.fail("get", name, Some(generation), Some(status), message));
            }
            resp.bytes().await.map(|b| b.to_vec()).map_err(|e| {
                let message = format!("object store get: {e}");
                self.fail("get", name, Some(generation), Some(status), message)
            })
        })
    }

    fn put_if_generation(
        &self,
        name: &str,
        bytes: &[u8],
        expected: u64,
        metadata: &BTreeMap<String, String>,
    ) -> Result<PutOutcome, GatewayError> {
        block_on(async {
            // `uploadType=multipart` so the custom metadata travels in the same request as the bytes
            // it describes; the object name moves into the JSON part with it, and the precondition
            // stays on the query string where the API wants it.
            let url = format!(
                "{}/upload/storage/v1/b/{}/o?uploadType=multipart&ifGenerationMatch={expected}",
                self.endpoint,
                Self::seg(&self.bucket)
            );
            let boundary = Self::multipart_boundary();
            // Shared rather than copied into each attempt: a retry resends the same snapshot-sized
            // buffer, and on a 512 MiB worker a copy per retry is memory the instance pays for.
            let body = axum::body::Bytes::from(Self::multipart_body(&boundary, name, metadata, bytes)?);
            let content_type = format!("multipart/related; boundary={boundary}");
            let bound = put_attempt_timeout(body.len());
            let attempts = Attempts { timeout: Some(bound), transport_retries: 0 };
            // An upload with no id of its own (the archive's create-only writes) is judged by its caller's content check, as before the read-back.
            let provable = metadata.contains_key(UPLOAD_ID_KEY);
            let mut resent = false;
            let sent = self
                .send_noting_resends(
                    "put",
                    name,
                    attempts,
                    |http, token| {
                        http.post(&url)
                            .bearer_auth(token)
                            .header("Content-Type", &content_type)
                            .body(body.clone())
                    },
                    &mut resent,
                )
                .await;
            let resp = match sent {
                Ok(resp) => resp,
                Err(SendFailure::Transport(e)) => {
                    tracing::warn!(
                        error = %e,
                        object = %name,
                        generation = expected,
                        bound_ms = bound.as_millis() as u64,
                        "{UNANSWERED_UPLOAD_MESSAGE}"
                    );
                    return Ok(PutOutcome::Uncertain);
                }
                Err(SendFailure::Answered(e)) if resent && provable => {
                    tracing::warn!(error = %e, object = %name, generation = expected, "{RESENT_UPLOAD_MESSAGE}");
                    return self.resolve_resent(name, bytes, expected, metadata, || e).await;
                }
                Err(other) => return Err(other.into_error()),
            };
            let status = resp.status().as_u16();
            // A 412 after a resend may be the earlier attempt's own landing, and a last 429 or 5xx may
            // have been applied as well, so both are settled by what the object now holds.
            if provable && ((status == 412 && resent) || retryable(status)) {
                tracing::warn!(object = %name, generation = expected, status, "{RESENT_UPLOAD_MESSAGE}");
                let unapplied = || {
                    let message = format!(
                        "object store put gs://{}/{name} returned {status} and the object did not move, so it was not applied",
                        self.bucket
                    );
                    self.fail("put", name, Some(expected), Some(status), message)
                };
                return self.resolve_resent(name, bytes, expected, metadata, unapplied).await;
            }
            if status == 412 {
                return Ok(PutOutcome::Conflict);
            }
            if status >= 400 {
                let message =
                    format!("object store put gs://{}/{name} returned {status}", self.bucket);
                return Err(self.fail("put", name, Some(expected), Some(status), message));
            }
            let body: serde_json::Value = match resp.json().await {
                Ok(body) => body,
                // The status said stored, so this write landed and only its generation was lost on the
                // way back: the same question as no answer at all, and never a definite failure.
                Err(e) => {
                    self.discard_connections();
                    tracing::warn!(
                        error = %e,
                        object = %name,
                        generation = expected,
                        status,
                        "{UNANSWERED_UPLOAD_MESSAGE}"
                    );
                    return Ok(PutOutcome::Uncertain);
                }
            };
            Ok(PutOutcome::Stored(self.generation_of("put", name, &body)?))
        })
    }

    fn describe(&self) -> String {
        format!("gs://{}", self.bucket)
    }
}

// ── in-memory, for tests ─────────────────────────────────────────────────────

/// One stored version: its generation, its bytes and the metadata the writer stamped on it.
#[derive(Clone, Default)]
struct MemoryObject {
    generation: u64,
    bytes: Vec<u8>,
    metadata: BTreeMap<String, String>,
}

/// An [`ObjectStore`] in a `HashMap`, with the same generation semantics, so the persistence
/// protocol can be tested without a network.
#[derive(Default)]
pub struct MemoryObjectStore {
    objects: Mutex<HashMap<String, MemoryObject>>,
    next_generation: Mutex<u64>,
    puts: Mutex<u64>,
}

impl MemoryObjectStore {
    /// An empty bucket.
    pub fn new() -> Self {
        MemoryObjectStore::default()
    }

    /// How many uploads have been accepted or rejected, for the group-commit test.
    pub fn put_count(&self) -> u64 {
        *self.puts.lock().unwrap()
    }

    /// Overwrite an object's bytes, keeping its generation, so a test can corrupt what a restore
    /// will read.
    pub fn corrupt(&self, name: &str, bytes: Vec<u8>) {
        if let Some(entry) = self.objects.lock().unwrap().get_mut(name) {
            entry.bytes = bytes;
        }
    }

    /// Total bytes held across every object, for a measurement that wants to say what an archive
    /// costs beside what the hot store costs.
    pub fn total_bytes(&self) -> u64 {
        self.objects.lock().unwrap().values().map(|o| o.bytes.len() as u64).sum()
    }

    /// Replace an object's bytes, bypassing every precondition.
    ///
    /// No gateway code path does this: an archive segment is published create-only (generation 0),
    /// and the index is replaced only under a generation precondition. That is a property of the
    /// code, not of the storage: a self-run gateway's archive is files its OS user owns, and a hosted
    /// bucket is only as append-only as its IAM grant. It exists so a test can be the thing the
    /// gateway is defending against, which is the only way to assert that a tampered segment is
    /// detected rather than assumed impossible.
    pub fn overwrite(&self, name: &str, bytes: &[u8]) {
        let mut objects = self.objects.lock().unwrap();
        if let Some(entry) = objects.get_mut(name) {
            entry.bytes = bytes.to_vec();
        }
    }

    /// Replace the stamped metadata without touching the bytes or the generation, so a test can
    /// produce the version an older gateway, or another instance, would have written.
    pub fn restamp(&self, name: &str, metadata: BTreeMap<String, String>) {
        if let Some(entry) = self.objects.lock().unwrap().get_mut(name) {
            entry.metadata = metadata;
        }
    }
}

impl ObjectStore for MemoryObjectStore {
    fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
        Ok(self.objects.lock().unwrap().get(name).map(|o| o.generation))
    }

    /// No checksum: nothing in the gateway reads one, and inventing a CRC the real store computes a
    /// different way would be worse than saying nothing.
    fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
        Ok(self.objects.lock().unwrap().get(name).map(|o| ObjectHead {
            generation: o.generation,
            metadata: o.metadata.clone(),
            size: o.bytes.len() as u64,
            crc32c: String::new(),
        }))
    }

    /// Nothing here can be deleted, so a live object is the only history there is.
    fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
        Ok(self.head(name)?.is_some())
    }

    fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
        match self.objects.lock().unwrap().get(name) {
            Some(o) if o.generation == generation => Ok(o.bytes.clone()),
            Some(o) => Err(GatewayError::Internal(format!(
                "memory object store: {name} is at generation {}, not {generation}",
                o.generation
            ))),
            None => Err(GatewayError::NotFound(format!("memory object store: {name}"))),
        }
    }

    fn put_if_generation(
        &self,
        name: &str,
        bytes: &[u8],
        expected: u64,
        metadata: &BTreeMap<String, String>,
    ) -> Result<PutOutcome, GatewayError> {
        *self.puts.lock().unwrap() += 1;
        let mut objects = self.objects.lock().unwrap();
        let current = objects.get(name).map(|o| o.generation).unwrap_or(0);
        if current != expected {
            return Ok(PutOutcome::Conflict);
        }
        let mut next = self.next_generation.lock().unwrap();
        *next += 1;
        objects.insert(
            name.to_string(),
            MemoryObject { generation: *next, bytes: bytes.to_vec(), metadata: metadata.clone() },
        );
        Ok(PutOutcome::Stored(*next))
    }

    fn describe(&self) -> String {
        "memory://objects".to_string()
    }
}

/// An [`ObjectStore`] in a directory, for a gateway its owner runs: the audit archive's segments, manifests and index on the same disk as the store, with a bucket's create-only and generation semantics.
///
/// One file per object, whose first line is a JSON header (the generation and the stamped metadata) and whose remainder is the bytes, so the two can never disagree. A write goes to a temporary file in the same directory and is renamed into place, so a reader sees the old object or the new one and never half of either. Every write in a process is serialized by one lock, which is all one gateway process needs.
pub struct LocalObjectStore {
    root: std::path::PathBuf,
    lock: Mutex<()>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct LocalHeader {
    generation: u64,
    #[serde(default)]
    metadata: BTreeMap<String, String>,
}

impl LocalObjectStore {
    /// A store rooted at `root`, created on the first write.
    pub fn new(root: impl Into<std::path::PathBuf>) -> Self {
        LocalObjectStore { root: root.into(), lock: Mutex::new(()) }
    }

    /// The file for `name`. Names are the archive's own (`audit/<tenant>/e0000/…`), and anything that could resolve outside the root is refused rather than trusted.
    fn path(&self, name: &str) -> Result<std::path::PathBuf, GatewayError> {
        let unsafe_segment = |s: &str| s.is_empty() || s == "." || s == "..";
        if name.contains('\\') || name.split('/').any(unsafe_segment) {
            return Err(GatewayError::Internal(format!("local object store: '{name}' is not an object name")));
        }
        Ok(self.root.join(name))
    }

    fn read(&self, name: &str) -> Result<Option<(LocalHeader, Vec<u8>)>, GatewayError> {
        let path = self.path(name)?;
        let raw = match std::fs::read(&path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(GatewayError::Internal(format!("local object store: reading {}: {e}", path.display()))),
        };
        let corrupt = || GatewayError::Internal(format!("local object store: {} has no readable header", path.display()));
        let end = raw.iter().position(|b| *b == b'\n').ok_or_else(corrupt)?;
        let header: LocalHeader = serde_json::from_slice(&raw[..end]).map_err(|_| corrupt())?;
        Ok(Some((header, raw[end + 1..].to_vec())))
    }

    /// The header alone, reading the file only up to its first newline: a `head` of the index must not cost a read of the whole index.
    fn read_header(&self, name: &str) -> Result<Option<LocalHeader>, GatewayError> {
        use std::io::BufRead;
        let path = self.path(name)?;
        let file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(GatewayError::Internal(format!("local object store: reading {}: {e}", path.display()))),
        };
        let corrupt = || GatewayError::Internal(format!("local object store: {} has no readable header", path.display()));
        let mut line = Vec::new();
        let read = std::io::BufReader::new(file)
            .read_until(b'\n', &mut line)
            .map_err(|e| GatewayError::Internal(format!("local object store: reading {}: {e}", path.display())))?;
        if read == 0 || line.last() != Some(&b'\n') {
            return Err(corrupt());
        }
        line.pop();
        serde_json::from_slice(&line).map(Some).map_err(|_| corrupt())
    }
}

impl ObjectStore for LocalObjectStore {
    fn head(&self, name: &str) -> Result<Option<u64>, GatewayError> {
        Ok(self.read_header(name)?.map(|header| header.generation))
    }

    /// No checksum, for the reason [`MemoryObjectStore::head_full`] gives none.
    fn head_full(&self, name: &str) -> Result<Option<ObjectHead>, GatewayError> {
        Ok(self.read(name)?.map(|(header, bytes)| ObjectHead {
            generation: header.generation,
            metadata: header.metadata,
            size: bytes.len() as u64,
            crc32c: String::new(),
        }))
    }

    /// Nothing here is ever deleted, so a live object is the only history there is.
    fn has_history(&self, name: &str) -> Result<bool, GatewayError> {
        Ok(self.head(name)?.is_some())
    }

    fn get(&self, name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
        match self.read(name)? {
            Some((header, bytes)) if header.generation == generation => Ok(bytes),
            Some((header, _)) => Err(GatewayError::Internal(format!(
                "local object store: {name} is at generation {}, not {generation}",
                header.generation
            ))),
            None => Err(GatewayError::NotFound(format!("local object store: {name}"))),
        }
    }

    fn put_if_generation(
        &self,
        name: &str,
        bytes: &[u8],
        expected: u64,
        metadata: &BTreeMap<String, String>,
    ) -> Result<PutOutcome, GatewayError> {
        let _serial = self.lock.lock().unwrap_or_else(|e| e.into_inner());
        let current = self.head(name)?.unwrap_or(0);
        if current != expected {
            return Ok(PutOutcome::Conflict);
        }
        let generation = current + 1;
        let path = self.path(name)?;
        let failed = |what: &str, e: std::io::Error| {
            GatewayError::Internal(format!("local object store: {what} {}: {e}", path.display()))
        };
        let dir = path.parent().unwrap_or(&self.root);
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
        builder.create(dir).map_err(|e| failed("creating the directory for", e))?;

        let mut header = serde_json::to_vec(&LocalHeader { generation, metadata: metadata.clone() })
            .map_err(|e| GatewayError::Internal(format!("local object store: {e}")))?;
        header.push(b'\n');
        let mut temp = path.clone().into_os_string();
        temp.push(format!(".tmp-{}", std::process::id()));
        let temp = std::path::PathBuf::from(temp);
        {
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let mut file = options.open(&temp).map_err(|e| failed("opening a temporary file for", e))?;
            file.write_all(&header).and_then(|_| file.write_all(bytes)).and_then(|_| file.sync_all())
                .map_err(|e| failed("writing", e))?;
        }
        std::fs::rename(&temp, &path).map_err(|e| failed("publishing", e))?;
        Ok(PutOutcome::Stored(generation))
    }

    fn describe(&self) -> String {
        format!("file://{}", self.root.display())
    }
}

/// An [`ObjectStore`] whose every call fails, for the "unreachable is not empty" test.
pub struct FailingObjectStore {
    /// The message every call reports.
    pub reason: String,
}

impl ObjectStore for FailingObjectStore {
    fn head(&self, _name: &str) -> Result<Option<u64>, GatewayError> {
        Err(GatewayError::Internal(self.reason.clone()))
    }

    fn head_full(&self, _name: &str) -> Result<Option<ObjectHead>, GatewayError> {
        Err(GatewayError::Internal(self.reason.clone()))
    }

    fn has_history(&self, _name: &str) -> Result<bool, GatewayError> {
        Err(GatewayError::Internal(self.reason.clone()))
    }

    fn get(&self, _name: &str, _generation: u64) -> Result<Vec<u8>, GatewayError> {
        Err(GatewayError::Internal(self.reason.clone()))
    }

    fn put_if_generation(
        &self,
        _name: &str,
        _bytes: &[u8],
        _expected: u64,
        _metadata: &BTreeMap<String, String>,
    ) -> Result<PutOutcome, GatewayError> {
        Err(GatewayError::Internal(self.reason.clone()))
    }

    fn describe(&self) -> String {
        "failing://objects".to_string()
    }
}

/// A stand-in for the slice of Cloud Storage's JSON API the client uses, over plain HTTP on a local
/// port, that can be told to take an upload and never answer it.
#[cfg(test)]
#[cfg_attr(not(feature = "sqlite"), allow(dead_code))]
pub(crate) mod fake_gcs {
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    /// What the stand-in does with an upload, in arrival order. Uploads past the script are answered.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum NextPut {
        /// Accept it and never answer, without applying it: an upload stall.
        Swallow,
        /// Accept it and never answer, and apply it the moment the next upload arrives, before that
        /// one's precondition is checked: an unanswered attempt that lands after the read that said
        /// it had not.
        LandWhenRetried,
        /// Apply it and answer this error status anyway, as Cloud Storage or the front end before it can
        /// for a write it committed.
        ApplyAndAnswer(u16),
        /// Answer this error status without applying it.
        Answer(u16),
        /// Answer this error status without applying it, and apply it once a later upload with another
        /// upload id arrives, before that one's precondition is checked: a write the front end failed
        /// that the backend committed after a read said it had not.
        AnswerAndLandLater(u16),
    }

    /// One request as the stand-in saw it: the connection it came in on, its method, and the status
    /// it was answered with (`None` for one never answered).
    #[derive(Clone, Debug)]
    pub(crate) struct Seen {
        pub(crate) connection: u64,
        pub(crate) method: String,
        pub(crate) status: Option<u16>,
    }

    struct Object {
        generation: u64,
        bytes: Vec<u8>,
        metadata: BTreeMap<String, String>,
    }

    struct Upload {
        /// `None` when the request carried no `ifGenerationMatch`, which Cloud Storage applies
        /// unconditionally.
        expected: Option<u64>,
        bytes: Vec<u8>,
        metadata: BTreeMap<String, String>,
    }

    #[derive(Default)]
    struct State {
        object: Option<Object>,
        last_generation: u64,
        script: Vec<NextPut>,
        deferred: Option<Upload>,
        late: Option<Upload>,
        connections: u64,
        seen: Vec<Seen>,
        latency: std::time::Duration,
    }

    impl State {
        fn apply(&mut self, upload: Upload) -> Option<u64> {
            let current = self.object.as_ref().map(|o| o.generation).unwrap_or(0);
            if upload.expected.is_some_and(|expected| expected != current) {
                return None;
            }
            self.last_generation += 1;
            self.object = Some(Object {
                generation: self.last_generation,
                bytes: upload.bytes,
                metadata: upload.metadata,
            });
            Some(self.last_generation)
        }
    }

    pub(crate) struct FakeGcs {
        pub(crate) endpoint: String,
        state: Arc<Mutex<State>>,
    }

    impl FakeGcs {
        pub(crate) async fn start() -> FakeGcs {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("a local port");
            let endpoint = format!("http://{}", listener.local_addr().expect("its address"));
            let state = Arc::new(Mutex::new(State { last_generation: 1000, ..State::default() }));
            let shared = state.clone();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let connection = {
                        let mut s = shared.lock().unwrap();
                        s.connections += 1;
                        s.connections
                    };
                    tokio::spawn(serve(stream, connection, shared.clone()));
                }
            });
            FakeGcs { endpoint, state }
        }

        pub(crate) fn script(&self, puts: &[NextPut]) {
            self.state.lock().unwrap().script.extend_from_slice(puts);
        }

        /// Hold every answer this long before sending it, as a bucket in another region would.
        pub(crate) fn set_latency(&self, latency: std::time::Duration) {
            self.state.lock().unwrap().latency = latency;
        }

        pub(crate) fn generation(&self) -> Option<u64> {
            self.state.lock().unwrap().object.as_ref().map(|o| o.generation)
        }

        pub(crate) fn bytes(&self) -> Option<Vec<u8>> {
            self.state.lock().unwrap().object.as_ref().map(|o| o.bytes.clone())
        }

        pub(crate) fn seen(&self) -> Vec<Seen> {
            self.state.lock().unwrap().seen.clone()
        }

        pub(crate) fn uploads(&self) -> Vec<Seen> {
            self.seen().into_iter().filter(|s| s.method == "POST").collect()
        }
    }

    fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    async fn serve(mut stream: TcpStream, connection: u64, state: Arc<Mutex<State>>) {
        let mut buf = Vec::new();
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let head_end = loop {
                if let Some(at) = find(&buf, b"\r\n\r\n") {
                    break at;
                }
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            };
            let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
            let mut lines = head.split("\r\n");
            let mut request_line = lines.next().unwrap_or_default().split(' ');
            let method = request_line.next().unwrap_or_default().to_string();
            let target = request_line.next().unwrap_or_default().to_string();
            let mut length = 0usize;
            let mut content_type = String::new();
            for line in lines {
                if let Some((key, value)) = line.split_once(':') {
                    match key.trim().to_ascii_lowercase().as_str() {
                        "content-length" => length = value.trim().parse().unwrap_or(0),
                        "content-type" => content_type = value.trim().to_string(),
                        _ => {}
                    }
                }
            }
            let start = head_end + 4;
            while buf.len() < start + length {
                match stream.read(&mut chunk).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                }
            }
            let body = buf[start..start + length].to_vec();
            buf.drain(..start + length);
            match respond(&state, connection, &method, &target, &content_type, &body) {
                Some((status, payload)) => {
                    let latency = state.lock().unwrap().latency;
                    if !latency.is_zero() {
                        tokio::time::sleep(latency).await;
                    }
                    let reason = match status {
                        200 => "OK",
                        404 => "Not Found",
                        412 => "Precondition Failed",
                        _ => "Other",
                    };
                    let head = format!(
                        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                        payload.len()
                    );
                    if stream.write_all(head.as_bytes()).await.is_err() || stream.write_all(&payload).await.is_err() {
                        return;
                    }
                }
                None => std::future::pending::<()>().await,
            }
        }
    }

    fn query<'a>(query: &'a str, key: &str) -> Option<&'a str> {
        query.split('&').find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == key).map(|(_, v)| v))
    }

    /// The JSON part's custom metadata and the octet-stream part's bytes.
    fn multipart(content_type: &str, body: &[u8]) -> (BTreeMap<String, String>, Vec<u8>) {
        let boundary = content_type.split("boundary=").nth(1).unwrap_or_default().trim();
        let json_start = find(body, b"\r\n\r\n").expect("a metadata part") + 4;
        let separator = format!("\r\n--{boundary}\r\n");
        let json_end = json_start + find(&body[json_start..], separator.as_bytes()).expect("a bytes part");
        let resource: serde_json::Value = serde_json::from_slice(&body[json_start..json_end]).expect("JSON metadata");
        let metadata = resource
            .get("metadata")
            .and_then(|m| m.as_object())
            .map(|m| m.iter().map(|(k, v)| (k.clone(), v.as_str().unwrap_or_default().to_string())).collect())
            .unwrap_or_default();
        let after = json_end + separator.len();
        let bytes_start = after + find(&body[after..], b"\r\n\r\n").expect("a part header") + 4;
        let closing = format!("\r\n--{boundary}--\r\n");
        (metadata, body[bytes_start..body.len() - closing.len()].to_vec())
    }

    fn respond(
        state: &Mutex<State>,
        connection: u64,
        method: &str,
        target: &str,
        content_type: &str,
        body: &[u8],
    ) -> Option<(u16, Vec<u8>)> {
        let (path, q) = target.split_once('?').unwrap_or((target, ""));
        let mut s = state.lock().unwrap();
        let reply = if method == "POST" && path.starts_with("/upload/") {
            let expected = query(q, "ifGenerationMatch").and_then(|v| v.parse().ok());
            let (metadata, bytes) = multipart(content_type, body);
            if let Some(earlier) = s.deferred.take() {
                s.apply(earlier);
            }
            let id = |m: &BTreeMap<String, String>| m.get("pm-upload-id").cloned();
            if s.late.as_ref().is_some_and(|late| id(&late.metadata) != id(&metadata)) {
                let late = s.late.take().expect("checked");
                s.apply(late);
            }
            let upload = Upload { expected, bytes, metadata };
            let next = if s.script.is_empty() { None } else { Some(s.script.remove(0)) };
            match next {
                Some(NextPut::Swallow) => None,
                Some(NextPut::LandWhenRetried) => {
                    s.deferred = Some(upload);
                    None
                }
                Some(NextPut::ApplyAndAnswer(status)) => {
                    s.apply(upload);
                    Some((status, serde_json::json!({ "error": "backendError" })))
                }
                Some(NextPut::Answer(status)) => Some((status, serde_json::json!({ "error": "backendError" }))),
                Some(NextPut::AnswerAndLandLater(status)) => {
                    s.late = Some(upload);
                    Some((status, serde_json::json!({ "error": "backendError" })))
                }
                None => Some(match s.apply(upload) {
                    Some(generation) => (200, serde_json::json!({ "generation": generation.to_string() })),
                    None => (412, serde_json::json!({ "error": "conditionNotMet" })),
                }),
            }
        } else if query(q, "alt") == Some("media") {
            let wanted: u64 = query(q, "generation").and_then(|v| v.parse().ok()).unwrap_or(0);
            match s.object.as_ref().filter(|o| o.generation == wanted) {
                Some(o) => {
                    let bytes = o.bytes.clone();
                    s.seen.push(Seen { connection, method: method.into(), status: Some(200) });
                    return Some((200, bytes));
                }
                None => Some((404, serde_json::json!({}))),
            }
        } else if query(q, "versions").is_some() {
            Some((200, match &s.object {
                Some(_) => serde_json::json!({ "items": [{ "name": "store.db" }] }),
                None => serde_json::json!({}),
            }))
        } else {
            Some(match &s.object {
                Some(o) => (200, serde_json::json!({
                    "generation": o.generation.to_string(),
                    "metadata": o.metadata,
                    "size": o.bytes.len().to_string(),
                    "crc32c": "",
                })),
                None => (404, serde_json::json!({})),
            })
        };
        let status = reply.as_ref().map(|(status, _)| *status);
        s.seen.push(Seen { connection, method: method.into(), status });
        reply.map(|(status, json)| (status, serde_json::to_vec(&json).expect("JSON")))
    }

    /// A client for the stand-in, with a token source that never leaves the process.
    pub(crate) fn client(fake: &FakeGcs) -> super::GcsObjectStore {
        let token = crate::connectors::MockHttpClient::with_response(crate::connectors::HttpResponse::json(
            200,
            serde_json::json!({ "access_token": "synthetic-token", "expires_in": 3600 }),
        ));
        let token = Arc::new(crate::backend::GcpTokenSource::new(Arc::new(token)));
        super::GcsObjectStore::at_endpoint(&fake.endpoint, "pw-store-test", token).expect("a client")
    }
}

#[cfg(test)]
mod tests {
    use super::fake_gcs::{client, FakeGcs, NextPut};
    use super::*;

    /// At the client, an upload that is taken and never answered gives up at its bound rather
    /// than at the 60 s the client used to allow, reports that it does not know whether it landed,
    /// and the request after it goes out on a connection opened after the failure.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unanswered_upload_gives_up_at_its_bound_and_the_next_request_opens_a_fresh_connection() {
        let fake = FakeGcs::start().await;
        let store = client(&fake);
        assert_eq!(store.head("store.db").unwrap(), None, "a first request puts a connection in the pool");

        fake.script(&[NextPut::Swallow]);
        let started = Instant::now();
        let outcome = store.put_if_generation("store.db", b"snapshot", 0, &BTreeMap::new()).unwrap();
        let took = started.elapsed();

        assert_eq!(outcome, PutOutcome::Uncertain, "no answer is not a failure: it may have landed");
        assert!(took >= PUT_ATTEMPT_FLOOR - Duration::from_millis(50), "it waited for its bound: {took:?}");
        assert!(took < PUT_ATTEMPT_FLOOR + Duration::from_secs(2), "and no longer: {took:?}");

        assert_eq!(store.head("store.db").unwrap(), None, "the swallowed upload did not land");
        let seen = fake.seen();
        let hung = seen.iter().find(|s| s.method == "POST").expect("the upload arrived").connection;
        let after = seen.last().expect("the read after it").connection;
        assert!(after > hung, "the read after the stall rode a new connection, not the one that hung: {seen:?}");

        let stored = store.put_if_generation("store.db", b"snapshot", 0, &BTreeMap::new()).unwrap();
        assert_eq!(stored, PutOutcome::Stored(fake.generation().unwrap()), "and an upload on it is answered");
    }

    /// A resent upload that carries no upload id cannot prove the object is its own by metadata and size alone, so a 412 after its resend is a conflict for the caller's own content check, as before the read-back existed.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_resent_upload_without_an_upload_id_meeting_a_412_is_a_conflict() {
        let fake = FakeGcs::start().await;
        let store = client(&fake);
        let theirs = store.put_if_generation("claim.json", b"aaaa", 0, &BTreeMap::new()).unwrap();
        assert!(matches!(theirs, PutOutcome::Stored(_)));
        fake.script(&[NextPut::Answer(503)]);
        let ours = store.put_if_generation("claim.json", b"bbbb", 0, &BTreeMap::new()).unwrap();
        assert_eq!(ours, PutOutcome::Conflict, "another writer's object of the same size is not this upload's");
    }

    #[test]
    fn a_large_snapshot_is_given_time_in_proportion_to_its_size() {
        assert_eq!(put_attempt_timeout(0), PUT_ATTEMPT_FLOOR);
        assert_eq!(put_attempt_timeout(64 * 1024 * 1024), PUT_ATTEMPT_FLOOR + Duration::from_secs(8));
    }
}
