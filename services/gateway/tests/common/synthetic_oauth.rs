//! A synthetic OAuth provider for the OAuth refresh tests, shared by the test binaries that drive it.
//!
//! The token endpoint holds every refresh until the test releases it, counts them, records what the
//! data endpoint was sent, and retires each refresh token on first use the way a rotating provider
//! does. No network, no real keys or providers.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use permaura_core::{open, seal, Cipher, ExecutionLocation, SecretRecord};
use permaura_gateway::connectors::{HttpClient, HttpRequest, HttpResponse};
use permaura_gateway::error::GatewayError;
use permaura_gateway::oauth_connect::{from_sealed_bytes, to_sealed_json};
use permaura_gateway::oauth_credential::{OAuthCredential, OAuthLayer};
use permaura_gateway::seed;
use permaura_gateway::service::{vault_passphrase, EnforcementService, InvokeOutcome};
use permaura_gateway::store::memory::MemoryStore;
use permaura_gateway::store::Store;
use tokio::sync::{Notify, Semaphore};

pub const TOKEN_URL: &str = "https://provider.example/token";
pub const GITHUB_SECRET: &str = "sec_github_acme";
pub const OLD_REFRESH: &str = "synthetic-old-refresh";

/// The provider. A refresh is answered only once `release` holds a permit; `entered` fires when one
/// reaches the endpoint.
pub struct Provider {
    pub entered: Notify,
    pub release: Semaphore,
    refreshes: AtomicUsize,
    /// Reject the next refresh with a 400 once, the way a provider refuses a dead refresh token.
    pub fail_next_refresh: AtomicBool,
    /// Every refresh token a successful refresh has retired. A rotating provider spends the presented
    /// token the moment it accepts the request, before its answer is on the wire, so a client that
    /// stops listening has still spent it, and presenting it again is refused.
    consumed: Mutex<HashSet<String>>,
    upstream_authorization: Mutex<Vec<String>>,
}

impl Provider {
    pub fn new() -> Arc<Self> {
        Arc::new(Provider {
            entered: Notify::new(),
            release: Semaphore::new(0),
            refreshes: AtomicUsize::new(0),
            fail_next_refresh: AtomicBool::new(false),
            consumed: Mutex::new(HashSet::new()),
            upstream_authorization: Mutex::new(Vec::new()),
        })
    }

    /// How many refreshes reached the endpoint, answered or not.
    pub fn refreshes(&self) -> usize {
        self.refreshes.load(Ordering::SeqCst)
    }

    /// The Authorization header of every call the data endpoint received, in order.
    pub fn upstream_authorization(&self) -> Vec<String> {
        self.upstream_authorization.lock().unwrap().clone()
    }
}

#[async_trait]
impl HttpClient for Provider {
    async fn send(&self, r: HttpRequest) -> anyhow::Result<HttpResponse> {
        if r.url != TOKEN_URL {
            let auth = r
                .headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
                .map(|(_, v)| v.clone())
                .unwrap_or_default();
            self.upstream_authorization.lock().unwrap().push(auth);
            return Ok(HttpResponse::json(200, serde_json::json!({ "data": [] })));
        }
        let form = |key: &str| r.form.as_ref().and_then(|f| f.get(key).cloned()).unwrap_or_default();
        if form("grant_type") == "authorization_code" {
            return Ok(HttpResponse::json(
                200,
                serde_json::json!({
                    "access_token": "synthetic-new-authorization",
                    "refresh_token": "synthetic-new-refresh",
                    "expires_in": 3600
                }),
            ));
        }
        let n = self.refreshes.fetch_add(1, Ordering::SeqCst);
        let refused = self.fail_next_refresh.swap(false, Ordering::SeqCst);
        let spent = !refused && !self.consumed.lock().unwrap().insert(form("refresh_token"));
        self.entered.notify_one();
        self.release.acquire().await.unwrap().forget();
        if refused || spent {
            return Ok(HttpResponse::json(400, serde_json::json!({ "error": "invalid_grant" })));
        }
        Ok(HttpResponse::json(
            200,
            serde_json::json!({
                "access_token": format!("synthetic-refreshed-{n}"),
                "refresh_token": format!("synthetic-rotated-{n}"),
                "expires_in": 3600
            }),
        ))
    }
}

pub fn cred(access: &str, expires_at: i64) -> OAuthCredential {
    cred_with_refresh(access, OLD_REFRESH, expires_at)
}

pub fn cred_with_refresh(access: &str, refresh: &str, expires_at: i64) -> OAuthCredential {
    OAuthCredential { token_auth: Default::default(), refresh_grant: Default::default(),
        layer: OAuthLayer::ByoApp,
        provider: "synthetic".into(),
        access_token: access.into(),
        refresh_token: Some(refresh.into()),
        expires_at,
        scopes: vec![],
        token_url: TOKEN_URL.into(),
        client_id: Some("synthetic-client".into()),
        client_secret: None,
    }
}

/// The BYO callback's write shape: a plain replace of the secret slot, metadata carried over.
pub fn put(store: &dyn Store, id: &str, c: &OAuthCredential) {
    let metadata = store.get_secret(id).unwrap().map(|s| s.metadata).unwrap_or_default();
    let sealed = seal(Cipher::Aes256Gcm, vault_passphrase(), to_sealed_json(c).unwrap().as_bytes()).unwrap();
    store.put_secret(SecretRecord { id: id.into(), sealed, metadata }).unwrap();
}

pub fn stored(store: &dyn Store, id: &str) -> OAuthCredential {
    let row = store.get_secret(id).unwrap().expect("the secret is still there");
    from_sealed_bytes(&open(&row.sealed, vault_passphrase()).unwrap()).expect("an OAuth bundle")
}

/// A seeded service over `store` whose GitHub credential is expired and refreshable.
pub fn service_over(store: Arc<dyn Store>, http: Arc<Provider>) -> Arc<EnforcementService> {
    super::isolate_from_the_real_install();
    seed::seed(store.as_ref()).unwrap();
    put(store.as_ref(), GITHUB_SECRET, &cred("synthetic-expired", 1));
    Arc::new(EnforcementService::new(store, http))
}

pub fn memory_service() -> (Arc<EnforcementService>, Arc<Provider>) {
    super::isolate_from_the_real_install();
    let http = Provider::new();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    (service_over(store, http.clone()), http)
}

pub async fn invoke(
    s: Arc<EnforcementService>,
    capability: &str,
    params: serde_json::Value,
) -> Result<InvokeOutcome, GatewayError> {
    let session = s.store().get_session("sess_demo").unwrap().unwrap();
    s.invoke(&session, capability, &params, None, ExecutionLocation::LocalOnly).await
}

pub async fn invoke_github(s: Arc<EnforcementService>) -> Result<InvokeOutcome, GatewayError> {
    invoke(s, "github.pull_requests.list", serde_json::json!({ "owner": "synthetic", "repo": "synthetic" })).await
}

pub fn allowed(outcome: &Result<InvokeOutcome, GatewayError>) -> bool {
    matches!(outcome, Ok(InvokeOutcome::Allowed { .. }))
}

/// What an invocation came back as, for an assertion message; the outcome itself is not `Debug`.
pub fn describe(outcome: &Result<InvokeOutcome, GatewayError>) -> String {
    match outcome {
        Ok(InvokeOutcome::Allowed { status, .. }) => format!("allowed ({status})"),
        Ok(InvokeOutcome::RequiresApproval { .. }) => "requires approval".into(),
        Ok(InvokeOutcome::Denied { decision, .. }) => format!("denied ({})", decision.reason),
        Err(e) => format!("error: {e}"),
    }
}
