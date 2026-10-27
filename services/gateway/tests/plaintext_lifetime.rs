//! Every path that holds a decrypted credential in the gateway wipes it wherever it copied it, up to the request handed to the HTTP client: a vault bundle's export and import, an OAuth bundle's open, refresh, re-seal and code exchange, every request shape a connector builds, a command's environment, and the Infisical backends. Run with its own global allocator, which reads each block as it is freed.
//!
//! The doubles below answer from wiped buffers and keep nothing they are sent, so every copy the scan finds is the gateway's. Their `send` turns the answer into a `serde_json::Value`, which nothing wipes: a path that still read a credential that way would fail here.

#[path = "../../../crates/permaura-core/tests/freed_scan/mod.rs"]
mod freed_scan;
mod common;

use std::sync::Arc;

use async_trait::async_trait;
use freed_scan::{needles_for, watch, FreedScan};
use permaura_core::{Cipher, ExecutionLocation, SecretRecord, SecretString};
use permaura_gateway::backend::SecretBackend as _;
use permaura_gateway::connectors::{HttpClient, HttpRequest, HttpResponse, RawHttpResponse};
use permaura_gateway::oauth_credential::{OAuthCredential, OAuthLayer};
use permaura_gateway::service::{vault_passphrase, EnforcementService, InvokeOutcome};
use permaura_gateway::store::{memory::MemoryStore, Store};
use zeroize::Zeroizing;

#[global_allocator]
static ALLOC: FreedScan = FreedScan;

const ACCESS: &str = "zz-access-token-probe-0123456789-abcdefghijklmno";
// The refresh token and the client secret carry reserved and non-ASCII characters and odd lengths, so the form encoding, the scrub's forms and every size computed from an expansion are exercised.
const REFRESH: &str = "zz+refresh/token=&%~é probe-0123456789-abcdefghijk";
const CLIENT: &str = "zz+client/secret=&%~é probe-0123456789-abcdefghijkl";
const MINTED: &str = "zz-minted-access-probe-012345678-abcdefghijklmno";
const VERIFIER: &str = "zz-pkce-verifier-probe-012345678-abcdefghijklmno";
const API_KEY: &str = "zz-api-key-probe-0123456789abcdef-abcdefghijklmn";
const RESERVED_KEY: &str = "zz+api/key=&%~é probe-0123456789-abcdefghijklmnopq";
/// What a PHP token endpoint writes, `/` escaped as `\/`, and what it means once unescaped.
const PHP_TOKEN_ESCAPED: &str = "zz\\/php\\/token-probe-0123456789-abcdefghijklmnop";
const PHP_TOKEN: &str = "zz/php/token-probe-0123456789-abcdefghijklmnop";
/// The middle line of a PEM key Infisical returns with its line breaks escaped.
const PEM_LINE: &str = "zzPEMprobeLINE0123456789abcdefghijklmnopqrstuvwxyzABCD";
const PASS: &[u8] = b"probe-passphrase";

fn oauth_needles() -> Vec<&'static [u8]> {
    [ACCESS, REFRESH, CLIENT, MINTED, VERIFIER].into_iter().flat_map(needles_for).collect()
}

fn credential(expires_at: i64) -> OAuthCredential {
    OAuthCredential { token_auth: Default::default(), refresh_grant: Default::default(),
        layer: OAuthLayer::ByoApp,
        provider: "synthetic".into(),
        access_token: ACCESS.into(),
        refresh_token: Some(REFRESH.into()),
        expires_at,
        scopes: vec![],
        token_url: "https://provider.example/token".into(),
        client_id: Some("synthetic-client".into()),
        client_secret: Some(CLIENT.into()),
    }
}

fn wiped(parts: &[&str]) -> Zeroizing<Vec<u8>> {
    let mut body = Zeroizing::new(Vec::with_capacity(parts.iter().map(|p| p.len()).sum()));
    for part in parts {
        body.extend_from_slice(part.as_bytes());
    }
    body
}

struct Upstream;

impl Upstream {
    fn answer(request: &HttpRequest) -> Zeroizing<Vec<u8>> {
        match request.url.as_str() {
            "https://provider.example/token" => {
                wiped(&["{\"access_token\":\"", MINTED, "\",\"refresh_token\":\"", REFRESH, "\",\"expires_in\":3600}"])
            }
            "https://php.example/token" => {
                wiped(&["{\"access_token\":\"", PHP_TOKEN_ESCAPED, "\",\"refresh_token\":\"", PHP_TOKEN_ESCAPED, "\",\"expires_in\":3600}"])
            }
            url if url.starts_with("https://vault.example/api/v3/secrets/raw/sec_pem") => wiped(&[
                "{\"secret\":{\"secretValue\":\"-----BEGIN PRIVATE KEY-----\\n",
                PEM_LINE,
                "\\n-----END PRIVATE KEY-----\\n\"}}",
            ]),
            "https://vault.example/api/v1/auth/universal-auth/login" => {
                wiped(&["{\"accessToken\":\"", ACCESS, "\",\"expiresIn\":3600}"])
            }
            url if url.starts_with("https://vault.example/api/v3/secrets/raw/") => {
                wiped(&["{\"secret\":{\"secretKey\":\"k\",\"secretValue\":\"", API_KEY, "\"}}"])
            }
            "https://vault.example/api/v1/dynamic-secrets/leases" => wiped(&[
                "{\"lease\":{\"id\":\"lease_probe\",\"expireAt\":\"2099-01-01T00:00:00Z\"},\"data\":{\"DB_USERNAME\":\"probe\",\"DB_PASSWORD\":\"",
                API_KEY,
                "\",\"port\":5432}}",
            ]),
            _ => wiped(&["{\"data\":[]}"]),
        }
    }
}

#[async_trait]
impl HttpClient for Upstream {
    async fn send(&self, request: HttpRequest) -> anyhow::Result<HttpResponse> {
        let raw = self.send_raw(request).await?;
        let body = serde_json::from_slice(&Zeroizing::new(raw.body))?;
        Ok(HttpResponse::json(raw.status, body))
    }

    async fn send_raw(&self, request: HttpRequest) -> anyhow::Result<RawHttpResponse> {
        let body = Self::answer(&request).to_vec();
        drop(request);
        Ok(RawHttpResponse { status: 200, body, headers: vec![] })
    }
}

#[test]
fn a_vault_bundle_export_and_import_leave_no_copy_of_a_credential() {
    use permaura_gateway::vault_bundle::{open_payload, seal_payload, BundlePayload, BundleSecret, SecretValue};
    let needles = needles_for(API_KEY);
    let source = permaura_core::BundleSource { gateway_id: "gw_probe".into(), mode: "self-run".into() };

    let w = watch(&needles);
    let payload = BundlePayload {
        secrets: vec![BundleSecret {
            id: "sec_probe".into(),
            metadata: Default::default(),
            custody: "local_vault".into(),
            value: SecretValue::new(API_KEY.as_bytes().to_vec()),
        }],
        ..Default::default()
    };
    let bundle = seal_payload(PASS, &payload, 1, source).unwrap();
    drop(payload);
    assert_eq!(w.hits(), 0, "export left a copy of a credential in freed memory");
    let back = open_payload(&bundle, PASS).unwrap();
    assert_eq!(back.secrets[0].value.bytes(), API_KEY.as_bytes());
    drop(back);
    assert_eq!(w.hits(), 0, "import left a copy of a credential in freed memory");
}

#[tokio::test]
async fn an_oauth_bundle_opened_refreshed_and_sealed_again_leaves_no_copy() {
    use permaura_gateway::oauth_connect::{from_sealed_bytes, to_sealed_json};
    let needles = oauth_needles();
    let w = watch(&needles);
    let cred = credential(1);
    let sealed = permaura_core::seal(Cipher::Aes256Gcm, PASS, to_sealed_json(&cred).unwrap().as_bytes()).unwrap();
    let opened = from_sealed_bytes(&permaura_core::open(&sealed, PASS).unwrap()).unwrap();
    assert_eq!(opened, cred);
    drop(opened);
    assert_eq!(w.hits(), 0, "sealing and opening an OAuth bundle left a copy in freed memory");

    let (token, updated) = permaura_gateway::oauth_credential::ensure_fresh(&cred, &Upstream, 1_000_000, 60_000).await.unwrap();
    assert_eq!(token, MINTED);
    drop(token);
    drop(updated);
    drop(cred);
    assert_eq!(w.hits(), 0, "a refresh left a copy of a token or the client secret in freed memory");
}

#[tokio::test]
async fn an_invoke_through_an_expired_oauth_connection_and_a_code_exchange_leave_no_copy() {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    permaura_gateway::seed::seed(store.as_ref()).unwrap();
    let id = store.get_capability("github.pull_requests.list").unwrap().unwrap().secret_id;
    let old = store.get_secret(&id).unwrap().unwrap();
    let service = Arc::new(EnforcementService::new(store.clone(), Arc::new(Upstream)));
    let session = store.get_session("sess_demo").unwrap().unwrap();
    let params = serde_json::json!({ "owner": "synthetic", "repo": "synthetic" });
    let connection = store.list_connections().unwrap().into_iter().find(|c| c.secret_id == id).unwrap();

    let needles = oauth_needles();
    let w = watch(&needles);
    let json = permaura_gateway::oauth_connect::to_sealed_json(&credential(1)).unwrap();
    let sealed = permaura_core::seal(Cipher::Aes256Gcm, vault_passphrase(), json.as_bytes()).unwrap();
    drop(json);
    store.put_secret(SecretRecord { id: id.clone(), sealed, metadata: old.metadata }).unwrap();
    for _ in 0..2 {
        let outcome = service.invoke(&session, "github.pull_requests.list", &params, None, ExecutionLocation::LocalOnly).await.unwrap();
        assert!(matches!(outcome, InvokeOutcome::Allowed { .. }));
    }
    assert_eq!(w.hits(), 0, "an OAuth invoke left a copy of a token or the client secret in freed memory");

    let pending = permaura_gateway::oauth_connect::PendingAuth { token_auth: Default::default(), refresh_grant: Default::default(),
        connection_id: connection.id.clone(),
        provider: "synthetic".into(),
        client_id: "synthetic-client".into(),
        client_secret: CLIENT.into(),
        redirect_uri: "http://127.0.0.1:7376/oauth/callback".into(),
        token_url: "https://provider.example/token".into(),
        code_verifier: Some(SecretString::from(VERIFIER)),
        scopes: vec![],
        created_ms: 0,
        binding: permaura_gateway::oauth_connect::PendingBinding::capture(&service, &connection, &session, false).unwrap(),
    };
    let cred = permaura_gateway::oauth_connect::exchange_code(&Upstream, &pending, "synthetic-code", 0).await.unwrap();
    assert_eq!(cred.access_token, MINTED);
    drop(cred);
    drop(pending);
    assert_eq!(w.hits(), 0, "a code exchange left a copy of a token, the client secret or the verifier in freed memory");
    // Every owner of a copy is dropped under the watch, so one a cache or a store row retained is freed and counted here.
    drop(session);
    drop(connection);
    drop(service);
    drop(store);
    assert_eq!(w.hits(), 0, "the service or the store retained a copy of a token or the client secret: {:?}", w.last_hit());
}

#[tokio::test]
async fn an_invoke_with_a_credential_that_is_not_utf8_leaves_no_copy() {
    common::isolate_from_the_real_install();
    let store: Arc<dyn Store> = Arc::new(MemoryStore::new());
    permaura_gateway::seed::seed(store.as_ref()).unwrap();
    let id = store.get_capability("github.pull_requests.list").unwrap().unwrap().secret_id;
    let old = store.get_secret(&id).unwrap().unwrap();
    let service = Arc::new(EnforcementService::new(store.clone(), Arc::new(Upstream)));
    let session = store.get_session("sess_demo").unwrap().unwrap();
    let params = serde_json::json!({ "owner": "synthetic", "repo": "synthetic" });

    let needles: Vec<&'static [u8]> = [API_KEY, RESERVED_KEY].into_iter().flat_map(needles_for).collect();
    let w = watch(&needles);
    for key in [API_KEY, RESERVED_KEY] {
        let not_utf8 = Zeroizing::new([key.as_bytes(), b"\xff\xfe"].concat());
        let sealed = permaura_core::seal(Cipher::Aes256Gcm, vault_passphrase(), &not_utf8).unwrap();
        drop(not_utf8);
        store.put_secret(SecretRecord { id: id.clone(), sealed, metadata: old.metadata.clone() }).unwrap();
        let outcome = service.invoke(&session, "github.pull_requests.list", &params, None, ExecutionLocation::LocalOnly).await.unwrap();
        assert!(matches!(outcome, InvokeOutcome::Allowed { .. }));
    }
    drop(session);
    drop(service);
    drop(store);
    assert_eq!(w.hits(), 0, "an invoke with a credential that is not UTF-8 left a copy in freed memory: {:?}", w.last_hit());
}

#[tokio::test]
async fn escaped_answers_from_a_vault_and_a_token_endpoint_are_unescaped_without_an_unwiped_copy() {
    use permaura_gateway::backend::{InfisicalBackend, InfisicalConfig};
    let needles: Vec<&'static [u8]> = [PEM_LINE, PHP_TOKEN, ACCESS, CLIENT].into_iter().flat_map(needles_for).collect();
    let w = watch(&needles);
    let backend = InfisicalBackend::new(
        InfisicalConfig {
            base_url: "https://vault.example".into(),
            client_id: "machine".into(),
            client_secret: CLIENT.into(),
            project_id: "proj".into(),
            environment: "prod".into(),
            secret_path: "/".into(),
        },
        Arc::new(Upstream),
    );
    let opened = backend.resolve("sec_pem").await.unwrap();
    // Compared in place: a formatted copy of the expected line would itself be a freed copy.
    let line = PEM_LINE.as_bytes();
    assert!(opened.bytes().windows(line.len() + 2).any(|w| w[0] == b'\n' && &w[1..=line.len()] == line && w[line.len() + 1] == b'\n'));
    drop(opened);
    drop(backend);
    assert_eq!(w.hits(), 0, "an escaped PEM from Infisical left a copy in freed memory: {:?}", w.last_hit());

    let mut cred = credential(1);
    cred.token_url = "https://php.example/token".into();
    let (token, updated) = permaura_gateway::oauth_credential::ensure_fresh(&cred, &Upstream, 1_000_000, 60_000).await.unwrap();
    assert_eq!(token, PHP_TOKEN);
    drop(token);
    drop(updated);
    drop(cred);
    assert_eq!(w.hits(), 0, "an escaped token answer left a copy in freed memory: {:?}", w.last_hit());
}

/// The shipped client, not a double: the form and the JSON body it sends are encoded and handed to the HTTP stack in buffers that are wiped when the stack lets them go. The loopback peer answers with nothing watched, so what the transport keeps of the answer is not in question here.
#[tokio::test]
async fn the_shipped_client_wipes_the_form_and_the_json_body_it_sends() {
    use permaura_gateway::connectors::ReqwestClient;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let needles: Vec<&'static [u8]> = [REFRESH, CLIENT].into_iter().flat_map(needles_for).collect();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut seen = Zeroizing::new(vec![0u8; 64 * 1024]);
            let mut n = 0;
            loop {
                let read = sock.read(&mut seen[n..]).await.unwrap();
                n += read;
                let text = &seen[..n];
                let Some(head_end) = text.windows(4).position(|w| w == b"\r\n\r\n") else {
                    if read == 0 { break; }
                    continue;
                };
                let head = std::str::from_utf8(&text[..head_end]).unwrap().to_ascii_lowercase();
                let length: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .map(|v| v.trim().parse().unwrap())
                    .unwrap_or(0);
                if n >= head_end + 4 + length || read == 0 {
                    break;
                }
            }
            assert!(n > 0);
            let answer = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 2\r\nconnection: close\r\n\r\n{}";
            sock.write_all(answer).await.unwrap();
            let _ = sock.shutdown().await;
        }
    });

    let w = watch(&needles);
    let client = ReqwestClient::loopback_for_tests(std::time::Duration::from_secs(10));
    let mut form = std::collections::BTreeMap::new();
    form.insert("grant_type".to_string(), "refresh_token".to_string());
    form.insert("refresh_token".to_string(), REFRESH.to_string());
    form.insert("client_secret".to_string(), CLIENT.to_string());
    let request = HttpRequest::post(format!("http://{addr}/token")).form_body(form).credentialed();
    let answer = client.send_secret(request).await.unwrap();
    assert_eq!(answer.status, 200);
    drop(answer);

    #[derive(serde::Serialize)]
    struct Login<'a> {
        client_secret: &'a SecretString,
    }
    let secret = SecretString::from(CLIENT);
    let request = HttpRequest::post(format!("http://{addr}/login")).secret_json_body(&Login { client_secret: &secret }).unwrap();
    drop(secret);
    let answer = client.send_secret(request).await.unwrap();
    assert_eq!(answer.status, 200);
    drop(answer);
    drop(client);
    server.await.unwrap();
    assert_eq!(w.hits(), 0, "a body the shipped client sent was freed unwiped: {:?}", w.last_hit());
}

#[test]
fn every_request_a_connector_builds_and_a_command_environment_are_wiped_when_dropped() {
    use permaura_gateway::connectors::{build_command, build_request_for, AuthScheme, Capability, CapabilityKind, CommandSpec, HttpSpec};
    let needles: Vec<&'static [u8]> = [API_KEY, RESERVED_KEY].into_iter().flat_map(needles_for).collect();
    let cap = |id: &str, auth: Option<AuthScheme>| Capability {
        id: id.into(),
        description: String::new(),
        risk: permaura_core::RiskTier::Low,
        action: permaura_core::Action::Read,
        requires_approval: false,
        resource: "probe".into(),
        secret_id: "sec_probe".into(),
        kind: CapabilityKind::Http,
        command: None,
        http: auth.map(|auth| HttpSpec {
            base_url: "https://api.example.com".into(),
            path: "/v1/items".into(),
            query_params: vec!["page".into()],
            auth,
            ..Default::default()
        }),
        ssh: None,
    };
    let page = serde_json::json!({ "page": "a-long-enough-page-token-to-make-the-query-grow" });
    let cases: Vec<(&str, Capability, serde_json::Value)> = vec![
        ("openapi", cap("probe.items.list", Some(AuthScheme::Bearer)), page.clone()),
        ("openapi", cap("probe.items.list", Some(AuthScheme::Basic { key_as_username: true })), page.clone()),
        ("openapi", cap("probe.items.list", Some(AuthScheme::Basic { key_as_username: false })), page.clone()),
        ("openapi", cap("probe.items.list", Some(AuthScheme::ApiKeyHeader { header: "X-Api-Key".into() })), page.clone()),
        ("openapi", cap("probe.items.list", Some(AuthScheme::ApiKeyQuery { param: "api_key".into() })), page.clone()),
        ("openapi", cap("probe.items.list", Some(AuthScheme::Raw { header: "Authorization".into(), prefix: "Token token=".into() })), page),
        ("github", cap("github.pull_requests.list", None), serde_json::json!({ "owner": "o", "repo": "r" })),
        ("braintree", cap("braintree.transactions.search", None), serde_json::json!({})),
        ("vercel", cap("vercel.projects.list", None), serde_json::json!({})),
        ("fal", cap("fal.image.generate", None), serde_json::json!({ "prompt": "p" })),
        ("generic_http", cap("generic_http.http.request", None), serde_json::json!({ "url": "https://api.example.com/x" })),
    ];
    let spec = CommandSpec {
        program: "vercel".into(),
        args_template: vec!["whoami".into()],
        secret_env: "VERCEL_TOKEN".into(),
        allowed_placeholders: vec![],
    };

    let w = watch(&needles);
    for key in [API_KEY, RESERVED_KEY] {
        for (connector, cap, params) in &cases {
            let request = build_request_for(connector, cap, params, key.as_bytes()).unwrap();
            // Formatting a request for a log must not copy the credential on the way to redacting it.
            let shown = format!("{request:?}");
            assert!(!shown.contains("probe"), "{shown}");
            drop(shown);
            drop(request);
            assert_eq!(w.hits(), 0, "a {connector} request for {} left the credential in freed memory: {:?}", cap.id, w.last_hit());
        }
    }
    let not_utf8 = Zeroizing::new([API_KEY.as_bytes(), b"\xff"].concat());
    drop(build_request_for("openapi", &cases[0].1, &cases[0].2, &not_utf8).unwrap());
    assert_eq!(w.hits(), 0, "a credential that is not UTF-8 left a copy in freed memory");
    for key in [API_KEY, RESERVED_KEY] {
        drop(build_command(&spec, &serde_json::json!({}), key.as_bytes()).unwrap());
    }
    assert_eq!(w.hits(), 0, "a command's environment left the credential in freed memory");
}

#[tokio::test]
async fn the_infisical_backends_leave_no_copy_of_what_they_resolve_or_mint() {
    use permaura_gateway::backend::{DynamicSecretRef, InfisicalBackend, InfisicalConfig, InfisicalDynamicBackend, InfisicalDynamicConfig};
    let needles: Vec<&'static [u8]> = [API_KEY, ACCESS, CLIENT].into_iter().flat_map(needles_for).collect();
    let w = watch(&needles);
    let backend = InfisicalBackend::new(
        InfisicalConfig {
            base_url: "https://vault.example".into(),
            client_id: "machine".into(),
            client_secret: CLIENT.into(),
            project_id: "proj".into(),
            environment: "prod".into(),
            secret_path: "/".into(),
        },
        Arc::new(Upstream),
    );
    let opened = backend.resolve("sec_probe").await.unwrap();
    assert_eq!(opened.bytes(), API_KEY.as_bytes());
    drop(opened);
    drop(backend);
    assert_eq!(w.hits(), 0, "an Infisical fetch left the secret, its login token or the machine secret in freed memory");

    let dynamic = InfisicalDynamicBackend::new(
        InfisicalDynamicConfig {
            base_url: "https://vault.example".into(),
            client_id: "machine".into(),
            client_secret: CLIENT.into(),
            project_slug: "proj".into(),
            environment: "prod".into(),
            path: "/".into(),
            ttl: "1m".into(),
            secrets: [("sec_db".to_string(), DynamicSecretRef { name: "pg".into(), field: Some("DB_PASSWORD".into()) })].into_iter().collect(),
        },
        Arc::new(Upstream),
    );
    let (opened, lease) = dynamic.acquire("sec_db").await.unwrap().into_parts();
    assert_eq!(opened.bytes(), API_KEY.as_bytes());
    drop(opened);
    dynamic.release(&lease.unwrap()).await;
    drop(dynamic);
    assert_eq!(w.hits(), 0, "an Infisical mint left the credential, its login token or the machine secret in freed memory");
}

/// The type-level half of the pin, for the items it names and only those: each function and field here names a wiping type, so changing one back to a plain `String`, `Vec` or `serde_json::Value` stops this binary compiling. The private members (token answers, Infisical and GCP KMS answers, cached tokens, `SecretValue`'s buffer) are pinned by `#[cfg(test)]` items inside the gateway, where they can be named; `HttpRequest`'s and `CommandInvocation`'s plain strings are wiped by `Drop`, which no type check can express, so the runtime half holds those.
#[allow(dead_code)]
fn credential_paths_name_wiping_types() {
    use permaura_gateway::connectors::SecretHttpResponse;
    use permaura_gateway::oauth_connect::PendingAuth;
    use permaura_gateway::vault_bundle::{BundlePayload, BundleSecret, OpenPayloadError, SecretValue};
    let _: fn(&[u8]) -> Option<OAuthCredential> = permaura_gateway::oauth_connect::from_sealed_bytes;
    let _: fn(&OAuthCredential) -> Result<SecretString, permaura_gateway::error::GatewayError> = permaura_gateway::oauth_connect::to_sealed_json;
    let _: fn(&permaura_core::VaultBundle, &[u8]) -> Result<BundlePayload, OpenPayloadError> = permaura_gateway::vault_bundle::open_payload;
    fn oauth_fields(c: &OAuthCredential) -> (&SecretString, Option<&SecretString>, Option<&SecretString>) {
        (&c.access_token, c.refresh_token.as_ref(), c.client_secret.as_ref())
    }
    fn pending_fields(p: &PendingAuth) -> (&SecretString, Option<&SecretString>) {
        (&p.client_secret, p.code_verifier.as_ref())
    }
    fn answer_body(r: &SecretHttpResponse) -> &Zeroizing<Vec<u8>> {
        &r.body
    }
    fn bundle_value(s: &BundleSecret) -> &SecretValue {
        &s.value
    }
    let _ = (oauth_fields, pending_fields, answer_body, bundle_value);
}

#[allow(dead_code)]
async fn credential_returning_async_functions_name_wiping_types(
    kms: &dyn permaura_gateway::backend::KmsClient,
    cred: &OAuthCredential,
    pending: &permaura_gateway::oauth_connect::PendingAuth,
) {
    use permaura_gateway::error::GatewayError;
    let _: Result<Zeroizing<Vec<u8>>, GatewayError> = kms.decrypt("", b"").await;
    let _: Result<(SecretString, Option<OAuthCredential>), GatewayError> =
        permaura_gateway::oauth_credential::ensure_fresh(cred, &Upstream, 0, 0).await;
    let _: Result<OAuthCredential, GatewayError> = permaura_gateway::oauth_connect::exchange_code(&Upstream, pending, "", 0).await;
}
