//! OAuth connector credentials: the zero-knowledge refresh core.
//!
//! For a **Layer 3 (BYO app)** or **Layer 2 (PKCE)** connection, the gateway holds the OAuth token
//! bundle (and, for Layer 3, the client id/secret) and refreshes the access token **itself**: the
//! credential never leaves the worker, and permaura.com is not involved. The refreshed access token
//! is then injected via the connection's existing `AuthScheme::Bearer`, so the connector request path
//! is unchanged; only custody + refresh differ.
//!
//! A `Layer 1 (Managed)` connection does not use this path: permaura.com holds the refresh token and
//! hands the gateway a short-lived access token, so the gateway just uses it directly.

use permaura_core::SecretString;
use serde::{Deserialize, Serialize};

use crate::connectors::{HttpClient, HttpRequest};
use crate::error::GatewayError;

/// Which custody layer minted this credential. Drives whether the gateway refreshes
/// locally (`Pkce` / `ByoApp`) or treats the token as externally-managed (`Managed`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OAuthLayer {
    /// permaura.com holds the refresh token; the gateway gets a short-lived access token. No local refresh.
    Managed,
    /// Permaura's public app, PKCE; the gateway holds + refreshes the tokens (no client secret).
    Pkce,
    /// The user's own app; the gateway holds the client id/secret + tokens and refreshes locally.
    #[default]
    ByoApp,
}

/// How the client id and secret reach the provider's token endpoint. RFC 6749 §2.3.1 makes HTTP Basic
/// the method every provider must accept and form fields an option, but in practice each provider takes
/// one and refuses the other: Google, GitHub, Slack and Dropbox want the form, Reddit answers 401 to
/// anything but the Basic header. Recorded on the credential so a refresh years later sends them the way
/// the exchange did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenAuth {
    /// `client_id` and `client_secret` as form fields in the request body.
    #[default]
    Body,
    /// An `Authorization: Basic` header over `client_id:client_secret`, nothing in the body.
    Basic,
}

/// How the gateway keeps an access token alive once the exchange is done. Almost every provider issues a
/// refresh token and takes it back at the token endpoint under `grant_type=refresh_token`. Meta issues
/// none: the code's short-lived user token is exchanged for a sixty-day one under
/// `grant_type=fb_exchange_token`, and a still-valid long-lived token can be exchanged the same way for a
/// fresh sixty days, so that exchange is the refresh. Recorded on the credential so a refresh sends the
/// grant the provider accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshGrant {
    /// `grant_type=refresh_token` with the refresh token the provider issued.
    #[default]
    RefreshToken,
    /// `grant_type=fb_exchange_token` with the current access token, which must still be valid.
    ExchangeToken,
}

impl RefreshGrant {
    /// Whether this grant renews the credential without a refresh token.
    pub fn renews_without_refresh_token(self) -> bool {
        self == RefreshGrant::ExchangeToken
    }
}

/// How far ahead of expiry an exchange-renewed token is exchanged again. The exchange needs a token
/// that is still valid, and a sixty-day token is used far less often than an hourly one, so the renewal
/// window is a week rather than the two minutes a refresh token gets: any call in the last week of the
/// token's life renews it for sixty more days.
pub const EXCHANGE_RENEWAL_WINDOW_MS: i64 = 7 * 24 * 60 * 60 * 1000;

/// A connection's OAuth credential, stored sealed (the same vault path as an API key). The access
/// token is what gets injected upstream; the rest is what the gateway needs to keep it fresh.
///
/// The access token, the refresh token and the client secret are [`SecretString`]s: wiped when the
/// credential drops, never printed by `Debug`, and read from the sealed bundle's raw text into a wiping
/// buffer, escaped or not. It is read only from a serde_json slice (`from_sealed_bytes`), which that needs.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OAuthCredential {
    /// Which custody layer this credential belongs to.
    #[serde(default)]
    pub layer: OAuthLayer,
    /// The provider key (e.g. `github`, `google`), for display + provider-specific quirks.
    pub provider: String,
    /// The current access token (injected as a Bearer).
    #[serde(deserialize_with = "permaura_core::secret::unescaped::deserialize")]
    pub access_token: SecretString,
    /// The refresh token, when the provider issued one. Absent → the gateway can't refresh.
    #[serde(default, deserialize_with = "permaura_core::secret::unescaped::option")]
    pub refresh_token: Option<SecretString>,
    /// Unix-millisecond expiry of the access token. `0` = unknown (treat as non-expiring).
    #[serde(default)]
    pub expires_at: i64,
    /// Granted scopes (informational + for re-auth diffing).
    #[serde(default)]
    pub scopes: Vec<String>,
    /// The provider's token endpoint, used to refresh.
    pub token_url: String,
    /// The OAuth client id (Layer 2/3). `None` for a Managed credential.
    #[serde(default)]
    pub client_id: Option<String>,
    /// The OAuth client secret (Layer 3 confidential app). `None` for PKCE (public client) / Managed.
    #[serde(default, deserialize_with = "permaura_core::secret::unescaped::option")]
    pub client_secret: Option<SecretString>,
    /// How the client credentials are presented at `token_url`.
    #[serde(default)]
    pub token_auth: TokenAuth,
    /// Which grant keeps the access token alive. A bundle sealed before the field existed refreshes with its refresh token.
    #[serde(default)]
    pub refresh_grant: RefreshGrant,
}

impl std::fmt::Debug for OAuthCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OAuthCredential")
            .field("layer", &self.layer)
            .field("provider", &self.provider)
            .field("expires_at", &self.expires_at)
            .field("scopes", &self.scopes)
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("refresh_token", &self.refresh_token.is_some())
            .field("client_secret", &self.client_secret.is_some())
            .field("token_auth", &self.token_auth)
            .field("refresh_grant", &self.refresh_grant)
            .finish_non_exhaustive()
    }
}

impl OAuthCredential {
    /// True if the access token is at or within `skew_ms` of expiry. `expires_at == 0` (unknown /
    /// non-expiring) is treated as fresh.
    pub fn needs_refresh(&self, now_ms: i64, skew_ms: i64) -> bool {
        let skew_ms = match self.refresh_grant {
            RefreshGrant::ExchangeToken => skew_ms.max(EXCHANGE_RENEWAL_WINDOW_MS),
            RefreshGrant::RefreshToken => skew_ms,
        };
        self.expires_at != 0 && now_ms.saturating_add(skew_ms) >= self.expires_at
    }

    /// Can this credential be refreshed locally by the gateway? (Has a refresh token, or a grant that
    /// renews without one, and isn't a Managed credential: those are refreshed by permaura.com.)
    pub fn is_locally_refreshable(&self) -> bool {
        self.layer != OAuthLayer::Managed && (self.refresh_token.is_some() || self.refresh_grant.renews_without_refresh_token())
    }

    /// The form a refresh sends to `token_url`, before the client credentials are added.
    fn refresh_form(&self) -> std::collections::BTreeMap<String, String> {
        let mut params = std::collections::BTreeMap::new();
        match self.refresh_grant {
            RefreshGrant::RefreshToken => {
                let refresh_token = self.refresh_token.as_ref().expect("is_locally_refreshable checked Some");
                params.insert("grant_type".to_string(), "refresh_token".to_string());
                params.insert("refresh_token".to_string(), refresh_token.expose().to_string());
            }
            RefreshGrant::ExchangeToken => {
                params.insert("grant_type".to_string(), "fb_exchange_token".to_string());
                params.insert("fb_exchange_token".to_string(), self.access_token.expose().to_string());
            }
        }
        params
    }
}

/// A request to a token endpoint: `form` as the `application/x-www-form-urlencoded` body (RFC 6749 §6:
/// Google, Xero, Slack, Dropbox and GitHub all reject JSON there) with the client credentials added
/// the way `token_auth` says. The Basic header's halves are form-encoded first as §2.3.1 requires,
/// which leaves the ids and secrets providers actually issue unchanged.
pub fn token_request(
    token_url: &str,
    mut form: std::collections::BTreeMap<String, String>,
    client_id: Option<&str>,
    client_secret: Option<&SecretString>,
    token_auth: TokenAuth,
) -> HttpRequest {
    let req = HttpRequest::post(token_url.to_string()).header("Accept", "application/json");
    let req = match token_auth {
        TokenAuth::Body => {
            if let Some(cid) = client_id {
                form.insert("client_id".to_string(), cid.to_string());
            }
            if let Some(sec) = client_secret {
                form.insert("client_secret".to_string(), sec.expose().to_string());
            }
            req
        }
        TokenAuth::Basic => {
            use base64::Engine;
            let mut pair = zeroize::Zeroizing::new(String::new());
            pair.push_str(&form_encode(client_id.unwrap_or_default()));
            pair.push(':');
            pair.push_str(&form_encode(client_secret.map(SecretString::expose).unwrap_or_default()));
            let encoded = zeroize::Zeroizing::new(base64::engine::general_purpose::STANDARD.encode(pair.as_bytes()));
            req.header("Authorization", format!("Basic {}", encoded.as_str()))
        }
    };
    req.form_body(form).credentialed()
}

/// `application/x-www-form-urlencoded` encoding of one value, as RFC 6749 §2.3.1 asks for the halves
/// of the Basic header.
fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'*' => out.push(b as char),
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// What the provider's token endpoint returns on a refresh.
#[derive(Deserialize)]
struct TokenResponse {
    #[serde(deserialize_with = "permaura_core::secret::unescaped::deserialize")]
    access_token: SecretString,
    /// Some providers rotate the refresh token on every refresh: persist it or the next refresh fails.
    #[serde(default, deserialize_with = "permaura_core::secret::unescaped::option")]
    refresh_token: Option<SecretString>,
    /// Seconds until the new access token expires.
    #[serde(default)]
    expires_in: Option<i64>,
}

/// Ensure a fresh access token for `cred`. Returns the token to use and, when the credential changed,
/// `Some(updated)` so the caller **persists** it: this is how a rotated refresh token survives.
///
/// Refreshes only when the token is near expiry **and** the credential is locally refreshable. A
/// Managed credential, or one with no refresh token, is returned as-is (a dead Managed/expired token
/// then fails the connector call, flipping the connection to `needs_reauth` upstream).
pub async fn ensure_fresh(
    cred: &OAuthCredential,
    http: &dyn HttpClient,
    now_ms: i64,
    skew_ms: i64,
) -> Result<(SecretString, Option<OAuthCredential>), GatewayError> {
    if !cred.needs_refresh(now_ms, skew_ms) || !cred.is_locally_refreshable() {
        return Ok((cred.access_token.clone(), None));
    }
    let req = token_request(
        &cred.token_url,
        cred.refresh_form(),
        cred.client_id.as_deref(),
        cred.client_secret.as_ref(),
        cred.token_auth,
    );

    let resp = http
        .send_secret(req)
        .await
        .map_err(|e| GatewayError::upstream("oauth refresh request failed", &e))?;
    if resp.status >= 400 {
        // Expired/revoked refresh token, bad client creds, etc. The caller marks the connection
        // needs_reauth; we surface a clear error rather than returning a stale token.
        return Err(GatewayError::Unauthorized(format!(
            "oauth refresh denied ({}) for provider '{}'",
            resp.status, cred.provider
        )));
    }
    let token: TokenResponse = serde_json::from_slice(&resp.body)
        .map_err(|e| GatewayError::Internal(format!("oauth refresh: bad token response: {e}")))?;
    drop(resp);

    let mut updated = cred.clone();
    updated.access_token = token.access_token.clone();
    if let Some(rotated) = token.refresh_token {
        updated.refresh_token = Some(rotated); // honour rotation
    }
    updated.expires_at = match token.expires_in {
        Some(secs) if secs > 0 => now_ms.saturating_add(secs.saturating_mul(1000)),
        _ => 0,
    };
    Ok((token.access_token, Some(updated)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The type-level pin for what this module reads: these stop compiling if a secret member stops being a wiping type.
    #[allow(dead_code)]
    fn secret_members_are_wiping_types<'a>(t: &'a TokenResponse, c: &'a OAuthCredential) -> [Option<&'a SecretString>; 5] {
        [Some(&t.access_token), t.refresh_token.as_ref(), Some(&c.access_token), c.refresh_token.as_ref(), c.client_secret.as_ref()]
    }
    use crate::connectors::{HttpResponse, MockHttpClient};

    fn cred(expires_at: i64, refresh: Option<&str>, layer: OAuthLayer) -> OAuthCredential {
        OAuthCredential {
            layer,
            provider: "github".into(),
            access_token: "old_access".into(),
            refresh_token: refresh.map(|s| s.into()),
            expires_at,
            scopes: vec!["repo".into()],
            token_url: "https://github.com/login/oauth/access_token".into(),
            client_id: Some("cid".into()),
            client_secret: Some("csec".into()),
            token_auth: TokenAuth::Body,
            refresh_grant: RefreshGrant::RefreshToken,
        }
    }

    #[tokio::test]
    async fn an_exchange_renewed_credential_refreshes_by_exchanging_its_own_token_a_week_ahead() {
        // Meta issues no refresh token; a valid long-lived token is exchanged for a new sixty-day one.
        let http = MockHttpClient::new();
        http.push_response(HttpResponse::json(200, serde_json::json!({ "access_token": "sixty_more_days", "token_type": "bearer", "expires_in": 5_184_000 })));
        let week = EXCHANGE_RENEWAL_WINDOW_MS;
        let mut c = cred(1_000_000 + week - 1, None, OAuthLayer::ByoApp);
        c.refresh_grant = RefreshGrant::ExchangeToken;
        assert!(c.is_locally_refreshable(), "renewable without a refresh token");
        let (tok, updated) = ensure_fresh(&c, &http, 1_000_000, 60_000).await.unwrap();
        assert_eq!(tok, "sixty_more_days");
        let updated = updated.expect("credential changed");
        assert_eq!(updated.expires_at, 1_000_000 + 5_184_000_000);
        assert!(updated.refresh_token.is_none());
        assert_eq!(updated.refresh_grant, RefreshGrant::ExchangeToken, "the renewed bundle keeps the grant");
        let form = http.last_request().unwrap().form.clone().unwrap_or_default();
        assert_eq!(form.get("grant_type").map(String::as_str), Some("fb_exchange_token"));
        assert_eq!(form.get("fb_exchange_token").map(String::as_str), Some("old_access"));
        assert_eq!(form.get("client_id").map(String::as_str), Some("cid"));
        assert_eq!(form.get("client_secret").map(String::as_str), Some("csec"));
        assert!(!form.contains_key("refresh_token"));

        // More than a week out it is left alone, where a refresh-token credential would have been too.
        let http = MockHttpClient::new();
        let mut far = cred(1_000_000 + week + 1, None, OAuthLayer::ByoApp);
        far.refresh_grant = RefreshGrant::ExchangeToken;
        let (tok, updated) = ensure_fresh(&far, &http, 1_000_000, 60_000).await.unwrap();
        assert_eq!(tok, "old_access");
        assert!(updated.is_none());
    }

    #[tokio::test]
    async fn body_token_auth_puts_the_client_credentials_in_the_form() {
        let http = MockHttpClient::new();
        http.push_response(HttpResponse::json(200, serde_json::json!({ "access_token": "new", "expires_in": 60 })));
        let c = cred(1, Some("rt"), OAuthLayer::ByoApp);
        ensure_fresh(&c, &http, 1_000_000, 60_000).await.unwrap();
        let sent = http.last_request().unwrap();
        assert!(sent.headers.get("Authorization").is_none());
        let form = sent.form.clone().unwrap_or_default();
        assert_eq!(form.get("client_id").map(String::as_str), Some("cid"));
        assert_eq!(form.get("client_secret").map(String::as_str), Some("csec"));
        assert_eq!(form.get("grant_type").map(String::as_str), Some("refresh_token"));
    }

    #[tokio::test]
    async fn basic_token_auth_sends_the_client_credentials_as_a_header_and_keeps_them_out_of_the_form() {
        // Reddit's token endpoint answers 401 to client credentials in the form, so a credential recorded
        // as Basic must refresh the way its exchange authenticated.
        let http = MockHttpClient::new();
        http.push_response(HttpResponse::json(200, serde_json::json!({ "access_token": "new", "expires_in": 86400 })));
        let mut c = cred(1, Some("rt"), OAuthLayer::ByoApp);
        c.token_auth = TokenAuth::Basic;
        let (tok, updated) = ensure_fresh(&c, &http, 1_000_000, 60_000).await.unwrap();
        assert_eq!(tok, "new");
        assert_eq!(updated.unwrap().token_auth, TokenAuth::Basic, "the refreshed bundle keeps the method");
        let sent = http.last_request().unwrap();
        // base64("cid:csec")
        assert_eq!(sent.headers.get("Authorization").map(String::as_str), Some("Basic Y2lkOmNzZWM="));
        let form = sent.form.clone().unwrap_or_default();
        assert!(!form.contains_key("client_id") && !form.contains_key("client_secret"), "{form:?}");
        assert_eq!(form.get("refresh_token").map(String::as_str), Some("rt"));
    }

    #[test]
    fn an_older_bundle_without_a_token_auth_reads_as_body() {
        // A bundle sealed before the field existed, read the way the invoke path reads one.
        let json = br#"{"kind":"permaura.oauth.v1","layer":"byo_app","provider":"github","access_token":"a","refresh_token":"r","expires_at":0,"scopes":[],"token_url":"https://t.example/token","client_id":"c","client_secret":"s"}"#;
        let c = crate::oauth_connect::from_sealed_bytes(json).unwrap();
        assert_eq!(c.token_auth, TokenAuth::Body);
    }

    #[tokio::test]
    async fn fresh_token_is_returned_without_refreshing() {
        let http = MockHttpClient::new(); // no responses queued: a refresh would panic/error
        let c = cred(10_000_000, Some("rt"), OAuthLayer::ByoApp);
        let (tok, updated) = ensure_fresh(&c, &http, 1_000, 60_000).await.unwrap();
        assert_eq!(tok, "old_access");
        assert!(updated.is_none());
    }

    #[tokio::test]
    async fn near_expiry_refreshes_and_rotates_the_refresh_token() {
        let http = MockHttpClient::new();
        http.push_response(HttpResponse::json(
            200,
            serde_json::json!({ "access_token": "new_access", "refresh_token": "rotated_rt", "expires_in": 3600 }),
        ));
        // now=1_000_000, expires at 1_010_000, skew 60_000 → within skew → refresh.
        let c = cred(1_010_000, Some("old_rt"), OAuthLayer::ByoApp);
        let (tok, updated) = ensure_fresh(&c, &http, 1_000_000, 60_000).await.unwrap();
        assert_eq!(tok, "new_access");
        let updated = updated.expect("credential changed");
        assert_eq!(updated.access_token, "new_access");
        assert_eq!(updated.refresh_token.as_ref().map(SecretString::expose), Some("rotated_rt"), "rotation must be persisted");
        assert_eq!(updated.expires_at, 1_000_000 + 3_600_000);
    }

    #[tokio::test]
    async fn managed_credential_is_never_refreshed_locally() {
        let http = MockHttpClient::new();
        let c = cred(1, Some("rt"), OAuthLayer::Managed); // expired, but Managed → permaura.com refreshes
        let (tok, updated) = ensure_fresh(&c, &http, 1_000_000, 60_000).await.unwrap();
        assert_eq!(tok, "old_access");
        assert!(updated.is_none());
    }

    #[tokio::test]
    async fn no_refresh_token_returns_current_token() {
        let http = MockHttpClient::new();
        let c = cred(1, None, OAuthLayer::ByoApp); // expired, no refresh token
        let (tok, updated) = ensure_fresh(&c, &http, 1_000_000, 60_000).await.unwrap();
        assert_eq!(tok, "old_access");
        assert!(updated.is_none());
    }

    #[tokio::test]
    async fn refresh_denied_is_unauthorized() {
        let http = MockHttpClient::new();
        http.push_response(HttpResponse::json(401, serde_json::json!({ "error": "bad_refresh_token" })));
        let c = cred(1, Some("dead_rt"), OAuthLayer::ByoApp);
        assert!(matches!(
            ensure_fresh(&c, &http, 1_000_000, 60_000).await.unwrap_err(),
            GatewayError::Unauthorized(_)
        ));
    }
}
