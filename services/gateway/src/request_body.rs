//! The extractors every mutating REST route reads its body with.
//!
//! A request member the gateway does not read is refused, never dropped: a dropped member answers 2xx for a request that did less than it said, and tells a caller who sent a constraint the gateway does not have that it was applied.
//! Each request type is `#[serde(deny_unknown_fields)]`, and these turn its refusal into a 400 in the gateway's own `{ "error": ... }` shape naming the member, where axum's own rejection is a `text/plain` 422.

use axum::async_trait;
use axum::body::Bytes;
use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::json;

use crate::error::GatewayError;

/// The start of every refusal this module writes for a body that is not JSON or does not fit the route's request type, after the `bad request: ` the error type adds.
pub const INVALID_BODY: &str = "invalid request body";

/// A required JSON request body, refused as [`json_rejection`] describes.
pub struct JsonBody<T>(pub T);

#[async_trait]
impl<T, S> FromRequest<S> for JsonBody<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        refuse_without_json_content_type(req.headers(), state).await?;
        let bytes = body_bytes(req, state).await?;
        Ok(JsonBody(one_value(&bytes)?))
    }
}

/// A JSON request body that may be left out: an empty body or `null` is `None`, and anything else is read as [`JsonBody`] reads it.
/// `Option<Json<T>>` is not this, because it answers `None` for any body that fails to parse, so a body carrying an unknown member was read as no body at all.
pub struct OptionalJsonBody<T>(pub Option<T>);

#[async_trait]
impl<T, S> FromRequest<S> for OptionalJsonBody<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = body_bytes(req, state).await?;
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(OptionalJsonBody(None));
        }
        Ok(OptionalJsonBody(one_value::<Option<T>>(&bytes)?))
    }
}

/// The body of a mutating route that reads none: empty, `{}` or `null`. A member sent to such a route would be ignored, so it is refused like any other unknown member.
pub struct NoBody;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[async_trait]
impl<S> FromRequest<S> for NoBody
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = body_bytes(req, state).await?;
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok(NoBody);
        }
        one_value::<Option<Empty>>(&bytes)?;
        Ok(NoBody)
    }
}

/// The body's bytes, a refusal to read them (over the route's limit, a broken stream) answered in the gateway's shape.
async fn body_bytes<S: Send + Sync>(req: Request, state: &S) -> Result<Bytes, Response> {
    Bytes::from_request(req, state).await.map_err(|e| json_rejection(JsonRejection::from(e)))
}

/// axum's own content-type refusal for a JSON body, read from the headers alone so the body is read once.
pub async fn refuse_without_json_content_type<S: Send + Sync>(headers: &axum::http::HeaderMap, state: &S) -> Result<(), Response> {
    let mut probe = Request::new(axum::body::Body::empty());
    *probe.headers_mut() = headers.clone();
    match Json::<serde::de::IgnoredAny>::from_request(probe, state).await {
        Err(missing @ JsonRejection::MissingJsonContentType(_)) => Err(json_rejection(missing)),
        _ => Ok(()),
    }
}

/// `bytes` read as exactly one JSON value of type `T`. axum's reading stops after the first value, so `{"paused":false}{"paused":true}` read as `false` while a second reader (the web proxy's `JSON.parse`) refused it; anything after the value is refused here.
pub fn one_value<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, Response> {
    let Json(value) = Json::<T>::from_bytes(bytes).map_err(json_rejection)?;
    nothing_after(bytes)?;
    Ok(value)
}

/// A refusal of anything after the first JSON value in `bytes`, which has already been read once.
pub fn nothing_after(bytes: &[u8]) -> Result<(), Response> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    serde::de::IgnoredAny::deserialize(&mut de).and_then(|_| de.end()).map_err(|e| invalid_body(&e.to_string()))
}

/// A body axum's JSON reading refused, in the gateway's error shape.
/// One that is not JSON, or does not fit the route's request type (an unknown member, a missing or mistyped one), is a 400 saying what was wrong with it, a member named by its path; anything else (no JSON content type, a body over the route's limit) keeps axum's status and says so in the same shape.
pub fn json_rejection(rejection: JsonRejection) -> Response {
    match rejection {
        JsonRejection::JsonDataError(e) => invalid_body(&e.body_text()),
        JsonRejection::JsonSyntaxError(e) => invalid_body(&e.body_text()),
        other => (other.status(), Json(json!({ "error": other.body_text() }))).into_response(),
    }
}

/// axum's text is "<what failed>: <serde's own words>", and only serde's half says anything about the body.
fn invalid_body(text: &str) -> Response {
    let detail = text.split_once(": ").map_or(text, |(_, detail)| detail);
    GatewayError::BadRequest(format!("{INVALID_BODY}: {detail}")).into_response()
}

// ── Strict readings of shared types ─────────────────────────────────────────────
//
// A request member typed with a type that stored rows, presets or exported documents are also read with cannot have that type refuse an unknown member, so the request reads it through a strict mirror here and converts.

/// A request's auth scheme, read strictly into the shared [`crate::connectors::AuthScheme`].
pub fn strict_auth<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<crate::connectors::AuthScheme>, D::Error> {
    Ok(Option::<AuthSchemeReq>::deserialize(d)?.map(Into::into))
}

/// A request's intermediate certificate, read strictly into the shared [`crate::manifest::IntermediateCert`].
pub fn strict_cert<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<crate::manifest::IntermediateCert>, D::Error> {
    Ok(Option::<IntermediateCertReq>::deserialize(d)?.map(Into::into))
}

/// A request's vault bundle, read strictly into the shared [`permaura_core::VaultBundle`]. A bundle from a later gateway is refused with the upgrade message, not as an unknown member: `source` and `sealed` are kept as raw text until the whole envelope has been read, wherever its `version` sits (a serializer that sorts keys puts it last), and read strictly only once the version is one this build reads.
pub fn strict_bundle<'de, D: serde::Deserializer<'de>>(d: D) -> Result<permaura_core::VaultBundle, D::Error> {
    Ok(d.deserialize_map(BundleVisitor)?.into())
}

/// A request's legacy grant target, `"all_agents"` or `{ "agent": <id> }`, read strictly into the shared [`permaura_core::GrantTarget`]: its own externally tagged reading refuses a second member without naming it.
pub fn strict_target<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<permaura_core::GrantTarget>, D::Error> {
    struct Target;
    impl<'de> serde::de::Visitor<'de> for Target {
        type Value = Option<permaura_core::GrantTarget>;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("\"all_agents\" or an object with one member, agent")
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
            match v {
                "all_agents" => Ok(Some(permaura_core::GrantTarget::AllAgents)),
                other => Err(E::unknown_variant(other, &["all_agents", "agent"])),
            }
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(self, map: A) -> Result<Self::Value, A::Error> {
            let target = GrantTargetAgentReq::deserialize(serde::de::value::MapAccessDeserializer::new(map))?;
            Ok(Some(permaura_core::GrantTarget::Agent(target.agent)))
        }
    }
    d.deserialize_any(Target)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantTargetAgentReq {
    agent: String,
}

#[derive(Deserialize)]
#[serde(tag = "scheme", rename_all = "snake_case", deny_unknown_fields)]
enum AuthSchemeReq {
    Bearer {},
    Basic {
        #[serde(default)]
        key_as_username: bool,
    },
    ApiKeyHeader {
        header: String,
    },
    ApiKeyQuery {
        param: String,
    },
    Raw {
        header: String,
        #[serde(default)]
        prefix: String,
    },
}

impl From<AuthSchemeReq> for crate::connectors::AuthScheme {
    fn from(auth: AuthSchemeReq) -> Self {
        use crate::connectors::AuthScheme;
        match auth {
            AuthSchemeReq::Bearer {} => AuthScheme::Bearer,
            AuthSchemeReq::Basic { key_as_username } => AuthScheme::Basic { key_as_username },
            AuthSchemeReq::ApiKeyHeader { header } => AuthScheme::ApiKeyHeader { header },
            AuthSchemeReq::ApiKeyQuery { param } => AuthScheme::ApiKeyQuery { param },
            AuthSchemeReq::Raw { header, prefix } => AuthScheme::Raw { header, prefix },
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IntermediateCertReq {
    key_id: String,
    pubkey: String,
    issued_at: i64,
    expires_at: i64,
    root_key_id: String,
    root_sig: String,
}

impl From<IntermediateCertReq> for crate::manifest::IntermediateCert {
    fn from(c: IntermediateCertReq) -> Self {
        crate::manifest::IntermediateCert {
            key_id: c.key_id,
            pubkey: c.pubkey,
            issued_at: c.issued_at,
            expires_at: c.expires_at,
            root_key_id: c.root_key_id,
            root_sig: c.root_sig,
        }
    }
}

/// A bundle as [`BundleVisitor`] reads it: by hand, so its version is known before `source` and `sealed` are read strictly, refusing an unknown member as the derived mirrors do.
struct VaultBundleReq {
    format: String,
    version: u32,
    created_at_ms: i64,
    source: BundleSourceReq,
    sealed: SealedSecretReq,
}

const BUNDLE_FIELDS: &[&str] = &["format", "version", "created_at_ms", "source", "sealed"];

struct BundleVisitor;

impl<'de> serde::de::Visitor<'de> for BundleVisitor {
    type Value = VaultBundleReq;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a Permaura vault bundle")
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(self, mut map: A) -> Result<VaultBundleReq, A::Error> {
        use serde::de::Error as _;
        let (mut format, mut version, mut created_at_ms, mut source, mut sealed) = (None, None, None, None, None);
        let mut unknown: Option<String> = None;
        while let Some(key) = map.next_key::<String>()? {
            let seen = match key.as_str() {
                "format" => format.replace(map.next_value::<String>()?).is_some(),
                "version" => version.replace(map.next_value::<u32>()?).is_some(),
                "created_at_ms" => created_at_ms.replace(map.next_value::<i64>()?).is_some(),
                "source" => source.replace(map.next_value::<Box<serde_json::value::RawValue>>()?).is_some(),
                "sealed" => sealed.replace(map.next_value::<Box<serde_json::value::RawValue>>()?).is_some(),
                other => {
                    map.next_value::<serde::de::IgnoredAny>()?;
                    if unknown.is_none() {
                        unknown = Some(other.to_string());
                    }
                    false
                }
            };
            if seen {
                return Err(A::Error::custom(format!("duplicate field `{key}`")));
            }
        }
        if let Some(v) = version.filter(|v| *v > permaura_core::BUNDLE_VERSION) {
            return Err(A::Error::custom(format!(
                "bundle version {v} is newer than this build understands (max {}): upgrade the gateway before importing",
                permaura_core::BUNDLE_VERSION
            )));
        }
        if let Some(key) = unknown {
            return Err(A::Error::unknown_field(&key, BUNDLE_FIELDS));
        }
        let source = match source {
            Some(raw) => nested::<BundleSourceReq, A::Error>("source", &raw)?,
            None => BundleSourceReq::default(),
        };
        let sealed = sealed.ok_or_else(|| A::Error::missing_field("sealed"))?;
        Ok(VaultBundleReq {
            format: format.ok_or_else(|| A::Error::missing_field("format"))?,
            version: version.ok_or_else(|| A::Error::missing_field("version"))?,
            created_at_ms: created_at_ms.ok_or_else(|| A::Error::missing_field("created_at_ms"))?,
            source,
            sealed: nested::<SealedSecretReq, A::Error>("sealed", &sealed)?,
        })
    }
}

/// A bundle member kept as raw text, read strictly now, its error naming the member's path under `name`.
fn nested<T: DeserializeOwned, E: serde::de::Error>(name: &str, raw: &serde_json::value::RawValue) -> Result<T, E> {
    Json::<T>::from_bytes(raw.get().as_bytes()).map(|Json(value)| value).map_err(|rejection| {
        let text = rejection.body_text();
        let detail = text.split_once(": ").map_or(text.as_str(), |(_, detail)| detail);
        match detail.split_once(": ") {
            Some((path, why)) if !path.contains(' ') => E::custom(format!("{name}.{path}: {why}")),
            _ => E::custom(format!("{name}: {detail}")),
        }
    })
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct BundleSourceReq {
    #[serde(default)]
    gateway_id: String,
    #[serde(default)]
    mode: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedSecretReq {
    cipher: permaura_core::Cipher,
    ciphertext: Vec<u8>,
    nonce: Vec<u8>,
    wrapped_dek: Vec<u8>,
    dek_nonce: Vec<u8>,
    kdf_params: KdfParamsReq,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfParamsReq {
    salt: Vec<u8>,
    mem_cost_kib: u32,
    time_cost: u32,
    parallelism: u32,
}

impl From<VaultBundleReq> for permaura_core::VaultBundle {
    fn from(b: VaultBundleReq) -> Self {
        let s = b.sealed;
        permaura_core::VaultBundle {
            format: b.format,
            version: b.version,
            created_at_ms: b.created_at_ms,
            source: permaura_core::BundleSource { gateway_id: b.source.gateway_id, mode: b.source.mode },
            sealed: permaura_core::SealedSecret {
                cipher: s.cipher,
                ciphertext: s.ciphertext,
                nonce: s.nonce,
                wrapped_dek: s.wrapped_dek,
                dek_nonce: s.dek_nonce,
                kdf_params: permaura_core::KdfParams {
                    salt: s.kdf_params.salt,
                    mem_cost_kib: s.kdf_params.mem_cost_kib,
                    time_cost: s.kdf_params.time_cost,
                    parallelism: s.kdf_params.parallelism,
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connectors::AuthScheme;

    /// One value of every [`AuthScheme`] variant. The match has no wildcard, so a new variant fails to compile here until the mirror reads it too: the console echoes a dry run's own scheme back, and the gateway must not refuse its own answer.
    fn one_of_each() -> Vec<AuthScheme> {
        let every = [
            AuthScheme::Bearer,
            AuthScheme::Basic { key_as_username: true },
            AuthScheme::ApiKeyHeader { header: "X-Api-Key".into() },
            AuthScheme::ApiKeyQuery { param: "api_key".into() },
            AuthScheme::Raw { header: "Authorization".into(), prefix: "Token ".into() },
        ];
        for scheme in &every {
            match scheme {
                AuthScheme::Bearer | AuthScheme::Basic { .. } | AuthScheme::ApiKeyHeader { .. } | AuthScheme::ApiKeyQuery { .. } | AuthScheme::Raw { .. } => {}
            }
        }
        every.to_vec()
    }

    #[test]
    fn every_auth_scheme_the_gateway_writes_reads_back_through_the_mirror() {
        for scheme in one_of_each() {
            let text = serde_json::to_string(&scheme).unwrap();
            let read = strict_auth(&mut serde_json::Deserializer::from_str(&text)).unwrap_or_else(|e| panic!("{text}: {e}"));
            assert_eq!(read, Some(scheme), "{text}");
        }
    }

    #[test]
    fn a_unit_scheme_refuses_a_member_beside_its_tag() {
        assert!(strict_auth(&mut serde_json::Deserializer::from_str(r#"{"scheme":"bearer","header":"X-API-Key"}"#)).is_err());
    }

    #[test]
    fn one_value_refuses_anything_after_it() {
        assert!(one_value::<serde_json::Value>(br#"{"paused":false}"#).is_ok());
        assert!(one_value::<serde_json::Value>(b"{\"paused\":false}  \n").is_ok());
        assert!(one_value::<serde_json::Value>(br#"{"paused":false}{"paused":true}"#).is_err());
        assert!(one_value::<serde_json::Value>(br#"{"paused":false} x"#).is_err());
    }
}
