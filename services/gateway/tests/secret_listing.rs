//! `GET /v1/secrets`, which `permaura vault list`, the console and the phone read, lists exactly the secrets an operator can name: every sealed row except a credential change parked for approval, plus every id an external custodian holds, each with where it is held.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use permaura_core::{seal, Cipher, SecretMetadata, SecretRecord};
use permaura_gateway::service::vault_passphrase;
use permaura_gateway::store::SecretCustody;
use permaura_gateway::{build_router, seed};
use serde_json::Value;
use tower::ServiceExt;

#[tokio::test]
async fn the_listing_is_the_secrets_an_operator_can_name() {
    common::isolate_from_the_real_install();
    let state = common::seeded();
    let store = state.service.store().clone();
    let sealed = |v: &[u8]| seal(Cipher::Aes256Gcm, vault_passphrase(), v).unwrap();
    let staged = format!("{}listing", permaura_gateway::secret_inventory::STAGING_SECRET_PREFIX);
    store.put_secret(SecretRecord { id: staged.clone(), sealed: sealed(b"parked"), metadata: SecretMetadata::default() }).unwrap();
    store.put_secret(SecretRecord { id: "sec_listed_local".into(), sealed: sealed(b"local"), metadata: SecretMetadata { labels: vec!["ci".into()], ..SecretMetadata::default() } }).unwrap();
    store.put_secret_custody(SecretCustody::kms("sec_listed_kms", b"wrapped".to_vec(), "projects/p/locations/l/keyRings/r/cryptoKeys/k", 0)).unwrap();
    store.put_secret_custody(SecretCustody::infisical("sec_listed_infisical", Some("BOX".into()), 0)).unwrap();

    let resp = build_router(state, "127.0.0.1:7376".parse().unwrap())
        .oneshot(Request::builder().uri("/v1/secrets").header("authorization", format!("Bearer {}", seed::DEMO_TOKEN)).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = serde_json::from_slice(&axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap()).unwrap();
    let rows = body["secrets"].as_array().expect("a list");
    let find = |id: &str| rows.iter().find(|r| r["id"] == id).cloned();
    assert!(find(&staged).is_none(), "a parked credential change is not a secret anyone can name: {body}");
    let local = find("sec_listed_local").expect("a sealed row is listed");
    assert_eq!(local["location"], "local_vault", "{local}");
    assert_eq!(local["labels"], serde_json::json!(["ci"]), "{local}");
    assert_eq!(find("sec_listed_kms").expect("a KMS-held id is listed")["location"], "kms");
    assert_eq!(find("sec_listed_infisical").expect("an Infisical-held id is listed")["location"], "infisical");
    for row in rows {
        assert!(row["location"].is_string(), "every row says where it is held: {row}");
        assert!(row.get("value").is_none() && row.get("sealed").is_none(), "never a value: {row}");
    }
}
