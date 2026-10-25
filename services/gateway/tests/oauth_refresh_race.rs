//! Independent synthetic refresh-race regression. No network, real keys or providers.
use std::sync::{Arc,atomic::{AtomicUsize,Ordering}};
use async_trait::async_trait;
use permaura_core::{Cipher,ExecutionLocation,SecretRecord,seal,open};
use permaura_gateway::{connectors::{HttpClient,HttpRequest,HttpResponse},oauth_credential::{OAuthCredential,OAuthLayer},oauth_connect::{to_sealed_json,from_sealed_bytes},service::{EnforcementService,InvokeOutcome,vault_passphrase},store::{Store,memory::MemoryStore},seed};
use tokio::sync::{Notify,Semaphore};
mod common;
struct Provider { entered:Notify, release:Semaphore, refreshes:AtomicUsize }
#[async_trait]
impl HttpClient for Provider {
 async fn send(&self,r:HttpRequest)->anyhow::Result<HttpResponse>{
  if r.url=="https://provider.example/token" {
   let n=self.refreshes.fetch_add(1,Ordering::SeqCst);
   self.entered.notify_one();
   self.release.acquire().await.unwrap().forget();
   if n>0 {return Ok(HttpResponse::json(400,serde_json::json!({"error":"refresh_token_already_used"})));}
   return Ok(HttpResponse::json(200,serde_json::json!({"access_token":"synthetic-refreshed","refresh_token":"synthetic-rotated","expires_in":3600})));
  }
  Ok(HttpResponse::json(200,serde_json::json!({"data":[]})))
 }
}
fn cred(access:&str,expiry:i64)->OAuthCredential {OAuthCredential{ token_auth: Default::default(),layer:OAuthLayer::ByoApp,provider:"synthetic".into(),access_token:access.into(),refresh_token:Some("synthetic-old-refresh".into()),expires_at:expiry,scopes:vec![],token_url:"https://provider.example/token".into(),client_id:Some("synthetic-client".into()),client_secret:None}}
fn put(store:&dyn Store,id:&str,c:&OAuthCredential){let old=store.get_secret(id).unwrap().unwrap();store.put_secret(SecretRecord{id:id.into(),sealed:seal(Cipher::Aes256Gcm,vault_passphrase(),to_sealed_json(c).unwrap().as_bytes()).unwrap(),metadata:old.metadata}).unwrap();}
fn setup()->(Arc<EnforcementService>,Arc<Provider>,String){
 common::isolate_from_the_real_install();
 let store:Arc<dyn Store>=Arc::new(MemoryStore::new());seed::seed(store.as_ref()).unwrap();
 let id=store.get_capability("github.pull_requests.list").unwrap().unwrap().secret_id;
 put(store.as_ref(),&id,&cred("synthetic-expired",1));
 let http=Arc::new(Provider{entered:Notify::new(),release:Semaphore::new(0),refreshes:AtomicUsize::new(0)});
 (Arc::new(EnforcementService::new(store,http.clone())),http,id)
}
async fn invoke(s:Arc<EnforcementService>)->Result<InvokeOutcome,permaura_gateway::error::GatewayError>{
 let session=s.store().get_session("sess_demo").unwrap().unwrap();
 s.invoke(&session,"github.pull_requests.list",&serde_json::json!({"owner":"synthetic","repo":"synthetic"}),None,ExecutionLocation::LocalOnly).await
}
#[tokio::test]
async fn concurrent_calls_share_one_refresh(){
 let(s,http,_)=setup();let a=tokio::spawn(invoke(s.clone()));http.entered.notified().await;
 let b=tokio::spawn(invoke(s));
 // If a per-secret refresh lock exists, b queues behind a and sends no second refresh.
 let _=tokio::time::timeout(std::time::Duration::from_millis(200),http.entered.notified()).await;
 http.release.add_permits(2);
 let(ra,rb)=(a.await.unwrap(),b.await.unwrap());
 println!("refresh requests={}, outcomes_ok=({}, {})",http.refreshes.load(Ordering::SeqCst),ra.is_ok(),rb.is_ok());
 assert_eq!(http.refreshes.load(Ordering::SeqCst),1,"the same one-use refresh token was sent twice");
 assert!(matches!(ra,Ok(InvokeOutcome::Allowed{..}))&&matches!(rb,Ok(InvokeOutcome::Allowed{..})));
}
#[tokio::test]
async fn completed_reauthorization_survives_an_older_inflight_refresh(){
 let(s,http,id)=setup();let task=tokio::spawn(invoke(s.clone()));http.entered.notified().await;
 put(s.store().as_ref(),&id,&cred("synthetic-new-authorization",i64::MAX));
 http.release.add_permits(1);task.await.unwrap().unwrap();
 let row=s.store().get_secret(&id).unwrap().unwrap();let plain=open(&row.sealed,vault_passphrase()).unwrap();let saved=from_sealed_bytes(&plain).unwrap();
 assert_eq!(saved.access_token,"synthetic-new-authorization","an older refresh overwrote the completed new authorization");
}

#[tokio::test]
async fn fresh_authorization_control_does_not_refresh(){
 let(s,http,id)=setup();put(s.store().as_ref(),&id,&cred("synthetic-fresh",i64::MAX));
 assert!(matches!(invoke(s).await,Ok(InvokeOutcome::Allowed{..})));
 assert_eq!(http.refreshes.load(Ordering::SeqCst),0);
}
#[tokio::test]
async fn sequential_calls_control_refresh_once_and_reuse_rotated_token(){
 let(s,http,id)=setup();http.release.add_permits(1);
 assert!(matches!(invoke(s.clone()).await,Ok(InvokeOutcome::Allowed{..})));
 assert!(matches!(invoke(s.clone()).await,Ok(InvokeOutcome::Allowed{..})));
 assert_eq!(http.refreshes.load(Ordering::SeqCst),1);
 let row=s.store().get_secret(&id).unwrap().unwrap();
 let saved=from_sealed_bytes(&open(&row.sealed,vault_passphrase()).unwrap()).unwrap();
 assert_eq!(saved.refresh_token.as_ref().map(|t| t.expose()),Some("synthetic-rotated"));
}
