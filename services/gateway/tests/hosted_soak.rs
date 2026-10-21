//! A hosted worker's memory and storage under sustained execution load.
//!
//! A speed test on 7 October 2026 drove one agent at an allowed SSH command whose host never
//! resolves, so every call runs the whole fence, execute and record path and writes two snapshot
//! uploads. This reproduces that run in-process: the real router over a real listener, the real SSH
//! transport failing at its lookup, and the persisted store over an object store that answers like
//! Cloud Storage does for one hot object (a round trip per request, about one write a second before
//! it says 429, and the client's three retries with their backoff).
//!
//! `soak` is the measuring harness and is ignored: run it with
//! `SOAK_RATE=1 SOAK_SECS=300 cargo test -p permaura-gateway --test hosted_soak -- --ignored --nocapture`,
//! on Linux inside a 512 MiB container for numbers comparable to a worker's. The regression that runs
//! everywhere counts allocations instead, because resident memory is the allocator's story and only
//! glibc tells the one that speed test saw.
#![cfg(feature = "sqlite")]

mod common;

use std::alloc::{GlobalAlloc, Layout, System};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use permaura_core::{ExecutionLocation, RiskTier};
use permaura_gateway::backend::{AuditKeyWrap, KmsClient};
use permaura_gateway::connectors::{
    Connector, MockHttpClient, MockSshRunner, RealSshRunner, SshConnector, SshExecCommand, SshHostKey,
    SshTarget,
};
use permaura_gateway::error::GatewayError;
use permaura_gateway::objectstore::{ObjectHead, ObjectStore, PutOutcome};
use permaura_gateway::service::EnforcementService;
use permaura_gateway::store::persisted::{PersistedSqliteStore, DEFAULT_OBJECT};
use permaura_gateway::store::Store;
use permaura_gateway::{build_router, AppState};

/// The system allocator, counting what is live, the most that was, and every block of
/// [`LARGE_BYTES`] or more.
struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
static LARGE: AtomicUsize = AtomicUsize::new(0);

/// Comfortably below the vault KDF's 19 MiB working set and far above anything else a call allocates.
const LARGE_BYTES: usize = 8 * 1024 * 1024;

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc(layout);
        if !p.is_null() {
            note_alloc(layout.size());
        }
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = System.alloc_zeroed(layout);
        if !p.is_null() {
            note_alloc(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let p = System.realloc(ptr, layout, new_size);
        if !p.is_null() {
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
            note_alloc(new_size);
        }
        p
    }
}

fn note_alloc(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
    if size >= LARGE_BYTES {
        LARGE.fetch_add(1, Ordering::Relaxed);
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

struct FakeKms;
#[async_trait]
impl KmsClient for FakeKms {
    async fn decrypt(&self, _: &str, b: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, GatewayError> {
        Ok(zeroize::Zeroizing::new(b.iter().map(|x| x ^ 0x5a).collect()))
    }
    async fn encrypt(&self, _: &str, b: &[u8]) -> Result<Vec<u8>, GatewayError> {
        Ok(b.iter().map(|x| x ^ 0x5a).collect())
    }
}

/// The shape of Cloud Storage that matters here, for one object.
pub struct GcsLike {
    latency: Duration,
    /// Writes a second the object accepts before answering 429, and how many may land back to back.
    writes_per_sec: f64,
    burst: f64,
    state: Mutex<GcsState>,
    pub puts: AtomicU64,
    pub throttled: AtomicU64,
    pub failed: AtomicU64,
}

struct GcsState {
    generation: u64,
    bytes: Vec<u8>,
    metadata: BTreeMap<String, String>,
    tokens: f64,
    refilled: Instant,
}

/// The real client's waits between attempts (`objectstore::RETRY_BACKOFF_MS`).
const BACKOFF_MS: [u64; 3] = [100, 400, 1600];

impl GcsLike {
    pub fn new(latency: Duration, writes_per_sec: f64, burst: f64) -> Self {
        GcsLike {
            latency,
            writes_per_sec,
            burst,
            state: Mutex::new(GcsState {
                generation: 0,
                bytes: Vec::new(),
                metadata: BTreeMap::new(),
                tokens: burst,
                refilled: Instant::now(),
            }),
            puts: AtomicU64::new(0),
            throttled: AtomicU64::new(0),
            failed: AtomicU64::new(0),
        }
    }

    fn round_trip(&self, bytes: usize) {
        // An assumed 20 MB/s on top of the request latency, so a bigger snapshot costs longer.
        std::thread::sleep(self.latency + Duration::from_micros(bytes as u64 / 20));
    }
}

impl ObjectStore for GcsLike {
    fn head(&self, _name: &str) -> Result<Option<u64>, GatewayError> {
        self.round_trip(0);
        let s = self.state.lock().unwrap();
        Ok((s.generation > 0).then_some(s.generation))
    }
    fn head_full(&self, _name: &str) -> Result<Option<ObjectHead>, GatewayError> {
        self.round_trip(0);
        let s = self.state.lock().unwrap();
        Ok((s.generation > 0).then(|| ObjectHead {
            generation: s.generation,
            metadata: s.metadata.clone(),
            size: s.bytes.len() as u64,
            crc32c: String::new(),
        }))
    }
    fn has_history(&self, _name: &str) -> Result<bool, GatewayError> {
        Ok(self.state.lock().unwrap().generation > 0)
    }
    fn get(&self, _name: &str, generation: u64) -> Result<Vec<u8>, GatewayError> {
        let s = self.state.lock().unwrap();
        if s.generation != generation {
            return Err(GatewayError::Internal("generation moved".into()));
        }
        Ok(s.bytes.clone())
    }
    fn put_if_generation(
        &self,
        _name: &str,
        bytes: &[u8],
        expected: u64,
        metadata: &BTreeMap<String, String>,
    ) -> Result<PutOutcome, GatewayError> {
        // The real client builds one multipart body and clones it into every attempt.
        let mut body = Vec::with_capacity(bytes.len() + 1024);
        body.extend_from_slice(&[b'-'; 512]);
        body.extend_from_slice(bytes);
        for attempt in 0..=BACKOFF_MS.len() {
            if attempt > 0 {
                std::thread::sleep(Duration::from_millis(BACKOFF_MS[attempt - 1]));
            }
            let sent = body.clone();
            self.round_trip(sent.len());
            self.puts.fetch_add(1, Ordering::Relaxed);
            let mut s = self.state.lock().unwrap();
            let now = Instant::now();
            let refill = now.duration_since(s.refilled).as_secs_f64() * self.writes_per_sec;
            s.tokens = (s.tokens + refill).min(self.burst);
            s.refilled = now;
            if s.tokens < 1.0 {
                self.throttled.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if s.generation != expected {
                return Ok(PutOutcome::Conflict);
            }
            s.tokens -= 1.0;
            s.generation += 1;
            s.bytes = sent[512..].to_vec();
            s.metadata = metadata.clone();
            return Ok(PutOutcome::Stored(s.generation));
        }
        self.failed.fetch_add(1, Ordering::Relaxed);
        Err(GatewayError::Internal("object store put gs://soak/store.db returned 429".into()))
    }
    fn describe(&self) -> String {
        "gs://soak".into()
    }
}

/// What `permaura start` does at boot on a glibc build (`cli::start::bound_allocator_retention`).
pub fn pin_mmap_threshold() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: mallopt only adjusts the allocator's tuning parameters.
    unsafe {
        libc::mallopt(libc::M_MMAP_THRESHOLD, permaura_gateway::MMAP_THRESHOLD_BYTES as libc::c_int);
    }
}

/// Resident memory of this process, in KiB.
pub fn rss_kib() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        status
            .lines()
            .find_map(|l| l.strip_prefix("VmRSS:"))
            .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let out = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        out.parse().unwrap_or(0)
    }
}

/// The container's own memory charge in KiB, where there is one to read: on Linux under cgroup v2 this
/// is what Cloud Run compares against the instance limit, files in an in-memory filesystem included.
pub fn cgroup_kib() -> Option<u64> {
    let raw = std::fs::read_to_string("/sys/fs/cgroup/memory.current").ok()?;
    raw.trim().parse::<u64>().ok().map(|b| b / 1024)
}

/// Threads in this process.
pub fn thread_count() -> u64 {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
        status
            .lines()
            .find_map(|l| l.strip_prefix("Threads:"))
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let out = std::process::Command::new("ps")
            .args(["-M", "-p", &std::process::id().to_string()])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().count() as u64)
            .unwrap_or(1);
        out.saturating_sub(1)
    }
}

/// Every file in `dir` with its size: on Cloud Run this is memory.
pub fn footprint(dir: &Path) -> (u64, Vec<(String, u64)>) {
    let mut files = Vec::new();
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            let len = e.metadata().map(|m| m.len()).unwrap_or(0);
            total += len;
            files.push((e.file_name().to_string_lossy().to_string(), len));
        }
    }
    files.sort();
    (total, files)
}

pub fn scratch(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "permaura-soak-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// Open a persisted store over `objects`, seed it, and point the demo SSH capability at a host that
/// can never resolve, as the speed test's connection did.
pub fn hosted_store(dir: &Path, objects: Arc<dyn ObjectStore>) -> Arc<PersistedSqliteStore> {
    common::isolate_from_the_real_install();
    let store = Arc::new(
        PersistedSqliteStore::open(
            &dir.join("store.db").to_string_lossy(),
            objects,
            DEFAULT_OBJECT,
            Some(AuditKeyWrap { kms: Arc::new(FakeKms), key_id: "synthetic".into(), adopt_plaintext: false }),
        )
        .unwrap()
        .with_fresh_read_window(Duration::ZERO),
    );
    permaura_gateway::seed::seed(store.as_ref()).unwrap();
    let caps = SshConnector::new(
        "ssh_prod",
        "sec_ssh_prod",
        SshTarget {
            host: "speed-test.invalid".into(),
            port: 22,
            user: "deploy".into(),
            host_key: SshHostKey::Fingerprint { sha256: "demo-host-key-fingerprint".into() },
        },
    )
    .with_exec(SshExecCommand {
        action: "uptime".into(),
        description: "Show remote host uptime".into(),
        risk: RiskTier::Low,
        requires_approval: false,
        args_template: vec!["uptime".into()],
        allowed_placeholders: vec![],
    })
    .capabilities();
    for cap in caps.into_iter().filter(|c| c.id == "ssh.uptime") {
        store.put_capability(cap).unwrap();
    }
    store
}

/// Serve the real router for `store` on a loopback port, on a runtime of its own with one worker
/// thread: a 1 vCPU worker, with the driver's own work kept off it.
pub fn serve(
    dir: &Path,
    objects: Arc<dyn ObjectStore>,
) -> (Arc<PersistedSqliteStore>, SocketAddr, tokio::runtime::Runtime) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()
        .unwrap();
    let dir = dir.to_path_buf();
    let (opened, addr) = rt.block_on(async move {
        let opened = tokio::task::block_in_place(|| hosted_store(&dir, objects));
        let store: Arc<dyn Store> = opened.clone();
        let service = EnforcementService::new(store.clone(), Arc::new(MockHttpClient::new()))
            .with_ssh_runner(Arc::new(RealSshRunner::new()));
        permaura_gateway::spawn_store_carrier(store.clone(), permaura_gateway::STORE_CARRY_INTERVAL);
        let state = AppState::new(service);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = build_router(state, addr);
        tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .unwrap();
        });
        (opened, addr)
    });
    (opened, addr, rt)
}

#[derive(Default)]
pub struct Tally {
    pub sent: AtomicU64,
    pub executed: AtomicU64,
    pub throttled: AtomicU64,
    pub storage: AtomicU64,
    pub other: AtomicU64,
}

/// One `tools/call` of the uptime command, classified the way the speed test's driver classified it.
pub async fn call(client: &reqwest::Client, addr: SocketAddr, n: u64, tally: &Tally) {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": n, "method": "tools/call",
        "params": { "name": "ssh.uptime", "arguments": { "reason": "hosted soak" } }
    });
    let resp = client
        .post(format!("http://{addr}/mcp"))
        .bearer_auth(permaura_gateway::seed::DEMO_TOKEN)
        .json(&body)
        .send()
        .await;
    let (status, text) = match resp {
        Ok(r) => {
            let status = r.status().as_u16();
            (status, r.text().await.unwrap_or_default())
        }
        Err(e) => (0, e.to_string()),
    };
    let counter = if text.contains("lookup") || text.contains("resolve") || text.contains("nodename") {
        &tally.executed
    } else if status == 429 || text.contains("429") || text.contains("rate limit") || text.contains("queue") || text.contains("concurrency limit") {
        &tally.throttled
    } else if text.contains("storage unavailable") || text.contains("storage") {
        &tally.storage
    } else {
        if tally.other.load(Ordering::Relaxed) < 3 {
            eprintln!("other: {status} {}", &text[..text.len().min(300)]);
        }
        &tally.other
    };
    counter.fetch_add(1, Ordering::Relaxed);
}

fn env_f64(key: &str, default: f64) -> f64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[test]
#[ignore]
fn soak() {
    let rate = env_f64("SOAK_RATE", 1.0);
    let secs = env_f64("SOAK_SECS", 120.0);
    let latency = Duration::from_millis(env_f64("SOAK_LATENCY_MS", 80.0) as u64);
    let writes = env_f64("SOAK_WRITES_PER_SEC", 1.0);
    let burst = env_f64("SOAK_WRITE_BURST", 3.0);
    if std::env::var("SOAK_MALLOPT").as_deref() != Ok("0") {
        pin_mmap_threshold();
    }
    let dir = scratch("soak");
    let gcs = Arc::new(GcsLike::new(latency, writes, burst));
    let (store, addr, _server) = serve(&dir, gcs.clone());
    let client_rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
    let tally = Arc::new(Tally::default());
    eprintln!("soak: rate {rate}/s for {secs}s, put latency {latency:?}, {writes} writes/s burst {burst}, store in {}", dir.display());
    eprintln!("t_s\tsent\texec\t429\tstorage\tother\trss_mib\tcg_mib\tthreads\tdir_kib\tfiles\tputs\tgcs429\tgcsfail");
    client_rt.block_on(async {
        let client = reqwest::Client::builder().timeout(Duration::from_secs(120)).build().unwrap();
        let start = Instant::now();
        let interval = Duration::from_secs_f64(1.0 / rate);
        let mut next = start;
        let mut n = 0u64;
        let mut report = start;
        let report_every = Duration::from_secs(10);
        while start.elapsed() < Duration::from_secs_f64(secs) {
            n += 1;
            tally.sent.fetch_add(1, Ordering::Relaxed);
            let (c, t) = (client.clone(), tally.clone());
            tokio::spawn(async move { call(&c, addr, n, &t).await });
            next += interval;
            if Instant::now() >= report {
                let (bytes, files) = footprint(&dir);
                eprintln!(
                    "{:.0}\t{}\t{}\t{}\t{}\t{}\t{:.1}\t{:.1}\t{}\t{}\t{}\t{}\t{}\t{}",
                    start.elapsed().as_secs_f64(),
                    tally.sent.load(Ordering::Relaxed),
                    tally.executed.load(Ordering::Relaxed),
                    tally.throttled.load(Ordering::Relaxed),
                    tally.storage.load(Ordering::Relaxed),
                    tally.other.load(Ordering::Relaxed),
                    rss_kib() as f64 / 1024.0,
                    cgroup_kib().unwrap_or(0) as f64 / 1024.0,
                    thread_count(),
                    bytes / 1024,
                    files.iter().map(|(n, l)| format!("{n}:{}", l / 1024)).collect::<Vec<_>>().join(","),
                    gcs.puts.load(Ordering::Relaxed),
                    gcs.throttled.load(Ordering::Relaxed),
                    gcs.failed.load(Ordering::Relaxed),
                );
                report += report_every;
            }
            tokio::time::sleep_until(next.into()).await;
        }
        tokio::time::sleep(Duration::from_secs(20)).await;
        let (bytes, _) = footprint(&dir);
        eprintln!(
            "end: sent {} exec {} 429 {} storage {} other {} rss {:.1} MiB cgroup {:.1} MiB threads {} dir {} KiB events {}",
            tally.sent.load(Ordering::Relaxed),
            tally.executed.load(Ordering::Relaxed),
            tally.throttled.load(Ordering::Relaxed),
            tally.storage.load(Ordering::Relaxed),
            tally.other.load(Ordering::Relaxed),
            rss_kib() as f64 / 1024.0,
            cgroup_kib().unwrap_or(0) as f64 / 1024.0,
            thread_count(),
            bytes / 1024,
            store.audit_len().unwrap_or(0),
        );
    });
}

/// The cause of the growth, pinned where it can be counted rather than inferred from a container's memory: every
/// execution used to run the vault KDF, a 19 MiB Argon2id working set, and glibc kept each freed one
/// in the arena that served it until a 512 MiB worker ran out. Sixty executions, four at a time, now
/// derive the key once, hold no more live memory at the end than a few kilobytes of audit history
/// each, and leave nothing in the store's directory but the database.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn sustained_executions_derive_the_vault_key_once_and_hold_no_growing_memory() {
    let dir = scratch("bounded");
    let store = tokio::task::block_in_place(|| hosted_store(&dir, Arc::new(GcsLike::new(Duration::ZERO, 1_000.0, 1_000.0))));
    let session = store.get_session("sess_demo").unwrap().unwrap();
    let dyn_store: Arc<dyn Store> = store.clone();
    let service = Arc::new(
        EnforcementService::new(dyn_store, Arc::new(MockHttpClient::new())).with_ssh_runner(Arc::new(MockSshRunner::new())),
    );
    let call = |n: usize| {
        let (service, session) = (service.clone(), session.clone());
        async move {
            service
                .invoke(&session, "ssh.uptime", &serde_json::json!({}), Some(&format!("soak {n}")), ExecutionLocation::LocalOnly)
                .await
                .expect("the call executes")
        }
    };
    // One call first, so the baseline already holds the one derived key and a warm store.
    call(0).await;
    let (live_before, large_before) = (LIVE.load(Ordering::Relaxed), LARGE.load(Ordering::Relaxed));
    PEAK.store(live_before, Ordering::Relaxed);
    for batch in 0..15 {
        let calls: Vec<_> = (0..4).map(|i| tokio::spawn(call(1 + batch * 4 + i))).collect();
        for c in calls {
            c.await.unwrap();
        }
    }
    let live_after = LIVE.load(Ordering::Relaxed);
    let large = LARGE.load(Ordering::Relaxed) - large_before;
    let peak = PEAK.load(Ordering::Relaxed);
    assert_eq!(large, 0, "sixty executions allocated {large} blocks of 8 MiB or more: the KDF is running per call again");
    assert!(
        peak.saturating_sub(live_before) < 16 * 1024 * 1024,
        "live memory peaked {} MiB above where the run started",
        peak.saturating_sub(live_before) / (1024 * 1024)
    );
    assert!(
        live_after.saturating_sub(live_before) < 4 * 1024 * 1024,
        "sixty executions left {} KiB more live memory behind",
        live_after.saturating_sub(live_before) / 1024
    );
    let (_, files) = footprint(&dir);
    let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, ["store.db"], "no snapshot copy, journal or WAL is left in the store's directory");
    assert_eq!(store.audit_events(None).unwrap().iter().filter(|e| e.payload.action == "ssh.uptime").count(), 122);
}
