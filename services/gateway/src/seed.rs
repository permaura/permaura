//! Demo seed data for the **marketing / demo** gateway, plus the clean-boot bootstrap for
//! a real paired install.
//!
//! [`seed`] populates the gateway in the redesigned domain model: first-class
//! **connections** (Braintree prod, GitHub @github_acme, a Vercel account, a fal.ai
//! endpoint), **policies** scoped to each connection (allow / deny / requires-approval), and
//! **grants** that bind a policy to the seeded `codex-cli` agent under limits. It reproduces
//! the signature scenario: a read-only Braintree policy whose `deny` list blocks
//! `transactions.refund` (the prompt-injection-blocks-a-refund demo), and a GitHub policy
//! whose High-risk `pull_requests.create` is auto-escalated to human approval.
//!
//! [`clean_bootstrap`] is the opposite: it seeds **no** demo data. A real install run by the
//! desktop app / installer starts empty (so "connected" means a clean slate) and mints
//! a real **per-gateway operator token** instead of the shared [`DEMO_TOKEN`].
//!
//! **Which one runs is not an environment decision.** Every gateway that could hold real
//! credentials or be reached from a network takes [`clean_bootstrap`], with no way to override it;
//! [`seed`] is reachable only through [`crate::AppState::in_memory_seeded`], which a caller picks
//! deliberately (`--demo`, the daemon, `permaura start`, the tests) and which is always in-memory with
//! mock transports. The customer-facing "look around before you connect anything" demo is the
//! console's, not this one.

use permaura_core::{
    seal, Action, Cipher, Connection, ExecutionLocation, Grant, GrantAgent, GrantAgents,
    GrantPeriod, Policy, RiskTier, SealedSecret, SecretMetadata, SecretRecord,
};

use crate::connectors::{
    Capability, CapabilityKind, Connector, FalConnector, SshConnector, SshExecCommand, SshHostKey,
    SshTarget, VercelConnector,
};
use crate::error::GatewayError;
use crate::service::{short_id, vault_passphrase};
use crate::store::{Agent, Session, SessionRole, Store, OPERATOR_SESSION_TTL_MS};

/// The bearer token the seeded `codex-cli` session presents on the **demo** gateway. Stable
/// so the README / demos / CLI can talk to a freshly-booted demo gateway without first
/// opening a session. A real paired install never uses this: see [`clean_bootstrap`].
pub const DEMO_TOKEN: &str = "demo-codex-cli-token";

/// The gateway's own identity, minted by [`clean_bootstrap`] and by the seed.
///
/// It is an `Agent` row because sessions are keyed on an agent id, not because anybody enrolled it,
/// which is why [`crate::service::EnforcementService::allowance_count`] leaves it out of the agent
/// count: a plan of N agents that spent one of them on the operator would be a plan of N-1.
pub const OPERATOR_AGENT_ID: &str = "operator";

/// Seal a demo secret value under the gateway vault passphrase.
fn seal_demo(value: &[u8]) -> Result<SealedSecret, GatewayError> {
    seal(Cipher::Aes256Gcm, vault_passphrase(), value)
        .map_err(|e| GatewayError::Internal(format!("failed to seal demo secret: {e}")))
}

/// Populate `store` with the demo agent, session, secrets, connections, policies and grants.
pub fn seed(store: &dyn Store) -> Result<(), GatewayError> {
    let now = now_ms();

    // ── Agent (approved) + session ──────────────────────────────────────────────
    store.put_agent(Agent::approved("codex-cli", "Codex CLI", now))?;
    store.put_session(Session {
        class: Default::default(),
        opened_by: None,
        id: "sess_demo".into(),
        agent_id: "codex-cli".into(),
        user_id: Some("sam".into()),
        device_id: Some("sam-macbook".into()),
        token: DEMO_TOKEN.into(),
        // The demo session is the operator's own: it drives the console as well as invoking.
        role: SessionRole::Operator,
        created_at: now,
        revoked: false,
        expires_at: Some(now + OPERATOR_SESSION_TTL_MS),
        last_used_at: None,
        actor: None,
    })?;

    // ── Sealed secrets (the agent never sees these) ──────────────────────────────
    store.put_secret(SecretRecord {
        id: "sec_braintree_prod".into(),
        sealed: seal_demo(b"bt_demo_private_key_value")?,
        metadata: SecretMetadata {
            labels: vec!["financial".into(), "production".into()],
            risk_classification: RiskTier::Critical,
            allowed_execution_locations: vec![ExecutionLocation::LocalOnly],
            last_used_at: None,
        },
    })?;
    store.put_secret(SecretRecord {
        id: "sec_github_acme".into(),
        sealed: seal_demo(b"ghp_demo_github_token_value")?,
        metadata: SecretMetadata {
            labels: vec!["scm".into()],
            risk_classification: RiskTier::High,
            allowed_execution_locations: vec![ExecutionLocation::LocalOnly],
            last_used_at: None,
        },
    })?;
    store.put_secret(SecretRecord {
        id: "sec_vercel".into(),
        sealed: seal_demo(b"vercel_demo_api_token_value")?,
        metadata: SecretMetadata {
            labels: vec!["hosting".into(), "deploy".into()],
            risk_classification: RiskTier::High,
            allowed_execution_locations: vec![ExecutionLocation::LocalOnly],
            last_used_at: None,
        },
    })?;
    // A demo SSH private key. Never a real key (and never leaves the vault); the demo gateway runs
    // the mock SSH transport, so this is only ever resolved and handed to `MockSshRunner`.
    store.put_secret(SecretRecord {
        id: "sec_ssh_prod".into(),
        sealed: seal_demo(b"-----BEGIN OPENSSH PRIVATE KEY-----\ndemo-not-a-real-key\n-----END OPENSSH PRIVATE KEY-----\n")?,
        metadata: SecretMetadata {
            labels: vec!["ssh".into(), "production".into()],
            risk_classification: RiskTier::Critical,
            allowed_execution_locations: vec![ExecutionLocation::LocalOnly],
            last_used_at: None,
        },
    })?;

    // ── Capabilities ─────────────────────────────────────────────────────────────
    // The Braintree + GitHub capabilities are hand-written; Vercel and fal.ai come straight
    // from their connector definitions so the risk tiers stay in lockstep. (The leftover
    // "Vercel CLI" command connection, cruft from the CLI-integration exploration, is no
    // longer seeded.)
    let mut caps: Vec<Capability> = vec![
        http_cap("braintree.transactions.search", "Search Braintree transactions", RiskTier::Medium, Action::Search, false, "braintree_production", "sec_braintree_prod"),
        http_cap("braintree.transactions.read", "Read a single Braintree transaction", RiskTier::Medium, Action::Read, false, "braintree_production", "sec_braintree_prod"),
        http_cap("braintree.transactions.refund", "Refund a Braintree transaction", RiskTier::Critical, Action::Refund, true, "braintree_production", "sec_braintree_prod"),
        http_cap("braintree.customers.read", "Read a Braintree customer", RiskTier::Medium, Action::Read, false, "braintree_production", "sec_braintree_prod"),
        http_cap("github.pull_requests.create", "Create pull requests", RiskTier::High, Action::Create, false, "github_acme", "sec_github_acme"),
        http_cap("github.pull_requests.list", "List pull requests", RiskTier::Low, Action::List, false, "github_acme", "sec_github_acme"),
        // The generic HTTP proxy capability stays registered (it backs `permaura.http_request`)
        // but is intentionally not wired to a connection/grant, so it is deny-by-default.
        http_cap("http.request", "Generic policy-gated HTTP request with server-side secret injection", RiskTier::High, Action::Execute, false, "generic_http", "sec_github_acme"),
    ];
    caps.extend(VercelConnector::new("vercel_acme", "sec_vercel").capabilities());
    caps.extend(FalConnector::new("fal", "sec_fal").capabilities());
    // A demo SSH host: a Low-risk read (`uptime`), a High-risk restart gated on approval, and
    // path-scoped SFTP under /var/data. Shows graduated risk on a single connection.
    caps.extend(
        SshConnector::new(
            "ssh_prod",
            "sec_ssh_prod",
            SshTarget {
                host: "db1.internal.example".into(),
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
        .with_exec(SshExecCommand {
            action: "restart-service".into(),
            description: "Restart a systemd service on the remote host".into(),
            risk: RiskTier::High,
            requires_approval: true,
            args_template: vec!["systemctl".into(), "restart".into(), "{service}".into()],
            allowed_placeholders: vec!["service".into()],
        })
        .with_sftp("/var/data", 1024 * 1024)
        .capabilities(),
    );
    for cap in &caps {
        store.put_capability(cap.clone())?;
    }
    let caps_for = |resource: &str| -> Vec<String> {
        let mut ids: Vec<String> = caps
            .iter()
            .filter(|c| c.resource == resource)
            .map(|c| c.id.clone())
            .collect();
        ids.sort();
        ids
    };

    // ── Connections (first-class configured integrations) ────────────────────────
    store.put_connection(Connection {
        id: "braintree_production".into(),
        connector: "braintree".into(),
        name: "Braintree (production)".into(),
        label: "Braintree".into(),
        secret_id: "sec_braintree_prod".into(),
        capabilities: caps_for("braintree_production"),
        disabled_capabilities: vec![],
        disabled: false,
        allowed_hosts: vec![],
        created_at: now,
        redact_fields: Vec::new(),
        source: None,
        made_from: None,
    })?;
    store.put_connection(Connection {
        id: "github_acme".into(),
        connector: "github".into(),
        name: "GitHub (@github_acme)".into(),
        label: "GitHub".into(),
        secret_id: "sec_github_acme".into(),
        capabilities: caps_for("github_acme"),
        disabled_capabilities: vec![],
        disabled: false,
        allowed_hosts: vec![],
        created_at: now,
        redact_fields: Vec::new(),
        source: None,
        made_from: None,
    })?;
    store.put_connection(Connection {
        id: "vercel_acme".into(),
        connector: "vercel".into(),
        name: "Vercel (acme)".into(),
        label: "Vercel".into(),
        secret_id: "sec_vercel".into(),
        capabilities: caps_for("vercel_acme"),
        disabled_capabilities: vec![],
        disabled: false,
        allowed_hosts: vec![],
        created_at: now,
        redact_fields: Vec::new(),
        source: None,
        made_from: None,
    })?;
    // fal.ai: a generic-http-style endpoint that must be labelled honestly. Seeded
    // with NO credential: it shows up Disconnected until the user adds their fal key.
    store.put_connection(Connection {
        id: "fal".into(),
        connector: "fal".into(),
        name: "fal.ai".into(),
        label: "fal.ai".into(),
        secret_id: "sec_fal".into(),
        capabilities: caps_for("fal"),
        disabled_capabilities: vec![],
        disabled: false,
        allowed_hosts: vec![],
        created_at: now,
        redact_fields: Vec::new(),
        source: None,
        made_from: None,
    })?;
    store.put_connection(Connection {
        id: "ssh_prod".into(),
        connector: "ssh".into(),
        name: "SSH (db1.internal)".into(),
        label: "SSH".into(),
        secret_id: "sec_ssh_prod".into(),
        capabilities: caps_for("ssh_prod"),
        disabled_capabilities: vec![],
        disabled: false,
        allowed_hosts: vec![],
        created_at: now,
        redact_fields: Vec::new(),
        source: None,
        made_from: None,
    })?;

    // ── Policies (templates scoped to a connection: allow / deny / requires-approval) ──
    // The signature demo policy: read-only Braintree, refund + sale + void explicitly DENIED.
    store.put_policy(Policy {
        id: "pol_braintree_readonly".into(),
        connection_id: "braintree_production".into(),
        name: "Read-only diagnostics".into(),
        allow: vec![
            "transactions.search".into(),
            "transactions.read".into(),
            "customers.read".into(),
        ],
        deny: vec![
            "transactions.refund".into(),
            "transactions.sale".into(),
            "transactions.void".into(),
        ],
        requires_approval: vec![],
        notify: vec![],
        device_signed: vec![],
        device_signed_quorum: 1,
        redact_fields: Vec::new(),
    })?;
    // GitHub: list + create PRs. `pull_requests.create` is High risk, so the engine escalates
    // it to human approval without the policy having to name it.
    store.put_policy(Policy {
        id: "pol_github_prs".into(),
        connection_id: "github_acme".into(),
        name: "Pull requests".into(),
        allow: vec!["pull_requests.list".into(), "pull_requests.create".into()],
        deny: vec![],
        requires_approval: vec![],
        notify: vec![],
        device_signed: vec![],
        device_signed_quorum: 1,
        redact_fields: Vec::new(),
    })?;
    // Vercel: reads are Low/Medium → allow; `deployments.create` is High → auto-escalated.
    store.put_policy(Policy {
        id: "pol_vercel".into(),
        connection_id: "vercel_acme".into(),
        name: "Project read + deploy-with-approval".into(),
        allow: vec![
            "projects.list".into(),
            "projects.read".into(),
            "deployments.list".into(),
            "deployments.read".into(),
            "deployments.create".into(),
            "env.read".into(),
            "domains.list".into(),
        ],
        deny: vec![],
        requires_approval: vec![],
        notify: vec!["deployments.list".into()],
        device_signed: vec![],
        device_signed_quorum: 1,
        redact_fields: Vec::new(),
    })?;
    // fal.ai: allow image generation (the connection has no credential yet, so it cannot run
    // until the user adds a key, the "add your own key" path).
    store.put_policy(Policy {
        id: "pol_fal".into(),
        connection_id: "fal".into(),
        name: "Image generation".into(),
        allow: vec!["image.generate".into()],
        deny: vec![],
        requires_approval: vec![],
        notify: vec![],
        device_signed: vec![],
        device_signed_quorum: 1,
        redact_fields: Vec::new(),
    })?;
    // SSH: allow the read (`uptime`), the SFTP reads and `restart-service`; DENY `sftp.put` (the
    // signature "read-only, writes blocked" shape). `restart-service` is High + self-declares
    // approval, so it escalates to a human even though it is allowed.
    store.put_policy(Policy {
        id: "pol_ssh_prod".into(),
        connection_id: "ssh_prod".into(),
        name: "Read + restart-with-approval".into(),
        allow: vec![
            "uptime".into(),
            "sftp.list".into(),
            "sftp.get".into(),
            "restart-service".into(),
        ],
        deny: vec!["sftp.put".into()],
        requires_approval: vec!["restart-service".into()],
        notify: vec![],
        device_signed: vec![],
        device_signed_quorum: 1,
        redact_fields: Vec::new(),
    })?;

    // ── Grants (v2 bundles: bind policies → the codex-cli agent, under two-tier limits) ──
    let codex = || GrantAgents::Agents(vec![GrantAgent::new("codex-cli")]);
    store.put_grant(Grant {
        grant_id: "gr_braintree_readonly".into(),
        name: "Braintree read-only".into(),
        enabled: true,
        is_default: false,
        policy_ids: vec!["pol_braintree_readonly".into()],
        agents: codex(),
        period: GrantPeriod::Total,
        overall_limit: None,
        default_per_agent_limit: Some(100),
        expires_at: None,
    })?;
    store.put_grant(Grant {
        grant_id: "gr_github_prs".into(),
        name: "GitHub pull requests".into(),
        enabled: true,
        is_default: false,
        policy_ids: vec!["pol_github_prs".into()],
        agents: codex(),
        period: GrantPeriod::Total,
        overall_limit: None,
        default_per_agent_limit: None,
        expires_at: None,
    })?;
    store.put_grant(Grant {
        grant_id: "gr_vercel_acme".into(),
        name: "Vercel deployments".into(),
        enabled: true,
        is_default: false,
        policy_ids: vec!["pol_vercel".into()],
        agents: codex(),
        period: GrantPeriod::Total,
        overall_limit: None,
        default_per_agent_limit: None,
        expires_at: None,
    })?;
    store.put_grant(Grant {
        grant_id: "gr_fal".into(),
        name: "Image generation".into(),
        enabled: true,
        is_default: false,
        policy_ids: vec!["pol_fal".into()],
        agents: codex(),
        period: GrantPeriod::Total,
        overall_limit: None,
        default_per_agent_limit: None,
        expires_at: None,
    })?;
    store.put_grant(Grant {
        grant_id: "gr_ssh_prod".into(),
        name: "SSH ops".into(),
        enabled: true,
        is_default: false,
        policy_ids: vec!["pol_ssh_prod".into()],
        agents: codex(),
        period: GrantPeriod::Total,
        overall_limit: None,
        default_per_agent_limit: None,
        expires_at: None,
    })?;

    // The always-present, pausable Default baseline every approved agent inherits.
    ensure_default_grant(store)?;
    Ok(())
}

/// Ensure exactly one always-present **Default** baseline grant exists. Idempotent and
/// called on every gateway bootstrap (seeded or clean): if some grant already holds `is_default`
/// it does nothing, otherwise it creates the empty all-agents [`Grant::default_baseline`]. There is
/// always a baseline, and it can be paused but not deleted while it is the default.
pub fn ensure_default_grant(store: &dyn Store) -> Result<(), GatewayError> {
    if store.list_grants()?.iter().any(|g| g.is_default) {
        return Ok(());
    }
    store.put_grant(Grant::default_baseline("gr_default"))?;
    Ok(())
}

/// Bootstrap a **clean** gateway for a real paired install: no demo connections, policies,
/// grants or agents, just a single approved `operator` identity holding a freshly-minted,
/// unguessable **per-gateway operator token** (returned so the caller can surface it for
/// pairing). This is what makes "connected" a true clean slate: the console comes up
/// empty with "add your first connection" affordances, and the only credential in play is a
/// real token, never the shared [`DEMO_TOKEN`].
pub fn clean_bootstrap(store: &dyn Store) -> Result<String, GatewayError> {
    let now = now_ms();
    let token = format!("pgt_{}", short_id());
    store.put_agent(Agent::approved(OPERATOR_AGENT_ID, "Operator", now))?;
    store.put_session(Session {
        class: crate::store::SessionClass::OperatorToken,
        opened_by: None,
        id: format!("sess_{}", short_id()),
        agent_id: OPERATOR_AGENT_ID.into(),
        user_id: None,
        device_id: None,
        token: token.clone(),
        role: SessionRole::Operator,
        created_at: now,
        revoked: false,
        // Capped now that rotation-with-overlap exists, which is the precondition this comment used to
        // name: `spawn_operator_token_refresher` replaces the published token before it expires and
        // leaves the previous session to run out on its own, so a client holding the older value is
        // never cut off mid-use. Without that, an expiry here stranded the install with no way back in.
        //
        // Why bother: this file is mode 0600 in the owner's home, so on a machine that runs agents
        // every agent the owner runs can read it, and a copy taken once worked for the life of the
        // install. The clock does not stop the read (on one OS user nothing can, which is what
        // `--service-user` is for). It stops a copy in an old backup, log or support bundle from still
        // working when someone finds it.
        expires_at: Some(now + crate::OPERATOR_TOKEN_TTL_MS),
        last_used_at: None,
        actor: None,
    })?;
    // Even a clean gateway has the always-present Default baseline (empty until the operator
    // attaches policies), so "approve an agent once → it inherits your general stuff" works day one.
    ensure_default_grant(store)?;
    Ok(token)
}

/// Build an HTTP-kind [`Capability`] (the common case in the seed).
#[allow(clippy::too_many_arguments)]
fn http_cap(
    id: &str,
    description: &str,
    risk: RiskTier,
    action: Action,
    requires_approval: bool,
    resource: &str,
    secret_id: &str,
) -> Capability {
    Capability {
        id: id.into(),
        description: description.into(),
        risk,
        action,
        requires_approval,
        resource: resource.into(),
        secret_id: secret_id.into(),
        kind: CapabilityKind::Http,
        command: None,
        http: None,
        ssh: None,
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    /// Nothing the seed writes takes an id the gateway keeps for its own holds and actions.
    #[test]
    fn nothing_seeded_takes_a_reserved_id() {
        use crate::store::Store as _;
        let store = crate::store::memory::MemoryStore::new();
        super::seed(&store).unwrap();
        let connections = store.list_connections().unwrap();
        assert!(!connections.is_empty());
        for c in connections {
            assert!(!crate::rest::is_reserved_id(&c.id), "{}", c.id);
        }
        for cap in store.list_capabilities().unwrap() {
            assert!(!crate::rest::is_reserved_id(&cap.id) && !crate::rest::is_reserved_id(&cap.resource), "{}", cap.id);
        }
    }
}
