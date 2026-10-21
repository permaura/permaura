# Data model

A gateway keeps its state in one SQLite database, `gateway.db` under the Permaura home, owner-only on disk. Secret values are sealed in it, as [security.md](./security.md) describes, and their vault key lives outside it. Everything else is plain rows protected by file permissions: the database is not itself encrypted. A hosted worker runs the same store in memory and writes a snapshot of it to its tenant's own object-storage bucket; only identity, scale and the custody of the keys differ.

## The tables

Most tables hold one JSON document per object, keyed by its id. The schema is versioned, and a gateway refuses a database written by a newer schema than it knows.

```text
agents               agent identities and their approval state (Pending, Approved, ...)
sessions             bearer sessions (agent or operator): id, the token's SHA-256, the session
enrolment_codes      one-time agent enrolment codes, keyed by their SHA-256
connections          configured integration instances: connector family, credential id,
                     capabilities, the operator's switches, host allowlist, redact_fields
capabilities         the named actions a connection exposes, with risk and approval flags
connector_manifests  installed connector manifests and their provenance
policies             per-connection rung lists (allow, notify, requires_approval,
                     device_signed with its quorum, deny) and redact_fields
grants               bindings of policies to agents (or all agents) under limits and expiry
grant_usage          the calls charged to each grant and agent, per period
secrets              one row per secret: its sealed record and its metadata
secret_custody       which custody layer holds a secret (local vault, KMS, an external store)
approvals            held calls and held control-plane changes, with their parameters
audit_events         the hash-chained, signed audit log, one event per sequence number
call_diagnostics     the text explaining a failed call, kept beside the chain, aged out
one_time_claims      the replay cache behind single-use tokens and tickets
gateway_meta         key/value: approver keys and the approval floor, the approval audience,
                     the audit chain's boundary, and on a hosted worker its wrapped audit key
```

Users, organizations, memberships and billing are permaura.com's, not the gateway's: a gateway knows the owner and the acting member a token names, and nothing else about accounts.

## Secrets

A secret is one row: its id, the sealed envelope (ciphertext, wrapped DEK, salt, nonces, cipher id) and its non-secret metadata (labels, a risk classification, the execution locations it allows) in the same document. To open it the gateway takes the vault key from its custody (the OS credential store or an owner-only file locally, Secret Manager on a hosted worker), derives the wrapping key with Argon2id and the stored salt, unwraps the DEK and decrypts the value. A secret enrolled to KMS custody, or held by an external custodian such as Infisical, is resolved through `secret_custody` instead. The vault key is never in the database.

A secret whose metadata names where it may run, and does not name remote execution, is refused for a call that would execute remotely; one that names nothing, which is every credential added through the console, records no restriction.

## Sessions and enrolment codes

No session token or enrolment code is stored in the clear. `sessions` keeps the SHA-256 of each session's token, in its key column and in its document, and `enrolment_codes` keeps the SHA-256 of each code; a presented bearer or code is looked up by its digest. A copy of the database therefore yields no working session token. The operator token a gateway publishes to `operator.token` in its home is a session like any other, and the file, not the database, is what a same-user process reads (see security.md, Same-user boundary).

## Approvals

`approvals` holds every held call and held control-plane change. A held agent call keeps the call's full parameters as the agent sent them, so that it can run verbatim once a person approves it, and after it runs, the redacted result the agent received and its status. These are plain rows: the parameters are not masked at rest, only in the renderings an approver is shown. A held agent call does not expire, a held control-plane change lapses 24 hours after it was held and a held vault export ten minutes after its request, and resolving a hold does not delete its row, so a held call's parameters and result stay in the database, in its backups and, on a hosted worker, in its retained snapshots until the row is removed. Keep values you would not store out of the parameters of a capability that can be held.

An approval is bound to the exact call: the device signature covers the request hash of the held parameters and a digest of the rendering the approver was shown, and an approval runs at most once: resolving one that is already resolved returns its outcome and runs nothing.

## The audit chain

`audit_events` holds one sealed event per sequence number. Every policy decision and every execution appends one, as do the configuration and trust changes security.md lists; a call refused before it reaches policy appends nothing.

```text
seq          the absolute sequence number, from 0
timestamp    unix milliseconds
prev_hash    the hash of the event before it            ← the chain link
payload      action (the capability or control-plane kind), resource, decision, the agent,
             user and session where known, execution location, and a summary: for a call, the
             grant and policy that authorized it, the agent's stated reason after masking, the
             upstream status and the result's shape ({"records": n} or {"fields": n}); for an
             approval, who resolved it and how
hash         sha256 over seq, timestamp, prev_hash and payload
signature    ed25519 over the hash
```

A representative event:

```json
{
  "seq": 1042,
  "timestamp": 1792666441000,
  "prev_hash": "9f2b7c...",
  "payload": {
    "action": "braintree.transactions.search",
    "resource": "braintree_production",
    "decision": "allow",
    "agent_id": "codex-cli",
    "session_id": "sess_123",
    "execution_location": "local",
    "summary": {
      "status": 200,
      "result_summary": { "records": 14 },
      "intent": "Find the refund for order 4411",
      "grant_id": "gr_default",
      "policy_id": "pol_braintree_read",
      "notified": false
    }
  },
  "hash": "4c1e75...",
  "signature": "7c10a4..."
}
```

Events carry no request or response bodies and no credential the gateway holds. The agent's stated reason is free text: it is cut to 4 KiB and masked by the same heuristics as an approval's rendering before it is written, which catches secrets by name and shape, not every secret an agent might paste.

What the chain proves, and what it does not:

- **Hash chaining.** Each event's hash covers its content and the previous event's hash, so altering or removing an event inside the chain breaks every later link, which verification reports.
- **Truncation.** Removing events from the end leaves a shorter chain that still verifies, because nothing in the store remembers how long it was. Only a checkpoint of the head shows it: a hosted worker publishes a signed one to its process log at each cold start, nothing compares the store against it automatically, and a self-run gateway publishes none.
- **The signature.** It is as strong as the custody of the key. On a self-run gateway the key is an owner-only file beside the database, so whoever can write the database as the owner can also sign a rewritten history; on a hosted worker it is wrapped under the tenant's Cloud KMS key. The authenticated audit surfaces report the chain's public key, which permaura.com's console pins on first sight (security.md).
- **The archive.** With the audit archive, the oldest events are moved to signed archive segments, each written create-only and read back, before they are pruned from the live store: a self-run gateway keeps them under `audit-archive` in its home unless `PERMAURA_AUDIT_ARCHIVE=0`, and a hosted worker publishes them to a bucket where one is configured. A segment in a bucket that grants create and no overwrite cannot be changed by the gateway; one in a self-run gateway's home can be rewritten by anything that can write the home, as the live store can. A signed boundary states where the live window starts.

## Design rules, restated

- **The vault key is never in the database.** A copy of `gateway.db` alone opens no secret and carries no working bearer, but it does carry every policy, grant, agent, approval (held parameters included), connection and audit event in plain rows.
- **Bodies are not audited.** The chain records shapes, counts, ids and the masked reason; held calls keep their parameters and result in `approvals`, outside the chain.
- **The audit chain is tamper-evident against an outsider.** Its limits are truncation and the custody of its key, as above.
- **Recorded calls are attributable.** Every recorded call names its agent and session, and an allowed or held one the grant and policy behind it; a call refused before policy is not recorded.
