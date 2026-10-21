# Policy language

Permaura's policy model answers one question deterministically: *may this agent run this capability, on this connection, right now, and does a person have to approve it first?* The answer is one of `allow`, `deny` or `requires_approval`, with a reason. A model is never in the decision path, and the resting state is `deny`: an agent can do only what a person bound to it.

The engine is `permaura-policy`, a structured model in Rust. This page describes what it evaluates, in the shape the gateway's REST API and console use. Anything not described here is not evaluated.

## The objects

```text
connection   a configured integration (braintree_production, github_acme): its capabilities,
             the operator's switches, a host allowlist, and the credential it uses
capability   one named action on a connection (braintree.transactions.search), with a risk tier
policy       per connection: which actions run, notify, need approval, need a device, or are denied
grant        binds policies to agents (or to every agent) under call limits and an expiry
agent        the caller, identified by its session; a new one waits Pending until approved
```

### Connections and capabilities

A capability id is a connection's connector family followed by a dotted action path, for example `braintree.transactions.search` or `github.pull_requests.create`. Policies refer to the action id, which is the capability id without its first segment (`transactions.search`).

Each capability carries a risk tier (`low`, `medium`, `high`, `critical`) and may declare that it always needs approval. Both are set where the capability is defined, and the operator can change them.

A connection carries three switches that act above every policy:

- `disabled`: every capability on the connection is denied.
- `disabled_capabilities`: the listed capabilities are denied for every grant.
- `allowed_hosts`: the hosts a generic-HTTP connection may call. It is required for a generic-HTTP connection, and a request to any other host, or over anything but `https`, is denied.

A connection and a policy may each list `redact_fields`: response field names redacted on every call, on top of the gateway's defaults. A redaction list can only add names, never remove a default.

### Policies

A policy is scoped to one connection and names no agent and no limits. It sorts action ids onto rungs:

```text
allow              run at once (the auto rung)
notify             run at once, then push a notification to the paired devices
requires_approval  hold for a person: the operator's session or a paired device resolves it
device_signed      hold for a paired device's signature only; an operator bearer cannot resolve it
deny               never run
```

`device_signed_quorum` (default 1) says how many distinct people must sign a `device_signed` action: a phone and a watch paired to one person count once. It applies only to the `device_signed` rung, and it is the only way to require two people.

Within one policy an action listed on several rungs takes the most restrictive one (`deny`, then `device_signed`, then `requires_approval`, then `notify`, then `allow`), and listing an action on any rung but `deny` permits it.

### Grants

A grant binds a set of policies (which may span connections) to a set of agents, or to every approved agent including future ones. It carries no action lists of its own: what it permits comes from its policies.

```text
policy_ids                the policies it activates
all_agents | agents       every approved agent, or a list (each with an optional per_agent_limit)
period                    day | week | month | total: the rolling window both limits count over
overall_limit             the most calls across all its agents per period
default_per_agent_limit   each agent's limit per period, unless the agent's own overrides it
expires_at                after this instant the grant is inert
enabled                   a paused grant is inert
```

One grant is always the Default: it covers every approved agent and starts with no policies, so binding a policy to it gives that policy to everyone.

## Risk tiers

| Risk tier | What it does to a permitted call |
| --- | --- |
| `low` | nothing: the policy's rung applies |
| `medium` | nothing: the policy's rung applies |
| `high` | raises the rung to at least `requires_approval` |
| `critical` | raises the rung to at least `requires_approval` |

A capability that declares it always needs approval is raised the same way. Neither raises a call to `device_signed` or to a quorum: at `requires_approval` the operator's session resolves the hold, so a call that should need a device, or two people, needs a policy that puts it on the `device_signed` rung (with a quorum). The gateway-wide approval floor (`PUT /v1/approval-floor`) can raise every hold to need a device signature; [security.md](./security.md#approval-trust-state) describes it.

## Decisions

```json
{
  "decision": "allow | deny | requires_approval",
  "reason": "human-readable explanation"
}
```

On `requires_approval` the call is held and the agent receives the approval's id; it polls `permaura_get_approval_status`, and on a denial `permaura_explain_denial` returns the reason. Over REST a denial is a 403 with the reason and a hold a 202 with the pending approval. The decision is recorded in the audit chain with the grant and policy behind it.

## Evaluation

The engine never falls through to allow. Before it runs, the gateway checks that the capability exists, its connection is enabled and the capability is not switched off, the agent is approved, and the gateway is not paused. Then, for the agent and the capability's action id:

1. **Gather** the enabled, unexpired grants covering this agent that hold at least one policy scoped to this connection. None: **deny**.
2. **Deny wins.** Any of those policies that denies the action: **deny**.
3. **Permit.** At least one of those policies must list the action on a rung other than `deny`, or: **deny**.
4. **Budget.** Keep only the grants with headroom in both limits for this agent. None: **deny** (budget exhausted). If several remain, the call is charged to the one with the most headroom.
5. **Rung.** Take the most restrictive rung, and the highest quorum, across every permitting policy of every gathered grant, so one permissive policy cannot lower what another sets. Raise it to `requires_approval` if the capability is High or Critical risk or always needs approval.
6. `requires_approval` or `device_signed`: **requires_approval**, held with that quorum. Otherwise **allow** (with a notification for `notify`).

The response is then redacted with the union of the gateway's defaults, the connection's, its manifest's and every permitting policy's `redact_fields`. A credential marked local-only is refused for a call that would execute remotely.

## Example

A read-only policy on a Braintree connection, a policy that lets refunds run only with two people's device signatures, and a grant that gives both to one agent for a day:

```json
{
  "id": "pol_braintree_read",
  "connection_id": "braintree_production",
  "name": "Read-only",
  "allow": ["transactions.search", "transactions.read", "customers.read"],
  "deny": ["transactions.void", "payment_methods.delete"]
}
```

```json
{
  "id": "pol_braintree_refunds",
  "connection_id": "braintree_production",
  "name": "Refunds, two people",
  "device_signed": ["transactions.refund"],
  "device_signed_quorum": 2
}
```

```json
{
  "grant_id": "gr_codex_braintree",
  "name": "Codex on Braintree",
  "policy_ids": ["pol_braintree_read", "pol_braintree_refunds"],
  "agents": [{ "agent_id": "codex-cli", "per_agent_limit": 100 }],
  "period": "day",
  "expires_at": "2026-06-22T18:00:00+10:00"
}
```

With these, `codex-cli` can search and read up to 100 calls a day until the grant expires; a refund is held until devices belonging to two different people sign it; a void is denied; and anything on the connection that neither policy lists is denied by default. Sent to `POST /v1/policies` and `POST /v1/grants`.

## What the model does not have

These are not evaluated anywhere, and a document that describes them describes an earlier design:

- No conditions on a grant: no amount ceiling, no business hours, no environment, repository or path scoping, and no per-call biometric requirement. An amount in the request is not compared with anything. To keep an agent away from large refunds, deny the action, or hold it at `device_signed` with a quorum.
- No principal facets beyond the agent: policies do not match on the user, the device a call came from or the organization.
- No action lists on a grant, and no wildcard that grants everything.

## The Cedar question

Cedar's `principal can perform action on resource when conditions` shape, and its forbid-overrides-permit rule, line up with this model's deny-wins evaluation, and it is a possible future engine. Nothing in the gateway compiles to Cedar or evaluates it today.
