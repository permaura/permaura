# Example: Stripe (read-only)

The simplest, safest posture for financial data: a connector that exposes **only reads**. The agent can list charges, read a charge, read a customer, and list disputes (exactly enough to diagnose and summarize), and the definition has no charge, refund or update capability. The gateway does not load SDK connectors; its own Stripe preset does include writes such as `refunds.create`, created switched off.

This is the read-only half of the payments patient-0 workflow: *"inspect failed payments and summarize the top failure reasons. Do not refund, retry, or modify anything."*

## What's here

- [`connector.ts`](./connector.ts): a `defineConnector` with four read capabilities and their input schemas.

## Capabilities

| Capability id | Risk | What it does |
| --- | --- | --- |
| `stripe.charges.list` | medium | List recent charges. |
| `stripe.charges.read` | medium | Read one charge by id. |
| `stripe.customers.read` | medium | Read one customer by id. |
| `stripe.disputes.list` | medium | List disputes. |

Reads of payment data are `medium`, not `low`, because they touch customer and card-adjacent data, so they are allowed within a grant but always with masking.

## Why read-only is its own security feature

There is no `stripe.charges.create`, no `stripe.refunds.create`, no `stripe.subscriptions.update`, and no `stripe.customers.delete`. A prompt injection that tells the agent to "refund this customer" or "issue a charge" finds no tool to call. The connector's *shape* is the control: you cannot misuse a capability that does not exist. If you later need a write, you add it deliberately as a `critical`, `requiresApproval` capability, never by accident.

## Redaction

Stripe payloads can carry card numbers, CVCs, expiry, addresses, emails, phone numbers, and client secrets. The connector strips these at the source (`number`, `cvc`, `exp_month`, `exp_year`, `address`, `email`, `phone`, `client_secret`); the gateway's own redaction applies only to capabilities it runs. The agent gets the structure it needs to reason (amounts, statuses, failure codes) without the sensitive fields. See [../../docs/security.md](../../docs/security.md).

## A matching grant

```bash
permaura grant \
  --agent claude-code \
  --resource stripe_production \
  --allow charges.list --allow charges.read --allow customers.read --allow disputes.list \
  --expires 2026-06-22T18:00:00Z \
  --max-calls 50
```

Field redaction is set on the connection or the policy, not the grant.

No `--deny` is needed for writes: deny-by-default refuses any capability no policy allows.

## How the agent uses it

```json
{
  "tool": "permaura_invoke",
  "arguments": {
    "capability": "stripe.charges.list",
    "params": { "limit": 50 },
    "reason": "User asked for a summary of recent failed charges."
  }
}
```

Permaura validates the params, checks the grant, injects the Stripe key, calls the API, redacts card/PII fields, and returns the structured list. The key never appears anywhere the agent can see, and the audit log records the read with the upstream status and the shape of the result.

See [../../docs/connector-authoring.md](../../docs/connector-authoring.md) for the full `defineConnector` reference and [../braintree-generic-http](../braintree-generic-http) for the contrasting example that adds a critical, approval-gated write.
