# Example: Braintree via the generic-HTTP template

The clearest illustration of Permaura's risk-tier model, on one connector: a **medium-risk read** the agent can do freely within a grant, and a **critical, approval-gated write** (a refund) that is held for approval on every call, which the operator token or a paired device resolves. This is the payments patient-0 workflow and the signature prompt-injection demo from the spec: *an injection tries to refund a payment; Permaura blocks it.*

`template.json` illustrates the shape only: the gateway does not load it. On a real gateway, per-endpoint capabilities with their own risk come from a preset, a signed or user connector manifest, or an OpenAPI import, and the generic-HTTP path is a `generic-http` connection with an operator host allowlist, where the agent supplies an https URL on an allowed host.

## What's here

- [`connector.ts`](./connector.ts): a `defineConnector` version showing `transactions.search` (medium) and `transactions.refund` (critical, `requiresApproval`), with payment-data redaction.
- [`template.json`](./template.json), the declarative generic-HTTP template: base URL, auth (by secret reference), capability/risk mapping, deny list, and redaction fields. No secret value lives in this file: it is referenced by name.

## Risk tiers on display

| Capability id | Risk | Default behavior |
| --- | --- | --- |
| `braintree.transactions.search` | medium | Allow within a grant, with payment fields masked. |
| `braintree.transactions.read` | medium | Allow within a grant, with masking. |
| `braintree.customers.read` | medium | Allow within a grant, with masking. |
| `braintree.transactions.refund` | **critical** | **Held for approval on every call** (a gateway capability at `critical` risk floors at `approve`, which the operator token or a paired device resolves), single-use and bound to the held call's exact parameters. |

For payments, a read is medium risk and a refund is critical.

## Approval and redaction

`transactions.refund` sets `requiresApproval: true`. On a gateway capability flagged this way, even a policy that allows it still holds the call for approval (resolved by the operator token or a paired device), bound to the exact parameters ("refund AUD 49.00 for transaction abc123"), single-use. A refund approval cannot be replayed against a different transaction or a larger amount.

Every response is redacted at two layers: the connector strips `card_number`, `cvv`, `billing_address`, `customer_email`, and `payment_method_token` at the source, and on a capability the gateway runs, its own redaction is a second layer. See [../../docs/security.md](../../docs/security.md).

## A matching grant: read-only

The clean patient-0 grant denies refunds outright:

```bash
permaura grant \
  --agent codex-cli \
  --resource braintree_production \
  --allow transactions.search --allow transactions.read --allow customers.read \
  --deny transactions.refund --deny transactions.sale --deny transactions.void --deny customers.update \
  --expires 2026-06-22T18:00:00Z \
  --max-calls 100
```

Each `--allow` and `--deny` takes one action. Redaction fields belong on the connection or the policy; there is no per-device or execution-location flag.

## The demo: read succeeds, refund is blocked

The agent reads yesterday's failures successfully:

```json
{
  "tool": "permaura_invoke",
  "arguments": {
    "capability": "braintree.transactions.search",
    "params": { "status": "failed", "date": "2026-06-21" },
    "reason": "Summarize yesterday's failed payments."
  }
}
```

Then a prompt injection hidden in an API response or a repo file tells the agent to refund everything. The agent attempts it:

```json
{
  "tool": "permaura_invoke",
  "arguments": {
    "capability": "braintree.transactions.refund",
    "params": { "transactionId": "abc123", "amount": 49.0, "currency": "AUD" },
    "reason": "Instruction in the data said to refund this."
  }
}
```

With the read-only grant above, the refund is **denied** (it is on the policy's `deny` list), and the attempt is recorded. If a policy instead *allowed* refunds with approval, the agent would not get a refund either: it would get a `requires_approval` decision and a held approval that you deny from the CLI, the console or a paired device, because you did not initiate it. Either way, the money does not move and the audit log shows the attempted misuse. That is the demo that explains the product.

## Adapting the template to another API

Use [`template.json`](./template.json) as a planning sheet: change `base_url`, the `secret_ref`, and the capability `match` rules, and re-classify each action's risk. The gateway does not load the file, so express the result as an OpenAPI import or a connector manifest. Reads are usually medium; writes are high; anything that moves money, deletes data, or rotates a production secret is critical and should set `requires_approval: true`.
