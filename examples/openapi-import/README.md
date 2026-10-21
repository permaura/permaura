# Example: OpenAPI import

Permaura's **Level 2** integration path: instead of hand-writing a connector, import an OpenAPI document and Permaura turns each operation into a guarded capability. You provide the spec; Permaura derives capability ids, a normalized action and a default risk tier per operation, and creates every `high` and `critical` capability switched off until you turn it on. This is how a user goes from "here is an API's spec" to "my agent can safely use a slice of it" in minutes.

## What's here

- [`petstore-payments.openapi.yaml`](./petstore-payments.openapi.yaml), a small sample spec that exercises every risk tier: a search and a read (medium), an export (high), an update (high), and a refund and a delete (critical).

## How operations map to capabilities

Permaura derives the capability id from the `operationId` (or, when absent, from the method and path), and the action and default risk from the method, the path and the operationId. A dry run returns the derived capabilities for review, and the import enables nothing above `medium`: writes, deletes and money movement land switched off.

| OpenAPI operation | Method + path | Capability id | Action | Default risk | Approval |
| --- | --- | --- | --- | --- | --- |
| `searchTransactions` | `GET /transactions` | `example_payments.searchTransactions` | search | medium | no |
| `readTransaction` | `GET /transactions/{id}` | `example_payments.readTransaction` | read | medium | no |
| `exportCustomers` | `GET /customers` | `example_payments.exportCustomers` | export | high | held by its `high` risk |
| `updateCustomer` | `PATCH /customers/{id}` | `example_payments.updateCustomer` | update | high | held by its `high` risk |
| `refundTransaction` | `POST /transactions/{id}/refund` | `example_payments.refundTransaction` | refund | **critical** | **yes** |
| `deleteCustomer` | `DELETE /customers/{id}` | `example_payments.deleteCustomer` | delete | **critical** | **yes** |

The classification heuristics, in plain terms:

- **`GET` on a collection** → `search`, medium, unless the operationId contains `export`, which makes it `export` and high. There is no result-size cap.
- **`GET` on an item** (`/transactions/{id}`) → `read`, medium.
- **`POST` / `PATCH` / `PUT`** → `create` / `update`, high, so a call a policy permits is still held for approval, and the capability starts switched off.
- **On a `POST`, `PUT`, `PATCH` or `DELETE`, a path or operationId containing `refund`, `charge`, `capture`, `payout` or `transfer`** → `refund` or `charge`, **critical**, always held for approval. A `GET` is never escalated this way.
- **`DELETE`** → `delete`, **critical**, `requiresApproval`.

The importer does not flag uncertain classifications: review the dry run. A capability no policy allows is denied at runtime whatever its tier.

## Parameters come from the document

Each operation's documented path, query, header and body parameter names become the capability's allow-list: the agent can fill only those, and anything else is dropped. Types and bounds (`exclusiveMinimum`, `minLength`, enums) are not carried over, so the gateway does not range-check `refundTransaction`'s `amount` or `currency`; the upstream API does.

## The secret stays out of the import

The `securitySchemes` entry (`apiKey`, bearer) decides how the key is presented, not what it is. The imported capabilities reference a credential slot derived from the connection id, never a key value; at call time the gateway injects the stored key into the outbound request. The agent never sees it.

## Importing the sample

There is no CLI command for this. Import from the console, or call the operator-authenticated `POST /v1/connections/import-openapi` with `name`, the document as `spec` (or `url` / `spec_url` to fetch it from the host you bind), optional `base_url` and `auth`, and `dry_run: true` first to review what it derives; send the returned `digest` with the real import so it refuses a document that changed since you reviewed it. A dry-run body for this sample:

```json
{
  "name": "example_payments",
  "spec": "<the contents of petstore-payments.openapi.yaml>",
  "base_url": "https://api.example-payments.com/v1",
  "dry_run": true
}
```

The import creates the six capabilities with the tiers in the table above; the update, export, refund and delete capabilities start switched off.

## A matching grant: read-only slice

Import gives you the *whole* surface as capabilities; a grant chooses the *slice* an agent may use. To let an agent only diagnose:

```bash
permaura grant \
  --agent codex-cli \
  --resource example_payments \
  --allow searchTransactions --allow readTransaction \
  --deny refundTransaction --deny deleteCustomer --deny updateCustomer --deny exportCustomers \
  --expires 2026-06-22T18:00:00Z
```

The refund and delete capabilities exist after import, but no grant exposes them to this agent, so the runtime answer for those is `deny`; even if a policy allowed the refund, it would still be held for approval, and it starts switched off.

See [../../docs/policy-language.md](../../docs/policy-language.md) for the grant model and [../../docs/connector-authoring.md](../../docs/connector-authoring.md) for writing capabilities by hand when you need more control than import provides.
