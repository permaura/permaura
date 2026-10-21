# Example: GitHub connector (guarded PR creation)

A `defineConnector` sketch that exposes only the common GitHub loop (read a repo, create a branch, open a pull request, and comment) and leaves merge, force-push, delete and secrets out of its definition. The gateway does not load SDK connectors; its own GitHub preset does define `pull_requests.merge` and `repos.delete`, both `critical` and switched off when the connection is created.

This is the GitHub patient-0 workflow: *"Find the bug in this repo, create a branch, and open a PR. Do not merge it."*

## What's here

- [`connector.ts`](./connector.ts): the connector definition with five capabilities and their input schemas.

## Capabilities

| Capability id | Risk | What it does |
| --- | --- | --- |
| `github.repo.read` | low | Read repository metadata. |
| `github.pull_requests.list` | low | List pull requests. |
| `github.branches.create` | high | Create a branch from a ref. |
| `github.pull_requests.create` | high | Open a pull request. |
| `github.pull_requests.comment` | medium | Comment on a pull request. |

## What is deliberately absent

There is no `github.pull_requests.merge`, no `github.branches.force_push`, no `github.repo.delete`, and no `github.secrets.write`. These capabilities are not defined on the connector, so an agent (or a prompt injection steering the agent) has no tool to call. The safest deny is a capability that does not exist. The spec's dangerous-action list (`repo.delete`, `secrets.write`, `actions.trigger_production`, `branches.force_push`) maps to "not exposed here."

## A matching grant

Create a grant that allows the safe loop and denies the rest. See [../../docs/policy-language.md](../../docs/policy-language.md).

```bash
permaura grant \
  --agent claude-code \
  --resource github_acme \
  --allow repo.read --allow pull_requests.list --allow branches.create \
  --allow pull_requests.create --allow pull_requests.comment \
  --deny pull_requests.merge --deny repo.delete --deny branches.force_push --deny secrets.write \
  --expires 2026-06-22T18:00:00Z
```

No grant restricts which repository the agent names; limit that with the GitHub token's own repository scope.

## How the agent uses it

The agent calls the stable MCP surface (it never names a token):

```json
{
  "tool": "permaura_invoke",
  "arguments": {
    "capability": "github.pull_requests.create",
    "params": {
      "owner": "acme",
      "repo": "app",
      "title": "Fix null deref in payment parser",
      "head": "fix/payment-parser",
      "base": "main",
      "body": "Closes the crash when `amount` is absent. Adds a regression test."
    },
    "reason": "User asked me to open a PR for the bug I found."
  }
}
```

Permaura checks that a policy bound to this agent allows `pull_requests.create`, injects the token, opens the PR, and returns the redacted PR object. A call to a capability that does not exist, such as `github.pull_requests.merge` here, is refused as not found and is not written to the audit log.

## Notes on the code

- **Input schemas run before `execute`.** Branch names are regex-constrained; bodies are size-bounded. Malformed input never reaches the secret.
- **Redaction at the source.** `repo.read` strips `token` / `key` / `deploy_key` / `private_key` from the payload; the gateway's own redaction applies only to capabilities it runs.
- **`secret` never returns.** The injected token is used only inside `execute` and never appears in any return value or error.

See [../../docs/connector-authoring.md](../../docs/connector-authoring.md) for the full `defineConnector` reference.
