# permaura (Python SDK)

> **Out of date and unsupported.** This client no longer matches the gateway's v1 REST API: it sends `principal` where session creation needs `agent_id`, sends `decision` where resolving an approval needs a boolean `approve`, and expects response shapes the gateway does not return. Do not use it until it is realigned. To drive a gateway today, follow the [REST API walkthrough](https://docs.permaura.com/developers/rest-api-walkthrough) and the [REST API reference](https://docs.permaura.com/developers/rest-api).

The Python SDK for [Permaura](https://permaura.com): _give agents permission, not keys._

A mirror of the TypeScript SDK, in two halves:

- **`PermauraClient`**: a typed REST client (httpx) over the Permaura gateway.
- **Connector authoring**: `define_connector(...)`, `Capability`, and the `redact()` helper, for describing risk-tiered capabilities and running them in your own process. They enforce no policy, and the gateway does not load them.

## Install

The SDK is not on PyPI yet, so install it from a checkout of this repository:

```bash
pip install ./packages/sdk-python      # from the repository root
```

Requires Python 3.10+. Until this README links a PyPI release, a package named `permaura` on PyPI is not this SDK.

## Talking to the gateway

```python
from permaura import PermauraClient, Principal
from permaura.types import DecisionKind

# Defaults to the local broker at http://127.0.0.1:7376.
with PermauraClient() as client:
    session = client.create_session(
        Principal(user="sam", agent="codex-cli", device="sam-macbook"),
        label="Failed payment triage",
    )
    client.set_token(session["token"])

    caps = client.list_capabilities(scope="current_session")

    res = client.invoke(
        capability="braintree.transactions.search",
        params={"status": "failed", "date": "2026-06-21"},
        reason="User asked me to summarize yesterday's failed payments.",
    )

    if res.decision.decision is DecisionKind.REQUIRES_APPROVAL:
        print("Waiting on a human:", res.decision.approval.message)
    elif res.decision.decision is DecisionKind.ALLOW:
        print(res.result)  # already redacted
```

Denials raise `PermauraApiError`, whose `.reason` carries the policy explanation:

```python
from permaura import PermauraApiError

try:
    client.invoke("braintree.transactions.refund", {})
except PermauraApiError as err:
    print(err.reason)
```

## Authoring a connector

`execute` receives whatever secret the caller of `invoke` passes, on the context; it should use it and never return it.

```python
from permaura import define_connector, Capability, redact
from permaura.types import RiskTier

braintree = define_connector(
    id="braintree",
    capabilities=[
        Capability(
            id="transactions.search",
            risk=RiskTier.MEDIUM,
            description="Search Braintree transactions",
            execute=lambda input, ctx: redact(
                braintree_api.search(input, ctx.secret), fields=ctx.redact_fields
            ),
        ),
        Capability(
            id="transactions.refund",
            risk=RiskTier.CRITICAL,
            requires_approval=True,
            execute=lambda input, ctx: braintree_api.refund(input, ctx.secret),
        ),
    ],
)

# Agent-safe specs: risk, description, no execution detail.
for spec in braintree.specs:
    print(spec.id, spec.risk.value)
# braintree.transactions.search medium
# braintree.transactions.refund critical
```

`redact()` strips an explicit field list plus a built-in set of always-dangerous keys (api keys, tokens, authorization headers, cookies, card PAN/CVV, private keys, passwords, database URLs). Use `redact_with_count()` when you also want the number of fields it redacted.

## Develop

```bash
pip install -e ".[dev]"
python -m py_compile src/permaura/*.py
mypy src/permaura
```
