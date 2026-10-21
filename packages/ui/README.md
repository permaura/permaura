# @permaura/ui

Shared, security-grade React components for the [Permaura](https://permaura.com) console and Tauri apps. Dark by default, token-driven, dependency-light (React is a peer dependency; nothing else ships at runtime).

## Install

```bash
pnpm add @permaura/ui react react-dom
```

## Use

Import the tokens once at your app root, then the components anywhere.

```tsx
import "@permaura/ui/tokens.css";
import { RiskBadge, DecisionBadge, ApprovalCard, AuditRow, StatusDot } from "@permaura/ui";

export function Demo() {
  return (
    <>
      <RiskBadge risk="critical" />
      <DecisionBadge decision="requires_approval" />
      <StatusDot status="online" label="Broker enabled" pulse />

      <ApprovalCard
        agent="codex-cli"
        capability="braintree.transactions.refund"
        risk="critical"
        type="push"
        message="Codex wants to refund AUD 49.00 for Braintree transaction abc123."
        onApprove={() => {/* client.resolveApproval(...) */}}
        onDeny={() => {/* client.resolveApproval(...) */}}
      />

      <AuditRow
        timestamp="2026-06-22T15:24:01+10:00"
        action="braintree.transactions.search"
        agent="codex-cli"
        resource="braintree_production"
        decision="allow"
        executionLocation="local"
        summary="14 records"
        verified
      />
    </>
  );
}
```

## Components

| Component | Purpose |
| --- | --- |
| `RiskBadge` | Risk tier chip: `low` / `medium` / `high` / `critical` |
| `DecisionBadge` | Policy outcome: `allow` / `deny` / `requires_approval` |
| `ApprovalCard` | The human approval gate (the "patient 0" demo centrepiece) |
| `AuditRow` | One dense, decision-colored row of the hash-chained audit log |
| `StatusDot` | Colored live-status dot with optional label and pulse |

## Theming

Everything is driven by CSS custom properties in `tokens.css` (`--bst-*`). Override any of them at `:root` or a scoped container to re-theme. A light theme ships behind `[data-theme="light"]`.

## Build

```bash
pnpm build      # tsup -> dist (esm + .d.ts), copies tokens.css
pnpm typecheck  # tsc --noEmit
```
