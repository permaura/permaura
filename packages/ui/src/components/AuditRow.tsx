import * as React from "react";
import { cn } from "../cn.js";
import { DecisionBadge, type DecisionKind } from "./DecisionBadge.js";

/** Where the action executed, mirroring `ExecutionSite` in @permaura/types. */
export type ExecutionSite = "local" | "remote" | "hosted" | "customer";

export interface AuditRowProps extends React.HTMLAttributes<HTMLDivElement> {
  /** ISO timestamp of the event. */
  timestamp: string;
  /** Capability / action, e.g. `braintree.transactions.search`. */
  action: string;
  decision: DecisionKind;
  /** Agent that acted, e.g. `codex-cli`. */
  agent?: string;
  resource?: string;
  executionLocation?: ExecutionSite;
  /** Short result summary, e.g. "14 records, 6 fields redacted". */
  summary?: string;
  /** When true, render a chain-link glyph indicating this row is hash-chained/verified. */
  verified?: boolean;
}

const SITE_LABEL: Record<ExecutionSite, string> = {
  local: "Local",
  remote: "Remote",
  hosted: "Hosted",
  customer: "Customer",
};

function formatTime(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/**
 * A single row in the audit log. Dense, monospaced where it matters, and decision-coloured. The optional `verified` flag renders a chain glyph to signal the row sits in the tamper-evident hash chain, and clicking through (host-wired) can show the signature and prev_hash.
 */
export const AuditRow = React.forwardRef<HTMLDivElement, AuditRowProps>(
  (
    { timestamp, action, decision, agent, resource, executionLocation, summary, verified, className, style, ...rest },
    ref,
  ) => {
    return (
      <div
        ref={ref}
        role="row"
        className={cn("bst-audit-row", className)}
        style={{
          display: "grid",
          gridTemplateColumns: "150px 1fr auto",
          alignItems: "center",
          gap: 14,
          padding: "10px 14px",
          borderBottom: "1px solid var(--bst-border)",
          background: "var(--bst-surface)",
          fontFamily: "var(--bst-font-sans)",
          fontSize: 13,
          color: "var(--bst-fg)",
          ...style,
        }}
        {...rest}
      >
        <span style={{ color: "var(--bst-fg-subtle)", fontFamily: "var(--bst-font-mono)", fontSize: 12 }}>
          {formatTime(timestamp)}
        </span>

        <div style={{ display: "flex", flexDirection: "column", gap: 2, minWidth: 0 }}>
          <span style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <code style={{ fontFamily: "var(--bst-font-mono)", color: "var(--bst-fg)", fontSize: 13 }}>{action}</code>
            {verified ? (
              <span aria-label="Hash-chained" title="Hash-chained, signed" style={{ color: "var(--bst-status-online)", display: "inline-flex" }}>
                <svg width={12} height={12} viewBox="0 0 16 16" fill="none" aria-hidden>
                  <path
                    d="M6.5 9.5l3-3M5 11a2.5 2.5 0 010-3.5l1.5-1.5M11 5a2.5 2.5 0 010 3.5L9.5 10"
                    stroke="currentColor"
                    strokeWidth={1.4}
                    strokeLinecap="round"
                  />
                </svg>
              </span>
            ) : null}
          </span>
          <span style={{ color: "var(--bst-fg-subtle)", fontSize: 12, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {agent ? <span style={{ fontFamily: "var(--bst-font-mono)" }}>{agent}</span> : null}
            {agent && resource ? " · " : ""}
            {resource ?? ""}
            {summary ? `${agent || resource ? " · " : ""}${summary}` : ""}
          </span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {executionLocation ? (
            <span style={{ fontSize: 11, color: "var(--bst-fg-subtle)" }}>{SITE_LABEL[executionLocation]}</span>
          ) : null}
          <DecisionBadge decision={decision} />
        </div>
      </div>
    );
  },
);
AuditRow.displayName = "AuditRow";
