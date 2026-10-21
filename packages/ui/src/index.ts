/**
 * @permaura/ui: shared, security-grade React components for the Permaura Tauri apps and web console. Dark-default, token-driven, dependency-light. Import the tokens once:
 *
 * ```ts
 * import "@permaura/ui/tokens.css";
 * import { RiskBadge, DecisionBadge, ApprovalCard, AuditRow, StatusDot } from "@permaura/ui";
 * ```
 */
export { RiskBadge, type RiskBadgeProps, type RiskTier } from "./components/RiskBadge.js";
export { DecisionBadge, type DecisionBadgeProps, type DecisionKind } from "./components/DecisionBadge.js";
export { ApprovalCard, type ApprovalCardProps, type ApprovalType } from "./components/ApprovalCard.js";
export { AuditRow, type AuditRowProps, type ExecutionSite } from "./components/AuditRow.js";
export { StatusDot, type StatusDotProps, type Status } from "./components/StatusDot.js";
export { cn, type ClassValue } from "./cn.js";
