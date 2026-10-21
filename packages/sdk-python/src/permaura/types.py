"""Domain types for the Permaura Python SDK.

These mirror the canonical TypeScript contract in ``@permaura/types``. They are
implemented as :class:`~dataclasses.dataclass` models with light ``from_dict`` /
``to_dict`` helpers rather than a heavy validation dependency, so the package
stays import-light. Enums are plain ``str`` subclasses of :class:`enum.Enum` so a
value like ``RiskTier.CRITICAL`` serialises straight to ``"critical"`` on the wire.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Mapping, Optional, Sequence


class RiskTier(str, Enum):
    """Risk tiers, in lockstep with the Rust core and TS contract."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    """Normalized, snake_case action verbs."""

    READ = "read"
    SEARCH = "search"
    LIST = "list"
    CREATE = "create"
    UPDATE = "update"
    DELETE = "delete"
    EXECUTE = "execute"
    DEPLOY = "deploy"
    REFUND = "refund"
    CHARGE = "charge"
    ROTATE_SECRET = "rotate_secret"
    EXPORT = "export"
    SEND = "send"


class ExecutionLocation(str, Enum):
    LOCAL_ONLY = "local_only"
    REMOTE_ALLOWED = "remote_allowed"


class DecisionKind(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRES_APPROVAL = "requires_approval"


class ApprovalType(str, Enum):
    TOUCH_ID = "touch_id"
    PUSH = "push"
    TWO_PERSON = "two_person"


def _clean(d: Mapping[str, Any]) -> dict[str, Any]:
    """Drop ``None`` values so optional fields are omitted from request bodies."""

    return {k: v for k, v in d.items() if v is not None}


@dataclass(slots=True)
class Principal:
    """Who or what is asking. Stringified as ``user:<id>`` / ``agent:<id>`` / ..."""

    user: Optional[str] = None
    agent: Optional[str] = None
    device: Optional[str] = None
    org: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return _clean(asdict(self))


@dataclass(slots=True)
class Conditions:
    """Deprecated and not implemented: the gateway has no grant conditions.

    None of these fields is applied, and a request carrying ``conditions`` is refused with a 400 naming it. A gateway enforces a grant's expiry and call limits and a policy's rungs, including ``device_signed`` with a quorum of distinct people.
    """

    expires_at: Optional[str] = None
    max_calls: Optional[int] = None
    max_amount: Optional[float] = None
    allowed_hosts: Optional[Sequence[str]] = None
    allowed_paths: Optional[Sequence[str]] = None
    allowed_repos: Optional[Sequence[str]] = None
    allowed_environments: Optional[Sequence[str]] = None
    approval_required: Optional[Sequence[str]] = None
    business_hours_only: Optional[bool] = None
    execution_location: Optional[ExecutionLocation] = None
    requires_touch_id: Optional[bool] = None
    requires_two_person_approval: Optional[bool] = None
    redact_fields: Optional[Sequence[str]] = None

    def to_dict(self) -> dict[str, Any]:
        data = _clean(asdict(self))
        if isinstance(data.get("execution_location"), ExecutionLocation):
            data["execution_location"] = data["execution_location"].value
        return data


@dataclass(slots=True)
class ApprovalRequirement:
    """The human gate returned inside a ``requires_approval`` decision."""

    type: ApprovalType
    message: str
    single_use: bool = True

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "ApprovalRequirement":
        return cls(
            type=ApprovalType(d["type"]),
            message=d.get("message", ""),
            single_use=bool(d.get("single_use", True)),
        )


@dataclass(slots=True)
class Decision:
    """The policy engine's verdict."""

    decision: DecisionKind
    reason: str
    policy_id: Optional[str] = None
    approval: Optional[ApprovalRequirement] = None

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "Decision":
        approval = d.get("approval")
        return cls(
            decision=DecisionKind(d["decision"]),
            reason=d.get("reason", ""),
            policy_id=d.get("policy_id"),
            approval=ApprovalRequirement.from_dict(approval) if approval else None,
        )


@dataclass(slots=True)
class CapabilitySpec:
    """The agent-facing spec for a capability. Carries no execution detail."""

    id: str
    risk: RiskTier
    description: Optional[str] = None
    action: Optional[Action] = None
    connector: Optional[str] = None
    requires_approval: Optional[bool] = None
    input_schema: Optional[dict[str, Any]] = None

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "CapabilitySpec":
        return cls(
            id=d["id"],
            risk=RiskTier(d["risk"]),
            description=d.get("description"),
            action=Action(d["action"]) if d.get("action") else None,
            connector=d.get("connector"),
            requires_approval=d.get("requiresApproval", d.get("requires_approval")),
            input_schema=d.get("inputSchema", d.get("input_schema")),
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "risk": self.risk.value,
            "connector": self.connector,
            "description": self.description,
            "action": self.action.value if self.action else None,
            "requiresApproval": self.requires_approval,
            "inputSchema": self.input_schema,
        }
        return _clean(data)


@dataclass(slots=True)
class InvokeResult:
    """Outcome of an invoke: the decision plus an optional redacted result."""

    decision: Decision
    result: Any = None
    approval_id: Optional[str] = None
    execution_location: Optional[str] = None
    tool_call_id: Optional[str] = None
    raw: Mapping[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "InvokeResult":
        return cls(
            decision=Decision.from_dict(d["decision"]),
            result=d.get("result"),
            approval_id=d.get("approval_id"),
            execution_location=d.get("execution_location"),
            tool_call_id=d.get("tool_call_id"),
            raw=d,
        )


__all__ = [
    "RiskTier",
    "Action",
    "ExecutionLocation",
    "DecisionKind",
    "ApprovalType",
    "Principal",
    "Conditions",
    "ApprovalRequirement",
    "Decision",
    "CapabilitySpec",
    "InvokeResult",
]
