"""permaura: the Python SDK for Permaura.

*Give agents permission, not keys.*

Two halves, mirroring the TypeScript SDK:

* :class:`PermauraClient`: a typed REST client over the Permaura gateway.
* The connector authoring API (:func:`define_connector`, :class:`Capability`,
  and the :func:`redact` helper) for describing capabilities and running them in
  your own process; the gateway does not load them.
"""

from __future__ import annotations

from .client import PermauraClient, PermauraApiError, DEFAULT_BASE_URL
from .connector import define_connector, Connector, Capability, ExecuteContext
from .redact import redact, redact_with_count, DEFAULT_REDACT_PATTERNS, REDACTION_PLACEHOLDER
from .types import (
    RiskTier,
    Action,
    ExecutionLocation,
    DecisionKind,
    ApprovalType,
    Principal,
    Conditions,
    ApprovalRequirement,
    Decision,
    CapabilitySpec,
    InvokeResult,
)

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # client
    "PermauraClient",
    "PermauraApiError",
    "DEFAULT_BASE_URL",
    # connector authoring
    "define_connector",
    "Connector",
    "Capability",
    "ExecuteContext",
    # redaction
    "redact",
    "redact_with_count",
    "DEFAULT_REDACT_PATTERNS",
    "REDACTION_PLACEHOLDER",
    # types
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
