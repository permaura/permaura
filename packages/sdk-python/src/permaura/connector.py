"""The connector authoring API for the Python SDK.

Mirror of the TypeScript ``defineConnector``. A connector describes
risk-tiered capabilities over a real upstream API and runs them in your own
process: it enforces no policy, and the gateway does not load it. ``execute``
receives whatever secret the caller of ``invoke`` passes, on
:class:`ExecuteContext`, and should never return it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Sequence

from .types import RiskTier, CapabilitySpec, Action


@dataclass(slots=True)
class ExecuteContext:
    """Metadata about an authorized invocation handed to ``execute``.

    ``secret`` is the upstream plaintext the caller of ``invoke`` supplied; no
    Permaura component calls ``execute``. Use it to talk upstream; do not return
    it.
    """

    secret: str
    session_id: Optional[str] = None
    principal: Optional[str] = None
    account: Optional[str] = None
    redact_fields: Optional[Sequence[str]] = None
    execution_location: Optional[str] = None
    reason: Optional[str] = None


#: An ``execute`` callable: ``(input, context) -> result``.
ExecuteFn = Callable[[Mapping[str, Any], ExecuteContext], Any]

#: An input validator/coercer applied before ``execute`` runs. Returns the
#: (possibly coerced) input or raises on invalid input. Optional: defaults to a
#: pass-through.
InputValidator = Callable[[Mapping[str, Any]], Mapping[str, Any]]


@dataclass(slots=True)
class Capability:
    """One capability definition within a connector."""

    id: str
    risk: RiskTier
    execute: ExecuteFn
    description: Optional[str] = None
    requires_approval: bool = False
    #: Optional callable that validates/coerces input before ``execute``.
    input_schema: Optional[InputValidator] = None
    #: Optional JSON-Schema dict surfaced in the public spec for agents/forms.
    input_json_schema: Optional[dict[str, Any]] = None


def _trailing_verb(cap_id: str) -> Optional[Action]:
    """Map a capability suffix to a normalized :class:`Action` where it matches."""

    verb = cap_id.split(".")[-1]
    try:
        return Action(verb)
    except ValueError:
        return None


@dataclass(slots=True)
class Connector:
    """A built connector with derived spec/lookup helpers."""

    id: str
    capabilities: list[Capability] = field(default_factory=list)
    description: Optional[str] = None
    _by_full_id: dict[str, Capability] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        for cap in self.capabilities:
            self._by_full_id[f"{self.id}.{cap.id}"] = cap

    @property
    def specs(self) -> list[CapabilitySpec]:
        """Agent-safe specs: risk, description, JSON schema, no execution detail."""

        out: list[CapabilitySpec] = []
        for cap in self.capabilities:
            full_id = f"{self.id}.{cap.id}"
            out.append(
                CapabilitySpec(
                    id=full_id,
                    risk=cap.risk,
                    description=cap.description,
                    action=_trailing_verb(cap.id),
                    connector=self.id,
                    requires_approval=cap.requires_approval or None,
                    input_schema=cap.input_json_schema,
                )
            )
        return out

    def get_capability(self, full_id: str) -> Optional[Capability]:
        """Resolve a capability by its full id, e.g. ``braintree.transactions.search``."""

        return self._by_full_id.get(full_id)

    def invoke(
        self,
        full_id: str,
        input: Mapping[str, Any],
        secret: str,
        context: Optional[ExecuteContext] = None,
    ) -> Any:
        """Validate and invoke a capability by full id. Raises if unknown."""

        cap = self._by_full_id.get(full_id)
        if cap is None:
            raise KeyError(f"Unknown capability: {full_id}")
        validated = cap.input_schema(input) if cap.input_schema else input
        ctx = context or ExecuteContext(secret=secret)
        if context is not None and not context.secret:
            ctx = ExecuteContext(
                secret=secret,
                session_id=context.session_id,
                principal=context.principal,
                account=context.account,
                redact_fields=context.redact_fields,
                execution_location=context.execution_location,
                reason=context.reason,
            )
        return cap.execute(validated, ctx)


def define_connector(
    id: str,
    capabilities: Sequence[Capability],
    description: Optional[str] = None,
) -> Connector:
    """Author a Permaura connector.

    Example::

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
                        api.search(input, ctx.secret), fields=ctx.redact_fields
                    ),
                ),
                Capability(
                    id="transactions.refund",
                    risk=RiskTier.CRITICAL,
                    requires_approval=True,
                    execute=lambda input, ctx: api.refund(input, ctx.secret),
                ),
            ],
        )
    """

    return Connector(id=id, capabilities=list(capabilities), description=description)


__all__ = ["define_connector", "Connector", "Capability", "ExecuteContext", "ExecuteFn"]
