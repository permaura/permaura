"""The redaction layer for the Python SDK.

Mirror of the TypeScript ``redact()`` helper: scrub sensitive material out of any
value before it is returned to the agent. Matches an explicit field list plus a
default set of always-dangerous key patterns, and never mutates the input.
"""

from __future__ import annotations

from typing import Any, Iterable, Optional

#: Default key-name substrings redacted unconditionally (case-insensitive).
DEFAULT_REDACT_PATTERNS: tuple[str, ...] = (
    "api_key",
    "apikey",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "auth",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "private_key",
    "client_secret",
    "card_number",
    "pan",
    "cvv",
    "cvc",
    "ssn",
    "database_url",
    "db_url",
    "connection_string",
)

#: Value written in place of any redacted field.
REDACTION_PLACEHOLDER = "[REDACTED]"


def _key_matches(key: str, exact_lower: set[str], patterns: tuple[str, ...]) -> bool:
    lower = key.lower()
    if lower in exact_lower:
        return True
    return any(p in lower for p in patterns)


def redact_with_count(
    value: Any,
    *,
    fields: Optional[Iterable[str]] = None,
    use_defaults: bool = True,
    placeholder: str = REDACTION_PLACEHOLDER,
    max_depth: int = 64,
) -> tuple[Any, int]:
    """Redact sensitive fields and return ``(scrubbed_copy, redacted_count)``.

    Use this when you also want the number of fields it redacted.
    """

    exact_lower = {f.lower() for f in (fields or [])}
    patterns = DEFAULT_REDACT_PATTERNS if use_defaults else ()
    count = 0
    seen: set[int] = set()

    def walk(node: Any, depth: int) -> Any:
        nonlocal count
        if depth > max_depth:
            return node
        if isinstance(node, dict):
            ident = id(node)
            if ident in seen:
                return node
            seen.add(ident)
            out: dict[Any, Any] = {}
            for key, val in node.items():
                if isinstance(key, str) and _key_matches(key, exact_lower, patterns):
                    out[key] = placeholder
                    count += 1
                else:
                    out[key] = walk(val, depth + 1)
            return out
        if isinstance(node, (list, tuple)):
            return type(node)(walk(item, depth + 1) for item in node)
        return node

    return walk(value, 0), count


def redact(
    value: Any,
    *,
    fields: Optional[Iterable[str]] = None,
    use_defaults: bool = True,
    placeholder: str = REDACTION_PLACEHOLDER,
    max_depth: int = 64,
) -> Any:
    """Redact sensitive fields from a value, returning a scrubbed deep copy.

    Call this on any upstream response before returning it from a capability's
    ``execute``::

        return redact(braintree.search(params, secret), fields=ctx.redact_fields)
    """

    scrubbed, _ = redact_with_count(
        value,
        fields=fields,
        use_defaults=use_defaults,
        placeholder=placeholder,
        max_depth=max_depth,
    )
    return scrubbed


__all__ = ["redact", "redact_with_count", "DEFAULT_REDACT_PATTERNS", "REDACTION_PLACEHOLDER"]
