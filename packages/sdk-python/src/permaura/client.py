"""The Permaura REST client for Python, backed by httpx.

Mirror of the TypeScript ``PermauraClient``. Every method maps to a ``/v1``
endpoint. Like its TS sibling, the client deliberately exposes no method that
returns a raw secret: ``create_secret`` / ``rotate_secret`` return only a
metadata reference. You can store and rotate credentials through Permaura, never
read them back out.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any, Mapping, Optional, Sequence
from urllib.parse import urlsplit, urlunsplit

import httpx

from .types import Principal, Conditions, Decision, CapabilitySpec, InvokeResult

#: The default local gateway address the ``perma`` daemon listens on.
DEFAULT_BASE_URL = "http://127.0.0.1:7376"


def _names_this_machine(base_url: str) -> bool:
    """Whether ``base_url`` names a loopback address: 127.0.0.0/8, ::1, an IPv4-mapped 127/8, ``localhost`` or ``*.localhost``."""
    host = (urlsplit(base_url).hostname or "").rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # 127.1 and 0x7f.1 are names to httpx, and the resolver reads them as 127.0.0.1.
        if not re.fullmatch(r"[0-9a-fx.]+", host):
            return False
        try:
            ip = ipaddress.IPv4Address(socket.inet_aton(host))
        except OSError:
            return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback


def _pinned_to_127_0_0_1(base_url: str) -> Optional[tuple[str, str]]:
    """For a ``localhost`` or ``*.localhost`` base URL, the same URL addressed to 127.0.0.1 and the Host header that keeps naming what the caller asked for; ``None`` for any other.

    The gateway listens on 127.0.0.1, and the resolver offers ::1 first on macOS, where any process may hold the same port. The TypeScript SDK and mcp-stdio pin these names the same way.
    """
    parts = urlsplit(base_url)
    host = (parts.hostname or "").rstrip(".").lower()
    if host != "localhost" and not host.endswith(".localhost"):
        return None
    port = f":{parts.port}" if parts.port is not None else ""
    userinfo = parts.netloc.rpartition("@")[0]
    netloc = f"{userinfo}@127.0.0.1{port}" if userinfo else f"127.0.0.1{port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment)), f"{host}{port}"


class PermauraApiError(Exception):
    """Raised when the gateway responds non-2xx.

    Carries the parsed error envelope when present, so ``.reason`` surfaces the
    policy reason for a denial.
    """

    def __init__(self, status: int, code: str, message: str, reason: Optional[str] = None) -> None:
        super().__init__(f"[{status}] {code}: {message}")
        self.status = status
        self.code = code
        self.message = message
        self.reason = reason


class PermauraClient:
    """Typed, synchronous client for the Permaura REST API (v1).

    Example::

        client = PermauraClient(token=session_token)
        caps = client.list_capabilities(scope="current_session")
        res = client.invoke(
            capability="braintree.transactions.search",
            params={"status": "failed"},
            reason="Summarize yesterday's failed payments.",
        )
        if res.decision.decision is DecisionKind.REQUIRES_APPROVAL:
            print(res.decision.approval.message)
    """

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        token: Optional[str] = None,
        *,
        timeout: float = 30.0,
        transport: Optional[httpx.BaseTransport] = None,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._token = token
        self._target = self.base_url
        self._host: Optional[str] = None
        if client is not None:
            self._client = client
            self._owns_client = False
        else:
            pinned = _pinned_to_127_0_0_1(self.base_url)
            if pinned is not None:
                self._target, self._host = pinned
            # httpx sends even 127.0.0.1 through HTTP_PROXY or ALL_PROXY unless NO_PROXY names it, handing the proxy the bearer and any secret in the body.
            self._client = httpx.Client(timeout=timeout, transport=transport, trust_env=not _names_this_machine(self.base_url))
            self._owns_client = True

    # -- lifecycle -----------------------------------------------------------

    def set_token(self, token: Optional[str]) -> None:
        """Update the bearer token in place, e.g. after ``create_session``."""

        self._token = token

    def close(self) -> None:
        if self._owns_client:
            self._client.close()

    def __enter__(self) -> "PermauraClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internals -----------------------------------------------------------

    def _headers(self) -> dict[str, str]:
        h = {"content-type": "application/json"}
        if self._host is not None:
            h["host"] = self._host
        if self._token:
            h["authorization"] = f"Bearer {self._token}"
        return h

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        params: Optional[Mapping[str, Any]] = None,
    ) -> Any:
        clean_params = (
            {k: v for k, v in params.items() if v is not None} if params else None
        )
        resp = self._client.request(
            method,
            self._target + path,
            headers=self._headers(),
            json=json,
            params=clean_params,
        )
        if resp.is_success:
            if not resp.content:
                return None
            return resp.json()

        # Try to parse the uniform error envelope.
        try:
            body = resp.json()
            err = body.get("error", {})
            raise PermauraApiError(
                resp.status_code,
                err.get("code", "http_error"),
                err.get("message", resp.text),
                err.get("reason"),
            )
        except ValueError:
            raise PermauraApiError(resp.status_code, "http_error", resp.text or resp.reason_phrase)

    # -- endpoints -----------------------------------------------------------

    def create_session(
        self,
        principal: Principal,
        *,
        label: Optional[str] = None,
        execution_location: Optional[str] = None,
    ) -> dict[str, Any]:
        """POST /v1/sessions: open a session, returning ``{session, token}``."""

        body = {
            "principal": principal.to_dict(),
            "label": label,
            "execution_location": execution_location,
        }
        return self._request("POST", "/v1/sessions", json={k: v for k, v in body.items() if v is not None})

    def list_capabilities(
        self,
        *,
        session_id: Optional[str] = None,
        scope: Optional[str] = None,
        connector: Optional[str] = None,
    ) -> list[CapabilitySpec]:
        """GET /v1/capabilities: capabilities visible to the session."""

        data = self._request(
            "GET",
            "/v1/capabilities",
            params={"session_id": session_id, "scope": scope, "connector": connector},
        )
        return [CapabilitySpec.from_dict(c) for c in (data or {}).get("capabilities", [])]

    def create_grant(
        self,
        principal: Principal,
        resource: str,
        allowed_actions: Sequence[str],
        *,
        denied_actions: Optional[Sequence[str]] = None,
        conditions: Optional[Conditions] = None,
        reason: Optional[str] = None,
    ) -> dict[str, Any]:
        """POST /v1/grants: bind a policy to an agent under limits."""

        body = {
            "principal": principal.to_dict(),
            "resource": resource,
            "allowed_actions": list(allowed_actions),
            "denied_actions": list(denied_actions) if denied_actions else None,
            "conditions": conditions.to_dict() if conditions else None,
            "reason": reason,
        }
        return self._request("POST", "/v1/grants", json={k: v for k, v in body.items() if v is not None})

    def invoke(
        self,
        capability: str,
        params: Optional[Mapping[str, Any]] = None,
        *,
        session_id: Optional[str] = None,
        reason: Optional[str] = None,
    ) -> InvokeResult:
        """POST /v1/invoke: call a capability; secret injected server-side, result redacted."""

        body = {
            "capability": capability,
            "params": dict(params) if params else {},
            "session_id": session_id,
            "reason": reason,
        }
        data = self._request("POST", "/v1/invoke", json={k: v for k, v in body.items() if v is not None})
        return InvokeResult.from_dict(data)

    def resolve_approval(
        self, approval_id: str, decision: str, *, approver: Optional[str] = None
    ) -> dict[str, Any]:
        """POST /v1/approvals: approve or deny a pending approval."""

        body = {"approval_id": approval_id, "decision": decision, "approver": approver}
        return self._request("POST", "/v1/approvals", json={k: v for k, v in body.items() if v is not None})

    def list_audit_events(
        self,
        *,
        session_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        since: Optional[str] = None,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> dict[str, Any]:
        """GET /v1/audit-events: page the hash-chained audit log."""

        return self._request(
            "GET",
            "/v1/audit-events",
            params={
                "session_id": session_id,
                "agent_id": agent_id,
                "since": since,
                "limit": limit,
                "cursor": cursor,
            },
        )

    def create_secret(
        self,
        name: str,
        type: str,
        value: str,
        *,
        integration: Optional[str] = None,
        execution_location: Optional[str] = None,
        risk_classification: Optional[str] = None,
        labels: Optional[Mapping[str, str]] = None,
    ) -> dict[str, Any]:
        """POST /v1/secrets: store a secret. The plaintext is never returned."""

        body = {
            "name": name,
            "type": type,
            "value": value,
            "integration": integration,
            "execution_location": execution_location,
            "risk_classification": risk_classification,
            "labels": dict(labels) if labels else None,
        }
        return self._request("POST", "/v1/secrets", json={k: v for k, v in body.items() if v is not None})

    def rotate_secret(self, secret_id: str, *, value: Optional[str] = None) -> dict[str, Any]:
        """POST /v1/secrets/:id/rotate: rotate to a new version. Returns only the ref."""

        body = {"value": value} if value is not None else {}
        return self._request("POST", f"/v1/secrets/{secret_id}/rotate", json=body)

    def enroll_device(
        self, name: str, *, platform: Optional[str] = None, public_key: Optional[str] = None
    ) -> dict[str, Any]:
        """POST /v1/devices/enroll: enroll a device into the org."""

        body = {"name": name, "platform": platform, "public_key": public_key}
        return self._request("POST", "/v1/devices/enroll", json={k: v for k, v in body.items() if v is not None})

    def register_agent(
        self, agent: str, *, display_name: Optional[str] = None, device: Optional[str] = None
    ) -> dict[str, Any]:
        """POST /v1/agents/register: register an agent identity."""

        body = {"agent": agent, "display_name": display_name, "device": device}
        return self._request("POST", "/v1/agents/register", json={k: v for k, v in body.items() if v is not None})


__all__ = ["PermauraClient", "PermauraApiError", "DEFAULT_BASE_URL"]
