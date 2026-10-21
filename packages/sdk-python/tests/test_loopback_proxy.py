"""httpx honors HTTP_PROXY and ALL_PROXY for 127.0.0.1 unless NO_PROXY names it, so a client for this machine's gateway handed its bearer, and a create_secret value, to whoever runs the proxy."""

from __future__ import annotations

import json
import socket
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator

import pytest

from permaura import PermauraApiError, PermauraClient

TOKEN = "session-token-must-not-reach-the-proxy"


class _Gateway(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, host: str, family: socket.AddressFamily) -> None:
        self.address_family = family
        self.seen: list[dict[str, str]] = []
        super().__init__((host, 0), _GatewayHandler)


class _GatewayHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        server: _Gateway = self.server  # type: ignore[assignment]
        server.seen.append({"path": self.path, "host": self.headers.get("host", ""), "authorization": self.headers.get("authorization", "")})
        body = json.dumps({"capabilities": []}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


class _Proxy(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self) -> None:
        self.lines: list[str] = []
        super().__init__(("127.0.0.1", 0), _ProxyHandler)


class _ProxyHandler(socketserver.StreamRequestHandler):
    """Records the first line of whatever it is handed, and refuses it."""

    def handle(self) -> None:
        server: _Proxy = self.server  # type: ignore[assignment]
        server.lines.append(self.rfile.readline().decode("latin-1").strip())
        self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")


def _serve(server: socketserver.BaseServer) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return t


@pytest.fixture
def proxy(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Proxy]:
    p = _Proxy()
    _serve(p)
    url = f"http://127.0.0.1:{p.server_address[1]}"
    for name in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(name, url)
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.delenv(name, raising=False)
    yield p
    p.shutdown()
    p.server_close()


@pytest.fixture
def gateway() -> Iterator[_Gateway]:
    g = _Gateway("127.0.0.1", socket.AF_INET)
    _serve(g)
    yield g
    g.shutdown()
    g.server_close()


@pytest.fixture
def gateway6() -> Iterator[_Gateway | None]:
    try:
        g = _Gateway("::1", socket.AF_INET6)
    except OSError:
        yield None
        return
    _serve(g)
    yield g
    g.shutdown()
    g.server_close()


def _reached(proxy: _Proxy, base_url: str) -> bool:
    authority = base_url.split("//", 1)[1].lower()
    # httpx writes an IPv6 target into the absolute-form request line without its brackets.
    forms = {authority, authority.replace("[", "").replace("]", "")}
    return any(f"//{a}/" in line.lower() or f" {a} " in line.lower() for a in forms for line in proxy.lines)


def test_a_gateway_on_this_machine_is_never_reached_through_the_environments_proxy(
    proxy: _Proxy, gateway: _Gateway, gateway6: _Gateway | None
) -> None:
    port = gateway.server_address[1]
    loopback = [
        f"http://127.0.0.1:{port}",
        f"http://localhost:{port}",
        f"http://LOCALHOST.:{port}",
        f"http://127.1:{port}",
        f"http://0x7f.1:{port}",
        f"http://[::ffff:127.0.0.1]:{port}",
    ]
    if gateway6 is not None:
        port6 = gateway6.server_address[1]
        loopback += [f"http://[::1]:{port6}", f"http://[0:0:0:0:0:0:0:1]:{port6}"]

    for base_url in loopback:
        with PermauraClient(base_url, TOKEN, timeout=5) as client:
            assert client.list_capabilities(scope="current_session") == [], base_url
        assert not _reached(proxy, base_url), f"{base_url} went through the proxy: {proxy.lines}"

    assert proxy.lines == []
    seen = gateway.seen + (gateway6.seen if gateway6 else [])
    assert len(seen) == len(loopback)
    for r in seen:
        assert r["path"] == "/v1/capabilities?scope=current_session"
        assert r["authorization"] == f"Bearer {TOKEN}"


def test_any_other_host_still_goes_through_the_environments_proxy(proxy: _Proxy, gateway: _Gateway) -> None:
    port = gateway.server_address[1]
    remote = [
        f"http://permaura-proxy-probe.invalid:{port}",
        f"http://localhost.permaura-proxy-probe.invalid:{port}",
        f"http://128.0.0.1:{port}",
        f"http://[::ffff:10.0.0.1]:{port}",
    ]
    for base_url in remote:
        with PermauraClient(base_url, TOKEN, timeout=5) as client:
            with pytest.raises(PermauraApiError) as err:
                client.list_capabilities()
        assert err.value.status == 502, base_url
        assert _reached(proxy, base_url), f"{base_url} should still go through the environment's proxy; the proxy saw: {proxy.lines}"
    assert gateway.seen == []


@pytest.mark.parametrize(
    ("base_url", "local"),
    [
        ("http://127.0.0.1:7376", True),
        ("http://127.255.255.254", True),
        ("http://localhost:7376/", True),
        ("http://LocalHost.:7376", True),
        ("http://gw.localhost:7376", True),
        ("http://127.1:7376", True),
        ("http://0x7f.1", True),
        ("http://[::1]:7376", True),
        ("http://[0:0:0:0:0:0:0:1]", True),
        ("http://[::ffff:127.0.0.1]:7376", True),
        ("http://[::ffff:7f00:1]", True),
        ("http://128.0.0.1", False),
        ("http://[::ffff:10.0.0.1]", False),
        ("http://localhost.example.com", False),
        ("http://127.0.0.1.nip.io", False),
        ("https://permaura.com", False),
        ("http://0.0.0.0:7376", False),
    ],
)
def test_which_base_urls_name_this_machine(base_url: str, local: bool) -> None:
    from permaura.client import _names_this_machine

    assert _names_this_machine(base_url) is local


@pytest.fixture
def squatter6(gateway: _Gateway) -> Iterator[_Gateway | None]:
    """Another listener on ::1 at the gateway's port, which macOS's resolver offers for `localhost` before 127.0.0.1."""
    try:
        s = _Gateway("::1", socket.AF_INET6)
        s.server_close()
        s = _Gateway.__new__(_Gateway)
        s.address_family = socket.AF_INET6
        s.seen = []
        ThreadingHTTPServer.__init__(s, ("::1", gateway.server_address[1]), _GatewayHandler)
    except OSError:
        yield None
        return
    _serve(s)
    yield s
    s.shutdown()
    s.server_close()


def test_a_localhost_name_connects_to_127_0_0_1_where_the_gateway_listens(gateway: _Gateway, squatter6: _Gateway | None) -> None:
    """The TypeScript SDK and mcp-stdio pin `localhost` names to 127.0.0.1, so whatever holds the same port on ::1 never sees the bearer."""
    port = gateway.server_address[1]
    for base_url in (f"http://localhost:{port}", f"http://LocalHost.:{port}", f"http://gw.localhost:{port}"):
        with PermauraClient(base_url, TOKEN, timeout=5) as client:
            assert client.list_capabilities(scope="current_session") == [], base_url
    assert len(gateway.seen) == 3, gateway.seen
    assert [r["host"] for r in gateway.seen] == [f"localhost:{port}", f"localhost:{port}", f"gw.localhost:{port}"], "the Host header still names what the caller asked for"
    if squatter6 is not None:
        assert squatter6.seen == [], f"the listener on ::1 was handed the bearer: {squatter6.seen}"
