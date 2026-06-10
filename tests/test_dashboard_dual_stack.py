"""Dashboard dual-stack loopback hotfix — empirical pin.

**Symptom this guards against:** the dashboard previously bound only to
``127.0.0.1`` (IPv4 loopback). Modern browsers (Chrome 95+) preferring
IPv6 per RFC 6555 Happy Eyeballs resolve ``localhost`` → ``::1`` first;
the connection is refused (no v6 listener), and the user sees
``ERR_CONNECTION_REFUSED`` in DevTools.

The fix is to bind BOTH ``127.0.0.1`` AND ``::1`` simultaneously
(``LoopbackDualStackServer`` wraps two ``ReusableHTTPServer`` instances),
preserving the localhost-only security constraint (no all-interfaces
binding) while making ``localhost:<port>`` URLs work for both v4 and v6
preferences.

Same class of bug as issue #75 (mitmdump IPv4-only); this is the
dashboard-side counterpart to PR #76 (which fixed it for mitmdump).
"""

from __future__ import annotations

import socket
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler

import pytest


def _free_port() -> int:
    """Grab an ephemeral free TCP port. We bind to IPv4 to pick the
    number; both v4 and v6 loopback will use it once the test starts."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _PingHandler(BaseHTTPRequestHandler):
    """200 OK / pong. Suppresses per-request logging during tests."""

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"pong")

    def log_message(self, format, *args) -> None:
        return


@pytest.fixture
def dual_stack_server():
    """Start a ``LoopbackDualStackServer`` bound to both 127.0.0.1 and
    ::1 on the same ephemeral port. Tears down on test exit."""
    from claude_monitoring.dashboard_server import LoopbackDualStackServer

    port = _free_port()
    server = LoopbackDualStackServer(port, _PingHandler)
    threads: list[threading.Thread] = []
    for sub in server.servers:
        t = threading.Thread(target=sub.serve_forever, daemon=True)
        t.start()
        threads.append(t)
    time.sleep(0.1)
    yield port, server
    server.shutdown()
    server.server_close()
    for t in threads:
        t.join(timeout=2.0)


class TestDualStackLoopbackBinding:
    """Pin the dual-stack-loopback contract: BOTH v4 and v6 loopback
    sockets reachable."""

    def test_ipv4_loopback_is_reachable(self, dual_stack_server) -> None:
        port, _ = dual_stack_server
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2.0) as resp:
            assert resp.status == 200
            assert resp.read() == b"pong"

    def test_ipv6_loopback_is_reachable(self, dual_stack_server) -> None:
        """The bug we're fixing: this is the URL Chrome's ``localhost``
        resolution actually tries first under Happy Eyeballs."""
        port, _ = dual_stack_server
        if not socket.has_ipv6:
            pytest.skip("IPv6 not available on this host")
        with urllib.request.urlopen(f"http://[::1]:{port}/", timeout=2.0) as resp:
            assert resp.status == 200
            assert resp.read() == b"pong"


class TestSecurityBoundary:
    """The dual-stack fix MUST preserve the localhost-only invariant.
    It is NOT an excuse to bind to all interfaces."""

    def test_does_not_bind_to_all_interfaces(self, dual_stack_server) -> None:
        """Confirm the dual-stack server is reachable from loopback ONLY,
        not from a non-loopback address. We probe a non-loopback v4
        socket on the same port — it should be free to bind, proving the
        dashboard isn't listening there."""
        port, _ = dual_stack_server
        # If the dashboard were bound to 0.0.0.0, this bind would fail
        # with EADDRINUSE. If it's bound only to loopback, this bind
        # succeeds (different address).
        host_ip = socket.gethostbyname(socket.gethostname())
        if host_ip in {"127.0.0.1", "::1"}:
            pytest.skip("test host has no non-loopback IPv4 address")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host_ip, port))
        finally:
            s.close()


class TestGracefulFallback:
    """If IPv6 loopback is unavailable (rare, but possible in containers
    or stripped environments), the dual-stack server falls back to
    v4-only and the dashboard remains usable."""

    def test_server_count_is_one_or_two(self, dual_stack_server) -> None:
        """Either v4-only (1 server) or v4+v6 (2 servers). Never zero."""
        _, server = dual_stack_server
        assert 1 <= len(server.servers) <= 2


class TestServerClassSurface:
    """The class is importable, has the expected API surface, and
    matches the existing ReusableHTTPServer protocol enough that the
    lifecycle code can substitute it."""

    def test_class_importable_from_dashboard_server_module(self) -> None:
        from claude_monitoring.dashboard_server import LoopbackDualStackServer

        assert callable(LoopbackDualStackServer)

    def test_class_exposes_shutdown_and_server_close(self) -> None:
        from claude_monitoring.dashboard_server import LoopbackDualStackServer

        assert hasattr(LoopbackDualStackServer, "shutdown")
        assert hasattr(LoopbackDualStackServer, "server_close")

    def test_class_exposes_servers_list(self) -> None:
        """The composed `servers` list lets the lifecycle code start each
        sub-server in its own thread (matching the existing pattern)."""
        from claude_monitoring.dashboard_server import LoopbackDualStackServer

        port = _free_port()
        server = LoopbackDualStackServer(port, _PingHandler)
        try:
            assert isinstance(server.servers, list)
            assert all(hasattr(s, "serve_forever") for s in server.servers)
        finally:
            server.server_close()
