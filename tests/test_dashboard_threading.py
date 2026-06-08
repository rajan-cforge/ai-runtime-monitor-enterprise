"""Empirical test for the dashboard's ``ReusableHTTPServer`` threading behavior.

**Symptom this guards against (issue #98, 3rd gap):** when the dashboard's
HTTP server is single-threaded (Python's ``http.server.HTTPServer``), Chrome's
3+ long-poll connections to the dashboard pin the server into serial execution.
A 4th request — your `curl` from terminal, a freshly-opened tab — queues
behind them forever. Users see ``ERR_CONNECTION_TIMED_OUT``.

The fix is to extend ``ThreadingHTTPServer`` (Python 3.7+) instead of plain
``HTTPServer``. Each request gets its own thread; long-polls no longer block
siblings.

This test pins the threading behavior empirically: it starts a real
``ReusableHTTPServer`` with a deliberately slow handler and asserts that
TWO concurrent requests complete in roughly the time of ONE (not the sum).
"""

from __future__ import annotations

import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler

import pytest

SLEEP_PER_REQUEST = 0.5
"""Each handler sleeps this many seconds before responding. Long enough to
make serial vs concurrent execution measurably distinguishable but short
enough that the test stays fast."""


class _SlowHandler(BaseHTTPRequestHandler):
    """Sleeps for ``SLEEP_PER_REQUEST`` then responds 200 OK."""

    def do_GET(self) -> None:
        time.sleep(SLEEP_PER_REQUEST)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args) -> None:
        """Suppress per-request logging noise during tests."""


def _free_port() -> int:
    """Grab an ephemeral free TCP port on loopback."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def slow_server():
    """Spin up the actual ``ReusableHTTPServer`` from ``monitor.py``
    with a slow handler. Tears down on test exit."""
    # Import here so the test surfaces the actual production class.
    from claude_monitoring.monitor import ReusableHTTPServer

    port = _free_port()
    server = ReusableHTTPServer(("127.0.0.1", port), _SlowHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _fetch(port: int) -> tuple[int, float]:
    """Return ``(http_status, elapsed_seconds)``."""
    started = time.monotonic()
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=10) as resp:
        status = resp.status
        resp.read()
    return status, time.monotonic() - started


class TestDashboardServesConcurrently:
    """Two concurrent requests must complete in roughly the time of ONE,
    not the sum of both. Proves the server runs each handler in its own
    thread (``ThreadingHTTPServer``) rather than serially (plain
    ``HTTPServer``)."""

    def test_two_concurrent_requests_do_not_serialize(self, slow_server) -> None:
        port = slow_server

        started = time.monotonic()
        with ThreadPoolExecutor(max_workers=2) as ex:
            futures = [ex.submit(_fetch, port) for _ in range(2)]
            results = [f.result() for f in futures]
        wall = time.monotonic() - started

        # Both requests succeeded
        for status, _elapsed in results:
            assert status == 200

        # Wall-clock time should be close to SLEEP_PER_REQUEST (concurrent),
        # NOT close to 2 * SLEEP_PER_REQUEST (serial). Allow a generous
        # margin for thread startup + CI jitter.
        serial_time = 2 * SLEEP_PER_REQUEST
        concurrent_threshold = SLEEP_PER_REQUEST * 1.6
        assert wall < concurrent_threshold, (
            f"two concurrent requests took {wall:.3f}s — looks serial "
            f"(serial would be ~{serial_time:.3f}s, concurrent ~{SLEEP_PER_REQUEST:.3f}s). "
            f"ReusableHTTPServer likely lost its ThreadingHTTPServer base class."
        )


class TestReusableHTTPServerBaseClass:
    """Static check that the production class inherits from a threading
    base. Catches regressions where someone swaps the base back to
    ``HTTPServer`` without running the concurrency test."""

    def test_extends_threading_http_server(self) -> None:
        from http.server import ThreadingHTTPServer

        from claude_monitoring.monitor import ReusableHTTPServer

        assert issubclass(ReusableHTTPServer, ThreadingHTTPServer), (
            "ReusableHTTPServer must extend ThreadingHTTPServer so dashboard "
            "long-polls from one Chrome tab don't starve other tabs / curl / "
            "the user's fresh tab open after restart. See issue #98."
        )

    def test_preserves_allow_reuse_address(self) -> None:
        from claude_monitoring.monitor import ReusableHTTPServer

        assert ReusableHTTPServer.allow_reuse_address is True
