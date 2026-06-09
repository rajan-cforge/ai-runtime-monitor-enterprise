"""Dashboard HTTP server — threaded so long-poll connections don't starve siblings.

**Issue #98 (3rd gap):** the previous in-function ``ReusableHTTPServer`` definition
in :mod:`monitor` extended plain ``http.server.HTTPServer``, which serializes every
request. Chrome's 3-4 dashboard tabs each hold a long-poll connection (live feed,
status auto-refresh) — a single-threaded server gets stuck serving them in serial
and refuses every other request, including ``curl`` from terminal and freshly-opened
tabs after a restart. Users see ``ERR_CONNECTION_TIMED_OUT``.

The fix is to extend ``ThreadingHTTPServer`` (Python 3.7+). Each connection gets its
own handler thread, so long-polls no longer block siblings.

``allow_reuse_address`` is preserved so the dashboard port can be re-bound quickly
after a kill (TIME_WAIT not required).

``handle_error`` suppresses ``BrokenPipeError`` tracebacks — those fire every time a
browser closes a long-poll connection, which is normal, not a bug.

**Dual-stack loopback (2026-06-09 hotfix):** the previous binding was IPv4-only
(``127.0.0.1``). Modern browsers (Chrome 95+) preferring IPv6 per RFC 6555 Happy
Eyeballs resolve ``localhost`` → ``::1`` first; the IPv4-only listener refuses the
connection. :class:`LoopbackDualStackServer` wraps two
:class:`ReusableHTTPServer` instances (one on ``127.0.0.1``, one on ``[::1]``) so
that BOTH v4 and v6 ``localhost`` URLs reach the dashboard. The localhost-only
security constraint is preserved (no all-interfaces binding). Same class of bug as
issue #75 (mitmproxy IPv4-only); this is the dashboard-side counterpart to PR #76
(``--listen-host ::`` for mitmdump).

Lives in its own module so the file-size ratchet on :mod:`monitor` stays under the
5500-line ceiling, AND so tests can import + exercise the classes directly.
"""

from __future__ import annotations

import logging
import sys
from http.server import ThreadingHTTPServer

logger = logging.getLogger("ai-runtime-monitor.dashboard_server")


class ReusableHTTPServer(ThreadingHTTPServer):
    """Threaded dashboard HTTP server. Extends ``ThreadingHTTPServer`` so
    per-request handlers run concurrently."""

    allow_reuse_address = True

    def handle_error(self, request, client_address):  # type: ignore[override]
        """Suppress ``BrokenPipeError`` tracebacks from disconnected clients."""
        exc_type = sys.exc_info()[0]
        if exc_type is BrokenPipeError:
            return
        super().handle_error(request, client_address)


class _IPv6ReusableHTTPServer(ReusableHTTPServer):
    """IPv6 variant of :class:`ReusableHTTPServer`.

    The ``http.server.ThreadingHTTPServer`` superclass defaults to
    ``socket.AF_INET`` (IPv4). Setting ``address_family = AF_INET6`` lets
    a single socket bind ``[::1]:port``. We do NOT enable ``IPV6_V6ONLY=0``
    here — we explicitly want this socket to handle ONLY v6 traffic, and a
    sibling IPv4 socket handles v4. Dual-binding two distinct sockets is
    the cleanest cross-platform way to get loopback-only dual-stack
    without binding all interfaces.
    """

    import socket as _socket  # avoid leaking the import name at class level

    address_family = _socket.AF_INET6


class LoopbackDualStackServer:
    """Loopback-only dual-stack dashboard wrapper.

    Wraps two :class:`ReusableHTTPServer` instances: one bound to
    ``127.0.0.1`` (IPv4 loopback) and one bound to ``[::1]`` (IPv6
    loopback), both on the same port. Browsers preferring IPv6 (Happy
    Eyeballs on modern Chrome/Firefox) and tools using IPv4 explicitly
    both reach the dashboard.

    **Localhost-only invariant preserved.** This class does NOT bind to
    ``0.0.0.0`` or ``::`` (all interfaces). Each sub-server is explicitly
    a loopback socket. The dashboard remains unreachable from anywhere
    except the local machine.

    **Graceful fallback.** If the IPv6 loopback bind fails (rare — some
    containerized environments disable v6), the class logs a warning and
    proceeds with v4-only. The dashboard is still usable; the user can
    use ``127.0.0.1`` URLs explicitly.

    The class exposes a small API surface matching the existing single-
    server usage in :mod:`monitor`: ``servers`` (the underlying list to
    iterate for ``serve_forever``), ``shutdown``, ``server_close``.

    Args:
        port: TCP port to listen on. Both sub-servers use the same port.
        handler: BaseHTTPRequestHandler subclass (same as the existing
            single-server case).
    """

    def __init__(self, port: int, handler) -> None:
        self.servers: list[ReusableHTTPServer] = []
        # v4 loopback first — this is the always-required bind. If THIS
        # fails, the caller's bind_with_retry handles it (port collision).
        self.servers.append(ReusableHTTPServer(("127.0.0.1", port), handler))
        # v6 loopback — best-effort. Container/stripped environments may
        # not have v6; degrade to v4-only with a logged warning.
        try:
            self.servers.append(_IPv6ReusableHTTPServer(("::1", port), handler))
        except OSError as exc:
            logger.warning(
                "dashboard: IPv6 loopback bind on port %d failed (%s); "
                "v4-only fallback. Use http://127.0.0.1:%d explicitly.",
                port,
                exc,
                port,
            )

    def shutdown(self) -> None:
        """Tell each sub-server to stop serving. Matches the BaseServer
        API so external lifecycle code can call this without knowing
        whether it's dealing with one server or two."""
        for srv in self.servers:
            srv.shutdown()

    def server_close(self) -> None:
        """Close each sub-server's listening socket. Matches BaseServer API."""
        for srv in self.servers:
            srv.server_close()


def start_dashboard_server(bind_addr: str, port: int, handler, bind_with_retry):
    """Build and start the dashboard HTTP server.

    When ``bind_addr`` is the loopback default (``"127.0.0.1"``), this
    returns a :class:`LoopbackDualStackServer` with sub-servers already
    serving on background daemon threads (one per bound socket — v4 and
    optionally v6). Any other address (e.g., ``"0.0.0.0"`` from
    ``--bind``) returns a single :class:`ReusableHTTPServer` instance
    with its own daemon thread.

    Lives in this module (not :mod:`monitor`) so the file-size ratchet on
    monitor stays under its ceiling. The dual-stack lifecycle wiring was
    introduced in the 2026-06-09 hotfix and is the only Phase-3 fix that
    touches the dashboard listener.

    Args:
        bind_addr: Resolved bind address from config (``get_bind_address()``).
        port: Dashboard TCP port.
        handler: BaseHTTPRequestHandler subclass.
        bind_with_retry: The caller's port-collision retry helper. Same
            signature as ``monitor.bind_with_retry`` — takes a factory
            lambda, ``port=``, ``address=`` kwargs, returns the server
            instance after a successful bind.

    Returns:
        The server instance. Caller treats it as opaque; downstream
        shutdown uses ``server.shutdown()`` which both wrapper classes
        expose. (For the dual-stack class, that propagates to both
        sub-servers.)
    """
    import threading

    if bind_addr == "127.0.0.1":
        server = bind_with_retry(
            lambda: LoopbackDualStackServer(port, handler),
            port=port,
            address=bind_addr,
        )
        for sub in server.servers:
            threading.Thread(
                target=sub.serve_forever,
                daemon=True,
                name=f"Dashboard-{sub.server_address[0]}",
            ).start()
        return server

    server = bind_with_retry(
        lambda: ReusableHTTPServer((bind_addr, port), handler),
        port=port,
        address=bind_addr,
    )
    threading.Thread(target=server.serve_forever, daemon=True, name="Dashboard").start()
    return server


__all__ = ["LoopbackDualStackServer", "ReusableHTTPServer", "start_dashboard_server"]
