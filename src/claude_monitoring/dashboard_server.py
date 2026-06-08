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

Lives in its own module so the file-size ratchet on :mod:`monitor` stays under the
5500-line ceiling, AND so tests can import + exercise the class directly.
"""

from __future__ import annotations

import sys
from http.server import ThreadingHTTPServer


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


__all__ = ["ReusableHTTPServer"]
