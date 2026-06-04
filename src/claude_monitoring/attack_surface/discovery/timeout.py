"""Thread-safe timeout helper for :func:`DiscoverySource.run_with_safety`.

**P1.1 architect-pass locked decision**: the timeout mechanism MUST be
thread-safe so the orchestrator (P1.3) can call
:meth:`DiscoverySource.run_with_safety` from worker threads. ``signal.alarm``
and ``signal.signal`` are **main-thread only** in CPython — they raise
``ValueError: signal only works in main thread`` when called from any
non-main thread.

This module uses :class:`concurrent.futures.ThreadPoolExecutor`, which is
thread-safe by construction.

Known limitation
----------------

A thread-based timeout returns control to the caller after ``timeout_sec``
elapses but **cannot force-kill a hung function**. If a discovery
implementation hangs in a CPU loop or a blocking I/O call without its own
timeout, the worker thread will keep running until the OS reaps the
process. Subsequent calls to :func:`_with_timeout` work fine (each gets a
fresh executor); the hung thread just accumulates in process memory.

For genuinely hard-hang-prone sources, the architect-pass §8 forward-
extension plan (subprocess isolation) is the only true interrupt. P1.1
does not ship subprocess timeouts — the discovery sources in scope for
Phase 1 (EASY tier — directory listing, ``ollama list``, PID enumeration)
have well-bounded runtimes.
"""

from __future__ import annotations

import concurrent.futures
import logging
from collections.abc import Callable
from typing import TypeVar

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.timeout")

T = TypeVar("T")


def _with_timeout(func: Callable[[], T], timeout_sec: float) -> T:
    """Run ``func()`` with a wall-clock timeout.

    On timeout, raises :class:`TimeoutError` (the built-in). The hung
    function continues executing in its worker thread until it completes
    or the process exits; we do NOT block on it (executor shutdown uses
    ``wait=False``) so the caller gets control back immediately.

    Args:
        func: Zero-argument callable to invoke.
        timeout_sec: Wall-clock budget in seconds. Float for sub-second
            granularity (useful in tests). Must be positive.

    Returns:
        The return value of ``func()`` if it completes within
        ``timeout_sec``.

    Raises:
        TimeoutError: If ``func()`` does not complete within
            ``timeout_sec``. The original
            :class:`concurrent.futures.TimeoutError` is chained via
            ``__cause__``.
        Any exception raised by ``func()`` itself, propagated unchanged
            (the caller — :meth:`DiscoverySource.run_with_safety` —
            catches generic ``Exception`` and returns an empty list per
            the locked source contract).
    """
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(func)
    try:
        result = future.result(timeout=timeout_sec)
    except concurrent.futures.TimeoutError as exc:
        # Don't block on the hung thread — abandon it. The caller gets
        # control back immediately; the leaked worker thread is the
        # documented limitation of the thread-based timeout.
        executor.shutdown(wait=False)
        raise TimeoutError(f"function exceeded {timeout_sec}s timeout") from exc
    except BaseException:
        # Resource-cleanup re-raise. ``func()`` raised something other
        # than a timeout (the common case for a misbehaving discover()),
        # which ``future.result()`` propagates here. Without this branch
        # the executor leaks (relying on GC __del__ for shutdown). We
        # use wait=False because the worker has already completed (it's
        # the one that raised) — wait=True would still be correct but
        # is needlessly conservative. ``BaseException`` re-raise keeps
        # ``KeyboardInterrupt`` and ``SystemExit`` propagating unchanged
        # to the caller (run_with_safety catches Exception, not
        # BaseException, per the locked contract).
        executor.shutdown(wait=False)
        raise
    else:
        # Happy path: worker completed; shut the executor down cleanly.
        executor.shutdown(wait=True)
        return result
