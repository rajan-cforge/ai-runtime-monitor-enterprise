"""Daemon-side discovery scheduler — closes the operator-path loop.

Closes the fifth and sixth consecutive shipped-but-dormant gaps of
v0.2.2 (after mappers → scoring → daemon-cadence → CLI-persistence):
the daemon now invokes ``DiscoveryOrchestrator.scan(trigger="scheduled")``
on startup (after a short delay) and then periodically, AND wires the
already-merged ``audit.finalize_crashed_runs`` (P1.5, dormant until
now — judge phase-a.a1 verdict caught the dormant duplicate). A
fresh-machine daemon start populates the Assets tab without the
operator running any manual incantation.

Lives in its own module (rather than ``monitor.py``) per the post-#118
pattern: feature surfaces with their own thread + state model land in
focused modules; ``monitor.py`` keeps the launch wiring and the cross-
cutting daemon-lifecycle code.

Three R1 cadence constants (judge AUTO-RATIFY pre-signaled 2026-06-12 per
CONTRACT §5a/§6a):

- ``DISCOVERY_STARTUP_DELAY = 60`` s — long enough for the daemon hot
  startup (CA trust, mitmdump warmup, JSONL backfill) to settle; short
  enough that a UI-watching operator sees data within "about a minute."
- ``DISCOVERY_CADENCE = 24 * 3600`` s — matches the CVE 24h TTL (P4.2
  §9.1.1) so each refreshed cache entry corresponds to one fresh asset
  snapshot. Mirrors directive §3 line 194: "Daily discovery scan +
  daily CVE poll."
- ``DISCOVERY_FAILURE_BACKOFF = 3600`` s — transient SQLite-busy or
  filesystem hiccup shouldn't blank the Assets tab for a day; short
  enough that "fix and wait" works, long enough that a persistent
  failure doesn't fill logs.

The in-flight-marker problem (daemon SIGKILL leaves ``discovery_runs.
completed_at = NULL`` forever) is handled by
``attack_surface/orchestrator/audit.finalize_crashed_runs(conn)`` —
shipped + tested in P1.5 with zero production callers until this PR.
``finalize_crashed_runs_at_startup`` (below) is the thin wrapper
``start_monitoring()`` calls: opens a conn via :func:`init_db`,
delegates to the merged finalizer, closes the conn, fail-open on any
exception (the operator sees a stale "Scan running…" banner at worst,
never a crashed daemon). The finalizer's 600s cutoff is docstring-paired
with ``ScanLock.STALE_THRESHOLD_SEC = 600`` so a stale lock and an
unfinished audit row reflect the same crashed-scan event. It sets
``status="crashed"`` + ``finalized_at_daemon_startup=True`` in the
errors JSON so a crash never becomes indistinguishable from a clean
completion in the audit trail.

P4.5 (background scheduler) will collapse the cadence constants into a
``schedule.toml``-driven config. No doc promise of configurability in
v0.2.2 — the constants are intentionally hardcoded.
"""

from __future__ import annotations

import logging
import time

from claude_monitoring.attack_surface.orchestrator import (
    DiscoveryOrchestrator,
    default_sources,
)
from claude_monitoring.db import get_db_path, init_db

DISCOVERY_STARTUP_DELAY = 60
DISCOVERY_CADENCE = 24 * 3600
DISCOVERY_FAILURE_BACKOFF = 3600


def _get_logger() -> logging.Logger:
    """Lazy logger fetch — `lifecycle.get_logger` configures the daemon
    logger as a side effect of import; avoid that here so unit tests
    don't pull in lifecycle machinery."""
    from claude_monitoring.lifecycle import get_logger

    return get_logger()


def discovery_scheduler_loop() -> None:
    """Daemon-side discovery cadence — first scan after a startup delay,
    then every ``DISCOVERY_CADENCE`` seconds. Lock-aware: a concurrent
    CLI scan during the delay or cadence window owns the slot; the
    scheduler short-circuits with ``lock_acquired=False`` and waits out
    the rest of its cadence window rather than retrying.

    Per architect-pass 2026-06-12 pin: the ``time.sleep(DISCOVERY_CADENCE)``
    call MUST be inside the ``try`` block after a successful scan. If
    it landed in ``finally``, a failed scan would sleep
    ``DISCOVERY_FAILURE_BACKOFF + DISCOVERY_CADENCE`` instead of just
    the backoff — defeating the point of the short backoff.

    Designed to be run from a ``threading.Thread(daemon=True)``. Daemon-
    thread semantics handle shutdown: when the parent process exits,
    the thread is torn down with it. In-flight ``_persist_assets`` is
    wrapped in ``with self.conn:`` (P1.3 follow-up #156) so partial
    writes cannot happen; the in-flight ``discovery_runs.completed_at``
    NULL row is cleaned by ``audit.finalize_crashed_runs`` on the next
    start, called via :func:`finalize_crashed_runs_at_startup` BEFORE
    this thread launches.
    """
    time.sleep(DISCOVERY_STARTUP_DELAY)
    while True:
        try:
            conn = init_db(get_db_path())
            try:
                orchestrator = DiscoveryOrchestrator(
                    sources=default_sources(),
                    persistence_connection=conn,
                )
                result = orchestrator.scan(trigger="scheduled")
                _get_logger().info(
                    "discovery scheduled scan complete: %d assets, lock_acquired=%s, duration=%.1fs",
                    len(result.assets),
                    result.lock_acquired,
                    result.total_duration_sec,
                )
            finally:
                conn.close()
            # Architect-pass pin: cadence sleep INSIDE try, not finally.
            time.sleep(DISCOVERY_CADENCE)
        except SystemExit:
            # Test hook — tests raise SystemExit from monkeypatched sleeps
            # to terminate the loop deterministically. Production never
            # reaches this branch.
            raise
        except Exception as exc:
            _get_logger().warning(
                "discovery scheduled scan failed: %s — retrying in %ds",
                exc,
                DISCOVERY_FAILURE_BACKOFF,
            )
            time.sleep(DISCOVERY_FAILURE_BACKOFF)


def finalize_crashed_runs_at_startup() -> int:
    """Wrap ``audit.finalize_crashed_runs`` with conn lifecycle + fail-open.

    Called once per daemon start from ``monitor.start_monitoring()``,
    BEFORE the :func:`discovery_scheduler_loop` thread launches, so the
    ``/api/assets`` envelope's ``scan_in_progress`` field starts clean
    regardless of whether the scheduler ever fires.

    Lives here (not in ``monitor.py``) so the wiring is unit-testable
    in isolation — the same coverage-ratchet rule that the
    coverage-ratchet baseline mechanism (#119) was built to defend.

    Returns the number of crashed rows finalized (for the start_monitoring
    print line). Returns 0 on any exception — the sweep is a hygiene step;
    if it fails, the scheduler still runs and the operator sees a stale
    "Scan running…" banner at worst.
    """
    try:
        from claude_monitoring.attack_surface.orchestrator import audit

        conn = init_db(get_db_path())
        try:
            return audit.finalize_crashed_runs(conn)
        finally:
            conn.close()
    except Exception as exc:
        _get_logger().warning("discovery startup crash-recovery failed: %s", exc)
        return 0
