"""P4.5 CVE-poll scheduler — separate-from-discovery thread per spec §8.3.

Spec §8.3 (verbatim, `v022-attack-surface-feature-spec-v1-LOCKED.md:1190`):
    "Separate from asset discovery. Runs daily."

Implementation:
  - Own ``threading.Thread(daemon=True)`` launched alongside
    ``discovery_scheduler_loop`` from ``monitor.start_monitoring()``.
  - Reads ``[cve_poll]`` from the same ``schedule.toml`` so operators
    have one config surface for the two cadences.
  - Default 03:30 local (30-min offset from discovery's 03:00 default to
    avoid rate-limit contention on OSV.dev if a daemon starts at
    exactly the configured discovery slot).
  - Walks ``assets`` for distinct ``(ecosystem, package, version)``
    triples matching the existing ``_SOURCE_TO_ECOSYSTEM`` map in
    ``cves/dispatcher.py``, then calls ``OSVClient.querybatch`` direct
    (NOT through ``DiscoveryOrchestrator``).
  - Does NOT touch ``ScanLock`` — CVE-cache refresh is a write to the
    file-backed cache, not to ``monitor.db``. Cannot collide with a
    concurrent discovery scan.
  - On poll failure: log WARNING + sleep ``CVE_POLL_FAILURE_BACKOFF`` +
    leave the cache UNTOUCHED (judge p4.5.a3 carry-forward — the
    authoritative staleness renderer is the merged
    ``rendering/cve_status_hints.py:71-73`` off ``assets.last_scanned``).
    Never stamp a fresh timestamp on a failed poll.
"""

from __future__ import annotations

import datetime as _dt
import logging
import time

from claude_monitoring.attack_surface.schedule_config import (
    load_schedule_config,
    resolve_schedule_path,
)

CVE_POLL_STARTUP_DELAY = 90  # 30s after discovery's startup delay
CVE_POLL_CADENCE = 24 * 3600
CVE_POLL_FAILURE_BACKOFF = 3600

_poll_counter = 0
_failure_counter = 0


def _get_logger() -> logging.Logger:
    from claude_monitoring.lifecycle import get_logger

    return get_logger()


def get_poll_count() -> int:
    """Operator-visible — total successful polls since daemon start."""
    return _poll_counter


def get_failure_count() -> int:
    """Operator-visible — total failed polls since daemon start. The
    cache is untouched on failure, so this is purely diagnostic."""
    return _failure_counter


def _compute_next_sleep_seconds(default_seconds: int = CVE_POLL_CADENCE) -> int:
    """Same logic as discovery_scheduler — read schedule.toml's
    ``[cve_poll]`` section."""
    try:
        cfg = load_schedule_config(resolve_schedule_path())
        next_at = cfg.cve_poll.next_slot()
        if next_at is None:
            return default_seconds
        delta = (next_at - _dt.datetime.now()).total_seconds()
        return max(60, int(delta))
    except Exception:
        return default_seconds


def cve_poll_once() -> int:
    """Single CVE-poll pass. Returns the number of distinct package
    triples refreshed (0 if nothing to poll).

    Walks ``assets`` for unique ``(ecosystem, package, version)`` triples
    that map to a known OSV.dev ecosystem; calls ``OSVClient.querybatch``
    direct; the cache layer handles 24h TTL + atomic file write internally.

    Defensive: if the OSV.dev call fails, the cache stays untouched and
    we propagate the exception so the loop's failure-backoff path
    triggers. The cache's existing `last_fetched` timestamp continues to
    age; the dashboard surfaces CVE-data-stale through the existing
    `cve_status_hints` renderer. Never stamp a fresh `last_scanned` on
    a failed poll.
    """
    from claude_monitoring.attack_surface.cves.dispatcher import _SOURCE_TO_ECOSYSTEM
    from claude_monitoring.db import get_db_path, init_db

    conn = init_db(get_db_path())
    try:
        # Pull distinct (source, name, version) and project to
        # (ecosystem, name, version) via the dispatcher's source map.
        rows = conn.execute(
            "SELECT DISTINCT source, name, version FROM assets WHERE source IS NOT NULL AND version IS NOT NULL"
        ).fetchall()
    finally:
        conn.close()

    # Project to (ecosystem, package, version) triples for known sources.
    triples: list[tuple[str, str, str]] = []
    for source, name, version in rows:
        ecosystem = _SOURCE_TO_ECOSYSTEM.get(source)
        if ecosystem is None or not name or not version:
            continue
        triples.append((ecosystem, name, version))
    if not triples:
        return 0

    # Direct OSV client call — bypass DiscoveryOrchestrator entirely
    # per spec §8.3 ("Separate from asset discovery").
    from claude_monitoring.attack_surface.cves.client import OSVClient
    from claude_monitoring.attack_surface.cves.config import get_querybatch_cache_path
    from claude_monitoring.attack_surface.cves.querybatch_cache import QuerybatchCache

    client = OSVClient()
    cache = QuerybatchCache(get_querybatch_cache_path())
    queries = [{"package": {"name": pkg, "ecosystem": eco}, "version": ver} for eco, pkg, ver in triples]
    # Whole-batch failure propagates to the loop's failure-backoff path.
    # Cache stays untouched on the batch path — judge p4.5.a3 carry-forward.
    per_query_vuln_ids = client.querybatch(queries)
    refreshed = 0
    for (ecosystem, name, version), vuln_ids in zip(triples, per_query_vuln_ids, strict=False):
        try:
            cache.set(ecosystem=ecosystem, package=name, version=version, vuln_ids=vuln_ids)
            refreshed += 1
        except Exception as exc:
            # Per-item isolation: one triple's cache-write failure must
            # not abort the others.
            _get_logger().warning("cve_poll: cache write failed for %s/%s@%s: %s", ecosystem, name, version, exc)
    return refreshed


def cve_poll_loop() -> None:
    """Daemon-side CVE-poll cadence — first poll after a startup delay,
    then per the schedule.toml ``[cve_poll]`` cadence.

    Designed to be run from ``threading.Thread(daemon=True)``."""
    global _poll_counter, _failure_counter

    time.sleep(CVE_POLL_STARTUP_DELAY)
    while True:
        try:
            refreshed = cve_poll_once()
            _poll_counter += 1
            _get_logger().info("cve_poll complete: %d packages refreshed", refreshed)
            time.sleep(_compute_next_sleep_seconds())
        except SystemExit:
            raise
        except Exception as exc:
            _failure_counter += 1
            _get_logger().warning(
                "cve_poll failed: %s — retrying in %ds (cache untouched)",
                exc,
                CVE_POLL_FAILURE_BACKOFF,
            )
            time.sleep(CVE_POLL_FAILURE_BACKOFF)
