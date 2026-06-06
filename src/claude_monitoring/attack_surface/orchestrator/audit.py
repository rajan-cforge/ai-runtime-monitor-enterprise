"""`discovery_runs` audit logging — P1.5 implementation.

Per the v0.2.2 implementation directive §16.4 + Rajan's 2026-06-05
Option β + observable refinement: P1.3 shipped stubs with DEBUG log
lines; P1.5 fills the bodies with real DB writes.

**Field-naming ratification (2026-06-05):** the per-source breakdown
JSON uses field name `outcome` storing `LastRunOutcome.value` lowercase
ALWAYS (never null when the source ran). A column named `failure_kind`
would never hold the literal string `"success"` — naming consistency
matters for downstream queries.

**Two-write lifecycle:**

1. ``record_run_started`` — INSERT row with ``completed_at = NULL``.
   Returns the run_id (rowid).
2. ``record_run_finished`` — UPDATE the row to set ``completed_at``,
   ``assets_discovered``, and the per-source breakdown JSON in
   ``errors`` with ``status="completed"``.
3. ``record_run_crashed`` — UPDATE with ``status="crashed"`` and
   exception details in the errors JSON.

**Crash recovery:** ``finalize_crashed_runs`` at daemon startup scans
for rows where ``completed_at IS NULL`` AND age > 600s, marking them
as crashed. Matches ``ScanLock.STALE_THRESHOLD_SEC``.

**Retention:** ``sweep_old_runs`` deletes rows older than 90 days
(matches the `permission_grants` precedent in the existing codebase).

**Trigger vocabulary:** `{"scheduled", "on_demand", "cli"}` —
duplicated from the orchestrator's lock module (also validates at the
orchestrator boundary, but the audit layer enforces too as a
defense-in-depth check).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time

from claude_monitoring.attack_surface.discovery.base import LastRunOutcome

logger = logging.getLogger("ai-runtime-monitor.attack_surface.orchestrator.audit")


VALID_TRIGGERS: frozenset[str] = frozenset({"scheduled", "on_demand", "cli"})
"""Locked trigger vocabulary. Mirrors the ScanLock module's set."""

DEFAULT_CRASH_CUTOFF_SEC: int = 600
"""Default age threshold for finalize_crashed_runs. Matches
ScanLock.STALE_THRESHOLD_SEC so a stale lock and an unfinished audit
row both reflect the same crashed-scan event."""

DEFAULT_RETENTION_SEC: int = 90 * 86400
"""90 days — matches the permission_grants retention precedent."""


def record_run_started(
    conn: sqlite3.Connection,
    *,
    trigger: str,
    source_count: int,
) -> int:
    """INSERT a new `discovery_runs` row. Returns the rowid.

    Raises:
        ValueError: trigger not in `VALID_TRIGGERS`.
    """
    if trigger not in VALID_TRIGGERS:
        raise ValueError(f"audit.record_run_started: trigger must be one of {sorted(VALID_TRIGGERS)}, got {trigger!r}")
    cursor = conn.execute(
        "INSERT INTO discovery_runs (started_at, trigger, errors) VALUES (?, ?, ?)",
        (time.time(), trigger, json.dumps({"status": "running", "sources": []})),
    )
    conn.commit()
    run_id = cursor.lastrowid
    logger.info("audit: run %d started (trigger=%s, sources=%d)", run_id, trigger, source_count)
    return int(run_id) if run_id is not None else 0


def record_run_finished(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    assets_discovered: int,
    per_source: tuple,
) -> None:
    """UPDATE the row with completion fields + per-source JSON breakdown."""
    breakdown = {
        "status": "completed",
        "sources": [_telemetry_to_dict(t) for t in per_source],
    }
    conn.execute(
        "UPDATE discovery_runs SET completed_at = ?, assets_discovered = ?, errors = ? WHERE id = ?",
        (time.time(), assets_discovered, json.dumps(breakdown), run_id),
    )
    conn.commit()
    logger.info("audit: run %d finished (assets=%d, sources=%d)", run_id, assets_discovered, len(per_source))


def record_run_crashed(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    exception_type: str,
    exception_message: str,
) -> None:
    """UPDATE the row to indicate a crash: status='crashed' + exception details."""
    if run_id <= 0:
        # P1.3's caller may pass 0 if the INSERT path wasn't reached.
        logger.warning("audit: record_run_crashed with run_id=0; no row to update")
        return
    breakdown = {
        "status": "crashed",
        "exception_type": exception_type,
        "exception_message": exception_message[:500],
        "sources": [],
    }
    conn.execute(
        "UPDATE discovery_runs SET completed_at = ?, errors = ? WHERE id = ?",
        (time.time(), json.dumps(breakdown), run_id),
    )
    conn.commit()
    logger.warning("audit: run %d crashed (%s)", run_id, exception_type)


def finalize_crashed_runs(
    conn: sqlite3.Connection,
    older_than_sec: int = DEFAULT_CRASH_CUTOFF_SEC,
) -> int:
    """Mark stale unfinished runs as crashed. Returns count of rows updated.

    Called at daemon startup to clean up rows left dangling by a crash
    or kill mid-scan. The cutoff matches `ScanLock.STALE_THRESHOLD_SEC`
    so the two finalization signals stay consistent.
    """
    cutoff = time.time() - older_than_sec
    # Find candidate rows
    candidates = list(
        conn.execute(
            "SELECT id, errors FROM discovery_runs WHERE completed_at IS NULL AND started_at < ?",
            (cutoff,),
        )
    )
    if not candidates:
        return 0
    updated = 0
    now = time.time()
    for run_id, existing_errors in candidates:
        try:
            existing = json.loads(existing_errors) if existing_errors else {}
        except json.JSONDecodeError:
            existing = {}
        existing["status"] = "crashed"
        existing["finalized_at_daemon_startup"] = True
        conn.execute(
            "UPDATE discovery_runs SET completed_at = ?, errors = ? WHERE id = ?",
            (now, json.dumps(existing), run_id),
        )
        updated += 1
    conn.commit()
    if updated:
        logger.info("audit: finalized %d crashed run(s) older than %ds", updated, older_than_sec)
    return updated


def sweep_old_runs(
    conn: sqlite3.Connection,
    retention_sec: int = DEFAULT_RETENTION_SEC,
) -> int:
    """Delete rows older than ``retention_sec``. Returns count deleted.

    Called at scan-end to keep `discovery_runs` from growing without
    bound. The 90-day default matches the `permission_grants`
    retention precedent in the existing codebase.
    """
    cutoff = time.time() - retention_sec
    cursor = conn.execute("DELETE FROM discovery_runs WHERE started_at < ?", (cutoff,))
    deleted = cursor.rowcount or 0
    conn.commit()
    if deleted:
        logger.info("audit: swept %d run(s) older than %ds", deleted, retention_sec)
    return int(deleted)


def read_recent_runs(conn: sqlite3.Connection, *, limit: int = 10) -> list[dict]:
    """Return the most recent N runs as dicts, ordered by started_at DESC.

    Used by the dashboard's "last scans" status panel + the CLI's
    ``--status`` extension.
    """
    rows = conn.execute(
        "SELECT id, started_at, completed_at, trigger, assets_discovered, errors "
        "FROM discovery_runs ORDER BY started_at DESC LIMIT ?",
        (limit,),
    ).fetchall()
    result: list[dict] = []
    for r in rows:
        result.append(
            {
                "id": r[0],
                "started_at": r[1],
                "completed_at": r[2],
                "trigger": r[3],
                "assets_discovered": r[4],
                "errors": json.loads(r[5]) if r[5] else None,
            }
        )
    return result


def _telemetry_to_dict(telem) -> dict:
    """Serialize a PerSourceTelemetry to its JSON-stored shape.

    Field `outcome` stores `LastRunOutcome.value` (lowercase string)
    per Rajan's 2026-06-05 architect-pass naming steer. Never use
    `str(member)` — `outcome.value` is the version-independent read.
    """
    outcome = telem.last_run_outcome
    return {
        "name": telem.name,
        "asset_count": telem.asset_count,
        "elapsed_sec": telem.elapsed_sec,
        "outcome": outcome.value if isinstance(outcome, LastRunOutcome) else str(outcome),
    }


__all__ = [
    "LastRunOutcome",
    "finalize_crashed_runs",
    "read_recent_runs",
    "record_run_crashed",
    "record_run_finished",
    "record_run_started",
    "sweep_old_runs",
]
