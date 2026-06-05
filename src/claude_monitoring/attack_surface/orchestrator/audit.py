"""Observable stub `audit.py` per Rajan's 2026-06-05 Option β + observable refinement.

P1.3 ships these stubs wired into the orchestrator. They DO NOT write
to `discovery_runs` — that lands in P1.5. Each stub emits a DEBUG log
line with the literal phrase ``"P1.5 stub — no DB write yet"`` so a
forgotten P1.5 cannot leave audit silently dead.

P1.5 will fill the bodies. The function signatures and call sites are
the contract that P1.3 ships; P1.5 may extend kwargs but must not
change the existing ones.

**Read discipline reminder** (carries through from `LastRunOutcome`):
read the stored form as ``outcome.value``, NEVER ``str(member)``.
"""

from __future__ import annotations

import logging
import sqlite3

from claude_monitoring.attack_surface.discovery.base import LastRunOutcome

logger = logging.getLogger("ai-runtime-monitor.attack_surface.orchestrator.audit")

_STUB_PHRASE = "P1.5 stub — no DB write yet"


def record_run_started(conn: sqlite3.Connection, trigger: str, source_count: int) -> int:
    """Stub — P1.5 will INSERT a row in `discovery_runs` and return its rowid."""
    logger.debug(
        "audit.record_run_started stub called: trigger=%s source_count=%d — %s", trigger, source_count, _STUB_PHRASE
    )
    return 0


def record_run_finished(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    assets_discovered: int,
    per_source: tuple,
) -> None:
    """Stub — P1.5 will UPDATE the existing row with completion fields."""
    logger.debug(
        "audit.record_run_finished stub called: run_id=%d assets=%d sources=%d — %s",
        run_id,
        assets_discovered,
        len(per_source),
        _STUB_PHRASE,
    )


def record_run_crashed(
    conn: sqlite3.Connection,
    run_id: int,
    *,
    exception_type: str,
    exception_message: str,
) -> None:
    """Stub — P1.5 will UPDATE the row with errors.status='crashed'."""
    logger.debug(
        "audit.record_run_crashed stub called: run_id=%d exc=%s — %s",
        run_id,
        exception_type,
        _STUB_PHRASE,
    )


def finalize_crashed_runs(conn: sqlite3.Connection, older_than_sec: int = 600) -> int:
    """Stub — P1.5 will scan for `completed_at IS NULL AND age > cutoff`
    rows and mark them as crashed. Returns count of rows updated.

    Called at daemon startup. Currently returns 0 (no-op)."""
    logger.debug("audit.finalize_crashed_runs stub called: older_than_sec=%d — %s", older_than_sec, _STUB_PHRASE)
    return 0


__all__ = [
    "LastRunOutcome",  # re-exported for P1.5 convenience
    "finalize_crashed_runs",
    "record_run_crashed",
    "record_run_finished",
    "record_run_started",
]
