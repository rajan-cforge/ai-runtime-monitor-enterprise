# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Section 7: ai-monitor --cleanup [--dry-run]

Removes accumulated cruft from the database without losing real data:

    1. Duplicate extension captures (same conversation + event_type +
       content_hash). Browser extensions can fire MutationObserver events
       for the same DOM update multiple times during streaming.
    2. Duplicate Chrome history visits (same URL within the same minute).
       Chrome's tab sync can record the same visit multiple times across
       profiles.
    3. Empty sessions — sessions with 0 turns, 0 tokens, no title, no
       events. Created when a Claude Code process spins up but exits
       before sending any messages.
    4. NULL content_hash backfill — older browser_sessions rows from before
       we had hashing get a hash computed from content_text.

Always backs up the database before running. Supports --dry-run which
counts what would be removed without modifying the DB.
"""

from __future__ import annotations

import hashlib
import shutil
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from claude_monitoring.config import get_db_path


def _open_db(db_path: Path | None = None) -> sqlite3.Connection:
    db_path = db_path or get_db_path()
    return sqlite3.connect(str(db_path))


def _backup_db(db_path: Path) -> Path:
    """Create a timestamped backup before any destructive cleanup."""
    backup_dir = db_path.parent / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    backup_path = backup_dir / f"monitor.db.backup-{timestamp}"
    shutil.copy2(str(db_path), str(backup_path))
    return backup_path


def count_duplicate_captures(db: sqlite3.Connection) -> int:
    """Count extension-source captures that would be removed by dedup."""
    try:
        row = db.execute(
            """SELECT COUNT(*) FROM browser_sessions
               WHERE source = 'extension'
               AND id NOT IN (
                   SELECT MIN(id) FROM browser_sessions
                   WHERE source = 'extension' AND content_text IS NOT NULL
                   GROUP BY conversation_id, event_type, content_hash
               )"""
        ).fetchone()
        return row[0] if row else 0
    except sqlite3.OperationalError:
        # browser_sessions might not have content_text/content_hash on a
        # very old DB — treat as nothing to dedup.
        return 0


def count_duplicate_visits(db: sqlite3.Connection) -> int:
    """Count Chrome history visits that would be removed by minute-bucket dedup."""
    try:
        row = db.execute(
            """SELECT COUNT(*) FROM browser_sessions
               WHERE source IN ('chrome_history', 'history')
               AND id NOT IN (
                   SELECT MIN(id) FROM browser_sessions
                   WHERE source IN ('chrome_history', 'history')
                   GROUP BY url, CAST(strftime('%s', visit_time) AS INTEGER) / 60
               )"""
        ).fetchone()
        return row[0] if row else 0
    except sqlite3.OperationalError:
        return 0


def count_empty_sessions(db: sqlite3.Connection) -> int:
    """Sessions with 0 turns, 0 tokens, no title, and no events."""
    try:
        row = db.execute(
            """SELECT COUNT(*) FROM sessions
               WHERE total_turns = 0
               AND COALESCE(total_input_tokens, 0) = 0
               AND COALESCE(total_output_tokens, 0) = 0
               AND title IS NULL
               AND session_id NOT IN (
                   SELECT DISTINCT session_id FROM events
                   WHERE session_id IS NOT NULL
               )"""
        ).fetchone()
        return row[0] if row else 0
    except sqlite3.OperationalError:
        return 0


def count_null_hashes(db: sqlite3.Connection) -> int:
    try:
        row = db.execute(
            """SELECT COUNT(*) FROM browser_sessions
               WHERE content_hash IS NULL AND content_text IS NOT NULL"""
        ).fetchone()
        return row[0] if row else 0
    except sqlite3.OperationalError:
        return 0


def remove_duplicate_captures(db: sqlite3.Connection) -> int:
    cur = db.execute(
        """DELETE FROM browser_sessions
           WHERE source = 'extension'
           AND id NOT IN (
               SELECT MIN(id) FROM browser_sessions
               WHERE source = 'extension' AND content_text IS NOT NULL
               GROUP BY conversation_id, event_type, content_hash
           )"""
    )
    return cur.rowcount or 0


def remove_duplicate_visits(db: sqlite3.Connection) -> int:
    cur = db.execute(
        """DELETE FROM browser_sessions
           WHERE source IN ('chrome_history', 'history')
           AND id NOT IN (
               SELECT MIN(id) FROM browser_sessions
               WHERE source IN ('chrome_history', 'history')
               GROUP BY url, CAST(strftime('%s', visit_time) AS INTEGER) / 60
           )"""
    )
    return cur.rowcount or 0


def remove_empty_sessions(db: sqlite3.Connection) -> int:
    cur = db.execute(
        """DELETE FROM sessions
           WHERE total_turns = 0
           AND COALESCE(total_input_tokens, 0) = 0
           AND COALESCE(total_output_tokens, 0) = 0
           AND title IS NULL
           AND session_id NOT IN (
               SELECT DISTINCT session_id FROM events
               WHERE session_id IS NOT NULL
           )"""
    )
    return cur.rowcount or 0


def backfill_content_hashes(db: sqlite3.Connection) -> int:
    """Compute content_hash for any browser_sessions row that's missing one."""
    try:
        rows = db.execute(
            """SELECT id, content_text FROM browser_sessions
               WHERE content_hash IS NULL AND content_text IS NOT NULL"""
        ).fetchall()
    except sqlite3.OperationalError:
        return 0
    n = 0
    for row in rows:
        text = row[1] if isinstance(row[1], str) else str(row[1] or "")
        if not text:
            continue
        h = hashlib.sha256(text[:200].encode("utf-8", errors="replace")).hexdigest()[:16]
        db.execute("UPDATE browser_sessions SET content_hash=? WHERE id=?", (h, row[0]))
        n += 1
    return n


def run_cleanup(dry_run: bool = False, db_path: Path | None = None) -> dict:
    """Execute the cleanup. Returns a summary dict suitable for printing.

    The CLI wrapper in monitor.py renders this as a human-readable report.
    Tests use the dict form so they can assert specific counts without
    parsing print output.
    """
    db_path = db_path or get_db_path()
    if not db_path.exists():
        return {
            "ok": False,
            "error": f"Database not found at {db_path}",
            "dry_run": dry_run,
        }

    summary: dict = {
        "ok": True,
        "dry_run": dry_run,
        "db_path": str(db_path),
        "backup_path": None,
        "duplicate_captures": 0,
        "duplicate_visits": 0,
        "empty_sessions": 0,
        "hashes_backfilled": 0,
        "remaining_sessions": 0,
        "remaining_browser": 0,
    }

    db = _open_db(db_path)
    try:
        summary["duplicate_captures"] = count_duplicate_captures(db)
        summary["duplicate_visits"] = count_duplicate_visits(db)
        summary["empty_sessions"] = count_empty_sessions(db)
        null_hashes = count_null_hashes(db)

        if dry_run:
            summary["hashes_backfilled"] = null_hashes  # would-be value
            return summary

        # Real run: backup first, then mutate
        summary["backup_path"] = str(_backup_db(db_path))

        summary["duplicate_captures"] = remove_duplicate_captures(db)
        summary["duplicate_visits"] = remove_duplicate_visits(db)
        summary["empty_sessions"] = remove_empty_sessions(db)
        summary["hashes_backfilled"] = backfill_content_hashes(db)
        db.commit()

        try:
            (rs,) = db.execute("SELECT COUNT(*) FROM sessions").fetchone()
            (rb,) = db.execute("SELECT COUNT(*) FROM browser_sessions").fetchone()
            summary["remaining_sessions"] = rs
            summary["remaining_browser"] = rb
        except sqlite3.OperationalError:
            pass

        return summary
    finally:
        db.close()


def print_cleanup_summary(summary: dict) -> None:
    """Render a cleanup summary as a human-readable report."""
    if not summary.get("ok"):
        print(f"❌ {summary.get('error', 'unknown error')}")
        return

    print("AI Runtime Monitor — Data Cleanup")
    if summary.get("dry_run"):
        print("  (DRY RUN — no changes will be made)")
    print()

    if summary.get("backup_path"):
        print(f"  Backup: {summary['backup_path']}")
        print()

    print(f"  Duplicate captures: {summary['duplicate_captures']}")
    print(f"  Duplicate visits:   {summary['duplicate_visits']}")
    print(f"  Empty sessions:     {summary['empty_sessions']}")
    print(f"  Hashes backfilled:  {summary['hashes_backfilled']}")
    print()

    if summary.get("dry_run"):
        total = summary["duplicate_captures"] + summary["duplicate_visits"] + summary["empty_sessions"]
        print(f"  Would remove: {total} rows")
        print(f"  Would backfill: {summary['hashes_backfilled']} hashes")
        print()
        print("  Run without --dry-run to execute.")
    else:
        print(f"  Remaining: {summary['remaining_sessions']} sessions, {summary['remaining_browser']} browser entries")
