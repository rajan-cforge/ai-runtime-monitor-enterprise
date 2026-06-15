#!/usr/bin/env python3
"""Privacy CI gate: every column in every monitor.db table is classified
in privacy_audit.SAFE_COLUMNS_BY_TABLE (or its table is in
CAPTURE_TABLES_NO_SAMPLES).

The runtime ``redact_value_for_display`` fails closed on unknown
columns — but the fail-closed default is the LAST resort, not a
contract. The contract is: the literal stays complete with every
column in every table that ``init_db()`` creates. This script enforces
that contract at PR-review time so a missing classification surfaces
in CI, not in production logs.

Phase A judge p5.1b.a2 APPROVE 2026-06-14: gate must pass before the
P5.1b PR can merge.

Exit code 0 = pass; 1 = at least one column in some table is missing
from the literal.
"""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    sys.path.insert(0, str(repo_root / "src"))

    from claude_monitoring.db import init_db
    from claude_monitoring.privacy_audit import (
        CAPTURE_TABLES_NO_SAMPLES,
        SAFE_COLUMNS_BY_TABLE,
    )

    with tempfile.TemporaryDirectory() as d:
        db_path = Path(d) / "schema_check.db"
        conn = init_db(db_path)
        # Walk every table the schema creates EXCEPT sqlite_-internal.
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchall()
        unclassified: list[tuple[str, str]] = []
        for (table,) in rows:
            if table in CAPTURE_TABLES_NO_SAMPLES:
                # Capture tables are intentionally without per-column policy —
                # no-samples means we never need to render their cells.
                continue
            classified = SAFE_COLUMNS_BY_TABLE.get(table)
            if classified is None:
                unclassified.append((table, "<table missing>"))
                continue
            actual_cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            for col in actual_cols:
                if col not in classified:
                    unclassified.append((table, col))
        conn.close()

    if unclassified:
        print("FAIL: db-audit classification is incomplete.")
        print("Each entry below is a (table, column) present in the live schema")
        print("but missing from privacy_audit.SAFE_COLUMNS_BY_TABLE.")
        print("Either add it to the literal with one of {raw, masked, opaque_id},")
        print("or — if it stores raw captured content — add the table to")
        print("CAPTURE_TABLES_NO_SAMPLES instead.")
        print()
        for table, col in sorted(unclassified):
            print(f"  - {table}.{col}")
        return 1
    print("PASS: every column in every table is classified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
