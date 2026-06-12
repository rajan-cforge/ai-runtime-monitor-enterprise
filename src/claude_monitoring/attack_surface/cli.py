"""Discovery scan CLI — runs one ``DiscoveryOrchestrator.scan(trigger="cli")``
against :func:`default_sources` and **persists results to the live monitor DB
by default** (feat/daemon-discovery-scheduler, Rajan 2026-06-12: "defaults
should do what an operator expects; the incantation is for the special case").

Usage::

    python -m claude_monitoring.attack_surface.cli scan              # persist
    python -m claude_monitoring.attack_surface.cli scan --dump        # persist + dump JSON
    python -m claude_monitoring.attack_surface.cli scan --no-persist  # legacy throwaway

``--no-persist`` preserves the pre-feat/daemon-discovery-scheduler behavior
("dump → eyeball → walk away") for development debugging where touching the
live DB is undesirable.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from claude_monitoring.attack_surface.orchestrator import (
    DiscoveryOrchestrator,
    ScanLock,
    default_sources,
)


def _asset_to_dict(asset) -> dict:
    """Convert an `Asset` dataclass to a JSON-serializable dict."""
    return asdict(asset)


def main(argv: list[str] | None = None) -> int:
    """Entry point — parse args, run a one-shot scan, optionally dump JSON."""
    parser = argparse.ArgumentParser(
        prog="claude_monitoring.attack_surface.cli",
        description="Vigil v0.2.2 attack-surface discovery dump (throwaway CLI).",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run a one-shot discovery scan.")
    scan.add_argument(
        "--dump",
        action="store_true",
        help="Dump the resulting ScanResult as JSON to stdout.",
    )
    scan.add_argument(
        "--no-persist",
        action="store_true",
        help=("Run discovery without writing to the live monitor DB (legacy throwaway mode). Default is persist."),
    )
    scan.add_argument(
        "--lock-path",
        type=Path,
        default=None,
        help="Override the ScanLock path (default ~/claude_watch_output/.discovery.lock).",
    )

    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.error(f"unknown command: {args.command}")

    lock = ScanLock(lock_path=args.lock_path) if args.lock_path else None

    # Default is persist; --no-persist preserves the legacy throwaway mode.
    conn = None
    if not args.no_persist:
        from claude_monitoring.db import get_db_path, init_db

        conn = init_db(get_db_path())
    try:
        orchestrator = DiscoveryOrchestrator(
            sources=default_sources(),
            lock=lock,
            persistence_connection=conn,
        )
        result = orchestrator.scan(trigger="cli")
    finally:
        if conn is not None:
            conn.close()

    if args.dump:
        payload = {
            "trigger": result.trigger,
            "lock_acquired": result.lock_acquired,
            "started_at": result.started_at,
            "completed_at": result.completed_at,
            "total_duration_sec": result.total_duration_sec,
            "assets_count": len(result.assets),
            "assets": [_asset_to_dict(a) for a in result.assets],
            "per_source": [
                {
                    "name": t.name,
                    "asset_count": t.asset_count,
                    "elapsed_sec": t.elapsed_sec,
                    "last_run_outcome": t.last_run_outcome.value,
                }
                for t in result.per_source
            ],
        }
        json.dump(payload, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
