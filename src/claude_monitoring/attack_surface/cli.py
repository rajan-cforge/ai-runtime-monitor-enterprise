"""Throwaway CLI for the first-real-discovery milestone.

Usage::

    python -m claude_monitoring.attack_surface.cli scan --dump

Runs ``DiscoveryOrchestrator.scan(trigger="cli")`` with the
:func:`default_sources` registry (Ollama models + AI tool versions at
P1.4-minimal merge time) and dumps the resulting ``Asset`` records as
JSON to stdout. No persistence; no audit DB writes; no dashboard.

This is the v0.2.2 proof-of-function — Vigil enumerating real assets
on the developer's machine end-to-end. Will be replaced by a proper
``claude-watch`` subcommand surface once the dashboard lands.
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
        "--lock-path",
        type=Path,
        default=None,
        help="Override the ScanLock path (default ~/claude_watch_output/.discovery.lock).",
    )

    args = parser.parse_args(argv)
    if args.command != "scan":
        parser.error(f"unknown command: {args.command}")

    lock = ScanLock(lock_path=args.lock_path) if args.lock_path else None
    orchestrator = DiscoveryOrchestrator(sources=default_sources(), lock=lock)
    result = orchestrator.scan(trigger="cli")

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
