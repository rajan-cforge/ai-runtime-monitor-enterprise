"""Scanner Protocol — the contract every supply-chain and sensitive-data
scanner across the codebase must satisfy.

A scanner takes some input (file, text, package install command, etc.)
and produces zero or more Findings. Each scanner exposes its own health
state so the dashboard can show liveness/readiness without instantiating
the scanner.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@dataclass(frozen=True)
class Finding:
    """A single scan result."""

    rule_id: str
    severity: str  # "critical" | "high" | "medium" | "low" | "info"
    description: str
    context: dict  # detector-specific structured data


@dataclass(frozen=True)
class ScannerHealth:
    """Scanner liveness/readiness state."""

    healthy: bool
    last_run_at: float | None  # unix timestamp
    error: str | None  # if not healthy


@runtime_checkable
class Scanner(Protocol):
    """A scanner takes some input and produces zero or more findings.

    Every class in ``src/claude_monitoring/`` whose name ends with
    ``Scanner`` must satisfy this Protocol. Conformance is enforced by
    ``tests/architecture/test_scanner_conformance.py``.
    """

    name: str  # unique identifier for this scanner

    def scan(self) -> list[Finding]:
        """Run the scan. Return zero or more findings."""
        ...

    def health_check(self) -> ScannerHealth:
        """Report scanner state for /api/health endpoints."""
        ...
