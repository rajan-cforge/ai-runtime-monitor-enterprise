"""Scanner Protocol — the contract every supply-chain and sensitive-data
scanner across the codebase must satisfy.

A scanner takes some input (file, text, package install command, etc.)
and produces zero or more Findings. Each scanner exposes its own health
state so the dashboard can show liveness/readiness without instantiating
the scanner.

The current ``scan()`` signature takes no input — the scanner is
assumed to hold its own input state (a watched directory, a queued
buffer, etc.). The companion ``Detector`` Protocol in
``detector.py`` will take an explicit ``event`` parameter. When the
first concrete Scanner lands, this signature may evolve toward
``scan(self, input: <type>) -> list[Finding]`` if that fits better.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class Severity(str, Enum):
    """Severity levels for a scanner Finding.

    Inherits from ``str`` so members compare equal to their string
    values, behaving like ``enum.StrEnum`` without requiring Python
    3.11+ (the project still ships on 3.9).
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Finding:
    """A single scan result."""

    rule_id: str
    severity: Severity
    description: str
    context: Mapping[str, Any]  # detector-specific structured data


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
