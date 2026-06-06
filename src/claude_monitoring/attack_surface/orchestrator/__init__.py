"""Discovery orchestrator package for v0.2.2 P1.3.

Public surface:

- :class:`DiscoveryOrchestrator` — coordinates scans across registered sources
- :class:`ScanResult` / :class:`PerSourceTelemetry` — return value of ``scan()``
- :class:`ScanLock` — file-based + in-process lock for non-overlapping scans
- :func:`default_sources` — factory returning the registered EASY-tier sources
- :mod:`audit` — observable stub module (filled by P1.5)
"""

from __future__ import annotations

from claude_monitoring.attack_surface.orchestrator.lock import ScanLock
from claude_monitoring.attack_surface.orchestrator.orchestrator import (
    DiscoveryOrchestrator,
    PerSourceTelemetry,
    ScanResult,
    default_sources,
)

__all__ = [
    "DiscoveryOrchestrator",
    "PerSourceTelemetry",
    "ScanLock",
    "ScanResult",
    "default_sources",
]
