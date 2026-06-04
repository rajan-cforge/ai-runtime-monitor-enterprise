"""Discovery layer for v0.2.2 attack surface.

P1.1 lands the foundation: :class:`DiscoverySource` base class +
``run_with_safety`` orchestration entry point + thread-safe timeout
helper. Phases 1-3 register concrete sources against this contract.

Public surface (P1.1):

- :class:`~claude_monitoring.attack_surface.discovery.base.DiscoverySource`
"""

from __future__ import annotations

from claude_monitoring.attack_surface.discovery.base import DiscoverySource

__all__ = ["DiscoverySource"]
