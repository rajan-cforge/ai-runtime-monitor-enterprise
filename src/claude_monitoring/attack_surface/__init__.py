"""Attack-surface domain for v0.2.2.

Houses the discovery, ontology, risk-scoring, and CVE-correlation layers
introduced across Phases 1-4 of the v0.2.2 sprint. P1.1 lands the
foundational interface (`Asset` dataclass + `DiscoverySource` ABC); Phases
1-3 register concrete sources against it; Phase 4 reads from the assets
table that sources write into.

Public surface (P1.1):

- :class:`~claude_monitoring.attack_surface.asset.Asset`
- :class:`~claude_monitoring.attack_surface.discovery.base.DiscoverySource`
"""

from __future__ import annotations

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import DiscoverySource

__all__ = ["Asset", "DiscoverySource"]
