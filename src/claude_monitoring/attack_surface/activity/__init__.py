"""Runtime activity correlation — P4.3 (spec §7 + §7.1.1 amendment).

Ratified Rajan 2026-06-12: spec §7.1 referenced an `api_calls.process_id`
column that never existed (verified against `db.py:167-202` + the
installed schema). PID-JOIN downscoped to host-based correlation per
§7.1.1 amendment. PID-capture itself (Path B) rejected as v0.2.2 C4
scope — capture-layer process-enumeration would require its own
security/privacy case for v0.3+.

Public surface:

    correlate_asset_activity(db, asset, window) -> ActivityResult
    expected_hosts_for_source(source) -> frozenset[str] | None

A `None` return from `expected_hosts_for_source` is a STRUCTURAL n/a
("this source has no runtime correlation contract"). An empty
top_destinations list is a MEANINGFUL NEGATIVE ("correlatable type,
no captures in window"). The two MUST NEVER collapse — Amendment-C
discipline applied to activity data per Rajan Q8 rider 2026-06-12.
"""

from __future__ import annotations

from claude_monitoring.attack_surface.activity.correlator import (
    ActivityResult,
    correlate_asset_activity,
)
from claude_monitoring.attack_surface.activity.expected_hosts import (
    expected_hosts_for_source,
)

__all__ = [
    "ActivityResult",
    "correlate_asset_activity",
    "expected_hosts_for_source",
]
