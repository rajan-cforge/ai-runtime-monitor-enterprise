"""Rendering-hint helpers — the per-state display contract the dashboard
consumes. Keeps the cve_status / risk_score → operator-facing label
mapping in one place so the spec §6.10 schema and the dashboard cannot
drift apart.

The visible dashboard view that calls into these helpers does not yet
exist (no asset-list view in `dashboard.html` as of scan-scoring-callsite).
This module ships the rules first; the UI lands separately when the asset
view does.
"""

from __future__ import annotations

from claude_monitoring.attack_surface.rendering.cve_status_hints import (
    UNKNOWN_PENDING_RESCAN_HINT,
    RenderHint,
    cve_status_hint,
    risk_score_hint,
)

__all__ = [
    "UNKNOWN_PENDING_RESCAN_HINT",
    "RenderHint",
    "cve_status_hint",
    "risk_score_hint",
]
