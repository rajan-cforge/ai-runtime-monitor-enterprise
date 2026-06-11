"""P4.1 CVE feed types.

`CVEResult` is the per-asset CVE lookup result. Wraps the
`{"cvss": float}` list format that `compute_risk_score`'s `cves`
parameter already accepts (since P2.3).

Tri-state semantics (Phase A §5):
  * `cves=None`  — "we did not look up" (kill switch / air-gapped /
    budget exhausted / network error). UI shows "CVE feed unavailable".
  * `cves=[]`    — "we looked up, no known vulns". UI shows "✓ no
    known vulns".
  * `cves=[...]` — list of `{"cvss": float, ...}` dicts. Scoring uses
    `max(cvss for ...)`.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class UnavailableReason(Enum):
    """Why the CVE lookup didn't return data — telemetry only, not
    scoring-load-bearing.

    Mirrors `attack_surface/reputation/types.py::UnavailableReason`
    pattern (so the dashboard renders both the same way)."""

    KILL_SWITCH = "kill_switch"
    """`VIGIL_NO_CVE_FEED=1` or `NO_NETWORK=1` set."""

    NO_NETWORK = "no_network"
    """`NO_NETWORK=1` (explicit air-gap flag) — distinguished from
    KILL_SWITCH for ops telemetry."""

    RATE_LIMITED = "rate_limited"
    """OSV.dev returned 429/503 even after the single 2s retry."""

    BUDGET_EXHAUSTED = "budget_exhausted"
    """Per-scan vuln-detail call cap (`VULN_DETAIL_CALLS_PER_SCAN_BUDGET`,
    default 50) hit before this asset was processed."""

    NETWORK_ERROR = "network_error"
    """DNS / connection / TLS / timeout failure."""

    PARSE_ERROR = "parse_error"
    """OSV.dev returned a response we couldn't decode."""


@dataclass(frozen=True)
class CVEResult:
    """Per-asset CVE lookup result.

    `frozen=True` so result objects are safe to share across the
    dispatcher's per-item-isolation boundary without surprise mutation.
    """

    cves: list[dict] | None
    """List of `{"cvss": float, ...}` dicts (scoring-formula shape),
    `[]` if the asset was looked up but has no known vulns, or `None`
    if the lookup did not run / failed."""

    reason: UnavailableReason | None = None
    """Only set when `cves is None` — explains why telemetry-wise."""
