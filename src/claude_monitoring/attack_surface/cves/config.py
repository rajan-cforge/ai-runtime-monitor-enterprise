"""P4.1 CVE feed config — env-var kill switches + TTL + budget constants.

Phase A §1, §3, §4, §6 ratifications. Override priority (low → high):

1. Module constants below (the defaults).
2. Environment variables (per-key, see each constant's docstring).

No file-based config in P4.1; same pattern as the P2.6 reputation
config module.
"""

from __future__ import annotations

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Kill-switches (§6 — default ENABLED, different from reputation's chrome/
# vscode default-OFF because CVE data is universally useful + API is
# privacy-safe per the CONTRACT §1a invariant)
# ---------------------------------------------------------------------------

VIGIL_NO_CVE_FEED_ENV: str = "VIGIL_NO_CVE_FEED"
"""Set to a truthy value (``1`` / ``true`` / ``yes`` / ``on``) to
disable the OSV.dev CVE lookups across the orchestrator scan flow."""

NO_NETWORK_ENV: str = "NO_NETWORK"
"""Shared air-gap flag — reputation honors the same env var. Setting
either VIGIL_NO_CVE_FEED or NO_NETWORK disables CVE lookups."""

_TRUTHY = frozenset({"1", "true", "yes", "on"})


def _is_truthy(env_value: str | None) -> bool:
    if env_value is None:
        return False
    return env_value.strip().lower() in _TRUTHY


def cve_feed_disabled() -> bool:
    """True iff CVE lookups should be skipped this scan.

    Read fresh from the environment on every call (not cached) so the
    operator can toggle live without restarting the daemon — same
    semantic as reputation's kill-switch.
    """
    return _is_truthy(os.environ.get(VIGIL_NO_CVE_FEED_ENV)) or _is_truthy(os.environ.get(NO_NETWORK_ENV))


# ---------------------------------------------------------------------------
# TTLs (§4 — CORRECTED per Rajan; clean→vulnerable transition is the catch
# case so the negative-cache TTL gets the SAME length as positive)
# ---------------------------------------------------------------------------

QUERYBATCH_NEGATIVE_TTL_SECONDS: int = 24 * 3600
"""24 hours for "no vulns found" cache entries on querybatch results.

Same TTL as positive (no asymmetry — the clean→vulnerable transition
is the very event Vigil exists to surface; a longer negative TTL would
make the dominant scoring factor structurally blind to it)."""

QUERYBATCH_POSITIVE_TTL_SECONDS: int = 24 * 3600
"""24 hours for "vulns found" querybatch cache entries."""

VULNS_DETAIL_TTL_SECONDS: int = 7 * 24 * 3600
"""7 days for `/v1/vulns/{id}` records. Near-immutable; severity
changes only on advisory revision."""


# ---------------------------------------------------------------------------
# Per-scan budget (§3 — cap at 50 vuln-detail calls; soft-fail beyond
# with reason=BUDGET_EXHAUSTED)
# ---------------------------------------------------------------------------

VULN_DETAIL_CALLS_PER_SCAN_BUDGET: int = 50
"""Hard cap on `/v1/vulns/{id}` calls per scan. After warm cache the
cap is rarely hit; on cold cache we soft-fail (asset gets cves=None)
rather than make N more network calls."""


# ---------------------------------------------------------------------------
# API base (§1 — allowlist `api.osv.dev` only; the `osv.dev` web UI is
# never called server-side)
# ---------------------------------------------------------------------------

OSV_API_BASE: str = "https://api.osv.dev"
"""HTTPS base URL for OSV.dev — must match the allowlist in
`scripts/check_privacy_no_telemetry.py::ALLOWED_HOSTNAMES`."""


# ---------------------------------------------------------------------------
# Cache file paths
# ---------------------------------------------------------------------------


def get_querybatch_cache_path() -> Path:
    """JSON cache file for package → vuln-ID-list (querybatch results).
    Lives under the operator's `~/claude_watch_output/` so chmod 600
    is enforced by the existing startup permission sweep."""
    from claude_monitoring.config import get_output_dir

    return get_output_dir() / "osv-querybatch-cache.json"


def get_vulns_cache_path() -> Path:
    """JSON cache file for vuln-ID → full record (vuln-detail records)."""
    from claude_monitoring.config import get_output_dir

    return get_output_dir() / "osv-vulns-cache.json"
