"""P2.6 reputation runtime configuration — feature flags + tunables.

All values here are either Rajan-ratified (cite work-log) or
judge-decidable defaults. Per-registry clients read this module
instead of hardcoding magic numbers — a single override point keeps
the kill-switch + dormant flag honest.

Override priority (low → high):

1. Module constants below (the defaults).
2. Environment variables (per-key; see each constant's docstring).

No file-based config in P2.6 (Rajan ratification item 7: env var only).
A future PR may add ``~/.vigil/config`` reading; until then, env wins.
"""

from __future__ import annotations

import os

# ---------------------------------------------------------------------------
# Kill-switch (item 7 ratified — env var only)
# ---------------------------------------------------------------------------


VIGIL_NO_REPUTATION_ENV: str = "VIGIL_NO_REPUTATION"
"""Set to ``1`` (or any truthy value) to disable ALL reputation lookups
for the current scan. Mirrors the established ``NO_NETWORK`` pattern.

When set, the dispatcher short-circuits before any per-registry call.
Every asset receives ``ReputationResult(present=None, reason=LOOKUP_FAILED)``
in the breakdown so the UI surfaces "Reputation disabled."
"""


# Spec §8.3 air-gapped mode. Pre-existing env var the rest of Vigil
# already honors; reputation joins the air-gapped contract.
NO_NETWORK_ENV: str = "NO_NETWORK"


def reputation_disabled() -> bool:
    """True if the operator has set either kill-switch env var."""
    return _truthy(os.environ.get(VIGIL_NO_REPUTATION_ENV)) or _truthy(os.environ.get(NO_NETWORK_ENV))


def _truthy(val: str | None) -> bool:
    if val is None:
        return False
    return val.strip().lower() in {"1", "true", "yes", "on"}


# ---------------------------------------------------------------------------
# Chrome / VSCode dormant flag (item 3 ratified — default OFF)
# ---------------------------------------------------------------------------


CHROME_VSCODE_ENABLED_ENV: str = "VIGIL_REPUTATION_CHROME_VSCODE_ENABLED"
"""Default False. Flipped True ONLY by the PR that lands managed-install
detection (P3.1 for VSCode, P3.2 for Chrome). Tied explicitly to
managed-install detection per Rajan ratification item 3 — don't flip the
default without it.

Env override exists for development / testing; production default is OFF."""


def chrome_vscode_enabled() -> bool:
    """True if the Chrome/VSCode reputation rules are enabled.

    Default False. Flipped to True only by the PR that lands managed-
    install detection (P3.1 / P3.2)."""
    return _truthy(os.environ.get(CHROME_VSCODE_ENABLED_ENV))


# ---------------------------------------------------------------------------
# pypistats budget + backoff (addendum ratified 2026-06-08)
# ---------------------------------------------------------------------------


PYPISTATS_PER_SCAN_BUDGET: int = 25
"""Per-scan call budget for pypistats.org (Rajan addendum 2026-06-08).

Empirically, pypistats returns HTTP 429 after only a handful of
requests in a fresh session (recon 2026-06-08). To keep scans
moving when many pip packages are present, the dispatcher tracks
a per-scan counter; once the budget is exhausted, remaining
pypistats lookups return
``ReputationResult(present=None, reason=BUDGET_EXCEEDED)``. The
modifier is NOT applied — silence is never all-clear, so the UI
surfaces "Download count unavailable for this scan."
"""


# ---------------------------------------------------------------------------
# HTTP timeouts (judge-decidable; conservative defaults)
# ---------------------------------------------------------------------------


REQUEST_TIMEOUT_SECONDS: int = 10
"""Per-request timeout for all reputation HTTP calls. Mirrors the
existing ``threat_intel.py`` 10s timeout."""


__all__ = [
    "CHROME_VSCODE_ENABLED_ENV",
    "NO_NETWORK_ENV",
    "PYPISTATS_PER_SCAN_BUDGET",
    "REQUEST_TIMEOUT_SECONDS",
    "VIGIL_NO_REPUTATION_ENV",
    "chrome_vscode_enabled",
    "reputation_disabled",
]
