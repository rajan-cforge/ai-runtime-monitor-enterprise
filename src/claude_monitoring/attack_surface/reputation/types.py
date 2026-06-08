"""Three-state result types for P2.6 reputation lookups.

**Ratification hard-requirement #2 (Rajan, 2026-06-08):** the result must
preserve a distinct ``reason`` end-to-end through to the UI when a lookup
is unavailable. "Silence must never render as all-clear" — the popover
shows ``rate_limited`` differently than ``checked_absent``.

Three states + four distinct unavailability reasons:

- ``present == True``  → asset is in the registry / verified.
  Reputation modifier NOT applied (presence is the "clean" outcome).
- ``present == False`` → asset is parseably ABSENT from the registry
  (e.g., npm 404, VSCode extensionquery returns empty array). Reputation
  modifier IS applied. This is the only branch that fires a modifier.
- ``present is None``  → lookup was unavailable for one of:
    * ``UnavailableReason.RATE_LIMITED`` — registry returned HTTP 429.
    * ``UnavailableReason.BUDGET_EXCEEDED`` — per-scan call budget cap
      hit before this asset (pypistats default cap = 25 per ratification).
    * ``UnavailableReason.LOOKUP_FAILED`` — generic non-429 failure
      (timeout, DNS-fail, TLS-fail, 5xx, parse error). Fail-open.
    * ``UnavailableReason.DORMANT`` — the registry's feature flag is off
      (Chrome/VSCode in P2.6). The code path didn't execute. No
      modifier; the popover should still surface "Chrome reputation
      pending P3.2 wiring."

  Reputation modifier NOT applied in any unavailable case (fail-open per
  ratification §6 inversion fix).

This module has no logic — it's a contract. Per-registry clients return
``ReputationResult``; the dispatcher composes them; the score-composition
layer consumes ``present`` for modifier-fire and ``reason`` for popover
attribution.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class ReputationSignal(str, enum.Enum):
    """Which signal a per-registry client emits.

    str-mixin matches the ``OntologyCategory`` / ``RiskBand`` /
    ``LastRunOutcome`` precedent — ``json.dumps(member)`` serializes
    directly to the lowercase value. Persistence uses ``member.value``.
    """

    NPM_LOW_DOWNLOADS = "npm_low_downloads"
    """npm package has < 100 weekly downloads (typosquat signal,
    spec §6.6.3). Modifier weight +15."""

    PIP_LOW_DOWNLOADS = "pip_low_downloads"
    """pip package has < 100 weekly downloads. Modifier weight +15."""

    CHROME_NOT_IN_STORE = "chrome_not_in_store"
    """Chrome extension is absent from the Chrome Web Store. Modifier
    weight +20. DORMANT in P2.6 (gated on ``reputation.chrome_vscode_enabled``)."""

    VSCODE_NOT_IN_MARKETPLACE = "vscode_not_in_marketplace"
    """VSCode extension is absent from the VS Marketplace. Modifier
    weight +20. DORMANT in P2.6 (gated on ``reputation.chrome_vscode_enabled``)."""

    MCP_AUTHOR_UNVERIFIED = "mcp_author_unverified"
    """MCP server's command / first-arg does not match the curated
    trust list in ``config/mcp-trusted-authors.yaml``. Modifier
    weight +10."""


class UnavailableReason(str, enum.Enum):
    """Why a reputation lookup did not produce a present/absent answer.

    Hard requirement #2 (Rajan 2026-06-08): this enum value MUST be
    preserved end-to-end to the UI. The popover renders the distinct
    reason; silence must never render as "all-clear."
    """

    RATE_LIMITED = "rate_limited"
    """HTTP 429 from the registry. Triggers exponential backoff per
    the per-registry policy (pypistats 5/15/60 min ratified)."""

    BUDGET_EXCEEDED = "budget_exceeded"
    """The per-scan call budget for this registry was exhausted before
    this asset's lookup. The remaining assets in the scan fall back to
    cache-only mode. Pypistats default cap = 25 per ratification."""

    LOOKUP_FAILED = "lookup_failed"
    """Generic non-429 failure: timeout, DNS-fail, TLS-fail, 5xx, parse
    error. Fail-open per ratification §6 inversion fix."""

    DORMANT = "dormant"
    """The registry's feature flag is off and the code path did not
    execute. Chrome/VSCode in P2.6 until P3.1/P3.2 lands managed-install
    detection."""


@dataclass(frozen=True)
class ReputationResult:
    """Single per-registry per-asset reputation lookup result.

    The three states (``present`` field):

    - ``True``  → asset is in the registry / verified.
    - ``False`` → asset is parseably absent. **The ONLY branch that fires
      a modifier.**
    - ``None``  → lookup unavailable; ``reason`` names which case.

    ``signal`` identifies which reputation rule this result feeds into
    (for the modifier-table lookup and the popover attribution).

    ``downloads`` carries the numeric download count when the registry
    returns one (npm Downloads API and pypistats both do). Used by the
    score-composition layer to apply the "< 100/week" threshold. ``None``
    for registries that don't have a download count (Chrome / VSCode /
    MCP-author).

    **Hard requirement #1 (Rajan 2026-06-08):** PyPI's
    ``info.downloads = -1`` sentinel from ``pypi.org`` must map to
    ``downloads=None`` here — never ``-1``. The pypi client is
    responsible for the sentinel-to-None translation; the threshold
    comparison MUST NOT see ``-1`` (it's less than 100 but isn't a
    "low downloads" signal).
    """

    signal: ReputationSignal
    present: bool | None
    downloads: int | None = None
    reason: UnavailableReason | None = None

    def __post_init__(self) -> None:
        """Invariants. Use ``if ... raise``, NOT ``assert`` — production
        guards must not be strippable under ``python -O``
        (memory ``feedback_assert_strippable_use_if_raise.md``)."""
        if self.present is None and self.reason is None:
            raise ValueError(
                f"ReputationResult({self.signal}) has present=None but no reason — "
                f"the three-state contract requires reason on every unavailable result"
            )
        if self.present is not None and self.reason is not None:
            raise ValueError(
                f"ReputationResult({self.signal}) has both present={self.present} and "
                f"reason={self.reason} — reason is only set when present is None"
            )
        if self.downloads is not None and self.downloads < 0:
            raise ValueError(
                f"ReputationResult({self.signal}) has downloads={self.downloads}; "
                f"negative download counts are invalid (PyPI -1 sentinel must be "
                f"translated to None by the per-registry client)"
            )


__all__ = [
    "ReputationResult",
    "ReputationSignal",
    "UnavailableReason",
]
