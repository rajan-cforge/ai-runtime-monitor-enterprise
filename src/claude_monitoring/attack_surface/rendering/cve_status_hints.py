"""C-rider rendering rules for asset-row display, per Rajan ratification
2026-06-11 + verdict scan-scoring-callsite.a1 Finding 3.

Surfaces the per-state display contract as pure functions so the future
dashboard PR (asset-list view) has a single load-bearing call site for
each render decision:

    +---------------------------------------+--------------------+--------------+
    | input                                 | label              | severity     |
    +=======================================+====================+==============+
    | cve_status="ok",  cves=[]             | "no known vulns"   | "info"       |
    | cve_status="ok",  cves=[v1, v2, …]    | "N known vulns"    | "warn-high"  |
    | cve_status="unavailable", reason=R    | "CVE lookup: <R>"  | "warn-low"   |
    | cve_status="not_applicable"           | "—"                | "neutral"    |
    | risk_score IS NULL (asset scored fail)| "not yet scored"   | "neutral"    |
    +---------------------------------------+--------------------+--------------+

The `severity` token is a renderer-agnostic level (`info` / `warn-low` /
`warn-high` / `neutral` / `critical`). Dashboard CSS picks colours; this
module makes no HTML/CSS decisions, only the policy.

Tested per §6.10 schema's four `cve_status` states + the NULL-risk_score
case. NOT a UI module — the actual asset-list view in `dashboard.html`
does not yet exist; this layer ships first so the contract is stable
when the view lands.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from claude_monitoring.attack_surface.cves.types import UnavailableReason

Severity = Literal["info", "warn-low", "warn-high", "neutral", "critical"]


@dataclass(frozen=True)
class RenderHint:
    """Renderer-agnostic display hint. The dashboard turns `severity`
    into CSS classes; this module never touches markup."""

    label: str
    severity: Severity
    tooltip: str


_NOT_APPLICABLE_HINT = RenderHint(
    label="—",
    severity="neutral",
    tooltip="CVE feed does not apply to this asset type (no ecosystem to query).",
)

_NULL_RISK_HINT = RenderHint(
    label="not yet scored",
    severity="neutral",
    tooltip="Scoring failed for this asset; it will be re-scored on the next scan.",
)

# Per-reason language. Each maps to a one-line operator-facing string that
# survives the renderer translation; the spec §8.3 fallback ("CVE data >24h
# old" warning) is rendered when reason=NETWORK_ERROR / NO_NETWORK and the
# cache is stale, which the dashboard determines from `last_scanned` — not
# from this module.
_REASON_LABELS: dict[UnavailableReason, str] = {
    UnavailableReason.KILL_SWITCH: "CVE feed disabled by operator",
    UnavailableReason.NO_NETWORK: "CVE feed offline (NO_NETWORK)",
    UnavailableReason.RATE_LIMITED: "CVE feed rate-limited; retry next scan",
    UnavailableReason.BUDGET_EXHAUSTED: "CVE budget exhausted this scan",
    UnavailableReason.NETWORK_ERROR: "CVE lookup network error",
    UnavailableReason.PARSE_ERROR: "CVE response parse error",
}


def cve_status_hint(
    cve_status: str,
    cves: list | None,
    cve_unavailable_reason: str | None,
) -> RenderHint:
    """Map the §6.10 `risk_factors` triple → operator-facing `RenderHint`.

    Args:
        cve_status: One of ``"ok"`` / ``"unavailable"`` / ``"not_applicable"``.
        cves: ``None`` for unavailable/not_applicable; a (possibly empty)
            list for ``"ok"``.
        cve_unavailable_reason: A `UnavailableReason.value` string when
            ``cve_status == "unavailable"``; ``None`` otherwise.

    Returns:
        `RenderHint` — invariant ``not_applicable`` and ``unavailable``
        NEVER share a label (Amendment C data-truthfulness rule).
    """
    if cve_status == "not_applicable":
        return _NOT_APPLICABLE_HINT
    if cve_status == "unavailable":
        reason_label = "CVE lookup unavailable"
        if cve_unavailable_reason is not None:
            try:
                reason_enum = UnavailableReason(cve_unavailable_reason)
                reason_label = _REASON_LABELS.get(reason_enum, reason_label)
            except ValueError:
                # Forward-compat: future enum values fall back to the generic
                # label so the operator still sees "something's off" rather
                # than a render crash.
                pass
        return RenderHint(
            label=reason_label,
            severity="warn-low",
            tooltip=f"OSV.dev lookup returned: {cve_unavailable_reason or 'unspecified'}",
        )
    if cve_status == "ok":
        count = len(cves) if cves else 0
        if count == 0:
            return RenderHint(
                label="no known vulns",
                severity="info",
                tooltip="OSV.dev returned no known vulnerabilities for this package@version.",
            )
        return RenderHint(
            label=f"{count} known vuln{'s' if count != 1 else ''}",
            severity="warn-high",
            tooltip="See risk-score breakdown for the CVE IDs and CVSS scores.",
        )
    # Unknown cve_status — fail-closed to a visible-but-quiet hint.
    return RenderHint(
        label=f"unknown CVE state ({cve_status})",
        severity="warn-low",
        tooltip="risk_factors.cve_status carried an unrecognized value; please file a bug.",
    )


def risk_score_hint(risk_score: int | None) -> RenderHint | None:
    """`None` → ``"not yet scored"`` hint; any int → ``None`` (the row's
    own risk badge renders the score directly). Per the C-rider's
    NULL-risk_score case."""
    if risk_score is None:
        return _NULL_RISK_HINT
    return None
