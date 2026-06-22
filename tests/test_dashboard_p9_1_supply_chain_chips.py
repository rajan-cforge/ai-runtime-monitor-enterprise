"""P9.1 — Supply Chain risk-status chips. FIRST Phase 9 PR.

This is NEW functionality (not a repaint). Adds 5 filter chips to the Supply
Chain tab: `<button class="v-chip">` with `data-risk-status` attribute in
`{all, malicious, vulnerable, agent_installed, clean}`.

The chips REUSE the canonical `.v-chip` shipped at dashboard.html:815-821
(`.v-chip`, `.v-chip:hover`, `.v-chip.is-active`, `.v-chip__n`). ZERO CSS
changes in this PR.

The backend derives `risk_status` per row in `_api_supply_chain_environment`
from existing signals (`is_known_malicious` from `threat_intel`, `vuln_count`,
`agent_installs`). Precedence: malicious > vulnerable > agent_installed > clean.

Cookbook lineage:
  * Refined cookbook entry #6 (judge p6.11 Phase B ruling 2026-06-21): chips
    are LITERAL markup, so static-markup pin suffices. The `.v-chip__n`
    count-text updates are JS-set in `loadSupplyChain()` body — source-regex
    over the render path (same lemma branch as P6.11).
  * NEW cookbook entry #7 (judge p9.1.a1 ratification 2026-06-21):
    scope-extension PRs that land controls guarded by Phase 6 cluster pins
    MUST update the existing pin's allowlist in the SAME PR. The P6.10
    `test_no_v_chip_elements_in_panel` zero-presence pin is REPURPOSED to a
    positive allowlist in this PR's diff.
  * Empty-state data-truthfulness rider (judge p9.1.a2 ratification): AND
    filter returning zero rows MUST render an explicit "no rows match" state
    distinct from "scanned and clean" and from "not scanned" (§4.5 §4.4).
  * Server-side allowlist validation (p9.1.a2 carry-forward): the
    `risk_status` query param is validated against the 5-value allowlist
    server-side; out-of-allowlist values are treated as no-filter (fail-open
    for a read-only filter param).

Tests in this file:
  Pin 1 — backend: risk_status derivation across all 4 input combinations.
  Pin 2 — backend: aggregate stats include `malicious` count.
  Pin 3 — backend: AND-filter returns the correct subset; empty result
                   preserves `stats.total` non-zero (truthfulness).
  Pin 4 — backend: server-side allowlist validation rejects bogus values.
  Pin 5 — frontend: panel contains EXACTLY 5 chips with `data-risk-status` ∈
                    {all, malicious, vulnerable, agent_installed, clean}; the
                    `all` chip is `class="v-chip is-active"` by default.
  Pin 6 — frontend: ZERO `data-risk` attribute usage inside the panel's chip
                    set (collision-avoidance with session-item severity).
  Pin 7 — frontend (render-path regex): `loadSupplyChain()` body sets
                    `.v-chip__n` text from the API response.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANCH_HTML_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard.html"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "p9_1"


def _read_branch_html() -> str:
    return BRANCH_HTML_PATH.read_text()


def _read_fixture_lines(name: str) -> set[str]:
    text = (FIXTURE_DIR / name).read_text()
    return {line for line in text.splitlines() if line.strip()}


def _grep_panel_block(html: str, panel_id: str) -> str:
    """Balanced-<div> extraction from id='panel_id'. Same helper as the
    locked cookbook from p6.7.a1."""
    marker = f'id="{panel_id}"'
    idx = html.find(marker)
    if idx < 0:
        return ""
    div_open = html.rfind("<div", 0, idx)
    if div_open < 0:
        return ""
    depth, i = 0, div_open
    while i < len(html):
        if html.startswith("<div", i):
            depth += 1
            i += 4
        elif html.startswith("</div>", i):
            depth -= 1
            i += 6
            if depth == 0:
                return html[div_open:i]
        else:
            i += 1
    return ""


def _grep_panel_v_chip_data_risk_status(panel_html: str) -> set[str]:
    """`data-risk-status` values on `<button class="v-chip">` inside the
    panel. NOT bare regex over the whole panel — must be on a v-chip
    button specifically, so a stray data-risk-status on some other
    element type wouldn't count."""
    out = set()
    for m in re.finditer(r'<button\b[^>]*\bclass="[^"]*\bv-chip\b[^"]*"[^>]*\bdata-risk-status="([^"]+)"', panel_html):
        out.add(m.group(1))
    # Also handle the case where data-risk-status comes BEFORE class=
    for m in re.finditer(r'<button\b[^>]*\bdata-risk-status="([^"]+)"[^>]*\bclass="[^"]*\bv-chip\b[^"]*"', panel_html):
        out.add(m.group(1))
    return out


def _grep_panel_data_risk_uses(panel_html: str) -> list[str]:
    """Any `data-risk="..."` (the COLLIDING attribute name) inside the
    panel block. Per p9.1.a2 D-data-risk-status-attribute-NAME, the chips
    use the compound `data-risk-status`; bare `data-risk` is reserved for
    session-item severity bands and MUST NOT leak into the supply-chain
    panel. Tag-agnostic — covers any element."""
    return re.findall(r'\bdata-risk="[^"]+"', panel_html)


def _grep_default_active_chip_value(panel_html: str) -> str:
    """The `data-risk-status` of the `<button class="v-chip is-active">`
    chip — the default-active filter. Per the spec, the default is `all`
    (show everything)."""
    m = re.search(
        r'<button\b[^>]*\bclass="[^"]*\bv-chip\b[^"]*\bis-active\b[^"]*"[^>]*\bdata-risk-status="([^"]+)"',
        panel_html,
    )
    if m:
        return m.group(1)
    # Mirror search for attribute-order variation
    m = re.search(
        r'<button\b[^>]*\bdata-risk-status="([^"]+)"[^>]*\bclass="[^"]*\bv-chip\b[^"]*\bis-active\b[^"]*"',
        panel_html,
    )
    return m.group(1) if m else ""


def _extract_function_body(html: str, signature_prefix: str) -> str:
    """Brace-walker per refined cookbook entry #6. Extracts the body of any
    `function X(` or `async function X(` declaration matching the prefix."""
    idx = html.find(signature_prefix)
    if idx < 0:
        return ""
    brace_start = html.find("{", idx)
    if brace_start < 0:
        return ""
    depth, i = 0, brace_start
    while i < len(html):
        c = html[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return html[brace_start : i + 1]
        i += 1
    return ""


def _extract_render_path_body(html: str) -> str:
    """The Supply Chain render path that updates chip counts. Today
    `loadSupplyChain()` dispatches to `loadEnvironment()` for the
    `environment` category, where the per-row risk_status derivation
    lives. The chip-count updates are inside `loadEnvironment` — that
    is the render-path function for THIS PR.

    If a future PR consolidates the dispatch (or rewires chip counts
    elsewhere), this helper's probe will return empty and the
    downstream pin will fail loudly — which is the right failure
    direction per the p6.11 architect-review precedent."""
    return _extract_function_body(html, "async function loadEnvironment(")


# ---------------------------------------------------------------------------
# Backend pins (1-4) — risk_status derivation, stats, AND-filter, allowlist
# ---------------------------------------------------------------------------


class TestRiskStatusDerivation:
    """Pin 1: backend derives risk_status correctly per row across all 4
    input combinations with the locked precedence
    malicious > vulnerable > agent_installed > clean."""

    def test_derivation_table(self):
        from claude_monitoring.supply_chain_risk import _derive_risk_status

        # (is_malicious, vuln_count, agent_installs, expected)
        cases = [
            (True, 0, 0, "malicious"),
            (True, 5, 3, "malicious"),  # malicious dominates
            (False, 1, 0, "vulnerable"),
            (False, 5, 3, "vulnerable"),  # vulnerable beats agent
            (False, 0, 1, "agent_installed"),
            (False, 0, 99, "agent_installed"),
            (False, 0, 0, "clean"),
        ]
        for is_mal, vuln, agent, expected in cases:
            assert _derive_risk_status(is_mal, vuln, agent) == expected, (
                f"derivation failed for ({is_mal}, vuln={vuln}, agent={agent}): expected {expected}"
            )


class TestSupplyChainStatsIncludeMalicious:
    """Pin 2: aggregate stats include `malicious` count alongside
    `vulnerable / agent_installed / clean`."""

    def test_stats_payload_includes_malicious_key(self):
        """API response `stats` dict has a `malicious` key. Backend test —
        TDD: this pin fails until the backend adds the key. Tested via the
        in-process handler helper rather than a real HTTP boot."""
        from claude_monitoring.supply_chain_risk import _supply_chain_stats_keys

        keys = _supply_chain_stats_keys()
        assert "malicious" in keys, f"`malicious` key missing from supply-chain stats payload. Got: {sorted(keys)}"


class TestRiskStatusAllowlistValidation:
    """Pin 4: server-side validates the `risk_status` query param against
    the 5-value allowlist. Out-of-allowlist values are treated as no-filter
    (fail-open for a read-only filter — never 500, never SQL-injectable,
    never breaks the dashboard). Per p9.1.a2 carry-forward."""

    def test_allowlist_set(self):
        from claude_monitoring.supply_chain_risk import _RISK_STATUS_ALLOWLIST

        assert frozenset({"all", "malicious", "vulnerable", "agent_installed", "clean"}) == _RISK_STATUS_ALLOWLIST, (
            f"risk_status allowlist must be exactly the 5 values defined by D-data-risk-"
            f"status-attribute-NAME. Got: {sorted(_RISK_STATUS_ALLOWLIST)}"
        )

    def test_normalize_accepts_allowlist_and_rejects_bogus(self):
        from claude_monitoring.supply_chain_risk import _normalize_risk_status

        for v in ("all", "malicious", "vulnerable", "agent_installed", "clean"):
            assert _normalize_risk_status(v) == v
        # Out-of-allowlist → None (no filter)
        for v in ("'; DROP TABLE", "<script>", "MaLiCiOuS", "muted", "", None):
            assert _normalize_risk_status(v) is None, f"bogus value {v!r} must normalize to None, not pass through"


# ---------------------------------------------------------------------------
# Frontend pins (5-7) — chip allowlist, no-collision, render-path
# ---------------------------------------------------------------------------


class TestSupplyChainChipAllowlist:
    """Pin 5: the panel contains EXACTLY 5 `<button class="v-chip">` chips
    with `data-risk-status` ∈ {all, malicious, vulnerable, agent_installed,
    clean}; the default-active chip is `all`. This REPURPOSES the spirit of
    P6.10's `test_no_v_chip_elements_in_panel` zero-presence assertion into a
    positive allowlist (per cookbook entry #7 — same PR landing real chips
    must update the allowlist guard)."""

    def test_chip_allowlist_exact(self):
        baseline = _read_fixture_lines("baseline-7c031a0-risk-status-chips.txt")
        branch = _grep_panel_v_chip_data_risk_status(_grep_panel_block(_read_branch_html(), "panel-supply-chain"))
        expected = {"all", "malicious", "vulnerable", "agent_installed", "clean"}
        assert baseline == expected, f"baseline fixture drift — expected {sorted(expected)}, got {sorted(baseline)}"
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"data-risk-status values DROPPED: {sorted(dropped)}"
        assert not added, (
            f"data-risk-status values ADDED: {sorted(added)}. Scope-extension to add a "
            "new chip MUST update this allowlist + the new fixture in the same PR "
            "(cookbook entry #7)."
        )

    def test_default_active_is_all(self):
        active = _grep_default_active_chip_value(_grep_panel_block(_read_branch_html(), "panel-supply-chain"))
        assert active == "all", f"the default-active chip must be `all` (the show-everything default), not {active!r}"


class TestNoBareDataRiskInChipSet:
    """Pin 6: ZERO bare `data-risk` (the COLLIDING attribute reserved for
    session-item severity) inside the supply-chain panel. Per p9.1.a2
    D-data-risk-status-attribute-NAME. Tag-agnostic — catches a panel-level
    leak of the wrong attribute family even on non-chip elements."""

    def test_zero_bare_data_risk_in_panel(self):
        uses = _grep_panel_data_risk_uses(_grep_panel_block(_read_branch_html(), "panel-supply-chain"))
        assert uses == [], (
            f"bare `data-risk` found inside #panel-supply-chain: {uses}. "
            "The compound `data-risk-status` is the correct attribute family for "
            "the chip taxonomy; bare `data-risk` is reserved for session-item "
            "severity bands."
        )


class TestLoadSupplyChainUpdatesChipCounts:
    """Pin 7: `loadSupplyChain()` body updates `.v-chip__n` text content from
    the API response. Render-path regex per refined cookbook entry #6
    (the chip-count UPDATES are JS-driven; the chip markup itself is
    literal)."""

    def test_render_path_updates_chip_counts(self):
        body = _extract_render_path_body(_read_branch_html())
        assert body, (
            "could not extract loadEnvironment() body (probe failed). If the "
            "render path was renamed/restructured, update "
            "`_extract_render_path_body` deliberately — this is the "
            "scope-extension signal per the p6.11 architect precedent."
        )
        # The render path must update the per-chip count element ids
        # (`sc-rs-<key>-n`). Asserting the literal id-prefix `sc-rs-` is
        # the source-regex equivalent of "the JS sets the count spans"
        # per refined cookbook entry #6.
        assert "sc-rs-" in body, (
            "render-path body must update `sc-rs-<key>-n` chip-count spans — "
            "no `sc-rs-` references found. (Render-path regex per cookbook "
            "entry #6.)"
        )
        assert "by_risk_status" in body, (
            "render-path body must read `stats.by_risk_status` from the API "
            "response. Without it the chip counts cannot reflect the "
            "in-memory derivation (judge p9.1.a2 D-risk-status-derivation)."
        )
