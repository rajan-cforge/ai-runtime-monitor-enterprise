"""P6.8 — Insights tab migration: structural preservation pins.

Directive line 240: same STRICT scope as P6.6 (line 238) — CSS classes
updated to `.v-*` equivalents only; existing JS unchanged; every
user-visible control preserved.

Cookbook (p6.6.a2 + p6.7.a1, locked):
  * Baselines from immutable fixtures captured from
    `git show 1de3af0:src/claude_monitoring/dashboard.html` at
    PR-creation time. NOT the live tree.
  * Three structural pins + one sanity pin. CSS rules use
    whole-file scope (definitions are unique even when use is
    shared across panels). Markup ids + titles use panel-scoped
    extraction via balanced-`<div>` (D-panel-scoped-extraction,
    p6.7.a1).
  * Phase C red-test mutation gate: each pin demonstrably RED on
    a deliberate drop, GREEN on restore.

Load-bearing thing for the judge: the `.stat-card .value.alert/
.blue/.purple` modifier classes are the analog of P6.6's
`.feed-item.<type>` tint set. JS applies them based on semantic
state (e.g., critical risk → `.alert`). A silently dropped
modifier loses a color state — the exact §4.4 inversion this
preservation contract exists to stop.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANCH_HTML_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard.html"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "p6_8"


def _read_branch_html() -> str:
    return BRANCH_HTML_PATH.read_text()


def _read_fixture_lines(name: str) -> set[str]:
    text = (FIXTURE_DIR / name).read_text()
    return {line for line in text.splitlines() if line.strip()}


def _grep_panel_block(html: str, panel_id: str) -> str:
    """Extract a panel's HTML by balanced-<div> counting from
    `id="panel_id"`. Robust against cross-panel pollution."""
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


def _grep_stat_card_selectors(html: str) -> set[str]:
    """All `.stat-card*` rule selectors. Whole-file scope — the
    definition is unique. Captures `.stat-card`, `.stat-card:hover`,
    `.stat-card .label`, `.stat-card .value`, and the 3 LOAD-BEARING
    modifier classes (`.value.alert`, `.value.blue`, `.value.purple`)."""
    out = set()
    for m in re.finditer(r"^(\.stat-card[^,{]*)\s*\{", html, re.MULTILINE):
        out.add(m.group(1).strip())
    return out


def _grep_chart_card_selectors(html: str) -> set[str]:
    """All `.chart-card*` rule selectors. Sanity pin for the P6.7-migrated
    rule, since `#panel-insights` consumes it via the shared definition.
    A P6.8 edit must NOT drop `.chart-card` rules."""
    out = set()
    for m in re.finditer(r"^(\.chart-card[^,{]*|\.charts-full|\.charts(?![\w-]))\s*\{", html, re.MULTILINE):
        out.add(m.group(1).strip())
    return out


def _grep_control_ids(panel_html: str) -> set[str]:
    """Markup ids inside the `#panel-insights` block."""
    ids = set(re.findall(r'id="([^"]+)"', panel_html))
    ids.discard("panel-insights")
    return ids


def _grep_chart_titles(panel_html: str) -> set[str]:
    """User-visible h3 titles inside `#panel-insights`. Nested tags
    are stripped."""
    titles = set()
    for m in re.finditer(r"<h3>(.*?)</h3>", panel_html, re.DOTALL):
        text = re.sub(r"<[^>]+>", "", m.group(1)).strip()
        if text:
            titles.add(text)
    return titles


# ---------------------------------------------------------------------------
# TestStatCardSelectorPreservation (Pin 1 — LOAD-BEARING, modifier set)
# ---------------------------------------------------------------------------


class TestStatCardSelectorPreservation:
    """Pin 1: the 7 `.stat-card*` rule selectors survive verbatim,
    INCLUDING the 3 modifier classes `.value.alert/.blue/.purple`.

    The modifier set is the §4.4 inversion guard — JS applies them by
    semantic state and a silently dropped modifier loses a color the
    operator depends on. Analog of P6.6's `.feed-item.<type>` tint set."""

    def test_stat_card_selectors_preserved(self):
        baseline = _read_fixture_lines("baseline-1de3af0-stat-card-selectors.txt")
        branch = _grep_stat_card_selectors(_read_branch_html())
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, (
            f"`.stat-card*` selectors DROPPED: {sorted(dropped)}. "
            "Modifier classes (.value.alert/.blue/.purple) are LOAD-BEARING; "
            "JS applies them by semantic state."
        )
        assert not added, (
            f"`.stat-card*` selectors ADDED: {sorted(added)}. STRICT scope forbids out-of-scope selector additions."
        )

    def test_baseline_has_exactly_7_selectors(self):
        """Sanity pin against the verdict's ground-truth count. If main
        moves, regenerate the fixture as part of a deliberate scope
        extension — never silently."""
        baseline = _read_fixture_lines("baseline-1de3af0-stat-card-selectors.txt")
        assert len(baseline) == 7, (
            f"baseline is supposed to be 7 `.stat-card*` selectors "
            f"(judge p6.8.a1 verdict 2026-06-19); got {len(baseline)}."
        )


# ---------------------------------------------------------------------------
# TestChartCardSanity (Pin 4 — P6.7-migrated rule shared with #panel-insights)
# ---------------------------------------------------------------------------


class TestChartCardSanity:
    """Pin 4 (sanity): the `.chart-card*` rules migrated by P6.7 are
    still present. `#panel-insights` consumes them via the shared
    definition — a P6.8 edit MUST NOT accidentally drop them."""

    def test_chart_card_selectors_preserved(self):
        baseline = _read_fixture_lines("baseline-1de3af0-chart-card-selectors.txt")
        branch = _grep_chart_card_selectors(_read_branch_html())
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"`.chart-card*` (P6.7-migrated) DROPPED: {sorted(dropped)}"
        assert not added, f"`.chart-card*` ADDED in P6.8 scope (forbidden): {sorted(added)}"


# ---------------------------------------------------------------------------
# TestInsightsControlPreservation (Pin 2 — panel-scoped)
# ---------------------------------------------------------------------------


class TestInsightsControlPreservation:
    """Pin 2: the 9 ids inside `#panel-insights` survive. PANEL-SCOPED
    via balanced-`<div>` extraction — Analytics's 8 `chart-*` ids are
    correctly excluded (inverse of the P6.7 case)."""

    def test_panel_scoped_control_ids_preserved(self):
        baseline = _read_fixture_lines("baseline-1de3af0-control-ids.txt")
        branch = _grep_control_ids(_grep_panel_block(_read_branch_html(), "panel-insights"))
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"control ids DROPPED from #panel-insights: {sorted(dropped)}"
        assert not added, f"control ids ADDED to #panel-insights: {sorted(added)}"


# ---------------------------------------------------------------------------
# TestInsightsChartTitlePreservation (Pin 3 — panel-scoped)
# ---------------------------------------------------------------------------


class TestInsightsChartTitlePreservation:
    """Pin 3: the 3 chart titles inside `#panel-insights` survive.
    PANEL-SCOPED — Analytics's 7 titles are correctly excluded."""

    def test_panel_scoped_chart_titles_preserved(self):
        baseline = _read_fixture_lines("baseline-1de3af0-chart-titles.txt")
        branch = _grep_chart_titles(_grep_panel_block(_read_branch_html(), "panel-insights"))
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"chart titles DROPPED: {sorted(dropped)}"
        assert not added, f"chart titles ADDED/RENAMED: {sorted(added)}"
