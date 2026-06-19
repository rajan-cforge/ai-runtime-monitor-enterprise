"""P6.7 — Analytics tab migration: structural preservation pins.

Directive line 239: same STRICT scope as P6.6 (line 238). CSS classes
updated to `.v-*` equivalents only; existing JS unchanged; every
user-visible control preserved.

The cookbook is locked by p6.6.a2 and refined by p6.7.a1
(D-panel-scoped-extraction):

  * Baselines live in tests/fixtures/p6_7/baseline-dbe9950-*.txt,
    extracted from `git show dbe9950:src/claude_monitoring/dashboard.html`
    at PR-creation time. Immutable; no git-at-test-time dependency.
  * BRANCH inventory greps the working-tree dashboard.html. Pins
    compare BRANCH vs FIXTURE (NOT branch vs branch — that would
    be a tautology, the trap Rajan flagged on p6.6.a2).
  * Three SEPARATE pins. Markup + h3 titles are PANEL-SCOPED via
    balanced-`<div>` extraction (because Analytics shares
    `.chart-card` with Insights — whole-file grep would leak
    `chart-ins-tools` and `Top Tools (All Sessions)` from
    `#panel-insights`). The CSS selector pin uses whole-file scope
    intentionally — the rule DEFINITIONS are unique even if their
    USE is shared across panels.
  * Phase C red-test gate: each pin MUST be demonstrably failed on
    a deliberate drop, then restored. Red-then-green output is
    pasted into the PR body as §8 artifact.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANCH_HTML_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard.html"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "p6_7"


def _read_branch_html() -> str:
    return BRANCH_HTML_PATH.read_text()


def _read_fixture_lines(name: str) -> set[str]:
    text = (FIXTURE_DIR / name).read_text()
    return {line for line in text.splitlines() if line.strip()}


def _grep_panel_block(html: str, panel_id: str) -> str:
    """Extract a panel's HTML by balanced-<div> counting from the opening
    div with `id="panel_id"`. Robust against the cross-panel pollution
    that broke p6.6's first awk-pass fixture extraction and that would
    leak Insights data into the Analytics inventory if grepped whole-file."""
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


def _grep_css_selectors(html: str) -> set[str]:
    """The 5 Analytics-scope CSS rule selectors. Whole-file scope is
    intentional — `.chart-card` is shared with Insights; preserving
    the rule definition preserves the visual for both tabs."""
    out = set(re.findall(r"^(\.charts-full|\.chart-card[^,{]*|\.charts(?![\w-]))", html, re.MULTILINE))
    return {s.strip() for s in out}


def _grep_control_ids(panel_html: str) -> set[str]:
    """Markup ids inside the #panel-analytics block. The panel id
    itself is excluded so the pin's coverage is about CONTROLS,
    not the panel wrapper."""
    ids = set(re.findall(r'id="([^"]+)"', panel_html))
    ids.discard("panel-analytics")
    return ids


def _grep_chart_titles(panel_html: str) -> set[str]:
    """User-visible h3 titles inside `#panel-analytics`. Nested tags
    (like the `<span id="forecast-label">`) are stripped — the inner
    span's id is preserved separately by the control-ids pin."""
    titles = set()
    for m in re.finditer(r"<h3>(.*?)</h3>", panel_html, re.DOTALL):
        text = re.sub(r"<[^>]+>", "", m.group(1)).strip()
        if text:
            titles.add(text)
    return titles


# ---------------------------------------------------------------------------
# TestAnalyticsCssSelectorPreservation (Pin 1 — whole-file shared rules)
# ---------------------------------------------------------------------------


class TestAnalyticsCssSelectorPreservation:
    """Pin 1: the 5 Analytics-scope CSS rule selectors survive verbatim.
    `.chart-card` is shared with Insights; preserving the rule
    definition preserves the visual for both tabs."""

    def test_selectors_preserved(self):
        baseline = _read_fixture_lines("baseline-dbe9950-css-selectors.txt")
        branch = _grep_css_selectors(_read_branch_html())
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"CSS selectors DROPPED from migration: {sorted(dropped)}"
        assert not added, (
            f"CSS selectors ADDED by migration: {sorted(added)}. "
            "Token-substitution scope: rules edit their declarations, not their selectors."
        )

    def test_baseline_has_exactly_5_selectors(self):
        baseline = _read_fixture_lines("baseline-dbe9950-css-selectors.txt")
        assert len(baseline) == 5, (
            f"baseline is supposed to be 5 selectors (judge p6.7.a1 verdict, "
            f"2026-06-19); got {len(baseline)} — regenerate the fixture if main moved."
        )


# ---------------------------------------------------------------------------
# TestAnalyticsControlPreservation (Pin 2 — panel-scoped)
# ---------------------------------------------------------------------------


class TestAnalyticsControlPreservation:
    """Pin 2: the 8 ids inside `#panel-analytics` survive. PANEL-SCOPED
    via balanced-`<div>` extraction — `chart-ins-tools` from
    `#panel-insights` is correctly excluded.

    LOAD-BEARING per p6.7.a1 D-panel-scoped-extraction:
    whole-file grep for `chart-*` would leak Insights ids into the
    Analytics inventory and silently let an Insights id satisfy a
    drop from Analytics. §4.4 inversion guard."""

    def test_panel_scoped_control_ids_preserved(self):
        baseline = _read_fixture_lines("baseline-dbe9950-control-ids.txt")
        branch = _grep_control_ids(_grep_panel_block(_read_branch_html(), "panel-analytics"))
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"control ids DROPPED from #panel-analytics: {sorted(dropped)}"
        assert not added, f"control ids ADDED to #panel-analytics: {sorted(added)}"


# ---------------------------------------------------------------------------
# TestAnalyticsChartTitlePreservation (Pin 3 — panel-scoped, tag-stripped)
# ---------------------------------------------------------------------------


class TestAnalyticsChartTitlePreservation:
    """Pin 3: the 7 chart titles inside `#panel-analytics` survive
    verbatim. PANEL-SCOPED — `Top Tools (All Sessions)` from
    `#panel-insights` is correctly excluded.

    The `Daily Token Burn Rate (14 days)` title has a nested
    `<span id="forecast-label">`. The span's id is pinned by the
    control-ids pin (Pin 2); the title pin compares only the
    user-visible text content."""

    def test_panel_scoped_chart_titles_preserved(self):
        baseline = _read_fixture_lines("baseline-dbe9950-chart-titles.txt")
        branch = _grep_chart_titles(_grep_panel_block(_read_branch_html(), "panel-analytics"))
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"chart titles DROPPED: {sorted(dropped)}"
        assert not added, f"chart titles ADDED/RENAMED: {sorted(added)}"
