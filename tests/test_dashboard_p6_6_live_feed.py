"""P6.6 — Live Feed migration: structural preservation pins.

Directive line 238 STRICT scope: CSS classes updated to `.v-*`
equivalents only; existing JS unchanged; every user-visible control
preserved. PRs that drop functionality "for cleaner migration" are
rejected.

The whole contract — and the cookbook P6.7–P6.9 inherit — rides on
these pins genuinely catching a drop. a1 verdict CHANGES (2026-06-18)
ratified the failure mode: conflating CSS tint with JS event-type
inventory; transcribing instead of grepping; or sourcing the baseline
from the same working tree as the branch (tautology).

a2 design (Rajan + judge ratified):

  * Baselines live in tests/fixtures/p6_6/baseline-5cc0a2f-*.txt
    extracted from `git show 5cc0a2f:src/claude_monitoring/dashboard.html`
    at PR-creation time. Immutable, traceable, no git-at-test-time
    dependency, no CI-checkout-depth flake.
  * BRANCH grep runs against the working-tree dashboard.html.
  * Three SEPARATE pins so the a1 conflation can't recur:
      - CSS tint preservation (the 11 `.feed-item.<type>` rules)
      - JS render-path preservation (sessionEventTypes + FEED_ICONS)
      - Markup controls preservation (4 control ids + 5 filter options)
  * Phase C red-test gate (Rajan, 2026-06-18): each pin MUST be shown to
    fail on a deliberate drop. The red-then-green output is pasted into
    the PR body as CONTRACT §8 empirical proof. Self-correcting means
    the pin doesn't hardcode names — it must NEVER mean it auto-absorbs
    a drop.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANCH_HTML_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard.html"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "p6_6"


def _read_branch_html() -> str:
    return BRANCH_HTML_PATH.read_text()


def _read_fixture_lines(name: str) -> set[str]:
    text = (FIXTURE_DIR / name).read_text()
    return {line for line in text.splitlines() if line.strip()}


def _grep_css_tint_types(html: str) -> set[str]:
    """All distinct event types that carry a `.feed-item.<type>` CSS rule."""
    return set(re.findall(r"\.feed-item\.([a-z_]+)", html))


def _grep_session_event_types(html: str) -> set[str]:
    """The set literal in `sessionEventTypes = new Set([...])`."""
    match = re.search(r"sessionEventTypes\s*=\s*new\s+Set\(\[([^\]]+)\]\)", html)
    if not match:
        return set()
    return set(re.findall(r"'([a-z_]+)'", match.group(1)))


def _grep_feed_icons(html: str) -> set[str]:
    """Keys in the `const FEED_ICONS = { ... }` object literal."""
    match = re.search(r"const\s+FEED_ICONS\s*=\s*\{([^}]+)\}", html, re.DOTALL)
    if not match:
        return set()
    return set(re.findall(r"([a-z_]+)\s*:", match.group(1)))


def _grep_panel_feed_block(html: str) -> str:
    """Just the #panel-feed div, so unrelated `feed-*` ids elsewhere
    (e.g. timeline-container .feed) can't pollute the assertion."""
    match = re.search(r'<div class="panel" id="panel-feed">(.*?)</div>\s*<!--', html, re.DOTALL)
    return match.group(1) if match else ""


def _grep_control_ids(panel_html: str) -> set[str]:
    return set(re.findall(r'id="feed-[a-z-]+"', panel_html))


def _grep_filter_options(panel_html: str) -> set[str]:
    """Values inside the <option value="..."> elements of the filter."""
    return set(re.findall(r'<option value="[a-z_]*"', panel_html))


# ---------------------------------------------------------------------------
# TestCssTintPreservation (LOAD-BEARING per directive line 238)
# ---------------------------------------------------------------------------


class TestCssTintPreservation:
    """Pin 1: the 11 distinct `.feed-item.<type>` tint classes on
    5cc0a2f survive verbatim. A drop of any tint class makes
    `branch - baseline` non-empty on the missing side and fails.

    Baseline source: tests/fixtures/p6_6/baseline-5cc0a2f-css-tint-types.txt
    extracted by `git show 5cc0a2f:src/claude_monitoring/dashboard.html`.
    NOT the live tree — that would be a tautology."""

    def test_css_tint_set_preserved(self):
        baseline = _read_fixture_lines("baseline-5cc0a2f-css-tint-types.txt")
        branch = _grep_css_tint_types(_read_branch_html())
        # Symmetric diff so we name BOTH directions explicitly —
        # the a1 inversion was that the executor's set was wrong in BOTH directions.
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"CSS tint classes DROPPED from migration: {sorted(dropped)}"
        assert not added, (
            f"CSS tint classes ADDED by migration: {sorted(added)}. "
            "Directive line 238 forbids out-of-scope tint additions "
            "(do NOT add CSS for JS-only types like mcp_call/bash_progress/system_event)."
        )

    def test_baseline_has_exactly_11_types(self):
        """Sanity pin: the captured baseline matches the verdict's
        ground-truth count. If this ever changes on main, the fixture
        must be regenerated as part of a deliberate scope-extension PR
        — never silently."""
        baseline = _read_fixture_lines("baseline-5cc0a2f-css-tint-types.txt")
        assert len(baseline) == 11, (
            f"baseline fixture is supposed to be 11 types (judge p6.6.a1 verdict, "
            f"2026-06-18); got {len(baseline)} — regenerate the fixture if main moved."
        )


# ---------------------------------------------------------------------------
# TestJsRenderPathPreservation (LOAD-BEARING — D-zero-js-change empirical proof)
# ---------------------------------------------------------------------------


class TestJsRenderPathPreservation:
    """Pin 2: the JS-side event-type inventory survives. DELIBERATELY
    distinct from Pin 1 so the a1 CSS-vs-JS conflation cannot recur.

    Phantom-three (`mcp_call`, `bash_progress`, `system_event`) live
    HERE, not in CSS. They render with default `.type` color. Adding
    CSS tint rules for them "to make a pin pass" is the out-of-scope
    behavior change directive line 238 explicitly forbids."""

    def test_session_event_types_preserved(self):
        baseline = _read_fixture_lines("baseline-5cc0a2f-js-session-event-types.txt")
        branch = _grep_session_event_types(_read_branch_html())
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"sessionEventTypes entries DROPPED: {sorted(dropped)}"
        assert not added, f"sessionEventTypes entries ADDED: {sorted(added)}"

    def test_feed_icons_preserved(self):
        baseline = _read_fixture_lines("baseline-5cc0a2f-js-feed-icons.txt")
        branch = _grep_feed_icons(_read_branch_html())
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"FEED_ICONS keys DROPPED: {sorted(dropped)}"
        assert not added, f"FEED_ICONS keys ADDED: {sorted(added)}"


# ---------------------------------------------------------------------------
# TestMarkupControlPreservation (directive "every user-visible control preserved")
# ---------------------------------------------------------------------------


class TestMarkupControlPreservation:
    """Pin 3: the 4 user-visible controls + 5 filter options in
    #panel-feed survive. Scoped to the #panel-feed block so unrelated
    `feed-*` ids elsewhere in the dashboard don't pollute the
    assertion."""

    def test_control_ids_preserved(self):
        # No `id="feed-*"` exists outside #panel-feed in the dashboard
        # (verified on 5cc0a2f); grep the whole file safely. Scoping to
        # the panel block via awk-style block-match is fragile — the
        # block may close on a different line than expected.
        baseline = _read_fixture_lines("baseline-5cc0a2f-control-ids.txt")
        branch = _grep_control_ids(_read_branch_html())
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"control ids DROPPED: {sorted(dropped)}"
        assert not added, f"control ids ADDED: {sorted(added)}"

    def test_filter_options_preserved(self):
        baseline = _read_fixture_lines("baseline-5cc0a2f-filter-options.txt")
        branch = _grep_filter_options(_grep_panel_feed_block(_read_branch_html()))
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"filter options DROPPED: {sorted(dropped)}"
        assert not added, f"filter options ADDED: {sorted(added)}"
