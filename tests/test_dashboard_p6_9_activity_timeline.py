"""P6.9 — Activity Timeline preservation contract (final lens tab).

Directive line 241: same STRICT scope as P6.6 (line 238). Activity
Timeline has ZERO timeline-specific CSS rules — `#panel-timeline`
visually reuses Live Feed's `class="feed"` container, so all visual
styling flows through P6.6's already-migrated `.feed*` selectors +
11 `.feed-item.<type>` tints.

Cookbook entries ratified by judge p6.9.a1 (2026-06-19 16:28Z):

  * D-zero-migration-shared-css — when a tab silently consumes a
    sibling's already-migrated CSS, the honest Phase A answer is
    "ship the preservation pins; that's the PR's value." A no-op
    migration is legitimate; without the pins, a future Live Feed
    edit could drop a tint class and silently break Activity
    Timeline.
  * D-cross-tab-sanity-pin — the shared-CSS preservation pin lives
    in the CONSUMER's test file (here, p6.9), NOT the defining
    tab's (p6.6). Reason: the consumer is where the visual
    regression manifests; independent observers catch the drop. If
    Pin 3 here ever fails, the SAME drop should also fail the
    corresponding P6.6 pin — that dual-fire is the contract.

This file ships ZERO production code changes. Pins read fixtures
captured at PR-creation time from `git show ad4f097:dashboard.html`.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANCH_HTML_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard.html"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "p6_9"


def _read_branch_html() -> str:
    return BRANCH_HTML_PATH.read_text()


def _read_fixture_lines(name: str) -> set[str]:
    text = (FIXTURE_DIR / name).read_text()
    return {line for line in text.splitlines() if line.strip()}


def _grep_panel_block(html: str, panel_id: str) -> str:
    """Balanced-<div> extraction from id="panel_id". Same helper the
    cookbook locked in p6.7.a1."""
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


def _grep_control_ids(panel_html: str) -> set[str]:
    ids = set(re.findall(r'id="([^"]+)"', panel_html))
    ids.discard("panel-timeline")
    return ids


def _grep_source_options(panel_html: str) -> set[str]:
    """`<option value="...">` values inside the timeline source filter.

    The "All Sources" option has an empty `value=""` — preserved via
    the `<EMPTY>` sentinel in the fixture file (the only way to round-
    trip an empty string through a line-based text fixture). Caught
    pre-migration on the first pin run: the fixture-write code stripped
    blank lines, dropping the empty-string value entirely. Sentinel
    fixes the round-trip; the pin now correctly includes the value."""
    return set(re.findall(r'<option value="([^"]*)"', panel_html))


_OPTION_EMPTY_SENTINEL = "<EMPTY>"


def _read_option_fixture(name: str) -> set[str]:
    """Like `_read_fixture_lines` but un-encodes the `<EMPTY>` sentinel
    back to `""` for the source-options pin."""
    text = (FIXTURE_DIR / name).read_text()
    out = set()
    for line in text.splitlines():
        if not line.strip() and line != "":
            continue
        out.add("" if line == _OPTION_EMPTY_SENTINEL else line)
    return out


def _grep_shared_feed_selectors(html: str) -> set[str]:
    """All `.feed*` rule selectors (whole-file scope). Activity Timeline
    consumes these via `class="feed"`. The cross-tab sanity pin —
    asserts the shared CSS P6.6 migrated is still present, since
    Activity Timeline silently depends on every one."""
    out = set()
    for m in re.finditer(r"^(\.feed[^,{]*|\.feed-item\.[a-z_]+[^,{]*)\s*\{", html, re.MULTILINE):
        out.add(m.group(1).strip())
    return out


# ---------------------------------------------------------------------------
# TestActivityTimelineControlPreservation (Pin 1 — panel-scoped)
# ---------------------------------------------------------------------------


class TestActivityTimelineControlPreservation:
    """Pin 1: the 3 ids inside `#panel-timeline` survive. PANEL-SCOPED
    via balanced-`<div>` extraction. None of these names collide with
    `#panel-feed`'s ids, but scoping is the cookbook contract."""

    def test_panel_scoped_control_ids_preserved(self):
        baseline = _read_fixture_lines("baseline-ad4f097-control-ids.txt")
        branch = _grep_control_ids(_grep_panel_block(_read_branch_html(), "panel-timeline"))
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"control ids DROPPED from #panel-timeline: {sorted(dropped)}"
        assert not added, f"control ids ADDED to #panel-timeline: {sorted(added)}"


# ---------------------------------------------------------------------------
# TestActivityTimelineSourceOptions (Pin 2 — panel-scoped)
# ---------------------------------------------------------------------------


class TestActivityTimelineSourceOptions:
    """Pin 2: the 4 source-filter `<option value="...">` values inside
    `#panel-timeline` survive. PANEL-SCOPED — Live Feed's source
    filter has different option values and would inversely pollute
    the inventory if grepped whole-file."""

    def test_panel_scoped_source_options_preserved(self):
        baseline = _read_option_fixture("baseline-ad4f097-source-options.txt")
        branch = _grep_source_options(_grep_panel_block(_read_branch_html(), "panel-timeline"))
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"source-filter options DROPPED: {sorted(dropped)}"
        assert not added, f"source-filter options ADDED/RENAMED: {sorted(added)}"


# ---------------------------------------------------------------------------
# TestSharedFeedSelectorsSanity (Pin 3 — D-cross-tab-sanity-pin, LOAD-BEARING)
# ---------------------------------------------------------------------------


class TestSharedFeedSelectorsSanity:
    """Pin 3: all `.feed*` selectors P6.6 migrated are still present on
    main. Activity Timeline silently depends on every one via
    `class="feed"` on its container.

    LOAD-BEARING per the cookbook's D-cross-tab-sanity-pin entry:
    if Live Feed's own pins ever lose coverage of a tint class, this
    independent observer still catches the drop. If this pin fails,
    the SAME drop should also fail
    `test_dashboard_p6_6_live_feed.py::TestCssTintPreservation` —
    that dual-fire is the contract."""

    def test_shared_feed_selectors_preserved(self):
        baseline = _read_fixture_lines("baseline-ad4f097-shared-feed-selectors.txt")
        branch = _grep_shared_feed_selectors(_read_branch_html())
        dropped = baseline - branch
        assert not dropped, (
            f"`.feed*` selectors DROPPED (consumed by Activity Timeline): {sorted(dropped)}. "
            "P6.6's TestCssTintPreservation should ALSO be failing on this drop — "
            "if not, P6.6's pin coverage has rotted."
        )
        # NOTE: asymmetric on purpose — we do NOT assert `branch <= baseline`.
        # Live Feed (P6.6) is the defining tab and is free to ADD new tint
        # classes; this consumer-side pin only guards against DROPS. The
        # symmetric drop+add check lives in P6.6's TestCssTintPreservation.
