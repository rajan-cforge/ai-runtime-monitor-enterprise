"""P6.10 — Supply Chain tab repaint-only preservation contract.

Directive line 242 + STATUS.md 2026-06-19 (Rajan REPAINT-ONLY ratification):
strict-scope `.v-*` token migration; live tab controls stay verbatim;
the mockup's new risk-status chips are explicitly Phase 9 scope.

Cookbook entries inherited from p6.6.a2 / p6.7.a1 / p6.8.a1 / p6.9.a1
and the p6.10.a1 verdict (2026-06-21 APPROVE):

  * D-data-cat-modifier-set-LOAD-BEARING — the 5 `data-cat` button
    values are the structural analog of P6.6's `.feed-item.<type>`
    tints and P6.8's `.stat-card .value.*` modifiers. JS dispatches
    the category filter on `dataset.cat`; a silently dropped value
    loses an entire class of supply-chain items. §4.4 inversion
    guard. Pinned by `TestSupplyChainDataCatButtons` (LOAD-BEARING).
  * D-system-section-cross-tab-sanity-pin — `.system-section` rules
    are shared with `#panel-system`. The sanity pin asserts the
    rules exist FILE-GLOBAL (not panel-scoped) so a System-tab-side
    drop fires the pin here. Cross-tab guard, p6.9 lineage.
  * D-no-new-controls-real-guard (NEW per p6.10.a1 verdict
    carry-forward 1) — the id-set pin is necessary but NOT
    sufficient as a REPAINT-ONLY guard: the Phase 9 mockup chips
    are `<button class="v-chip">` (class-only, no id, no data-cat),
    so they would slip past both Pin 1 and Pin 2. This file pins
    the actual structural property: zero `class~="v-chip"` and
    the `<button>` set equals the 5 data-cat toggle buttons.

All baselines come from immutable fixtures captured from
`git show 767ee61:dashboard.html`. Pins are grep/content-anchored,
NOT line-numbered (the verdict cites lines 233–234 — don't depend
on them).
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANCH_HTML_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard.html"
FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "p6_10"


def _read_branch_html() -> str:
    return BRANCH_HTML_PATH.read_text()


def _read_fixture_lines(name: str) -> set[str]:
    text = (FIXTURE_DIR / name).read_text()
    return {line for line in text.splitlines() if line.strip()}


def _grep_panel_block(html: str, panel_id: str) -> str:
    """Balanced-<div> extraction from id="panel_id". Same helper as
    the locked cookbook from p6.7.a1."""
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
    ids.discard("panel-supply-chain")
    return ids


def _grep_data_cat_values(panel_html: str) -> set[str]:
    """The `data-cat` attribute values inside the supply-chain panel.
    JS dispatches the category filter on `dataset.cat`."""
    return set(re.findall(r'data-cat="([^"]+)"', panel_html))


def _grep_system_section_selectors(html: str) -> set[str]:
    """All `.system-section*` rule selectors. Whole-file scope —
    the rule definitions are global. Shared with `#panel-system` and
    any other consumer."""
    out = set()
    for m in re.finditer(r"^(\.system-section(?![\w-])[^,{]*)\s*\{", html, re.MULTILINE):
        out.add(m.group(1).strip())
    return out


def _grep_panel_buttons(panel_html: str) -> list[str]:
    """All `<button …>` opening tags inside the panel block, in
    source order. Used by the no-new-controls guard."""
    return re.findall(r"<button\b[^>]*>", panel_html)


def _grep_panel_v_chips(panel_html: str) -> list[str]:
    """All elements with `v-chip` in their class list inside the
    panel. The Phase 9 mockup risk-status chips are
    `<button class="v-chip …">` — this pin's REAL job is to fire if
    any leaks into P6.10's repaint."""
    # Match any opening tag whose class attribute contains v-chip as
    # a token (whitespace-separated). Don't false-positive on
    # `.v-chip-something` non-token substrings.
    out = []
    for m in re.finditer(r"<\w+\b[^>]*class=\"([^\"]*)\"[^>]*>", panel_html):
        classes = m.group(1).split()
        if "v-chip" in classes:
            out.append(m.group(0))
    return out


# ---------------------------------------------------------------------------
# TestSupplyChainControlIds (Pin 1 — panel-scoped, NECESSARY but not sufficient)
# ---------------------------------------------------------------------------


class TestSupplyChainControlIds:
    """Pin 1: the 9 ids inside `#panel-supply-chain` survive. Pinned
    via balanced-`<div>` extraction.

    NOTE: this pin is necessary but NOT sufficient as a REPAINT-ONLY
    guard. The Phase 9 mockup risk-status chips are
    `<button class="v-chip">` (class-only, no id, no data-cat) — they
    would slip past this pin. The real no-new-controls guard lives
    in `TestSupplyChainNoNewControls` below. See p6.10.a1 verdict
    carry-forward 1."""

    def test_panel_scoped_control_ids_preserved(self):
        baseline = _read_fixture_lines("baseline-767ee61-control-ids.txt")
        branch = _grep_control_ids(_grep_panel_block(_read_branch_html(), "panel-supply-chain"))
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, f"control ids DROPPED from #panel-supply-chain: {sorted(dropped)}"
        assert not added, (
            f"control ids ADDED to #panel-supply-chain: {sorted(added)}. "
            "REPAINT-ONLY scope forbids new controls. Mockup chips are Phase 9 scope."
        )


# ---------------------------------------------------------------------------
# TestSupplyChainDataCatButtons (Pin 2 — LOAD-BEARING §4.4 modifier guard)
# ---------------------------------------------------------------------------


class TestSupplyChainDataCatButtons:
    """Pin 2: the 5 `data-cat` button values survive verbatim.
    LOAD-BEARING — JS dispatches the category filter on
    `dataset.cat`; dropping any value silently loses a whole class
    of supply-chain items.

    Structural analog of:
      - P6.6's `.feed-item.<type>` tint set (event-type colors)
      - P6.8's `.stat-card .value.alert/.blue/.purple` modifiers
        (semantic-state colors)
    Three worked examples of the §4.4 modifier-drop inversion guard
    pattern (p6.10.a1 verdict ratified)."""

    def test_panel_scoped_data_cat_values_preserved(self):
        baseline = _read_fixture_lines("baseline-767ee61-buttons.txt")
        branch = _grep_data_cat_values(_grep_panel_block(_read_branch_html(), "panel-supply-chain"))
        dropped = baseline - branch
        added = branch - baseline
        assert not dropped, (
            f"`data-cat` values DROPPED: {sorted(dropped)}. "
            "Each value gates a class of supply-chain items in the JS category filter — "
            "a silent drop loses that whole class from the operator view."
        )
        assert not added, f"`data-cat` values ADDED: {sorted(added)}"


# ---------------------------------------------------------------------------
# TestSupplyChainNoNewControls (Pin 3 — REAL REPAINT-ONLY guard, p6.10.a1 cf #1)
# ---------------------------------------------------------------------------


class TestSupplyChainNoNewControls:
    """Pin 3 (NEW per p6.10.a1 verdict carry-forward 1): the REAL
    no-new-controls structural guard. Asserts:

      (a) Zero elements with `v-chip` in their class list inside
          `#panel-supply-chain`. The Phase 9 risk-status chips are
          `<button class="v-chip">`; this pin fires if any leak in.
      (b) The total `<button>` count inside the panel equals the 5
          `data-cat` toggle buttons. Any new button (whether
          v-chip-styled or not) trips this assertion.

    These are the actual structural properties REPAINT-ONLY needs,
    not the id-set proxy Pin 1 provides. p6.10.a1 verdict refused
    to ratify the id-set claim as sufficient; this is the
    correction."""

    def test_no_v_chip_elements_in_panel(self):
        """The Phase 9 risk-status chips would land as
        `<button class="v-chip …">` per the mockup. Zero allowed."""
        panel = _grep_panel_block(_read_branch_html(), "panel-supply-chain")
        chips = _grep_panel_v_chips(panel)
        assert chips == [], (
            f"`v-chip` elements found inside #panel-supply-chain — REPAINT-ONLY scope "
            f"forbids the Phase 9 mockup chips: {chips}"
        )

    def test_button_count_equals_immutable_baseline(self):
        """Total <button> count in the panel must equal the IMMUTABLE
        baseline count (5 data-cat toggle buttons captured at 767ee61).

        IMPORTANT: this assertion pins against the FIXTURE count, NOT
        the live data-cat count. An earlier version derived both sides
        from the live branch HTML — a `<button data-cat="risk-status">`
        Phase 9 chip would have incremented both sides equally and
        silently passed. p6.10 code-review + architect-review caught
        this. The fix locks the expected count to the baseline at
        PR-creation time; ANY new <button> (with or without data-cat)
        now trips the pin.

        Blind spot disclosed (architect-review): this counts <button>
        tags only. A Phase 9 chip rendered as <span class="v-chip"> or
        <a class="v-chip"> is caught by `test_no_v_chip_elements_in_panel`
        above, NOT by this pin. The two pins together cover both
        topologies: tag-agnostic v-chip detection AND tag-specific
        button-count discipline."""
        panel = _grep_panel_block(_read_branch_html(), "panel-supply-chain")
        buttons = _grep_panel_buttons(panel)
        expected = len(_read_fixture_lines("baseline-767ee61-buttons.txt"))
        assert len(buttons) == expected, (
            f"<button> count = {len(buttons)} but immutable baseline = {expected}. "
            f"REPAINT-ONLY allows ONLY the 5 data-cat toggle buttons captured at "
            f"the 767ee61 baseline; any new <button> (whether v-chip-styled or not, "
            f"whether carrying a new data-cat or not) is out of scope. "
            f"Buttons found: {buttons}"
        )


# ---------------------------------------------------------------------------
# TestSystemSectionCrossTabSanity (Pin 4 — p6.9 D-cross-tab-sanity-pin lineage)
# ---------------------------------------------------------------------------


class TestSystemSectionCrossTabSanity:
    """Pin 4: `.system-section` and `.system-section h3` rules exist
    FILE-GLOBAL. CSS is global — the rules are defined once and
    consumed by `#panel-supply-chain`, `#panel-system`, and any
    other panel using the wrapper. The pin asserts existence
    whole-file so a System-tab-side drop also fires the pin here
    — that's what makes it a real cross-tab sanity guard
    (p6.10.a1 verdict carry-forward 3).

    Inherits the dual-fire contract from p6.9's
    D-cross-tab-sanity-pin."""

    def test_system_section_selectors_preserved(self):
        baseline = _read_fixture_lines("baseline-767ee61-css-selectors.txt")
        branch = _grep_system_section_selectors(_read_branch_html())
        dropped = baseline - branch
        assert not dropped, (
            f"`.system-section*` selectors DROPPED (consumed by Supply Chain AND System): "
            f"{sorted(dropped)}. "
            "If a System-tab-side preservation pin exists, it should ALSO be firing — "
            "if not, that pin's coverage has rotted."
        )
        # NOTE: asymmetric on purpose — `.system-section` is shared
        # infrastructure. Future System-tab work is free to ADD related
        # rules; this consumer-side sanity pin only guards against DROPS.
        # Matches the lineage from p6.9's TestSharedFeedSelectorsSanity.
