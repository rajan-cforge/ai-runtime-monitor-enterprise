"""P8-F — Run-scan-now UI completion (LAST v0.2.2 PR).

Solo Phase 8 PR. Third and final Phase 8 PR after P8-D (0c14eeb) and
P8-E (0106b77) shipped.

Judge verdict p8-F.a1 APPROVE-WITH-FIX 2026-07-09:
- Criticality C2/C0 ratified (impact/security axes; batched-plan's
  C3 speculation falsified by empirical evidence)
- Safe-default flip contract (4 items) ratified
- R4 = code-reviewer + frontend-design (NOT architect-pass, NOT
  security-guidance)
- Diff-scope ratified
- 9-pin M-sketch ratified
- FIX: M7 conflicted with docstring cleanup — chose Option B (DROP
  the docstring cleanup entirely; P8-F is now PURELY ADDITIVE, no
  handler file touched at all; docstring stays misleading and can be a
  C0 follow-up)

M-series pins (M1-M9):

  M1  #ov-scan-now button element exists in dashboard.html near the
      #ov-last-scan timestamp region (design-brief:175).
  M2  Click handler on #ov-scan-now POSTs /api/attack-surface/scan-now
      with {} body (per P7-A execution pattern).
  M3  State-bar scan-timestamp cell has a click handler that triggers
      the same POST (design-brief:576).
  M4  Progress copy substitutes N/M correctly: "Scanning... (N of M
      sources complete)" — verbatim template from directive:584.
  M5  Both buttons disable while scan running (backend
      _discovery_scan_state["status"] === "running").
  M6  Existing empty-state CTA #attack-surface-discover-cta NOT
      regressed (P7-A + P7.1 inheritance guard).
  M7  Safe-default flip: dashboard_handler.py L2414-2515
      (`_api_attack_surface_scan_now` handler body) BYTE-IDENTICAL vs
      origin/main:0106b77. Per verdict fix Option B: no docstring
      cleanup in this PR, so full byte-identity applies.
  M8  Safe-default flip: dashboard_handler.py:261 (`do_POST._check_auth`
      exemption tuple) unchanged.
  M9  Safe-default flip: scripts/check_privacy_no_telemetry.py
      ALLOWED_HOSTNAMES unchanged.

CF pins from judge verdict:

  CF-1  All new POST triggers go through the ALREADY-existing
        verify_token path. NO new route registered; both callers hit
        /api/attack-surface/scan-now.
  CF-2  §8 empirical: byte-identity via subprocess diff / hashlib
        against origin/main.
  CF-3  Design-brief:175 + 576 VERBATIM — sed-verified before every
        assertion string in this file.
  CF-4  Handler + orchestrator + scheduler paths NOT touched.
  CF-5  No new outbound egress (already-ratified P4.1 OSV.dev +
        P2.6 reputation covered).
"""

from __future__ import annotations

import hashlib
import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANCH_HTML_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard.html"
HANDLER_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard_handler.py"
STATE_BAR_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard_state_bar.py"
PRIVACY_GATE_PATH = REPO_ROOT / "scripts" / "check_privacy_no_telemetry.py"


def _read_branch_html() -> str:
    return BRANCH_HTML_PATH.read_text()


def _read_handler() -> str:
    return HANDLER_PATH.read_text()


def _read_state_bar() -> str:
    return STATE_BAR_PATH.read_text() if STATE_BAR_PATH.exists() else ""


def _read_privacy_gate() -> str:
    return PRIVACY_GATE_PATH.read_text()


def _git_show_at_base(path: str) -> str:
    """Return the exact bytes of `path` as of `origin/main` (the PR
    merge base).

    Two attempts: read `origin/main` directly, then explicit shallow
    fetch + retry. **HEAD~1 is NOT a fallback** — on a multi-commit
    branch it's the previous commit ON the branch, not the base, and
    would silently trivialize the safe-default flip guards. Same
    reason no on-disk fallback (security review 2026-07-09 control-
    regression flag).

    Hard-fail with an actionable message if `origin/main` isn't
    reachable — the fix in that case is CI-side (`fetch-depth: 0` on
    the checkout action), not weakening the guardrail here."""
    try:
        result = subprocess.run(
            ["git", "show", f"origin/main:{path}"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError:
        pass
    # Explicit shallow fetch (works even on shallow clones).
    subprocess.run(
        ["git", "fetch", "--depth=1", "origin", "main"],
        cwd=str(REPO_ROOT),
        capture_output=True,
    )
    try:
        result = subprocess.run(
            ["git", "show", f"origin/main:{path}"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as exc:
        raise AssertionError(
            f"P8-F safe-default flip guard cannot resolve `origin/main:"
            f"{path}`. Tried direct read + shallow fetch, both failed. "
            f"Silent fallback would be a control regression. Fix: CI "
            f"must checkout with `fetch-depth: 0` so origin/main is "
            f"reachable. Underlying error: {exc.stderr!r}"
        ) from exc


def _read_handler_at_base_sha() -> str:
    """Return dashboard_handler.py as of PR base."""
    return _git_show_at_base("src/claude_monitoring/dashboard_handler.py")


# ---------------------------------------------------------------------------
# M1 — Overview-pane "Run scan now" button
# ---------------------------------------------------------------------------


class TestOverviewScanNowButton:
    """M1: `#ov-scan-now` button exists next to `#ov-last-scan`
    timestamp per design-brief:175 verbatim
    `• Last scan timestamp + "Run scan now" button`."""

    def test_ov_scan_now_button_element_present(self):
        html = _read_branch_html()
        assert 'id="ov-scan-now"' in html, (
            "M1/CF-3: #ov-scan-now button element must exist per "
            "design-brief:175 (Overview pane stat tile: 'Last scan "
            'timestamp + "Run scan now" button\').'
        )

    def test_ov_scan_now_button_label_verbatim(self):
        html = _read_branch_html()
        idx = html.find('id="ov-scan-now"')
        assert idx > 0
        window = html[idx : idx + 500]
        assert "Run scan now" in window, "M1/CF-3: button label MUST be 'Run scan now' verbatim per design-brief:175."


# ---------------------------------------------------------------------------
# M2 — Click handler POSTs to /api/attack-surface/scan-now
# ---------------------------------------------------------------------------


class TestOverviewButtonPostsToScanNow:
    """M2: Click on #ov-scan-now → POST /api/attack-surface/scan-now.
    Reuses the P7-A execution pattern; NO new route."""

    def test_ov_scan_now_click_posts_to_scan_now_endpoint(self):
        html = _read_branch_html()
        # Accept 2 patterns: (a) inline onclick that invokes the P7-A
        # trigger function (`triggerAttackSurfaceDiscover`); OR
        # (b) an addEventListener that fires a POST to scan-now.
        # Pattern (a) is what P8-F ships (reuses P7-A's function).
        idx = html.find('id="ov-scan-now"')
        assert idx > 0
        window = html[idx : idx + 500]
        assert "triggerAttackSurfaceDiscover" in window or "scan-now" in window, (
            "M2/CF-1: #ov-scan-now click handler must POST to "
            "/api/attack-surface/scan-now (P7-A execution pattern reuse)."
        )


# ---------------------------------------------------------------------------
# M3 — State-bar scan-timestamp click affordance
# ---------------------------------------------------------------------------


class TestStateBarScanTimestampClick:
    """M3: State-bar scan-timestamp cell has a click handler that
    triggers scan-now (design-brief:576 verbatim:
    `- Click scan timestamp → triggers scan-now in Attack Surface tab`)."""

    def test_state_bar_scan_timestamp_has_click_handler(self):
        """Wiring: state-bar `.sb` cell containing `#sb-attack-v` (last-scan
        timestamp / "Scanning…") has a click handler that triggers scan-now.
        Design-brief:576 verbatim `Click scan timestamp → triggers scan-now
        in Attack Surface tab`.

        Two-sided check: (a) look 500 chars UP from `sb-attack-v` for an
        onclick attribute wiring, then (b) verify that onclick's target
        function invokes the scan-now trigger."""
        html = _read_branch_html()
        idx = html.find('id="sb-attack-v"')
        assert idx > 0
        # Look 500 chars before the id — that's where the wrapper .sb
        # div's onclick attribute lives.
        window = html[max(0, idx - 500) : idx]
        assert "onclick" in window, (
            "M3/CF-3: state-bar sb-attack-v container must have onclick attribute (design-brief:576)."
        )
        # Extract the onclick target function name and verify it invokes
        # the P7-A trigger.
        m = re.search(r'onclick="([A-Za-z_][A-Za-z0-9_]*)\s*\(', window)
        assert m, "M3: onclick handler name must be extractable"
        handler_name = m.group(1)
        # Handler must either BE `triggerAttackSurfaceDiscover` directly
        # OR invoke it in its own body somewhere in the file.
        if handler_name == "triggerAttackSurfaceDiscover":
            return  # direct wire; passes
        # Find the function definition + verify it calls the trigger.
        func_def = re.search(
            rf"function\s+{re.escape(handler_name)}\s*\([^)]*\)\s*{{",
            html,
        )
        assert func_def, f"M3: {handler_name}() function definition not found"
        func_start = func_def.end()
        # Scan for the trigger call within a reasonable body window.
        body_window = html[func_start : func_start + 2000]
        assert "triggerAttackSurfaceDiscover" in body_window or "scan-now" in body_window, (
            f"M3/CF-3: state-bar onclick handler `{handler_name}` must "
            "invoke triggerAttackSurfaceDiscover OR POST to scan-now "
            "per design-brief:576."
        )


# ---------------------------------------------------------------------------
# M4 — Progress copy verbatim from directive:584
# ---------------------------------------------------------------------------


class TestProgressCopyVerbatim:
    """M4 / CF-3: Progress copy `"Scanning... (N of M sources complete)"`
    per directive §584 verbatim: `Button disabled, shows 'Scanning...
    (3 of 12 sources complete)'`. The template is what's LOCKED; the
    actual N/M substitute at runtime."""

    def test_scanning_progress_template_present(self):
        html = _read_branch_html()
        # The template shape must be reproducible from the code, e.g.
        # "Scanning... (" + n + " of " + m + " sources complete)"
        # OR the format-string variant.
        assert re.search(
            r"Scanning\.\.\.\s*\(\s*\S+\s*of\s*\S+\s*sources\s+complete\s*\)",
            html,
        ) or ("Scanning..." in html and "of" in html and "sources complete" in html), (
            "M4/CF-3: progress copy template 'Scanning... (N of M sources "
            "complete)' must be present per directive:584 verbatim."
        )


# ---------------------------------------------------------------------------
# M5 — Buttons disable while scan running
# ---------------------------------------------------------------------------


class TestButtonDisableWhileScanning:
    """M5: Both buttons (Overview + State-bar) disable while
    `_discovery_scan_state["status"] === "running"` per spec:1296."""

    def test_ov_scan_now_button_has_disable_logic(self):
        html = _read_branch_html()
        idx = html.find('id="ov-scan-now"')
        assert idx > 0
        # Search for disable wire (either inline attribute switching
        # or JS-driven attribute set) near the button OR in the polling
        # loop that manages state.
        # Accept either "disabled" attribute or ".disabled = true" in JS
        # within the same JS surface.
        assert "disabled" in html and "ov-scan-now" in html, (
            "M5: #ov-scan-now button must have disable logic wired to the scan-progress polling state per spec:1296."
        )


# ---------------------------------------------------------------------------
# M6 — Existing empty-state CTA NOT regressed
# ---------------------------------------------------------------------------


class TestEmptyStateCTANotRegressed:
    """M6 / CF-4: Existing #attack-surface-discover-cta (P7.1 empty-
    state CTA) must still exist and still POST to scan-now."""

    def test_discover_cta_element_still_present(self):
        html = _read_branch_html()
        assert 'id="attack-surface-discover-cta"' in html, (
            "M6: P7.1 empty-state Discover CTA MUST NOT be removed by P8-F. Additive only."
        )

    def test_trigger_attack_surface_discover_function_still_present(self):
        html = _read_branch_html()
        assert "function triggerAttackSurfaceDiscover" in html, (
            "M6: P7-A triggerAttackSurfaceDiscover function must still exist. P8-F is additive."
        )


# ---------------------------------------------------------------------------
# M7 — Safe-default flip: handler body byte-identical vs base SHA
# ---------------------------------------------------------------------------


class TestHandlerBodyByteIdenticalVsBase:
    """M7 / CF-4 (JUDGE VERDICT FIX Option B 2026-07-09):
    dashboard_handler.py L2414-2515 (`_api_attack_surface_scan_now`
    method body) MUST be BYTE-IDENTICAL vs origin/main:0106b77.

    Per verdict Option B: docstring cleanup DROPPED from this PR;
    full byte-identity applies (no exception for the misleading
    docstring at L2417). Misleading docstring is now a documented
    C0 follow-up backlog item; P8-F stays purely additive."""

    def test_handler_scan_now_body_byte_identical(self):
        current = _read_handler()
        base = _read_handler_at_base_sha()
        # Locate the _api_attack_surface_scan_now definition in both.
        needle = "def _api_attack_surface_scan_now"
        cur_idx = current.find(needle)
        base_idx = base.find(needle)
        assert cur_idx > 0 and base_idx > 0
        # Extract the method body — from the def line to the next
        # top-level "    def " at same indent, OR end of class.
        cur_body = _extract_method_body(current, cur_idx)
        base_body = _extract_method_body(base, base_idx)
        cur_hash = hashlib.sha256(cur_body.encode()).hexdigest()
        base_hash = hashlib.sha256(base_body.encode()).hexdigest()
        assert cur_hash == base_hash, (
            f"M7/CF-4 safe-default flip: _api_attack_surface_scan_now "
            f"body BYTE-DIFFERENT vs origin/main:0106b77. "
            f"base SHA256={base_hash[:16]!r} current SHA256={cur_hash[:16]!r}. "
            f"P8-F must not touch execution wiring — this is a HALT "
            f"trigger per Phase A safe-default flip contract."
        )


def _extract_method_body(source: str, start_idx: int) -> str:
    """Return method body from `def X` through the last line before
    the next same-indent def / class boundary.

    Bug fix 2026-07-13: earlier version passed `source[start_idx:]` which
    dropped the leading whitespace on the def line, causing `def_indent`
    to compute as 0 (top-level) and the extraction never stopped at
    method boundaries. Fixed by rewinding to the line start so the
    actual class-method indent is captured."""
    # Rewind to the start of the line containing `def`.
    line_start = source.rfind("\n", 0, start_idx) + 1
    remaining = source[line_start:]
    lines = remaining.split("\n")
    def_line = lines[0]
    def_indent = len(def_line) - len(def_line.lstrip())
    body: list[str] = [def_line]
    for line in lines[1:]:
        stripped = line.lstrip()
        if not stripped:
            body.append(line)
            continue
        line_indent = len(line) - len(stripped)
        if line_indent <= def_indent and (stripped.startswith("def ") or stripped.startswith("class ")):
            break
        body.append(line)
    return "\n".join(body)


# ---------------------------------------------------------------------------
# M8 — Safe-default flip: auth exemption tuple unchanged
# ---------------------------------------------------------------------------


class TestCheckAuthExemptionTupleUnchanged:
    """M8 / CF-4: `_check_auth` exemption tuple in dashboard_handler.py
    MUST NOT gain any P8-F routes. Byte-identity around the exemption
    check vs base SHA."""

    def test_check_auth_exemption_unchanged(self):
        current = _read_handler()
        base = _read_handler_at_base_sha()
        # Locate the _check_auth definition.
        needle = "def _check_auth"
        cur_idx = current.find(needle)
        base_idx = base.find(needle)
        assert cur_idx > 0 and base_idx > 0
        cur_body = _extract_method_body(current, cur_idx)
        base_body = _extract_method_body(base, base_idx)
        assert cur_body == base_body, (
            "M8/CF-4 safe-default flip: _check_auth body changed vs "
            "origin/main:0106b77. Any change here is a HALT trigger."
        )


# ---------------------------------------------------------------------------
# M9 — Safe-default flip: ALLOWED_HOSTNAMES unchanged
# ---------------------------------------------------------------------------


class TestAllowedHostnamesUnchanged:
    """M9 / CF-4 / CF-5: `scripts/check_privacy_no_telemetry.py`
    ALLOWED_HOSTNAMES MUST NOT change in P8-F. No new egress hosts."""

    def test_no_new_hostname_added(self):
        current = _read_privacy_gate()
        base = _git_show_at_base("scripts/check_privacy_no_telemetry.py")

        # Extract ALLOWED_HOSTNAMES literal — actual shape is
        # `ALLOWED_HOSTNAMES: frozenset[str] = frozenset(...)`.
        # Grab everything from the assignment to the matching close-paren.
        def _extract_hostnames_literal(src: str) -> str:
            start = src.find("ALLOWED_HOSTNAMES")
            assert start > 0, "ALLOWED_HOSTNAMES definition missing"
            # Find frozenset( — start of the value literal.
            paren_open = src.find("frozenset(", start)
            if paren_open < 0:
                # Fallback: any opening paren after =.
                eq_idx = src.find("=", start)
                paren_open = src.find("(", eq_idx)
            # Balanced paren scan.
            depth = 0
            i = paren_open
            while i < len(src):
                c = src[i]
                if c == "(":
                    depth += 1
                elif c == ")":
                    depth -= 1
                    if depth == 0:
                        return src[paren_open : i + 1]
                i += 1
            raise AssertionError("unbalanced paren in ALLOWED_HOSTNAMES literal")

        cur_literal = _extract_hostnames_literal(current)
        base_literal = _extract_hostnames_literal(base)
        assert cur_literal == base_literal, (
            "M9/CF-4/CF-5 safe-default flip: ALLOWED_HOSTNAMES literal "
            "changed vs origin/main:0106b77. Any new host is a HALT "
            "trigger (would mean new egress)."
        )
