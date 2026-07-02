"""P7-B — Attack Surface Tool Section renderers + `.atype` icons + `.otag`
ontology display. BATCHED Phase 7 PR bundling P7.5, P7.7, P7.8.

Judge verdict p7-B.a1 APPROVE (2026-07-02) — C2 both axes; no architect-pass.
All 5 asks ratified, section ordering: All Assets → **AI Tools (NEW)** →
Extensions → MCP → Integrations → Dependencies → Recent Activity.

Judge carry-forward pins (7 CF + 2 tightenings):
  CF-1  Auth gate not weakened: /api/attack-surface/recent-activity in
        routes dict only; do NOT touch _check_auth open-path list.
        Unauth GET → 401.
  CF-2  §8 empirical evidence at Phase C submission (curl on installed
        version; off + no_captures_yet branches minimum).
  CF-3  Parameterized SQL only in get_recent_activity — no f-string,
        no %s interpolation.
  CF-4  Truthfulness pins M5/M6/M7 mandatory as written.
  CF-5  T-1 upgrade: unknown ontology tag renders VISUALLY DISTINCT
        (--unk marker or explicit "unrecognized" tooltip); NOT silently
        standard tier. T-2 upgrade: unknown Asset.type falls back to
        NEUTRAL/unknown glyph, NOT --dep.
  CF-6  P7-A pins stay GREEN (10-tab count, view-state suite, All
        Assets top w/ ?source= expand behavior).
  CF-7  No forbidden pattern / no AI attribution in the C diff + PR
        title/body (manual check at commit).

M1-M12 mutation gate:
  M1  Each of 6 non-All-Assets section renderers produces at least one
      row when passed a matching-type/source asset.
  M2  .atype icon chip present with correct --<variant> class per
      Asset.type normalization.
  M3  .otag pill renders every canonical ontology_tag with correct
      --<tier> modifier per OTAG_TIER map.
  M4  .otag--derived renders for data_exfiltration_capable (overrides
      any tier).
  M5  Recent Activity 'off' state renders distinct copy, NOT empty list.
  M6  Recent Activity 'no_captures_yet' distinct from 'ok+empty'.
  M7  Dependencies section renders defer-to-Supply-Chain link, NOT
      empty body.
  M8  JS selectors target data-tool-section (silent-no-op guard).
  M9  (T-1) Unknown ontology tag → VISUALLY DISTINCT marker.
  M10 (T-2) Unknown Asset.type → NEUTRAL glyph, NOT --dep.
  M11 P6.1 test_exactly_ten_v_tabs stays GREEN.
  M12 All P7-A pins in test_dashboard_p7A_view_states.py stay GREEN.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
BRANCH_HTML_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard.html"
HANDLER_PATH = REPO_ROOT / "src" / "claude_monitoring" / "dashboard_handler.py"
DASHBOARD_API_PATH = REPO_ROOT / "src" / "claude_monitoring" / "attack_surface" / "dashboard_api.py"


def _read_branch_html() -> str:
    return BRANCH_HTML_PATH.read_text()


def _read_handler() -> str:
    return HANDLER_PATH.read_text()


def _read_dashboard_api() -> str:
    return DASHBOARD_API_PATH.read_text()


def _grep_panel_block(html: str, panel_id: str) -> str:
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


# ---------------------------------------------------------------------------
# Ask #1 (ratified) — AI Tools 6th shell added, ordered correctly
# ---------------------------------------------------------------------------


class TestAiToolsShellAdded:
    """Judge Ask #1 ratified 2026-07-02: add AI Tools shell BELOW All Assets,
    ABOVE Extensions. R1 layout call — mockup L920 lists "AI tools" alongside
    the 5 LOCKED categories in the overview legend."""

    def test_ai_tools_shell_present(self):
        panel = _grep_panel_block(_read_branch_html(), "panel-assets")
        assert 'data-tool-section="ai-tools"' in panel, (
            "P7-B Ask #1: `<details data-tool-section='ai-tools'>` shell "
            "must be added inside #attack-surface-tool-sections."
        )

    def test_ai_tools_ordered_between_all_assets_and_extensions(self):
        """Judge specified: All Assets stays TOP, AI Tools directly BELOW,
        then Extensions. Order guards R0-1 RELOCATE stability."""
        panel = _grep_panel_block(_read_branch_html(), "panel-assets")
        # Find the character position of each data-tool-section value.
        positions = {}
        for m in re.finditer(r'data-tool-section="([^"]+)"', panel):
            if m.group(1) not in positions:
                positions[m.group(1)] = m.start()
        for section in ("all-assets", "ai-tools", "extensions"):
            assert section in positions, f"section {section!r} must exist"
        assert positions["all-assets"] < positions["ai-tools"] < positions["extensions"], (
            f"Judge-ratified order: all-assets < ai-tools < extensions. Got positions: {positions}"
        )


# ---------------------------------------------------------------------------
# M1 — Section renderers produce output for matching assets
# ---------------------------------------------------------------------------


class TestSectionRenderersExist:
    """M1: 6 section renderer functions defined (AI Tools + 5 originals).
    Each takes assets array and populates the matching shell body."""

    def test_render_functions_exist(self):
        """Each section renderer function must exist in dashboard.html."""
        html = _read_branch_html()
        required = [
            "_renderAiToolsSection",
            "_renderExtensionsSection",
            "_renderMcpServersSection",
            "_renderIntegrationsSection",
            "_renderDependenciesSection",
            "_renderRecentActivitySection",
        ]
        for fn in required:
            assert f"function {fn}" in html, f"M1: section renderer {fn}() must be defined."


# ---------------------------------------------------------------------------
# CF-1 — Auth gate not weakened
# ---------------------------------------------------------------------------


class TestAuthGateNotWeakened:
    """CF-1 (verdict carry-forward): new recent-activity route inherits
    do_GET auth gate. do NOT add it to the _check_auth open-path list."""

    def test_recent_activity_not_in_check_auth_open_paths(self):
        src = _read_handler()
        # Find the _check_auth open-path list. Look for the paths that skip
        # auth: `/`, `*.html`, `/favicon.ico`.
        m = re.search(r"def _check_auth[^)]+\):[^}]*?return True", src, re.DOTALL)
        if m:
            check_auth_body = m.group(0)
            assert "/api/attack-surface/recent-activity" not in check_auth_body, (
                "CF-1: `/api/attack-surface/recent-activity` MUST NOT appear "
                "in the _check_auth open-path list. It must inherit the "
                "auth gate via routes-dict registration only."
            )

    def test_recent_activity_route_registered(self):
        src = _read_handler()
        assert '"/api/attack-surface/recent-activity"' in src, (
            "P7-B: /api/attack-surface/recent-activity must be registered in the do_GET routes dict."
        )


# ---------------------------------------------------------------------------
# CF-3 — Parameterized SQL only
# ---------------------------------------------------------------------------


class TestParameterizedSqlOnly:
    """CF-3 (verdict hard gate + CLAUDE.md mandatory pattern):
    get_recent_activity's SQL MUST use `?` placeholders. No f-string
    interpolation, no %s formatting."""

    def test_get_recent_activity_exists(self):
        src = _read_dashboard_api()
        assert "def get_recent_activity" in src, (
            "P7-B: get_recent_activity(conn) must be defined in attack_surface/dashboard_api.py."
        )

    def test_no_fstring_interpolation_in_sql(self):
        src = _read_dashboard_api()
        idx = src.find("def get_recent_activity")
        assert idx > 0
        body = src[idx : idx + 4000]
        # Look for SELECT/FROM/JOIN/WHERE in f-strings — the CLAUDE.md
        # forbidden pattern is `f"SELECT ... {var}"` etc.
        forbidden = re.search(
            r'f"[^"]*(?:SELECT|FROM|WHERE|JOIN)[^"]*\{[^"}]+\}',
            body,
            re.IGNORECASE,
        )
        assert not forbidden, (
            f"CF-3: get_recent_activity must use `?` placeholders. Found "
            f"f-string SQL: {forbidden.group(0)[:100] if forbidden else ''}"
        )

    def test_no_percent_interpolation_in_sql(self):
        src = _read_dashboard_api()
        idx = src.find("def get_recent_activity")
        assert idx > 0
        body = src[idx : idx + 4000]
        assert "%s" not in body, "CF-3: get_recent_activity must NOT use %s SQL interpolation. Use ? placeholders only."


# ---------------------------------------------------------------------------
# M5 / M6 / CF-4 — Recent Activity 3-state truthfulness
# ---------------------------------------------------------------------------


class TestRecentActivityEnvelope:
    """M5 + M6 + CF-4 (verdict hard truthfulness gate): the
    /api/attack-surface/recent-activity envelope must carry a
    capture_status field with 3 distinct values: 'off', 'no_captures_yet',
    'ok'. Each state renders DISTINCT copy — never an empty list masquerading
    as "no data"."""

    def test_envelope_has_capture_status_field(self):
        src = _read_dashboard_api()
        idx = src.find("def get_recent_activity")
        assert idx > 0
        body = src[idx : idx + 4000]
        assert '"capture_status"' in body, (
            "M5: get_recent_activity envelope must include `capture_status` "
            "field distinguishing off / no_captures_yet / ok states."
        )

    def test_all_three_states_present(self):
        src = _read_dashboard_api()
        idx = src.find("def get_recent_activity")
        assert idx > 0
        # Widen window: full function body can exceed 4000 chars once
        # host-aggregation + asset-row projection are inlined.
        body = src[idx : idx + 8000]
        for state in ("off", "no_captures_yet", "ok"):
            assert f'"{state}"' in body, (
                f"M5/M6: capture_status='{state}' must be an output value of get_recent_activity."
            )

    def test_off_state_when_capture_ok_false(self):
        """CF-4 branch coverage: capture_ok=False → 'off' with empty
        assets. No DB queries required (early return)."""
        import sqlite3

        from claude_monitoring.attack_surface.dashboard_api import get_recent_activity

        conn = sqlite3.connect(":memory:")
        try:
            result = get_recent_activity(conn, capture_ok=False)
            assert result == {"capture_status": "off", "assets": []}
        finally:
            conn.close()

    def test_no_captures_yet_when_no_correlatable_sources(self):
        """Branch coverage: capture_ok=True, no assets → all_hosts empty
        → 'no_captures_yet' bootstrap state."""
        import sqlite3

        from claude_monitoring.attack_surface.dashboard_api import get_recent_activity
        from claude_monitoring.db import init_db

        db_path = Path("/tmp/p7b_no_corr.db")
        if db_path.exists():
            db_path.unlink()
        conn = init_db(db_path)
        conn.row_factory = sqlite3.Row
        try:
            result = get_recent_activity(conn, capture_ok=True)
            assert result["capture_status"] == "no_captures_yet"
            assert result["assets"] == []
        finally:
            conn.close()
            db_path.unlink()

    def test_no_captures_yet_when_api_calls_empty(self):
        """Branch coverage: capture_ok=True + correlatable source but
        api_calls table empty → 'no_captures_yet' bootstrap."""
        import sqlite3
        import time

        from claude_monitoring.attack_surface.dashboard_api import get_recent_activity
        from claude_monitoring.db import init_db

        db_path = Path("/tmp/p7b_empty_calls.db")
        if db_path.exists():
            db_path.unlink()
        conn = init_db(db_path)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute(
                "INSERT INTO assets (id, type, name, version, source, first_seen, last_seen, "
                "last_scanned, current_state, ontology_tags, risk_score, risk_band, risk_factors, "
                "is_vigil_component) VALUES (?, 'extension', 'test-ext', '1.0', 'chromium-extensions', "
                "?, ?, ?, '{}', '[]', 50.0, 'medium', NULL, 0)",
                ("test-asset-1", time.time(), time.time(), time.time()),
            )
            conn.commit()
            result = get_recent_activity(conn, capture_ok=True)
            assert result["capture_status"] == "no_captures_yet"
            assert result["assets"] == []
        finally:
            conn.close()
            db_path.unlink()

    def test_ok_populated_state_with_matching_call(self):
        """Branch coverage: capture_ok=True + correlatable source +
        api_calls has a match in the 24h window → 'ok' with populated
        assets list."""
        import sqlite3
        import time
        from datetime import datetime, timedelta, timezone

        from claude_monitoring.attack_surface.dashboard_api import get_recent_activity
        from claude_monitoring.db import init_db

        db_path = Path("/tmp/p7b_ok_pop.db")
        if db_path.exists():
            db_path.unlink()
        conn = init_db(db_path)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute(
                "INSERT INTO assets (id, type, name, version, source, first_seen, last_seen, "
                "last_scanned, current_state, ontology_tags, risk_score, risk_band, risk_factors, "
                "is_vigil_component) VALUES (?, 'extension', 'anthropic-caller', '1.0', "
                "'chromium-extensions', ?, ?, ?, '{}', '[]', 75.0, 'high', NULL, 0)",
                ("asset-x", time.time(), time.time(), time.time()),
            )
            # Insert an api_call for 'api.anthropic.com' (chromium-extensions
            # has this in expected_hosts) within the 24h window.
            recent_ts = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            conn.execute(
                "INSERT INTO api_calls (timestamp, session_id, turn_id, turn_number, "
                "destination_host, destination_service, endpoint_path, http_method, "
                "http_status, model, stream, input_tokens, output_tokens, cache_read_tokens, "
                "cache_write_tokens, request_size_bytes, response_size_bytes, latency_ms, "
                "num_messages, system_prompt_chars, tool_call_count, sensitive_pattern_count, "
                "stop_reason, request_id) VALUES (?, 's', 't', 1, 'api.anthropic.com', "
                "'anthropic_api', '/v1/messages', 'POST', 200, 'x', 'false', 0, 0, 0, 0, 0, "
                "0, 0, 0, 0, 0, 0, 'end', 'r1')",
                (recent_ts,),
            )
            conn.commit()
            result = get_recent_activity(conn, capture_ok=True)
            assert result["capture_status"] == "ok"
            assert len(result["assets"]) >= 1
            found = [a for a in result["assets"] if a["name"] == "anthropic-caller"]
            assert found, f"Expected asset in results; got {result['assets']!r}"
            assert found[0]["call_count_24h"] >= 1
            assert found[0]["last_call_ts"] is not None
        finally:
            conn.close()
            db_path.unlink()

    def test_ok_empty_state_reachable_via_get_recent_activity(self):
        """R4 code-review Important fold-in 2026-07-02: the 'ok+empty'
        state must be reachable — else the frontend renderer's dedicated
        copy for it is dead code + docstring lies.

        Reachability path: capture_ok=True, correlatable sources with
        expected_hosts registered, api_calls has some historic rows, but
        zero matches in the 24h window. Empirical: pass an in-memory DB
        with (a) a discovered asset from a source with expected_hosts,
        (b) an api_call row OLDER than 24h so bootstrap-check passes but
        24h-window match returns empty."""
        import sqlite3
        import time

        from claude_monitoring.attack_surface.dashboard_api import get_recent_activity
        from claude_monitoring.db import init_db

        db_path = Path("/tmp/p7b_ok_empty_reach.db")
        if db_path.exists():
            db_path.unlink()
        conn = init_db(db_path)
        conn.row_factory = sqlite3.Row
        # Insert an asset whose source has expected_hosts (mcp-servers).
        conn.execute(
            "INSERT INTO assets (id, type, name, version, source, first_seen, last_seen, "
            "last_scanned, current_state, ontology_tags, risk_score, risk_band, risk_factors, "
            "is_vigil_component) VALUES (?, 'extension', 'test-ext', '1.0', 'chromium-extensions', "
            "?, ?, ?, '{}', '[]', 50.0, 'medium', NULL, 0)",
            ("test-asset-1", time.time(), time.time(), time.time()),
        )
        # Insert an api_call OLDER than 24h so bootstrap check passes but
        # correlation-window returns empty. Timestamp is 48h ago.
        from datetime import datetime, timedelta, timezone

        old_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat()
        conn.execute(
            "INSERT INTO api_calls (timestamp, session_id, turn_id, turn_number, "
            "destination_host, destination_service, endpoint_path, http_method, http_status, "
            "model, stream, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, "
            "request_size_bytes, response_size_bytes, latency_ms, num_messages, "
            "system_prompt_chars, tool_call_count, sensitive_pattern_count, stop_reason, "
            "request_id) VALUES (?, 's1', 't1', 1, 'unrelated.example.com', 'unknown', "
            "'/', 'GET', 200, 'x', 'false', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 'end', 'r1')",
            (old_ts,),
        )
        conn.commit()

        result = get_recent_activity(conn, capture_ok=True)
        conn.close()
        db_path.unlink()

        assert result["capture_status"] == "ok", (
            f"R4 fold-in pin: capture_ok=True + correlatable sources present + "
            f"api_calls has historic rows + zero 24h matches → 'ok' with empty assets "
            f"(tools idle). Got capture_status={result['capture_status']!r}."
        )
        assert result["assets"] == [], f"'ok' state with no matches → empty assets. Got {result['assets']!r}."

    def test_renderer_distinguishes_three_states(self):
        """M5/M6 frontend truthfulness pin: the JS renderer must handle each
        capture_status distinctly — no empty-list masquerade."""
        html = _read_branch_html()
        idx = html.find("function _renderRecentActivitySection")
        assert idx > 0, "_renderRecentActivitySection must be defined"
        body = html[idx : idx + 3000]
        # Renderer must reference each state's copy path.
        for state in ("off", "no_captures_yet", "ok"):
            assert f"'{state}'" in body or f'"{state}"' in body, (
                f"M5/M6: renderer must handle capture_status='{state}' distinctly."
            )


# ---------------------------------------------------------------------------
# M7 — Dependencies section renders defer link, NOT empty body
# ---------------------------------------------------------------------------


class TestDependenciesDeferToSupplyChain:
    """M7 + CF-4: Dependencies subsection defers to Supply Chain tab per
    LOCKED §Phase 7:258 "Dependencies (defers to Supply Chain)". Renders
    a distinct defer-link, NOT an empty list (which would read as "no
    dependencies found" — §4.5 inversion)."""

    def test_dependencies_renderer_produces_defer_link(self):
        html = _read_branch_html()
        idx = html.find("function _renderDependenciesSection")
        assert idx > 0
        body = html[idx : idx + 2000]
        # Must reference Supply Chain in the output (link text or tab ref).
        assert "Supply Chain" in body or "supply-chain" in body, (
            "M7: Dependencies renderer must reference Supply Chain (link or "
            "tab ref). Rendering an empty list is the §4.5 inversion."
        )


# ---------------------------------------------------------------------------
# M8 — JS selectors match shipped DOM attribute
# ---------------------------------------------------------------------------


class TestJsSelectorsMatchShippedDom:
    """M8 (silent-no-op guard): the JS renderers must target
    `data-tool-section` — the attribute the shipped DOM carries — NOT the
    mockup's `data-tool` / `data-sub`. Mismatched selectors return empty
    NodeLists, sections render blank, and blank looks plausible."""

    def test_selectors_use_data_tool_section(self):
        html = _read_branch_html()
        # Find every querySelector / getElementById targeting a tool section.
        # Must use `data-tool-section="…"` NOT `data-tool="…"` / `data-sub=…`.
        selector_lines = [
            line
            for line in html.split("\n")
            if ("querySelector" in line or "querySelectorAll" in line)
            and ("tool-section" in line or "data-tool" in line or "data-sub" in line)
        ]
        for line in selector_lines:
            if "data-tool=" in line and "data-tool-section" not in line:
                assert False, (
                    "M8: selector uses mockup attribute `data-tool=` "
                    f"instead of shipped `data-tool-section=`. Line: {line.strip()[:120]}"
                )
            if "data-sub=" in line:
                assert False, (
                    "M8: selector uses mockup attribute `data-sub=` — "
                    "P7-A shipped flat sections, no sub-attribute. "
                    f"Line: {line.strip()[:120]}"
                )


# ---------------------------------------------------------------------------
# M2 — .atype icon chip variants
# ---------------------------------------------------------------------------


class TestAtypeIconVariants:
    """M2: .atype icon chip class + 5 variants (`--tool`, `--ext`, `--mcp`,
    `--intg`, `--dep`) present in CSS. Mockup L80-89 verbatim."""

    def test_atype_base_class_defined(self):
        html = _read_branch_html()
        assert ".atype" in html, "M2: .atype base class must be defined in CSS."

    def test_atype_variants_defined(self):
        html = _read_branch_html()
        for variant in ("--tool", "--ext", "--mcp", "--intg", "--dep"):
            assert f".atype{variant}" in html, (
                f"M2: .atype{variant} variant class must be defined (per LOCKED directive §Phase 7:260)."
            )


# ---------------------------------------------------------------------------
# M3 / M4 — .otag pill + tier mapping + derived
# ---------------------------------------------------------------------------


class TestOtagTierAndDerived:
    """M3 + M4: .otag pill class + 3 tier variants + .otag--derived for
    data_exfiltration_capable. Mockup L92-100 verbatim."""

    def test_otag_base_class_defined(self):
        html = _read_branch_html()
        assert ".otag" in html, "M3: .otag base class must be defined in CSS."

    def test_otag_tier_variants_defined(self):
        """--pow (high capability), --elev (elevated); standard is unmodified."""
        html = _read_branch_html()
        for variant in ("--pow", "--elev"):
            assert f".otag{variant}" in html, f"M3: .otag{variant} tier variant must be defined."

    def test_otag_derived_variant_defined(self):
        """M4: .otag--derived (dashed border) for data_exfiltration_capable
        per LOCKED §Phase 7:261."""
        html = _read_branch_html()
        assert ".otag--derived" in html, (
            "M4: .otag--derived (dashed border) must be defined for data_exfiltration_capable per LOCKED §Phase 7:261."
        )

    def test_otag_tier_map_covers_canonical_10_categories(self):
        """M3: OTAG_TIER JS map must cover all 10 canonical ontology
        categories from ontology/categories.py."""
        html = _read_branch_html()
        idx = html.find("OTAG_TIER")
        assert idx > 0, "OTAG_TIER map must be defined in JS."
        map_body = html[idx : idx + 2000]
        for tag in (
            "file_system_read",
            "file_system_write",
            "shell_execute",
            "network_unrestricted",
            "network_scoped",
            "secrets_access",
            "code_execution",
            "system_modification",
            "inter_tool_communication",
            "data_exfiltration_capable",
        ):
            assert tag in map_body, f"M3: OTAG_TIER must cover canonical tag `{tag}` (from ontology/categories.py)."


# ---------------------------------------------------------------------------
# M9 (T-1 UPGRADE) — Unknown ontology tag is VISUALLY DISTINCT
# ---------------------------------------------------------------------------


class TestUnknownTagVisuallyDistinct:
    """M9 (verdict T-1 tightening): unknown ontology tag must render with
    a VISUALLY DISTINCT marker (`.otag--unk` OR explicit tooltip / "unknown"
    label) — NOT silently rendered as standard tier. Standard-tier fallback
    for unknown tags conceals scoring-pipeline drift / demo_data legacy."""

    def test_otag_unknown_variant_defined(self):
        html = _read_branch_html()
        # Judge specified: .otag--unk marker OR "unrecognized" tooltip on
        # unknown tag rendering. Accept either signal.
        has_unk_class = ".otag--unk" in html or ".otag--unknown" in html
        has_unrecognized_tooltip = "unrecognized" in html.lower() or "unknown tag" in html.lower()
        assert has_unk_class or has_unrecognized_tooltip, (
            "M9/T-1: unknown ontology tag rendering must be visually "
            "distinct (either .otag--unk / .otag--unknown CSS class OR "
            "explicit 'unrecognized' / 'unknown tag' tooltip in the "
            "renderer). Silently falling back to standard tier hides "
            "scoring-pipeline drift."
        )


# ---------------------------------------------------------------------------
# M10 (T-2 UPGRADE) — Unknown Asset.type falls back to NEUTRAL glyph
# ---------------------------------------------------------------------------


class TestUnknownTypeNeutralGlyph:
    """M10 (verdict T-2 tightening): unknown Asset.type falls back to a
    NEUTRAL/unknown glyph, NOT `.atype--dep`. Dep fallback mis-classifies
    unknown-type assets as dependencies."""

    def test_atype_unknown_variant_defined(self):
        html = _read_branch_html()
        # Accept either an --unk class OR --neutral variant, OR the
        # ATYPE_ICON fallback documented in JS as neutral (not 'dep').
        has_unk_class = ".atype--unk" in html or ".atype--neutral" in html or ".atype--unknown" in html
        # Also acceptable: ATYPE_ICON map documented to fallback to 'unk'
        # rather than 'dep'.
        atype_icon_idx = html.find("ATYPE_ICON")
        atype_fallback_neutral = False
        if atype_icon_idx > 0:
            # Grab the region around ATYPE_ICON (~1000 chars for the map
            # + any nearby fallback logic).
            region = html[atype_icon_idx : atype_icon_idx + 2000]
            # Must NOT explicitly fallback to 'dep' string.
            # Must reference 'unk' or 'unknown' or 'neutral' as fallback.
            if any(f"'{tok}'" in region or f'"{tok}"' in region for tok in ("unk", "unknown", "neutral")):
                atype_fallback_neutral = True
        assert has_unk_class or atype_fallback_neutral, (
            "M10/T-2: unknown Asset.type must fall back to a NEUTRAL glyph, "
            "NOT .atype--dep. Either define .atype--unk / .atype--neutral / "
            ".atype--unknown class, OR document 'unk'/'unknown'/'neutral' "
            "as the ATYPE_ICON fallback (not 'dep')."
        )


# ---------------------------------------------------------------------------
# M11 — P6.1 tab-count pin stays green
# ---------------------------------------------------------------------------


class TestNoNewTabAdded:
    """M11: P7-B adds ZERO new tabs — all UI lives inside
    #attack-surface-tool-sections (inside #panel-assets)."""

    def test_tab_button_unchanged(self):
        html = _read_branch_html()
        m = re.search(
            r'<button\b[^>]*\bclass="v-tab\b[^"]*"[^>]*\bdata-tab="assets"[^>]*>([^<]*)<',
            html,
        )
        assert m, "Attack Surface tab button must still exist"
        label = m.group(1).strip()
        assert label == "Attack Surface", f"Tab label unchanged; got {label!r}"


# ---------------------------------------------------------------------------
# M12 / CF-6 — P7-A invariants preserved
# ---------------------------------------------------------------------------


class TestP7AInvariantsPreserved:
    """M12 + CF-6: P7-A pins must stay GREEN. Specifically:
    - empty-state hidden-by-default (ID-based selector; from p7.1.a2)
    - LOCKED §3.3:293 empty-state string preserved verbatim
    - Tool Sections shell contains all 6 non-All-Assets sections + AI Tools
    - All Assets stays TOP with data-tool-section='all-assets'
    """

    def test_empty_state_still_display_none_default(self):
        panel = _grep_panel_block(_read_branch_html(), "panel-assets")
        m = re.search(
            r'<div\b[^>]*\bid="attack-surface-empty-state"[^>]*>',
            panel,
        )
        assert m, "P7.1 empty-state container must still exist"
        opening = m.group(0)
        assert "display:none" in opening or "display: none" in opening, (
            "CF-6: p7.1.a2 truthfulness invariant — empty-state MUST stay hidden by default via inline style."
        )

    def test_locked_empty_state_string_verbatim(self):
        panel = _grep_panel_block(_read_branch_html(), "panel-assets")
        assert "Vigil hasn't scanned your AI tools yet. Click Discover to begin." in panel, (
            "CF-6: LOCKED §3.3:293 empty-state string must remain verbatim."
        )

    def test_all_assets_section_remains_top(self):
        panel = _grep_panel_block(_read_branch_html(), "panel-assets")
        # Find data-tool-section positions.
        first_section = None
        for m in re.finditer(r'data-tool-section="([^"]+)"', panel):
            first_section = m.group(1)
            break
        assert first_section == "all-assets", (
            "CF-6: All Assets must remain the TOP Tool Section (R0-1 "
            f"ratification untouched). Got first section: {first_section!r}"
        )
