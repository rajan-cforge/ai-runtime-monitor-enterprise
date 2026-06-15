"""P5.3 — Demo-mode data tests (Phase B / TDD).

Phase A judge p5.3.a1 APPROVE 2026-06-15. Tests pin:
  * directive §8.6 quantitative bounds (6-8 tools, 20-30 assets,
    2 CRITICAL / 4 HIGH / 8 MEDIUM / rest LOW+INFO)
  * the three required findings per directive line 208
  * column-set shape matching ``SAFE_COLUMNS_BY_TABLE["assets"]``
    so the merged P5.2 exports render the demo set unchanged
  * deterministic ``get_demo_assets()`` (directive line 1492 — HARDCODED,
    not random)
  * end-to-end composition with merged P5.2 renderers
  * defense-in-depth: no raw ``/Users/<realname>/`` substring leaks
"""

from __future__ import annotations

import csv
import io
import json

import pytest

from claude_monitoring.attack_surface.demo_data import (
    DEMO_ASSETS,
    get_demo_assets,
    get_demo_assets_for_export,
)
from claude_monitoring.exports import render_csv, render_json, render_markdown
from claude_monitoring.privacy_audit import SAFE_COLUMNS_BY_TABLE

# ---------------------------------------------------------------------------
# Directive §8.6 quantitative structure
# ---------------------------------------------------------------------------


class TestDemoDataMeetsDirectiveStructure:
    """Pins the verbatim quantitative requirements from directive §8.6:
    6-8 tools, 20-30 total assets, 2 CRITICAL / 4 HIGH / 8 MEDIUM /
    rest LOW/INFO."""

    def test_asset_count_within_directive_bounds(self):
        rows = get_demo_assets()
        assert 20 <= len(rows) <= 30, f"directive §8.6 requires 20-30 assets, got {len(rows)}"

    def test_distinct_tool_sources_within_directive_bounds(self):
        rows = get_demo_assets()
        # Distinct user-facing AI tools: ai-tool-versions, ollama-models,
        # claude-code-skills, plus extension/dep hosts that imply a tool
        # (vscode-extensions → VS Code, chromium-extensions → Chrome,
        # claude-desktop-integrations → Claude Desktop). The directive's
        # named list is Claude Code, Cursor, Claude Desktop, ChatGPT
        # Desktop, Ollama, "plus 1-2 others" — count sources that map
        # onto an AI-tool host.
        tool_sources = {
            "ai-tool-versions",
            "ollama-models",
            "claude-code-skills",
            "vscode-extensions",
            "chromium-extensions",
            "claude-desktop-integrations",
            "homebrew-formulae",
            "mcp-servers",
        }
        used_tool_sources = {r["source"] for r in rows} & tool_sources
        assert 6 <= len(used_tool_sources) <= 8, (
            f"directive §8.6 requires 6-8 tools, demo covers {len(used_tool_sources)}: {sorted(used_tool_sources)}"
        )

    def test_band_distribution_is_2_4_8_rest(self):
        rows = get_demo_assets()
        bands: dict[str, int] = {}
        for r in rows:
            bands[r["risk_band"]] = bands.get(r["risk_band"], 0) + 1
        assert bands.get("critical", 0) == 2, f"directive §8.6: 2 CRITICAL, got {bands.get('critical', 0)}"
        assert bands.get("high", 0) == 4, f"directive §8.6: 4 HIGH, got {bands.get('high', 0)}"
        assert bands.get("medium", 0) == 8, f"directive §8.6: 8 MEDIUM, got {bands.get('medium', 0)}"
        rest = bands.get("low", 0) + bands.get("info", 0)
        assert rest == len(rows) - 14, (
            f"directive §8.6: 'rest LOW/INFO' must cover the remainder, got {rest} of {len(rows) - 14} expected"
        )


# ---------------------------------------------------------------------------
# Three required findings (directive line 208)
# ---------------------------------------------------------------------------


class TestDemoDataIncludesThreeRequiredFindings:
    """Directive line 208 names three specific findings the demo set MUST
    include. Phase A judge binding carry-forward (a): the ACTIVITY EXCEEDS
    DECLARED SCOPE finding is presented as curated `applied_rules[].label`
    content (not as a reference to a live rule ID, since the runtime-
    correlation rule has not yet merged)."""

    def _parse_factors(self, row):
        return json.loads(row["risk_factors"]) if row.get("risk_factors") else {}

    def test_exactly_one_activity_exceeds_declared_scope_finding(self):
        matches = [
            r
            for r in get_demo_assets()
            if any(
                rule.get("label") == "ACTIVITY EXCEEDS DECLARED SCOPE"
                for rule in self._parse_factors(r).get("applied_rules", [])
            )
        ]
        assert len(matches) == 1, (
            f"directive line 208: exactly one 'ACTIVITY EXCEEDS DECLARED SCOPE' finding, got {len(matches)}"
        )
        # And per directive §8.6 it's a Cursor extension specifically.
        finding = matches[0]
        assert finding["type"] == "extension"
        assert "cursor" in finding["install_path"].lower(), (
            f"directive §8.6: scope-violation must be on a Cursor extension, install_path={finding['install_path']}"
        )

    def test_exactly_one_known_malicious_typosquat_package(self):
        matches = [
            r
            for r in get_demo_assets()
            if r["source"] == "python-packages"
            and r["risk_band"] == "critical"
            and any("TYPOSQUAT" in rule.get("label", "") for rule in self._parse_factors(r).get("applied_rules", []))
        ]
        assert len(matches) == 1, (
            f"directive line 208: exactly one known-malicious typosquat package, got {len(matches)}"
        )
        # Realistic typosquat name (one-edit of a popular package).
        assert matches[0]["name"] == "requets"

    def test_exactly_one_admin_org_github_oauth_integration(self):
        matches = []
        for r in get_demo_assets():
            if r["type"] != "integration":
                continue
            state = json.loads(r.get("current_state") or "{}")
            scopes = state.get("oauth_scopes", [])
            if "admin:org" in scopes:
                matches.append(r)
        assert len(matches) == 1, (
            f"directive line 208: exactly one high-sensitivity GitHub OAuth with admin:org scope, got {len(matches)}"
        )
        assert matches[0]["risk_band"] in {"critical", "high"}


# ---------------------------------------------------------------------------
# Column-set contract — must match SAFE_COLUMNS_BY_TABLE["assets"]
# ---------------------------------------------------------------------------


class TestDemoDataShapeMatchesAssetsTable:
    """Phase A D-shape decision: every demo row carries exactly the
    `SAFE_COLUMNS_BY_TABLE["assets"]` key set. This is the contract that
    lets the merged P5.2 exports render demo data without modification."""

    def test_every_row_has_exactly_the_assets_column_set(self):
        expected = set(SAFE_COLUMNS_BY_TABLE["assets"].keys())
        for row in get_demo_assets():
            actual = set(row.keys())
            assert actual == expected, (
                f"row {row.get('name')!r} keys mismatch: missing={expected - actual}, extra={actual - expected}"
            )

    def test_risk_factors_is_v1_json_dict_shape(self):
        """Phase A judge binding carry-forward (b): risk_factors must
        shape as the v1 JSON dict that ``dashboard_api.render_asset_row``
        parses — keys schema_version, contributions, weights,
        applied_rules, applied_reputation, cves, cve_status,
        cve_unavailable_reason."""
        required_keys = {
            "schema_version",
            "contributions",
            "weights",
            "applied_rules",
            "applied_reputation",
            "cves",
            "cve_status",
            "cve_unavailable_reason",
        }
        for row in get_demo_assets():
            raw = row.get("risk_factors")
            assert raw is not None, f"row {row['name']!r} has null risk_factors"
            payload = json.loads(raw)
            assert isinstance(payload, dict)
            assert required_keys.issubset(payload.keys()), (
                f"row {row['name']!r} risk_factors missing keys: {required_keys - set(payload.keys())}"
            )
            assert payload["schema_version"] == 1


# ---------------------------------------------------------------------------
# Determinism — directive line 1492: HARDCODED, not random
# ---------------------------------------------------------------------------


class TestDemoDataIsHardcodedNotRandom:
    """Directive line 1492 (verbatim): 'Demo data is HARDCODED, not
    random. This ensures CISOs see the same examples Rajan describes in
    pitches.' Two calls must return identical content."""

    def test_two_calls_return_identical_content(self):
        first = get_demo_assets()
        second = get_demo_assets()
        assert first == second

    def test_returns_module_level_constant(self):
        assert get_demo_assets() is DEMO_ASSETS


# ---------------------------------------------------------------------------
# Composes with merged P5.2 renderers (proof P5.3 + P5.2 stack)
# ---------------------------------------------------------------------------


class TestDemoDataExportRendersThroughExistingPrimitives:
    """Phase A D-redaction-defense: piping
    ``get_demo_assets_for_export()`` into each merged P5.2 renderer
    produces a non-empty, well-formed string with the expected shape.
    This is the proof P5.3 + P5.2 compose cleanly without P8.3 UI."""

    def test_json_renderer_round_trip(self):
        rows = get_demo_assets_for_export()
        output = render_json(rows)
        envelope = json.loads(output)
        assert set(envelope.keys()) >= {"generated_at", "asset_count", "assets"}
        assert envelope["asset_count"] == len(DEMO_ASSETS)
        assert len(envelope["assets"]) == len(DEMO_ASSETS)

    def test_csv_renderer_round_trip(self):
        rows = get_demo_assets_for_export()
        output = render_csv(rows)
        reader = csv.DictReader(io.StringIO(output))
        parsed = list(reader)
        assert len(parsed) == len(DEMO_ASSETS)
        assert set(reader.fieldnames or []) == set(SAFE_COLUMNS_BY_TABLE["assets"].keys())

    def test_markdown_renderer_round_trip(self):
        rows = get_demo_assets_for_export()
        output = render_markdown(rows)
        assert output.strip(), "markdown render returned empty"
        # Sanity: contains an asset count + a table marker.
        assert "|" in output
        assert str(len(DEMO_ASSETS)) in output


# ---------------------------------------------------------------------------
# Defense-in-depth: no real-username path leaks
# ---------------------------------------------------------------------------


class TestDemoDataDoesNotLeakRealUsernames:
    """Defense-in-depth: walk every cell of every demo asset, assert no
    string contains `/Users/` followed by anything other than `<USER>`
    (the home-dir normalization placeholder shipped by P5.1b). A future
    edit that accidentally pastes a developer's actual `/Users/rajan/...`
    path through the demo set gets caught here."""

    @pytest.mark.parametrize("row_index", range(len(DEMO_ASSETS)))
    def test_no_users_path_leak_in_raw_row(self, row_index):
        row = DEMO_ASSETS[row_index]
        for col, value in row.items():
            if not isinstance(value, str):
                continue
            self._assert_no_user_leak(row.get("name"), col, value)

    @pytest.mark.parametrize("row_index", range(len(DEMO_ASSETS)))
    def test_no_users_path_leak_in_exported_row(self, row_index):
        rendered = get_demo_assets_for_export()
        row = rendered[row_index]
        for col, value in row.items():
            self._assert_no_user_leak(row.get("name"), col, value)

    @staticmethod
    def _assert_no_user_leak(name, col, value):
        marker = "/Users/"
        idx = 0
        while True:
            pos = value.find(marker, idx)
            if pos == -1:
                break
            tail = value[pos + len(marker) :]
            # Allow only the literal "<USER>" placeholder.
            assert tail.startswith("<USER>"), f"row {name!r} col {col!r} leaks a real-looking /Users/ path: {value!r}"
            idx = pos + len(marker)
