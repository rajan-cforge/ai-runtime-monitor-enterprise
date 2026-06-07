"""P2.4 — Curated rules engine: loader + per-rule isolation + max-wins composition.

Spec §6.2 (verbatim):
    final_risk = min(100, base_risk + max(rule_modifiers))

Key contracts pinned here:

1. **Loader** — `safe_yaml_load` enforces anchor/alias caps + byte cap
   (third structured-input surface; same posture as SKILL.md + MCP configs).
2. **Whole-file fail-closed** — unparseable file → empty rule list + CRITICAL log;
   base scorer's output stands (judge-decidable mechanical fail-closed).
3. **Per-rule isolation** — one malformed rule MUST NOT zero out the rest.
4. **Max-wins** — `max(rule_modifiers)`, NOT `sum(...)`. One rule wins, never stacking.
5. **Modifier range** — [-10, +30] per spec §6.2 (lower) + directive §7.4 (upper).
6. **Predicate inventory**: `has_tags` (ALL-OF), `source_in`, `unknown_capability`
   are live in Phase 2; `integration_sensitivity` / `cve_severity` /
   `package_in_malicious_list` are schema-accepted no-ops for forward compat.
7. **Additive `RiskScoreResult.applied_rules: list[dict]`** — for P7.9 popover.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.ontology.categories import OntologyCategory
from claude_monitoring.attack_surface.risk.bands import RiskBand
from claude_monitoring.attack_surface.risk.rules import (
    Rule,
    apply_curated_rules,
    load_curated_rules,
    score_asset_with_rules,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _asset(*, source: str = "mcp-servers", current_state: dict | None = None) -> Asset:
    return Asset(
        id="x",
        type="mcp_server" if source == "mcp-servers" else "ai_tool",
        parent_asset_id=None,
        name="x",
        version=None,
        install_path="/tmp/x.json",
        source=source,
        current_state=current_state or {},
        discovered_at=time.time(),
    )


def _write_yaml(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


_VALID_RULE_YAML = """\
- id: rule_test_shell_secrets
  pattern:
    has_tags: [shell_execute, secrets_access]
  modifier: 15
  explanation: |
    Test rule firing on shell-exec + secrets.
  framework_ref:
    nist_csf: PR.AC-4
"""


# ---------------------------------------------------------------------------
# Loader: spec §6.2 schema + safe_yaml_load
# ---------------------------------------------------------------------------


class TestLoaderHappyPath:
    def test_loads_single_valid_rule(self, tmp_path: Path) -> None:
        path = _write_yaml(tmp_path / "rules.yaml", _VALID_RULE_YAML)
        rules = load_curated_rules(path)
        assert len(rules) == 1
        assert rules[0].id == "rule_test_shell_secrets"
        assert rules[0].modifier == 15
        assert rules[0].pattern == {"has_tags": ["shell_execute", "secrets_access"]}
        assert "nist_csf" in rules[0].framework_ref

    def test_loads_multiple_rules(self, tmp_path: Path) -> None:
        path = _write_yaml(
            tmp_path / "rules.yaml",
            _VALID_RULE_YAML
            + """
- id: rule_two
  pattern:
    has_tags: [code_execution]
  modifier: 5
  explanation: |
    Second rule.
  framework_ref:
    mitre_attack: T1059
""",
        )
        rules = load_curated_rules(path)
        assert len(rules) == 2
        assert {r.id for r in rules} == {"rule_test_shell_secrets", "rule_two"}


class TestLoaderFailClosed:
    """Whole-file failure → empty list + CRITICAL log + base scorer stands.

    Judge-decidable mechanical fail-closed per Phase A §4.
    """

    def test_missing_file_returns_empty_list(self, tmp_path: Path) -> None:
        result = load_curated_rules(tmp_path / "nonexistent.yaml")
        assert result == []

    def test_malformed_yaml_returns_empty_and_logs_critical(self, tmp_path: Path, caplog) -> None:
        path = _write_yaml(tmp_path / "rules.yaml", "not: valid: yaml: at all:\n  - [")
        with caplog.at_level("CRITICAL", logger="ai-runtime-monitor.attack_surface.risk.rules"):
            result = load_curated_rules(path)
        assert result == []
        # CRITICAL log fired
        assert any(r.levelname == "CRITICAL" for r in caplog.records), (
            "fail-closed must log CRITICAL so operators see the rule set is missing"
        )

    def test_yaml_bomb_returns_empty_list(self, tmp_path: Path, caplog) -> None:
        """`safe_yaml_load`'s anchor/alias caps reject the bomb before parse;
        the loader translates that to fail-closed."""
        bomb = "\n".join([f"a{i}: &a{i} [*a{i - 1 if i else 0}, *a{i - 1 if i else 0}]" for i in range(20)])
        path = _write_yaml(tmp_path / "rules.yaml", bomb)
        with caplog.at_level("CRITICAL", logger="ai-runtime-monitor.attack_surface.risk.rules"):
            result = load_curated_rules(path)
        assert result == []

    def test_top_level_not_a_list_returns_empty(self, tmp_path: Path) -> None:
        """Spec example shows a list at top level; a dict is malformed."""
        path = _write_yaml(tmp_path / "rules.yaml", "rules:\n  - id: x\n")
        result = load_curated_rules(path)
        assert result == []


class TestLoaderPerRuleSkip:
    """One bad rule must not poison the others (Phase A §5 contract)."""

    def test_missing_required_field_skips_that_rule(self, tmp_path: Path, caplog) -> None:
        path = _write_yaml(
            tmp_path / "rules.yaml",
            _VALID_RULE_YAML
            + """
- id: rule_broken
  pattern:
    has_tags: [code_execution]
  modifier: 10
  # framework_ref missing — required field
  explanation: |
    Missing framework_ref.
""",
        )
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.risk.rules"):
            rules = load_curated_rules(path)
        assert len(rules) == 1
        assert rules[0].id == "rule_test_shell_secrets"

    def test_modifier_out_of_range_skips_that_rule(self, tmp_path: Path, caplog) -> None:
        """[-10, +30] per spec §6.2."""
        path = _write_yaml(
            tmp_path / "rules.yaml",
            _VALID_RULE_YAML
            + """
- id: rule_too_big
  pattern:
    has_tags: [shell_execute]
  modifier: 50
  explanation: |
    Out of range.
  framework_ref:
    nist_csf: PR.AC-4
""",
        )
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.risk.rules"):
            rules = load_curated_rules(path)
        assert {r.id for r in rules} == {"rule_test_shell_secrets"}

    def test_modifier_below_minus_ten_skips_that_rule(self, tmp_path: Path) -> None:
        path = _write_yaml(
            tmp_path / "rules.yaml",
            """\
- id: rule_too_small
  pattern:
    has_tags: [shell_execute]
  modifier: -20
  explanation: |
    Below -10.
  framework_ref:
    nist_csf: PR.AC-4
""",
        )
        rules = load_curated_rules(path)
        assert rules == []


# ---------------------------------------------------------------------------
# apply_curated_rules — per-rule isolation + predicate dispatch + max-wins
# ---------------------------------------------------------------------------


class TestPerRuleMatchIsolation:
    def test_one_bad_rule_does_not_poison_others(self) -> None:
        """A rule that raises during predicate evaluation must be skipped;
        other matching rules still fire."""
        bad_rule = Rule(
            id="bad",
            pattern={"has_tags": "this should be a list, not a string"},
            modifier=10,
            explanation="malformed",
            framework_ref={"nist_csf": "X"},
        )
        good_rule = Rule(
            id="good",
            pattern={"has_tags": ["code_execution"]},
            modifier=5,
            explanation="good",
            framework_ref={"nist_csf": "Y"},
        )
        asset = _asset(source="claude-code-skills")
        tags = frozenset({OntologyCategory.CODE_EXECUTION})
        max_mod, applied = apply_curated_rules(asset, tags, [bad_rule, good_rule])
        assert max_mod == 5
        assert len(applied) == 1
        assert applied[0]["id"] == "good"


class TestPredicateDispatch:
    def test_has_tags_all_of_semantics(self) -> None:
        """`has_tags: [A, B]` requires BOTH A and B in ontology_tags (Phase A Q3)."""
        rule = Rule(
            id="r",
            pattern={"has_tags": ["shell_execute", "secrets_access"]},
            modifier=10,
            explanation="x",
            framework_ref={"nist_csf": "X"},
        )
        asset = _asset()
        # Only one of the required tags → no match
        partial = frozenset({OntologyCategory.SHELL_EXECUTE})
        max_mod, applied = apply_curated_rules(asset, partial, [rule])
        assert max_mod == 0
        assert applied == []
        # Both required tags → match
        full = frozenset({OntologyCategory.SHELL_EXECUTE, OntologyCategory.SECRETS_ACCESS})
        max_mod, applied = apply_curated_rules(asset, full, [rule])
        assert max_mod == 10
        assert len(applied) == 1

    def test_source_in_predicate(self) -> None:
        rule = Rule(
            id="r",
            pattern={"source_in": ["mcp-servers"]},
            modifier=5,
            explanation="x",
            framework_ref={"nist_csf": "X"},
        )
        mcp_asset = _asset(source="mcp-servers")
        skill_asset = _asset(source="claude-code-skills")
        max_mod_mcp, _ = apply_curated_rules(mcp_asset, frozenset(), [rule])
        max_mod_skill, _ = apply_curated_rules(skill_asset, frozenset(), [rule])
        assert max_mod_mcp == 5
        assert max_mod_skill == 0

    def test_unknown_capability_predicate_fires_on_singleton_mcp(self) -> None:
        """The exfil-shape hook the P2.5 NEEDS-RAJAN rule will use."""
        rule = Rule(
            id="r",
            pattern={"unknown_capability": True, "has_tags": ["secrets_access"]},
            modifier=20,
            explanation="exfil shape",
            framework_ref={"nist_csf": "X"},
        )
        asset = _asset(
            source="mcp-servers",
            current_state={"command": "node", "args": ["/opt/custom/x.js"]},
        )
        # ITC + SECRETS_ACCESS is the exfil shape unknown-cap signature
        tags = frozenset({OntologyCategory.INTER_TOOL_COMMUNICATION, OntologyCategory.SECRETS_ACCESS})
        max_mod, applied = apply_curated_rules(asset, tags, [rule])
        assert max_mod == 20
        assert applied[0]["id"] == "r"

    def test_unknown_capability_predicate_does_not_fire_on_recognized_mcp(self) -> None:
        rule = Rule(
            id="r",
            pattern={"unknown_capability": True},
            modifier=20,
            explanation="x",
            framework_ref={"nist_csf": "X"},
        )
        asset = _asset(
            source="mcp-servers",
            current_state={"command": "npx", "args": ["@modelcontextprotocol/server-filesystem"]},
        )
        tags = frozenset(
            {
                OntologyCategory.INTER_TOOL_COMMUNICATION,
                OntologyCategory.FILE_SYSTEM_READ,
                OntologyCategory.FILE_SYSTEM_WRITE,
            }
        )
        max_mod, _ = apply_curated_rules(asset, tags, [rule])
        assert max_mod == 0

    @pytest.mark.parametrize(
        "predicate_key,predicate_value",
        [
            ("integration_sensitivity", ">= 70"),
            ("cve_severity", ">= 7"),
            ("package_in_malicious_list", True),
        ],
    )
    def test_forward_compat_predicates_noop_in_phase_2(self, predicate_key: str, predicate_value: object) -> None:
        """Schema-accepted predicates with no Phase-2 inputs must NO-OP
        (return False), not raise. P2.5 / Phase-3 wires them on real input."""
        rule = Rule(
            id="r",
            pattern={predicate_key: predicate_value},
            modifier=10,
            explanation="x",
            framework_ref={"nist_csf": "X"},
        )
        max_mod, applied = apply_curated_rules(_asset(), frozenset(), [rule])
        assert max_mod == 0
        assert applied == []


class TestMaxWinsSemantics:
    """Spec §6.2: `final_risk = min(100, base_risk + max(rule_modifiers))`.
    `max(...)` NOT `sum(...)`. One rule wins; never stacking."""

    def test_two_rules_match_only_higher_modifier_applies(self) -> None:
        rule_small = Rule(
            id="small",
            pattern={"has_tags": ["code_execution"]},
            modifier=5,
            explanation="x",
            framework_ref={"nist_csf": "X"},
        )
        rule_big = Rule(
            id="big",
            pattern={"has_tags": ["code_execution"]},
            modifier=20,
            explanation="x",
            framework_ref={"nist_csf": "Y"},
        )
        asset = _asset(source="claude-code-skills")
        tags = frozenset({OntologyCategory.CODE_EXECUTION})
        max_mod, applied = apply_curated_rules(asset, tags, [rule_small, rule_big])
        # max(5, 20) = 20, NOT 25
        assert max_mod == 20
        # BUT both applied rules surface in the breakdown so P7.9 can render
        # "fired but suppressed by max-wins"
        ids = {r["id"] for r in applied}
        assert ids == {"small", "big"}

    def test_no_matches_yields_zero_modifier_empty_list(self) -> None:
        rule = Rule(
            id="x",
            pattern={"has_tags": ["shell_execute"]},
            modifier=20,
            explanation="x",
            framework_ref={"nist_csf": "X"},
        )
        asset = _asset(source="claude-code-skills")
        max_mod, applied = apply_curated_rules(asset, frozenset({OntologyCategory.CODE_EXECUTION}), [rule])
        assert max_mod == 0
        assert applied == []

    def test_empty_rule_set_yields_zero_modifier(self) -> None:
        max_mod, applied = apply_curated_rules(_asset(), frozenset(), [])
        assert max_mod == 0
        assert applied == []


# ---------------------------------------------------------------------------
# Composition: score_asset_with_rules
# ---------------------------------------------------------------------------


class TestScoreAssetWithRules:
    """Composition entry point: base scorer → rules → final result.
    Implements `min(100, base_risk + max(rule_modifiers))` per spec §6.2."""

    def test_no_rules_matches_base_score_unchanged(self) -> None:
        asset = _asset(source="claude-code-skills")
        result = score_asset_with_rules(asset, ontology_tags=frozenset({OntologyCategory.CODE_EXECUTION}), rules=[])
        # 1 tag → permission_breadth = 10 * 0.3 = 3 → INFO
        assert result.final_score == 3
        assert result.band == RiskBand.INFO
        assert result.applied_rules == []

    def test_unknown_capability_floor_plus_rule_bump_exfil_shape(self) -> None:
        """The Phase A §7 exfil-shape question, mechanically demonstrated.
        Unknown-cap MCP at floor 40 + 20 modifier → 60 (HIGH).
        The RULE itself ships in P2.5 (NEEDS-RAJAN); P2.4 demonstrates the
        composition works."""
        exfil_rule = Rule(
            id="rule_exfil_capable_unrecognized",
            pattern={"unknown_capability": True, "has_tags": ["secrets_access"]},
            modifier=20,
            explanation="Unrecognized server handling secrets — exfil shape.",
            framework_ref={"nist_csf": "ID.RA-3", "mitre_attack": "T1041"},
        )
        asset = _asset(
            source="mcp-servers",
            current_state={"command": "node", "args": ["/opt/custom/server.js"]},
        )
        tags = frozenset({OntologyCategory.INTER_TOOL_COMMUNICATION, OntologyCategory.SECRETS_ACCESS})
        result = score_asset_with_rules(asset, ontology_tags=tags, rules=[exfil_rule])
        assert result.final_score == 60
        assert result.band == RiskBand.HIGH
        # The breakdown includes both the floor (P2.3 contract) AND the applied rule
        assert "unknown_capability_floor" in result.contributions
        assert any(r["id"] == "rule_exfil_capable_unrecognized" for r in result.applied_rules)

    def test_score_clamped_at_100(self) -> None:
        """min(100, ...). A rule pushing past 100 still caps."""
        big_rule = Rule(
            id="big",
            pattern={"has_tags": ["code_execution"]},
            modifier=30,
            explanation="x",
            framework_ref={"nist_csf": "X"},
        )
        # All 10 tags → breadth = 30 contribution; + 30 modifier = 60. Need a higher
        # base to test clamping. Use synthetic CVEs to push base near 100.
        asset = _asset(source="claude-code-skills")
        result = score_asset_with_rules(
            asset,
            ontology_tags=frozenset(OntologyCategory),
            rules=[big_rule],
            cves=[{"cvss": 10.0}],
        )
        assert result.final_score <= 100

    def test_orphan_derived_tag_still_raises(self) -> None:
        """P2.3's Q4 strict invariant must hold even through the rules pipeline."""
        rule = Rule(
            id="r",
            pattern={"has_tags": ["shell_execute"]},
            modifier=10,
            explanation="x",
            framework_ref={"nist_csf": "X"},
        )
        asset = _asset(source="claude-code-skills")
        bad_tags = frozenset({OntologyCategory.SHELL_EXECUTE, OntologyCategory.DATA_EXFILTRATION_CAPABLE})
        with pytest.raises(ValueError, match=r"orphan|data_exfiltration_capable"):
            score_asset_with_rules(asset, ontology_tags=bad_tags, rules=[rule])


# ---------------------------------------------------------------------------
# RiskScoreResult.applied_rules additive contract extension
# ---------------------------------------------------------------------------


class TestAppliedRulesContractField:
    def test_applied_rules_default_empty(self) -> None:
        """A base scorer call with no rules pipeline still must have the field."""
        from claude_monitoring.attack_surface.risk.scoring import compute_risk_score

        result = compute_risk_score(_asset(), ontology_tags=frozenset())
        assert hasattr(result, "applied_rules")
        assert result.applied_rules == []

    def test_applied_rule_entry_shape(self) -> None:
        rule = Rule(
            id="rule_x",
            pattern={"has_tags": ["code_execution"]},
            modifier=10,
            explanation="test",
            framework_ref={"nist_csf": "AC-4", "mitre_attack": "T1059"},
        )
        result = score_asset_with_rules(
            _asset(source="claude-code-skills"),
            ontology_tags=frozenset({OntologyCategory.CODE_EXECUTION}),
            rules=[rule],
        )
        assert len(result.applied_rules) == 1
        entry = result.applied_rules[0]
        # Required fields for P7.9 popover rendering
        assert entry["id"] == "rule_x"
        assert entry["modifier_applied"] == 10
        assert entry["explanation"] == "test"
        assert "framework_ref" in entry


# ---------------------------------------------------------------------------
# Defaults pointing at config/risk-rules.yaml
# ---------------------------------------------------------------------------


class TestDefaultConfigPath:
    def test_default_path_is_config_risk_rules_yaml(self) -> None:
        from claude_monitoring.attack_surface.risk.rules import DEFAULT_RULES_PATH

        assert str(DEFAULT_RULES_PATH).endswith("config/risk-rules.yaml")
