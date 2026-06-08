"""P2.5 — Curated risk rules + citations + YAML-bomb empirical repro.

Locks the shipped ``config/risk-rules.yaml`` against:

1. **Schema validity** — schema gate already accepts; here we also assert
   the loader accepts the same file (defense-in-depth).
2. **Per-rule firing semantics** — each of the 9 rules fires on its
   intended input and does NOT fire on missing-tag input
   (proves ALL-OF semantics across the tag set).
3. **Citation format** — every shipped rule has correctly-formatted
   NIST CSF subcategory IDs (``XX.YY-N``) and MITRE ATT&CK technique
   IDs (``T\\d{4}(\\.\\d{3})?``). Format-level validation; the
   semantic accuracy of the citation/threat mapping is reviewed in
   architect-pass.
4. **Forward-compat predicate hygiene** — no shipped rule uses any
   predicate outside ``LIVE_PREDICATES`` (Q-A ratification, defense-
   in-depth on top of the schema gate).
5. **YAML-bomb empirical repro on installed PyYAML** — a billion-laughs
   construction targeted at risk-rules.yaml is rejected by
   :func:`safe_yaml_load` BEFORE parse, on the actual installed
   PyYAML version. Closes the STATUS carry-forward "YAML-bomb
   empirical repro on installed PyYAML" deferred from P2.4.a1.
6. **End-to-end composition** — the exfil-unrecognized rule composes
   with the spec §6.8 unknown-capability floor (40) via the §6.9
   re-assertion to land at 60 (HIGH).

The shipped rules + weighting per work-log/2026-06-07-P2.5-ratification.md:
Q1 = +20 (exfil-unrecognized), Q2 = +20 (secrets+network), Q3 = defaults,
Path (A) tightened (ship all 9 in a1).
"""

from __future__ import annotations

import re
import time

import pytest
import yaml as pyyaml_module

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.helpers import (
    MAX_YAML_ALIASES,
    MAX_YAML_ANCHORS,
    safe_yaml_load,
)
from claude_monitoring.attack_surface.ontology.categories import OntologyCategory
from claude_monitoring.attack_surface.risk.bands import RiskBand
from claude_monitoring.attack_surface.risk.rules import (
    DEFAULT_RULES_PATH,
    FORWARD_COMPAT_PREDICATES,
    LIVE_PREDICATES,
    apply_curated_rules,
    load_curated_rules,
    score_asset_with_rules,
)

# ---------------------------------------------------------------------------
# Constants for citation format validation
# ---------------------------------------------------------------------------

# NIST CSF v1.1 subcategory: "FF.SS-N" — function (2 letters), category
# (2 letters), subcategory number. Examples: PR.AC-4, ID.RA-3, PR.DS-5.
_NIST_CSF_RE = re.compile(r"^(ID|PR|DE|RS|RC)\.[A-Z]{2}-\d+$")

# MITRE ATT&CK enterprise technique: "T####" with optional ".###" subtechnique.
# Examples: T1059, T1059.004, T1567, T1041.
_MITRE_ATTACK_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

_EXPECTED_RULE_IDS = frozenset(
    {
        "rule_shell_filesystem_combo_001",
        "rule_shell_network_combo_001",
        "rule_exfil_capable_001",
        "rule_secrets_network_001",
        "rule_shell_secrets_combo_001",
        "rule_filesystem_read_network_001",
        "rule_code_execution_network_001",
        "rule_unknown_capability_sharpener_001",
        "rule_exfil_capable_unrecognized",
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _asset(*, source: str = "claude-code-skills") -> Asset:
    """Default asset is a skill (NOT unknown-capability eligible) so the
    unknown-capability path does not silently change tag-rule outcomes."""
    return Asset(
        id="x",
        type="ai_tool" if source != "mcp-servers" else "mcp_server",
        parent_asset_id=None,
        name="x",
        version=None,
        install_path="/tmp/x",
        source=source,
        current_state={},
        discovered_at=time.time(),
    )


def _tags(*categories: OntologyCategory) -> frozenset[OntologyCategory]:
    return frozenset(categories)


@pytest.fixture(scope="module")
def shipped_rules() -> list:
    """Load the actual shipped ``config/risk-rules.yaml`` once per module."""
    rules = load_curated_rules(DEFAULT_RULES_PATH)
    assert rules, "shipped config/risk-rules.yaml MUST load at least one rule"
    return rules


# ---------------------------------------------------------------------------
# Shipped rule set — identity + schema + citation format
# ---------------------------------------------------------------------------


class TestShippedRuleSetIdentity:
    """The set of rules actually shipped matches the ratified set."""

    def test_shipped_rules_load(self, shipped_rules: list) -> None:
        assert len(shipped_rules) == 9, (
            f"P2.5 ships exactly 9 rules (8 curated + exfil-unrecognized at +20 "
            f"per Path A tightened); loaded {len(shipped_rules)}"
        )

    def test_shipped_rule_ids_match_ratified_set(self, shipped_rules: list) -> None:
        actual = {r.id for r in shipped_rules}
        assert actual == _EXPECTED_RULE_IDS, (
            f"shipped rule IDs diverged from ratified set; "
            f"missing={_EXPECTED_RULE_IDS - actual} extra={actual - _EXPECTED_RULE_IDS}"
        )

    def test_no_duplicate_ids(self, shipped_rules: list) -> None:
        ids = [r.id for r in shipped_rules]
        assert len(ids) == len(set(ids)), "rule IDs must be unique"


class TestShippedPredicateHygiene:
    """Q-A defense-in-depth: no shipped rule references a forward-compat
    predicate. Schema gate enforces this; here we lock the invariant at
    the test layer too so a gate regression cannot silently ship rules
    using unwired predicates."""

    def test_every_predicate_is_live(self, shipped_rules: list) -> None:
        offenders: list[tuple[str, str]] = []
        for rule in shipped_rules:
            for predicate_key in rule.pattern:
                if predicate_key not in LIVE_PREDICATES:
                    offenders.append((rule.id, predicate_key))
        assert not offenders, (
            f"shipped rules use non-live predicates: {offenders}; "
            f"LIVE_PREDICATES={sorted(LIVE_PREDICATES)}, "
            f"FORWARD_COMPAT_PREDICATES={sorted(FORWARD_COMPAT_PREDICATES)}"
        )


class TestShippedCitationFormat:
    """Every shipped rule has format-valid NIST CSF + MITRE ATT&CK IDs.

    Format-level validation. The accuracy of the chosen subcategory /
    technique against the rule's threat pattern is reviewed in
    architect-pass per directive §12.1."""

    def test_every_rule_has_nist_csf_citation(self, shipped_rules: list) -> None:
        missing = [r.id for r in shipped_rules if "nist_csf" not in r.framework_ref]
        assert not missing, f"rules missing nist_csf citation: {missing}"

    def test_every_rule_has_mitre_attack_citation(self, shipped_rules: list) -> None:
        missing = [r.id for r in shipped_rules if "mitre_attack" not in r.framework_ref]
        assert not missing, f"rules missing mitre_attack citation: {missing}"

    def test_nist_csf_ids_are_format_valid(self, shipped_rules: list) -> None:
        invalid: list[tuple[str, str]] = []
        for rule in shipped_rules:
            nist = rule.framework_ref.get("nist_csf", "")
            if not _NIST_CSF_RE.match(nist):
                invalid.append((rule.id, nist))
        assert not invalid, f"NIST CSF IDs must match 'FF.SS-N' (function.category-number); invalid: {invalid}"

    def test_mitre_attack_ids_are_format_valid(self, shipped_rules: list) -> None:
        invalid: list[tuple[str, str]] = []
        for rule in shipped_rules:
            mitre = rule.framework_ref.get("mitre_attack", "")
            if not _MITRE_ATTACK_RE.match(mitre):
                invalid.append((rule.id, mitre))
        assert not invalid, (
            f"MITRE ATT&CK IDs must match 'T####' or 'T####.###' (enterprise technique); invalid: {invalid}"
        )


class TestShippedExplanationsArePopoverReady:
    """Explanations render in P7.9's breakdown popover; they must be
    non-empty + a sane length for UI consumption."""

    def test_explanations_non_empty(self, shipped_rules: list) -> None:
        blanks = [r.id for r in shipped_rules if not r.explanation.strip()]
        assert not blanks, f"rules with empty explanations: {blanks}"

    def test_explanations_have_some_substance(self, shipped_rules: list) -> None:
        """A 5-word explanation is uninformative in the popover. Lower
        bound is a quality-floor, not a spec invariant — bump it if the
        UI ratifies a stricter minimum."""
        too_short = [(r.id, r.explanation) for r in shipped_rules if len(r.explanation.split()) < 10]
        assert not too_short, f"explanations should be at least 10 words: {too_short}"


# ---------------------------------------------------------------------------
# Per-rule firing semantics
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "rule_id,intended_tags,withheld_tag",
    [
        (
            "rule_shell_filesystem_combo_001",
            (OntologyCategory.SHELL_EXECUTE, OntologyCategory.FILE_SYSTEM_WRITE),
            OntologyCategory.FILE_SYSTEM_WRITE,
        ),
        (
            "rule_shell_network_combo_001",
            (OntologyCategory.SHELL_EXECUTE, OntologyCategory.NETWORK_UNRESTRICTED),
            OntologyCategory.NETWORK_UNRESTRICTED,
        ),
        (
            "rule_shell_secrets_combo_001",
            (OntologyCategory.SHELL_EXECUTE, OntologyCategory.SECRETS_ACCESS),
            OntologyCategory.SECRETS_ACCESS,
        ),
        (
            "rule_secrets_network_001",
            (OntologyCategory.SECRETS_ACCESS, OntologyCategory.NETWORK_UNRESTRICTED),
            OntologyCategory.NETWORK_UNRESTRICTED,
        ),
        (
            "rule_filesystem_read_network_001",
            (OntologyCategory.FILE_SYSTEM_READ, OntologyCategory.NETWORK_UNRESTRICTED),
            OntologyCategory.NETWORK_UNRESTRICTED,
        ),
        (
            "rule_code_execution_network_001",
            (OntologyCategory.CODE_EXECUTION, OntologyCategory.NETWORK_UNRESTRICTED),
            OntologyCategory.NETWORK_UNRESTRICTED,
        ),
    ],
)
class TestTagBasedRuleFiring:
    """The 6 two-tag combo rules + 1 single-tag rule (`rule_exfil_capable_001`
    covered separately). For each rule:

    - With both required tags present → match (asserted via the rule appearing
      in ``apply_curated_rules`` output for an asset bearing only those tags).
    - With one required tag withheld → no match (proves ALL-OF semantics).
    """

    def test_fires_on_intended_tags(
        self,
        shipped_rules: list,
        rule_id: str,
        intended_tags: tuple,
        withheld_tag: OntologyCategory,
    ) -> None:
        _, applied = apply_curated_rules(_asset(), _tags(*intended_tags), shipped_rules)
        ids = {r["id"] for r in applied}
        assert rule_id in ids, f"rule {rule_id} should fire on tags={intended_tags}; got applied={sorted(ids)}"

    def test_does_not_fire_when_required_tag_missing(
        self,
        shipped_rules: list,
        rule_id: str,
        intended_tags: tuple,
        withheld_tag: OntologyCategory,
    ) -> None:
        reduced = tuple(t for t in intended_tags if t is not withheld_tag)
        _, applied = apply_curated_rules(_asset(), _tags(*reduced), shipped_rules)
        ids = {r["id"] for r in applied}
        assert rule_id not in ids, (
            f"rule {rule_id} must NOT fire when {withheld_tag.value} withheld; "
            f"tags={reduced}; got applied={sorted(ids)}"
        )


class TestExfilCapableDerivedRuleFiring:
    """`rule_exfil_capable_001` fires on the derived ``data_exfiltration_capable``
    tag (spec §5.4). The derivation itself is P2.2; here we only assert the
    rule fires whenever the derived tag is present and not otherwise."""

    def test_fires_when_derived_tag_present(self, shipped_rules: list) -> None:
        tags = _tags(
            OntologyCategory.SECRETS_ACCESS,
            OntologyCategory.NETWORK_UNRESTRICTED,
            OntologyCategory.DATA_EXFILTRATION_CAPABLE,
        )
        _, applied = apply_curated_rules(_asset(), tags, shipped_rules)
        ids = {r["id"] for r in applied}
        assert "rule_exfil_capable_001" in ids

    def test_does_not_fire_when_derived_tag_absent(self, shipped_rules: list) -> None:
        tags = _tags(OntologyCategory.INTER_TOOL_COMMUNICATION)
        _, applied = apply_curated_rules(_asset(), tags, shipped_rules)
        ids = {r["id"] for r in applied}
        assert "rule_exfil_capable_001" not in ids


class TestUnknownCapabilitySharpenerRuleFiring:
    """`rule_unknown_capability_sharpener_001` (+5, ID.RA-1, T1195) fires on
    any unknown-capability MCP — including those with non-recognition tags
    only (``INTER_TOOL_COMMUNICATION`` and/or ``SECRETS_ACCESS``)."""

    def test_fires_on_unknown_mcp(self, shipped_rules: list) -> None:
        # Bare MCP with only the universal-for-MCP tag — unknown-capability path.
        tags = _tags(OntologyCategory.INTER_TOOL_COMMUNICATION)
        _, applied = apply_curated_rules(_asset(source="mcp-servers"), tags, shipped_rules)
        ids = {r["id"] for r in applied}
        assert "rule_unknown_capability_sharpener_001" in ids

    def test_does_not_fire_on_recognized_mcp(self, shipped_rules: list) -> None:
        # A command-derived tag like CODE_EXECUTION makes the MCP recognized.
        tags = _tags(
            OntologyCategory.INTER_TOOL_COMMUNICATION,
            OntologyCategory.CODE_EXECUTION,
        )
        _, applied = apply_curated_rules(_asset(source="mcp-servers"), tags, shipped_rules)
        ids = {r["id"] for r in applied}
        assert "rule_unknown_capability_sharpener_001" not in ids

    def test_does_not_fire_on_non_mcp_source(self, shipped_rules: list) -> None:
        """Skill sources are never `unknown_capability` per
        :data:`unknown._UNKNOWN_CAPABILITY_SOURCES`."""
        _, applied = apply_curated_rules(_asset(source="claude-code-skills"), _tags(), shipped_rules)
        ids = {r["id"] for r in applied}
        assert "rule_unknown_capability_sharpener_001" not in ids


class TestExfilUnrecognizedRuleFiring:
    """`rule_exfil_capable_unrecognized` (+20, ID.RA-3, T1041) is the
    ratified-NEEDS-RAJAN rule: unknown_capability AND secrets_access.

    Per the §6.8 set-difference signature, ``SECRETS_ACCESS`` is one of the
    non-recognition tags — so an MCP with only ``INTER_TOOL_COMMUNICATION
    + SECRETS_ACCESS`` is BOTH unknown-capability AND tagged secrets_access,
    and this rule fires on exactly that pairing.
    """

    def test_fires_on_unknown_mcp_with_secrets_access(self, shipped_rules: list) -> None:
        tags = _tags(
            OntologyCategory.INTER_TOOL_COMMUNICATION,
            OntologyCategory.SECRETS_ACCESS,
        )
        _, applied = apply_curated_rules(_asset(source="mcp-servers"), tags, shipped_rules)
        ids = {r["id"] for r in applied}
        assert "rule_exfil_capable_unrecognized" in ids, (
            f"exfil-unrecognized rule must fire on unknown_mcp + secrets_access; got applied={sorted(ids)}"
        )

    def test_does_not_fire_when_secrets_access_absent(self, shipped_rules: list) -> None:
        tags = _tags(OntologyCategory.INTER_TOOL_COMMUNICATION)
        _, applied = apply_curated_rules(_asset(source="mcp-servers"), tags, shipped_rules)
        ids = {r["id"] for r in applied}
        assert "rule_exfil_capable_unrecognized" not in ids

    def test_does_not_fire_on_recognized_mcp_with_secrets_access(
        self,
        shipped_rules: list,
    ) -> None:
        """If the MCP is recognized (has a command-derived tag), the unknown-
        capability predicate is False, so the exfil-unrecognized rule must
        not fire — even if secrets_access is present. The recognized-MCP
        secrets-exfil path is covered by `rule_secrets_network_001` instead."""
        tags = _tags(
            OntologyCategory.INTER_TOOL_COMMUNICATION,
            OntologyCategory.SECRETS_ACCESS,
            OntologyCategory.CODE_EXECUTION,
        )
        _, applied = apply_curated_rules(_asset(source="mcp-servers"), tags, shipped_rules)
        ids = {r["id"] for r in applied}
        assert "rule_exfil_capable_unrecognized" not in ids


# ---------------------------------------------------------------------------
# End-to-end composition with spec §6.8 floor + §6.9 re-assertion
# ---------------------------------------------------------------------------


class TestExfilUnrecognizedComposesWithFloor:
    """The exfil-unrecognized rule (+20) composes with the spec §6.8
    unknown-capability floor (40) via the spec §6.9 re-assertion to land
    at exactly 60 (HIGH band lower edge).

    This is the load-bearing demonstration of Path (A) tightened: a
    credential-bearing unrecognized MCP lands in HIGH, not MEDIUM."""

    def test_floor_plus_exfil_unrecognized_lands_at_60_high(self, shipped_rules: list) -> None:
        tags = _tags(
            OntologyCategory.INTER_TOOL_COMMUNICATION,
            OntologyCategory.SECRETS_ACCESS,
        )
        result = score_asset_with_rules(
            _asset(source="mcp-servers"),
            ontology_tags=tags,
            rules=shipped_rules,
        )
        # Floor (40) + winning modifier (+20 exfil-unrecognized) = 60 HIGH.
        # The unknown-capability sharpener (+5) and exfil-unrecognized (+20)
        # both match; max-wins → +20 prevails.
        assert result.final_score == 60, (
            f"exfil-unrecognized + floor should land at 60 (HIGH lower edge); "
            f"got {result.final_score}, contributions={result.contributions}, "
            f"applied={[r['id'] for r in result.applied_rules]}"
        )
        assert result.band is RiskBand.HIGH

    def test_max_wins_suppresses_lower_modifier(self, shipped_rules: list) -> None:
        """Both the +5 sharpener and the +20 exfil-unrecognized rule
        match here. Both surface in `applied_rules` (popover attribution
        per spec §6.4); the +20 wins per max-wins.
        """
        tags = _tags(
            OntologyCategory.INTER_TOOL_COMMUNICATION,
            OntologyCategory.SECRETS_ACCESS,
        )
        result = score_asset_with_rules(
            _asset(source="mcp-servers"),
            ontology_tags=tags,
            rules=shipped_rules,
        )
        applied_ids = {r["id"] for r in result.applied_rules}
        assert "rule_exfil_capable_unrecognized" in applied_ids
        assert "rule_unknown_capability_sharpener_001" in applied_ids
        # Floor 40 + max_modifier (+20) = 60. If +5 had won, would be 45 (still MEDIUM).
        assert result.final_score == 60


# ---------------------------------------------------------------------------
# YAML-bomb empirical repro on installed PyYAML 6.0.3
# ---------------------------------------------------------------------------


class TestYAMLBombEmpiricalReproOnInstalledPyYAML:
    """Closes the STATUS carry-forward: empirical YAML-bomb repro on the
    actual installed PyYAML version, targeted at the risk-rules surface.

    Why this is here, not in P1.2's test_helpers_safe_yaml_load: P2.5
    introduces the third structured-input surface (after SKILL.md +
    MCP configs) and the bomb-defense contract is the load-bearing
    invariant for shipping a YAML-backed rule set. This file pins the
    invariant at the rule-loader entry point on the production
    PyYAML version, not on a mocked parser.
    """

    def test_pyyaml_version_is_pinned_known_safe(self) -> None:
        """Defense-in-depth: lock the PyYAML version assumption explicit
        in the test, so a transitive bump moving below 6.0 surfaces
        loudly. (PyYAML 6.0+ uses the safe loader by default.)"""
        ver = pyyaml_module.__version__
        major = int(ver.split(".")[0])
        assert major >= 6, (
            f"safe_yaml_load's bomb defense is pinned against PyYAML 6.x; "
            f"installed version {ver} is below the assumption"
        )

    def test_billion_laughs_structural_bomb_rejected_pre_parse(self) -> None:
        """Classic billion-laughs at the YAML *structural* level — anchors
        and aliases are real YAML nodes, not literal text inside a block
        scalar. PyYAML 6.0.3 would otherwise expand `d` to 10×10×10×10 =
        10 000 string copies on `yaml.safe_load(bomb)`.

        Level a: scalar anchor.
        Level b: list of 10 aliases to a.
        Level c: list of 10 aliases to b.
        Level d: list of 10 aliases to c.

        4 structural anchors + 30 structural aliases.
        ``MAX_YAML_ALIASES = 15`` rejects pre-parse; the cap line
        identifies why."""
        bomb = (
            "a: &a lol\n"
            "b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\n"
            "c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\n"
            "d: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]\n"
        )
        with pytest.raises(ValueError, match=r"alias|anchor"):
            safe_yaml_load(bomb)

    def test_installed_pyyaml_would_expand_bomb_without_caps(self) -> None:
        """Empirical proof that the cap is doing real work on the installed
        PyYAML: feed the *same* bomb to ``yaml.safe_load`` directly (with no
        cap layer) and observe that PyYAML expands it to a memory-amplified
        structure. If a future PyYAML version starts rejecting bombs natively,
        this assertion fails loudly and the cap design can be reviewed.

        Smaller fanout (10x10x10 = 1000) keeps the test fast without
        relying on the cap as the safety mechanism. PyYAML 6.0.3
        deserializes this successfully — the cap is the only thing
        stopping the larger bomb above from reaching the parser."""
        small_bomb = (
            "a: &a lol\n"
            "b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]\n"
            "c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]\n"
            "d: [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]\n"
        )
        parsed = pyyaml_module.safe_load(small_bomb)
        # 10 copies of c, each holding 10 copies of b, each holding 10 of a.
        assert len(parsed["d"]) == 10
        assert len(parsed["d"][0]) == 10
        assert len(parsed["d"][0][0]) == 10
        assert parsed["d"][0][0][0] == "lol"

    def test_anchor_cap_rejects_pre_parse(self) -> None:
        """Independent verification: a YAML with > MAX_YAML_ANCHORS
        anchors is rejected before PyYAML sees it."""
        # MAX_YAML_ANCHORS=10; produce 12 anchors (each used once → 12 aliases too).
        # The anchor check fires first so we use few aliases per anchor.
        lines = [f"k{i}: &a{i} v{i}" for i in range(12)]
        text = "\n".join(lines)
        with pytest.raises(ValueError, match=r"anchor"):
            safe_yaml_load(text)

    def test_alias_cap_rejects_pre_parse(self) -> None:
        """Independent verification: a YAML with > MAX_YAML_ALIASES
        aliases is rejected before PyYAML sees it."""
        # 1 anchor + 20 aliases referencing it → 20 > 15.
        text = "anchor: &a 1\n" + "\n".join(f"k{i}: *a" for i in range(20))
        with pytest.raises(ValueError, match=r"alias"):
            safe_yaml_load(text)

    def test_caps_match_documented_thresholds(self) -> None:
        """If MAX_YAML_ANCHORS/MAX_YAML_ALIASES are ever changed without
        re-running architect-pass, this assertion makes the change
        visible loudly — the test docstring above quotes the thresholds."""
        assert MAX_YAML_ANCHORS == 10, "MAX_YAML_ANCHORS changed from 10 — re-verify bomb defense + update tests"
        assert MAX_YAML_ALIASES == 15, "MAX_YAML_ALIASES changed from 15 — re-verify bomb defense + update tests"
