"""P2.4 — `risk-rules-schema-validation` CI gate (directive §11.2).

Validates:
1. YAML loads via `safe_yaml_load` (catches bombs + oversize).
2. Top-level is a list.
3. Every rule has all 5 required fields (id, pattern, modifier, explanation, framework_ref).
4. `id` is unique across the rule set.
5. `modifier` is an int in [-10, +30].
6. `pattern` has ≥1 predicate.
7. `framework_ref` has ≥1 known framework entry.
8. **Q-A (Rajan 2026-06-07):** every predicate in `pattern` must be in
   `LIVE_PREDICATES`. Forward-compat predicates (cve_severity,
   integration_sensitivity, package_in_malicious_list) FAIL the gate
   with a message naming the wiring PR. Unknown predicates also FAIL.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _REPO_ROOT / "scripts" / "check_risk_rules_schema.py"


def _run_gate(rules_file: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(_SCRIPT), str(rules_file)],
        capture_output=True,
        text=True,
    )


_VALID_RULE = """\
- id: rule_one
  pattern:
    has_tags: [shell_execute]
  modifier: 10
  explanation: |
    valid rule
  framework_ref:
    nist_csf: PR.AC-4
"""


class TestSchemaGateGoldenValid:
    def test_valid_single_rule_exits_zero(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yaml"
        path.write_text(_VALID_RULE)
        result = _run_gate(path)
        assert result.returncode == 0, result.stdout + result.stderr


class TestSchemaGateMissingFields:
    def test_missing_id_fails(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- pattern:
    has_tags: [shell_execute]
  modifier: 10
  explanation: x
  framework_ref:
    nist_csf: X
""")
        result = _run_gate(path)
        assert result.returncode == 1
        assert "id" in (result.stdout + result.stderr).lower()

    def test_missing_pattern_fails(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: r
  modifier: 10
  explanation: x
  framework_ref:
    nist_csf: X
""")
        assert _run_gate(path).returncode == 1

    def test_missing_modifier_fails(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: r
  pattern:
    has_tags: [x]
  explanation: x
  framework_ref:
    nist_csf: X
""")
        assert _run_gate(path).returncode == 1

    def test_missing_explanation_fails(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: r
  pattern:
    has_tags: [x]
  modifier: 10
  framework_ref:
    nist_csf: X
""")
        assert _run_gate(path).returncode == 1

    def test_missing_framework_ref_fails(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: r
  pattern:
    has_tags: [x]
  modifier: 10
  explanation: x
""")
        assert _run_gate(path).returncode == 1


class TestSchemaGateUniqueness:
    def test_duplicate_id_fails(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yaml"
        path.write_text(_VALID_RULE + _VALID_RULE)
        result = _run_gate(path)
        assert result.returncode == 1
        assert "duplicate" in (result.stdout + result.stderr).lower()


class TestSchemaGateModifierRange:
    def test_modifier_above_thirty_fails(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: r
  pattern:
    has_tags: [x]
  modifier: 50
  explanation: x
  framework_ref:
    nist_csf: X
""")
        assert _run_gate(path).returncode == 1

    def test_modifier_below_minus_ten_fails(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: r
  pattern:
    has_tags: [x]
  modifier: -20
  explanation: x
  framework_ref:
    nist_csf: X
""")
        assert _run_gate(path).returncode == 1

    def test_boundary_thirty_passes(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: r
  pattern:
    has_tags: [x]
  modifier: 30
  explanation: x
  framework_ref:
    nist_csf: X
""")
        assert _run_gate(path).returncode == 0

    def test_boundary_minus_ten_passes(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: r
  pattern:
    has_tags: [x]
  modifier: -10
  explanation: x
  framework_ref:
    nist_csf: X
""")
        assert _run_gate(path).returncode == 0


class TestSchemaGatePatternStructure:
    def test_empty_pattern_dict_fails(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: r
  pattern: {}
  modifier: 10
  explanation: x
  framework_ref:
    nist_csf: X
""")
        assert _run_gate(path).returncode == 1


class TestSchemaGatePredicateGating:
    """**Rajan ratification 2026-06-07 Q-A.** The schema gate FAILS
    (blocking) on any rule using a predicate not in ``LIVE_PREDICATES``.
    Forward-compat predicates produce a precise error naming the wiring
    PR. Unknown predicates also fail. The prior "WARN + runtime no-op"
    path is gone — it let known-malicious-package rules ship inert."""

    def test_truly_unknown_predicate_fails(self, tmp_path: Path) -> None:
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: r
  pattern:
    has_tags: [x]
    a_predicate_we_never_heard_of: 42
  modifier: 10
  explanation: x
  framework_ref:
    nist_csf: X
""")
        result = _run_gate(path)
        assert result.returncode == 1
        assert "a_predicate_we_never_heard_of" in (result.stdout + result.stderr)

    def test_cve_severity_forward_compat_predicate_fails_naming_p4_1(self, tmp_path: Path) -> None:
        """The §6.2 example using `cve_severity` cannot ship until P4.1
        wires the input. Q-A: error must name the wiring PR."""
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: r
  pattern:
    has_tags: [x]
    cve_severity: ">= 7"
  modifier: 10
  explanation: x
  framework_ref:
    nist_csf: X
""")
        result = _run_gate(path)
        assert result.returncode == 1
        out = result.stdout + result.stderr
        assert "cve_severity" in out
        assert "P4.1" in out

    def test_integration_sensitivity_forward_compat_predicate_fails_naming_p3_7(self, tmp_path: Path) -> None:
        """Spec §6.2's own example rule uses `integration_sensitivity`. Per
        Q-A it cannot ship until P3.7 wires the input. Gate names the PR."""
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: r
  pattern:
    has_tags: [x]
    integration_sensitivity: ">= 70"
  modifier: 25
  explanation: x
  framework_ref:
    nist_csf: PR.AC-4
""")
        result = _run_gate(path)
        assert result.returncode == 1
        out = result.stdout + result.stderr
        assert "integration_sensitivity" in out
        assert "P3.7" in out

    def test_package_in_malicious_list_forward_compat_fails_naming_phase_3(self, tmp_path: Path) -> None:
        """The catastrophic case Rajan named (known-malicious-package
        scoring clean because the predicate no-ops). Gate MUST reject."""
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: r
  pattern:
    package_in_malicious_list: true
  modifier: 30
  explanation: Remove immediately.
  framework_ref:
    mitre_attack: T1195
""")
        result = _run_gate(path)
        assert result.returncode == 1
        out = result.stdout + result.stderr
        assert "package_in_malicious_list" in out
        assert "Phase 3" in out

    def test_live_only_predicate_combination_passes(self, tmp_path: Path) -> None:
        """A rule using only LIVE_PREDICATES (here: has_tags +
        unknown_capability) passes the gate cleanly. This is the exfil
        shape — the rule itself is NEEDS-RAJAN for P2.5."""
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: rule_exfil_shape
  pattern:
    unknown_capability: true
    has_tags: [secrets_access]
  modifier: 20
  explanation: |
    Exfil shape — unrecognized MCP with credentials.
  framework_ref:
    nist_csf: ID.RA-3
    mitre_attack: T1041
""")
        assert _run_gate(path).returncode == 0


class TestSchemaGateBombRejection:
    def test_billion_laughs_rejected(self, tmp_path: Path) -> None:
        """safe_yaml_load's anchor/alias caps must reject the bomb;
        the gate translates that to a non-zero exit."""
        path = tmp_path / "rules.yaml"
        bomb = "\n".join([f"a{i}: &a{i} [*a{i - 1 if i else 0}, *a{i - 1 if i else 0}]" for i in range(20)])
        path.write_text(bomb)
        result = _run_gate(path)
        assert result.returncode == 1
