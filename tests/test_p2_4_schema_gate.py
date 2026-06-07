"""P2.4 — `risk-rules-schema-validation` CI gate (directive §11.2).

Validates:
1. YAML loads via `safe_yaml_load` (catches bombs + oversize).
2. Top-level is a list.
3. Every rule has all 5 required fields (id, pattern, modifier, explanation, framework_ref).
4. `id` is unique across the rule set.
5. `modifier` is an int in [-10, +30].
6. `pattern` has ≥1 predicate.
7. `framework_ref` has ≥1 known framework entry.
8. Unknown predicate keys WARN (forward-compat) but do not fail.
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


class TestSchemaGateForwardCompat:
    def test_unknown_predicate_warns_but_passes(self, tmp_path: Path) -> None:
        """Forward-compat: P2.5 / Phase-3 may add predicates the v0.2.2
        runtime doesn't know yet. Don't reject the YAML; runtime no-ops."""
        path = tmp_path / "rules.yaml"
        path.write_text("""\
- id: r
  pattern:
    has_tags: [x]
    some_future_predicate: 42
  modifier: 10
  explanation: x
  framework_ref:
    nist_csf: X
""")
        result = _run_gate(path)
        assert result.returncode == 0
        # The unknown predicate must surface as a warning in output
        assert "warn" in (result.stdout + result.stderr).lower() or "some_future_predicate" in (
            result.stdout + result.stderr
        )


class TestSchemaGateBombRejection:
    def test_billion_laughs_rejected(self, tmp_path: Path) -> None:
        """safe_yaml_load's anchor/alias caps must reject the bomb;
        the gate translates that to a non-zero exit."""
        path = tmp_path / "rules.yaml"
        bomb = "\n".join([f"a{i}: &a{i} [*a{i - 1 if i else 0}, *a{i - 1 if i else 0}]" for i in range(20)])
        path.write_text(bomb)
        result = _run_gate(path)
        assert result.returncode == 1
