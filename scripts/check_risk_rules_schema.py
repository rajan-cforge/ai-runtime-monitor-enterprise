#!/usr/bin/env python3
"""`risk-rules-schema-validation` — directive §11.2 gate.

Validates `config/risk-rules.yaml` (or an override path) against the
spec §6.2 schema. Owned by P2.4 per the v0.2.2 gate-ownership map.

**Exit codes:**

- 0 — pass (schema valid)
- 1 — fail (one or more rules malformed; reasons printed)

**Validates (Phase A §6):**

1. YAML loads via `safe_yaml_load` (catches bombs + oversize).
2. Top-level is a list.
3. Every rule has all 5 required fields (id, pattern, modifier,
   explanation, framework_ref).
4. `id` is unique across the rule set.
5. `modifier` is an int in [-10, +30] per spec §6.2.
6. `pattern` is a non-empty dict.
7. `framework_ref` is a non-empty dict.
8. Unknown predicate keys WARN (forward-compat for P2.5 / Phase-3)
   but do NOT fail.

Usage: `python scripts/check_risk_rules_schema.py <path-to-yaml>`
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure src/ is importable when invoked from repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

from claude_monitoring.attack_surface.discovery.helpers import safe_yaml_load  # noqa: E402
from claude_monitoring.attack_surface.risk.rules import (  # noqa: E402
    _KNOWN_PREDICATES,
    MODIFIER_MAX,
    MODIFIER_MIN,
)

_REQUIRED_FIELDS = ("id", "pattern", "modifier", "explanation", "framework_ref")


def _fail(failures: list[str], path: Path) -> int:
    print(f"FAIL: {path} has {len(failures)} schema violation(s):")
    for f in failures:
        print(f"  - {f}")
    return 1


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} <path-to-risk-rules.yaml>")
        return 2
    path = Path(argv[1])
    if not path.is_file():
        print(f"FAIL: {path} does not exist")
        return 1

    try:
        raw = path.read_text(errors="replace")
    except OSError as exc:
        print(f"FAIL: cannot read {path}: {exc}")
        return 1

    try:
        payload = safe_yaml_load(raw)
    except Exception as exc:
        print(f"FAIL: {path} YAML parse rejected (bomb / oversize / malformed): {exc}")
        return 1

    if not isinstance(payload, list):
        print(f"FAIL: {path} top-level must be a list of rules (got {type(payload).__name__})")
        return 1

    failures: list[str] = []
    warnings: list[str] = []
    seen_ids: dict[str, int] = {}

    for idx, entry in enumerate(payload):
        loc = f"rule[{idx}]"
        if not isinstance(entry, dict):
            failures.append(f"{loc}: not a dict (got {type(entry).__name__})")
            continue
        missing = [f for f in _REQUIRED_FIELDS if f not in entry]
        if missing:
            failures.append(f"{loc} (id={entry.get('id')!r}): missing required fields {missing}")
            continue

        rid = entry["id"]
        if not isinstance(rid, str) or not rid.strip():
            failures.append(f"{loc}: id must be a non-empty string")
            continue
        if rid in seen_ids:
            failures.append(f"{loc} (id={rid!r}): duplicate id (first seen at rule[{seen_ids[rid]}])")
        else:
            seen_ids[rid] = idx

        pattern = entry["pattern"]
        if not isinstance(pattern, dict) or not pattern:
            failures.append(f"rule {rid!r}: pattern must be a non-empty dict")
        else:
            for predicate_key in pattern:
                if predicate_key not in _KNOWN_PREDICATES:
                    warnings.append(
                        f"rule {rid!r}: unknown predicate {predicate_key!r} "
                        f"(forward-compat warn; runtime will no-op until predicate is implemented)"
                    )

        modifier = entry["modifier"]
        if not isinstance(modifier, int) or isinstance(modifier, bool):
            failures.append(f"rule {rid!r}: modifier must be int (got {type(modifier).__name__})")
        elif not (MODIFIER_MIN <= modifier <= MODIFIER_MAX):
            failures.append(
                f"rule {rid!r}: modifier {modifier} outside spec §6.2 range [{MODIFIER_MIN}, {MODIFIER_MAX}]"
            )

        framework_ref = entry["framework_ref"]
        if not isinstance(framework_ref, dict) or not framework_ref:
            failures.append(f"rule {rid!r}: framework_ref must be a non-empty dict")

        explanation = entry["explanation"]
        if not isinstance(explanation, str):
            failures.append(f"rule {rid!r}: explanation must be a string")

    if failures:
        return _fail(failures, path)

    if warnings:
        print(f"PASS (with {len(warnings)} forward-compat warning(s)):")
        for w in warnings:
            print(f"  WARN: {w}")
    else:
        print(f"PASS: {path} — {len(payload)} rule(s), schema valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
