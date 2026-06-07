"""P2.0 — Structural completeness gate (directive §11.2, Q5 ratification).

**Q5 ratification (2026-06-06):** the gate is STRUCTURAL — "every
registered discovery source has a corresponding mapping function" —
NOT functional ("every source produces at least one tag"). A
functional gate would contradict Q1 (zero-tag asset is legitimate
and lands at INFO band per spec §6.5).

This test invokes the same `_discover_source_classes` helper the
CI gate uses, so the test and the CI gate cannot drift apart. (An
earlier draft hand-imported each of the 6 sources and would have
stayed green if a 7th source landed without a registered mapper.)
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# Load the gate script as a module so the test reuses its source-discovery logic.
_SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "check_ontology_mapping_completeness.py"
_spec = importlib.util.spec_from_file_location("check_ontology_mapping_completeness", _SCRIPT_PATH)
assert _spec is not None and _spec.loader is not None
_gate = importlib.util.module_from_spec(_spec)
sys.modules["check_ontology_mapping_completeness"] = _gate
_spec.loader.exec_module(_gate)

from claude_monitoring.attack_surface.ontology.mapping import REGISTERED_SOURCES  # noqa: E402


def test_every_discovered_source_has_a_registered_mapper() -> None:
    """The CI gate's own source-discovery walk finds 6 sources, and every
    one of their `name()` values appears in `REGISTERED_SOURCES`. If a
    7th source lands without a mapper, this test fails alongside the CI
    gate — they cannot drift."""
    source_classes = _gate._discover_source_classes()
    assert len(source_classes) >= 1, "discovery walk found no sources"
    source_names = {cls().name() for cls in source_classes}
    missing = source_names - REGISTERED_SOURCES
    assert not missing, (
        f"discovery sources without an ontology mapper: {sorted(missing)}. "
        f"Wire a mapping function in ontology/mapping.py._REGISTRY."
    )


def test_registry_contains_no_phantom_sources() -> None:
    """Inverse direction: every name in `REGISTERED_SOURCES` corresponds
    to a real DiscoverySource. Uses the same source-discovery walk."""
    source_classes = _gate._discover_source_classes()
    real_source_names = {cls().name() for cls in source_classes}
    phantoms = REGISTERED_SOURCES - real_source_names
    assert not phantoms, (
        f"ontology registry contains source names that don't match any discovery source: {sorted(phantoms)}"
    )


def test_gate_script_exits_zero_on_current_state() -> None:
    """End-to-end: the CI gate script `main()` returns 0 today."""
    exit_code = _gate.main()
    assert exit_code == 0
