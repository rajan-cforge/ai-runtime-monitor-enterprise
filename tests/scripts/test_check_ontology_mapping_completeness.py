"""Tests for ``scripts/check_ontology_mapping_completeness.py``.

P2.2-gate: the gate script was wired into CI in the CI-infra PR;
this file pins its observable behaviors so a future refactor cannot
silently change which conditions FAIL vs PASS.

Pinned behaviors (per directive §11.2 + spec §6.5 + Q5 ratification
2026-06-06 — STRUCTURAL completeness only):

1. PASS when every concrete ``DiscoverySource`` subclass has a mapper
   in ``ontology.mapping.REGISTERED_SOURCES``.
2. FAIL when a source class exists but its ``name()`` is not in the
   registry (missing-mapper case — the failure mode this gate exists to
   catch).
3. FAIL when the registry contains a phantom name with no matching
   ``DiscoverySource`` subclass (orphan-registry case).
4. FAIL with a structured exit code 1 + each issue printed on its own
   line so a contributor reading CI output can attribute the failure.
5. PASS line names the counts (``N discovery source(s), M registered
   mapper(s)``) — empirical assertion the script's success output is
   stable.
6. **Today's repo** passes the gate (no missing mappers, no phantoms).
   This is the integration test pin.

Per spec §6.5 + Q5 ratification: the gate is STRUCTURAL. A mapper
returning ``frozenset()`` is acceptable. Functional completeness would
contradict the Q1 ratification (zero-tag asset is valid → INFO band).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "check_ontology_mapping_completeness.py"


def _run() -> subprocess.CompletedProcess[str]:
    """Run the script against the live repo. Used for the integration
    pin (test #6 below)."""
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        capture_output=True,
        text=True,
        check=False,
    )


class TestGateAgainstLiveRepo:
    """Integration pin: the shipped Phase-2 source set + ontology
    registry must pass the gate. If a new source lands without its
    mapper, this fails the build."""

    def test_live_repo_passes_today(self) -> None:
        result = _run()
        assert result.returncode == 0, (
            f"ontology completeness gate FAILED against the live repo. "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )
        assert "PASS" in result.stdout

    def test_pass_line_names_counts(self) -> None:
        """The PASS line shape is the audit signal a contributor reads.
        Pin its structure so a refactor of the print format doesn't
        silently drop the counts."""
        result = _run()
        assert "discovery source(s)" in result.stdout
        assert "registered mapper(s)" in result.stdout


class TestGateMissingMapper:
    """Unit-style: invoke the script's ``main`` in-process with monkey-
    patched discovery + registry to exercise the FAIL paths the live
    repo cannot reach today.

    Imports the script as a module via ``importlib`` so we can replace
    ``_discover_source_classes`` and ``REGISTERED_SOURCES`` at the
    boundary the script reads."""

    @pytest.fixture
    def gate_module(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location("_check_ontology_mapping_completeness_under_test", str(SCRIPT))
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_fail_when_source_missing_from_registry(self, gate_module, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        """The failure mode the gate exists to catch: a contributor
        adds a new ``DiscoverySource`` but forgets the mapper."""

        from claude_monitoring.attack_surface.discovery.base import DiscoverySource

        class FakeNewSource(DiscoverySource):
            def name(self) -> str:
                return "unmapped-new-source"

            def requires_auth(self) -> bool:
                return False

            def discover(self):
                return []

        monkeypatch.setattr(gate_module, "_discover_source_classes", lambda: [FakeNewSource])
        # Registry doesn't contain "unmapped-new-source"
        monkeypatch.setattr(gate_module, "REGISTERED_SOURCES", set())

        rc = gate_module.main()
        out = capsys.readouterr().out
        assert rc == 1
        assert "FAIL" in out
        assert "unmapped-new-source" in out
        assert "no mapping function" in out

    def test_fail_lists_every_missing_mapper(self, gate_module, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        """A single FAIL line per issue lets a contributor fix them in
        batch instead of one-at-a-time CI cycles."""

        from claude_monitoring.attack_surface.discovery.base import DiscoverySource

        class FakeA(DiscoverySource):
            def name(self) -> str:
                return "fake-a"

            def requires_auth(self) -> bool:
                return False

            def discover(self):
                return []

        class FakeB(DiscoverySource):
            def name(self) -> str:
                return "fake-b"

            def requires_auth(self) -> bool:
                return False

            def discover(self):
                return []

        monkeypatch.setattr(gate_module, "_discover_source_classes", lambda: [FakeA, FakeB])
        monkeypatch.setattr(gate_module, "REGISTERED_SOURCES", set())

        rc = gate_module.main()
        out = capsys.readouterr().out
        assert rc == 1
        assert "fake-a" in out
        assert "fake-b" in out

    def test_pass_when_every_source_has_a_mapper(self, gate_module, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        from claude_monitoring.attack_surface.discovery.base import DiscoverySource

        class FakeA(DiscoverySource):
            def name(self) -> str:
                return "fake-a"

            def requires_auth(self) -> bool:
                return False

            def discover(self):
                return []

        monkeypatch.setattr(gate_module, "_discover_source_classes", lambda: [FakeA])
        monkeypatch.setattr(gate_module, "REGISTERED_SOURCES", {"fake-a"})

        rc = gate_module.main()
        out = capsys.readouterr().out
        assert rc == 0
        assert "PASS" in out


class TestGatePhantomRegistry:
    """Inverse failure mode: registry has a name with no matching
    ``DiscoverySource`` subclass — a leftover from a removed source
    or a typo in the mapper module."""

    @pytest.fixture
    def gate_module(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "_check_ontology_mapping_completeness_under_test_phantom", str(SCRIPT)
        )
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_fail_on_phantom_registry_entry(self, gate_module, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        from claude_monitoring.attack_surface.discovery.base import DiscoverySource

        class FakeA(DiscoverySource):
            def name(self) -> str:
                return "fake-a"

            def requires_auth(self) -> bool:
                return False

            def discover(self):
                return []

        monkeypatch.setattr(gate_module, "_discover_source_classes", lambda: [FakeA])
        # Registry has "fake-a" (matched) AND "phantom-deleted-source" (orphan)
        monkeypatch.setattr(
            gate_module,
            "REGISTERED_SOURCES",
            {"fake-a", "phantom-deleted-source"},
        )

        rc = gate_module.main()
        out = capsys.readouterr().out
        assert rc == 1
        assert "phantom-deleted-source" in out
        assert "phantom entry" in out


class TestGateNoSourcesFound:
    """Edge case: pkgutil.iter_modules returns nothing. The gate must
    FAIL rather than report misleading PASS. Defensive — protects against
    a refactor that breaks the source discovery."""

    @pytest.fixture
    def gate_module(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "_check_ontology_mapping_completeness_under_test_empty", str(SCRIPT)
        )
        assert spec is not None and spec.loader is not None
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def test_fail_when_no_sources_found(self, gate_module, monkeypatch: pytest.MonkeyPatch, capsys) -> None:
        monkeypatch.setattr(gate_module, "_discover_source_classes", lambda: [])
        rc = gate_module.main()
        out = capsys.readouterr().out
        assert rc == 1
        assert "FAIL" in out
        assert "no DiscoverySource subclasses found" in out
