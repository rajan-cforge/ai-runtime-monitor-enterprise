"""P3.3 — Python package discovery (pip global + per-venv).

Pins the discovery contract: invokes ``<python_bin> -m pip list --format=json``
against the system Python and each detected venv (canonical home paths,
shallow project-dir globs, pipenv/pyenv/conda venv roots). Each
package becomes one ``Asset`` with stable id and venv attribution.

Tests follow the P3.1 / P3.2 precedent with one new wrinkle:
**binary-trust boundary** — each discovered ``python`` binary is
``validate_path``-checked against ratified prefixes BEFORE exec, so a
malicious repo cannot drop a fake interpreter outside known roots and
have it executed.

See ``~/Documents/vigil-notes/v022/phase-3/p3.3-phase-a-investigation.md``
for the full investigation that scoped the source.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

from claude_monitoring.attack_surface.discovery.base import (
    DiscoverySource,
    LastRunOutcome,
)
from claude_monitoring.attack_surface.discovery.sources.python_packages import (
    PythonPackagesSource,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_fake_venv(tmp_path: Path, name: str = "venv") -> Path:
    """Create a synthetic venv structure: ``<tmp>/<name>/bin/python``.

    Returns the venv root (the parent of ``bin/``). The 'python' file is
    not a real interpreter — tests that exercise pip invocation must
    monkeypatch ``safe_subprocess`` or ``list_pip_packages``.
    """
    venv_root = tmp_path / name
    bin_dir = venv_root / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    python_bin = bin_dir / "python"
    python_bin.write_text("#!/bin/sh\necho fake\n")
    python_bin.chmod(0o755)
    return venv_root


def _src(candidates: list[tuple[str, Path]]) -> PythonPackagesSource:
    """Construct the source with the given (venv_label, python_bin) pairs."""
    return PythonPackagesSource(venv_candidates=candidates)


# ---------------------------------------------------------------------------
# 1. Contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_is_a_DiscoverySource(self) -> None:
        assert issubclass(PythonPackagesSource, DiscoverySource)

    def test_name_is_python_packages(self) -> None:
        # Pin the registered name (P2.2-gate CI gate consumes this).
        assert PythonPackagesSource().name() == "python-packages"

    def test_does_not_require_auth(self) -> None:
        assert PythonPackagesSource().requires_auth() is False

    def test_appears_in_REGISTERED_SOURCES(self) -> None:
        """The new source must be wired into the ontology mapping registry
        so the P2.2-gate CI doesn't fail. P3.8 will fill the mapper with
        the real ontology tags; until then it returns frozenset()."""
        from claude_monitoring.attack_surface.ontology.mapping import (
            REGISTERED_SOURCES,
        )

        assert "python-packages" in REGISTERED_SOURCES


# ---------------------------------------------------------------------------
# 2. Happy path
# ---------------------------------------------------------------------------


class TestHappyPath:
    def test_one_venv_one_package_yields_one_asset(self, tmp_path: Path) -> None:
        venv_root = _make_fake_venv(tmp_path, "v1")
        python_bin = venv_root / "bin" / "python"
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[{"name": "requests", "version": "2.31.0"}],
        ):
            assets = _src([("home-venv", python_bin)]).discover()
        assert len(assets) == 1
        a = assets[0]
        assert a.type == "python_package"
        assert a.source == "python-packages"
        assert a.name == "requests"
        assert a.version == "2.31.0"
        assert a.current_state["venv_label"] == "home-venv"
        assert a.current_state["package_name"] == "requests"
        assert a.current_state["package_name_normalized"] == "requests"

    def test_multiple_venvs_each_contribute(self, tmp_path: Path) -> None:
        v1 = _make_fake_venv(tmp_path, "v1")
        v2 = _make_fake_venv(tmp_path, "v2")
        outputs = {
            str(v1 / "bin" / "python"): [{"name": "requests", "version": "2.31.0"}],
            str(v2 / "bin" / "python"): [{"name": "django", "version": "5.0.0"}],
        }
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            side_effect=lambda p: outputs[str(p)],
        ):
            assets = _src(
                [
                    ("system", v1 / "bin" / "python"),
                    ("project:foo", v2 / "bin" / "python"),
                ]
            ).discover()
        labels = {a.current_state["venv_label"] for a in assets}
        names = {a.name for a in assets}
        assert labels == {"system", "project:foo"}
        assert names == {"requests", "django"}

    def test_multiple_packages_per_venv(self, tmp_path: Path) -> None:
        venv_root = _make_fake_venv(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[
                {"name": "requests", "version": "2.31.0"},
                {"name": "django", "version": "5.0.0"},
                {"name": "numpy", "version": "1.26.0"},
            ],
        ):
            assets = _src([("system", venv_root / "bin" / "python")]).discover()
        assert len(assets) == 3
        names = {a.name for a in assets}
        assert names == {"requests", "django", "numpy"}

    def test_install_path_is_venv_root(self, tmp_path: Path) -> None:
        """install_path must be the venv root (parent of bin/), NOT the
        python binary path and NOT the package install dir."""
        venv_root = _make_fake_venv(tmp_path, "myvenv")
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[{"name": "requests", "version": "2.31.0"}],
        ):
            a = _src([("system", venv_root / "bin" / "python")]).discover()[0]
        assert a.install_path == str(venv_root)
        assert not a.install_path.endswith("python")

    def test_package_name_normalization_for_digest(self, tmp_path: Path) -> None:
        """PEP 503: package names are case-insensitive. Digest must use
        normalized lowercase so 'Requests' and 'requests' UPSERT to the
        same row, not duplicate."""
        venv_root = _make_fake_venv(tmp_path)
        python_bin = venv_root / "bin" / "python"

        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[{"name": "Requests", "version": "2.31.0"}],
        ):
            a_mixed = _src([("system", python_bin)]).discover()[0]
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[{"name": "requests", "version": "2.31.0"}],
        ):
            a_lower = _src([("system", python_bin)]).discover()[0]
        # original casing preserved for display
        assert a_mixed.current_state["package_name"] == "Requests"
        assert a_lower.current_state["package_name"] == "requests"
        # but normalized name + digest match
        assert a_mixed.current_state["package_name_normalized"] == "requests"
        assert a_lower.current_state["package_name_normalized"] == "requests"
        assert a_mixed.id == a_lower.id, (
            "PEP 503 normalization required for stable id across case variations of the same package"
        )

    def test_python_executable_captured(self, tmp_path: Path) -> None:
        venv_root = _make_fake_venv(tmp_path)
        python_bin = venv_root / "bin" / "python"
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[{"name": "requests", "version": "2.31.0"}],
        ):
            a = _src([("system", python_bin)]).discover()[0]
        assert a.current_state["python_executable"] == str(python_bin)
        assert a.current_state["venv_path"] == str(venv_root)


# ---------------------------------------------------------------------------
# 3. Per-item isolation
# ---------------------------------------------------------------------------


class TestPerItemIsolation:
    def test_subprocess_timeout_per_venv_skips_that_venv(self, tmp_path: Path) -> None:
        """If pip hangs on one venv, the timeout fires per-venv;
        sibling venvs continue."""
        v1 = _make_fake_venv(tmp_path, "slow")
        v2 = _make_fake_venv(tmp_path, "ok")

        def fake_list(python_bin):
            if str(python_bin).endswith("/slow/bin/python"):
                raise subprocess.TimeoutExpired(cmd=["pip"], timeout=30)
            return [{"name": "requests", "version": "2.31.0"}]

        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            side_effect=fake_list,
        ):
            assets = _src(
                [
                    ("slow", v1 / "bin" / "python"),
                    ("ok", v2 / "bin" / "python"),
                ]
            ).discover()
        labels = {a.current_state["venv_label"] for a in assets}
        assert labels == {"ok"}

    def test_nonzero_returncode_per_venv_skips_that_venv(self, tmp_path: Path) -> None:
        """Some venvs may have broken pip; non-zero returncode is logged
        + skipped; siblings continue."""
        v1 = _make_fake_venv(tmp_path, "broken")
        v2 = _make_fake_venv(tmp_path, "ok")

        def fake_list(python_bin):
            if "broken" in str(python_bin):
                raise RuntimeError("pip exited 1")
            return [{"name": "requests", "version": "2.31.0"}]

        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            side_effect=fake_list,
        ):
            assets = _src(
                [
                    ("broken", v1 / "bin" / "python"),
                    ("ok", v2 / "bin" / "python"),
                ]
            ).discover()
        labels = {a.current_state["venv_label"] for a in assets}
        assert labels == {"ok"}

    def test_malformed_pip_output_per_venv_skipped(self, tmp_path: Path) -> None:
        v1 = _make_fake_venv(tmp_path, "v1")
        v2 = _make_fake_venv(tmp_path, "v2")

        def fake_list(python_bin):
            if "v1" in str(python_bin):
                raise json.JSONDecodeError("expecting value", "doc", 0)
            return [{"name": "requests", "version": "2.31.0"}]

        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            side_effect=fake_list,
        ):
            assets = _src(
                [
                    ("v1", v1 / "bin" / "python"),
                    ("v2", v2 / "bin" / "python"),
                ]
            ).discover()
        assert {a.current_state["venv_label"] for a in assets} == {"v2"}

    def test_absent_python_binary_skipped(self, tmp_path: Path) -> None:
        """A candidate path that doesn't exist on disk is skipped silently;
        siblings continue."""
        nonexistent = tmp_path / "ghost" / "bin" / "python"
        v2 = _make_fake_venv(tmp_path, "real")
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[{"name": "requests", "version": "2.31.0"}],
        ):
            assets = _src(
                [
                    ("ghost", nonexistent),
                    ("real", v2 / "bin" / "python"),
                ]
            ).discover()
        assert {a.current_state["venv_label"] for a in assets} == {"real"}

    def test_per_package_malformed_entry_skipped_others_emit(self, tmp_path: Path) -> None:
        """A pip-output entry missing 'name' or 'version' is skipped;
        sibling packages still emit."""
        venv_root = _make_fake_venv(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[
                {"name": "good", "version": "1.0.0"},
                {"version": "1.0.0"},  # missing name
                {"name": "alsoGood", "version": "2.0.0"},
                {"name": 12345, "version": "1.0.0"},  # bad type
                "not even a dict",
            ],
        ):
            assets = _src([("system", venv_root / "bin" / "python")]).discover()
        names = {a.name for a in assets}
        assert names == {"good", "alsoGood"}


# ---------------------------------------------------------------------------
# 4. Empty / absent
# ---------------------------------------------------------------------------


class TestEmptyAndAbsent:
    def test_no_candidates_returns_empty(self) -> None:
        assert _src([]).discover() == []

    def test_venv_with_no_packages_returns_empty(self, tmp_path: Path) -> None:
        venv_root = _make_fake_venv(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[],
        ):
            assets = _src([("system", venv_root / "bin" / "python")]).discover()
        assert assets == []


# ---------------------------------------------------------------------------
# 5. Asset.id stability (memory project_asset_id_must_be_stable_digest.md)
# ---------------------------------------------------------------------------


class TestAssetIdStability:
    def test_same_inputs_same_id(self, tmp_path: Path) -> None:
        venv_root = _make_fake_venv(tmp_path)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[{"name": "requests", "version": "2.31.0"}],
        ):
            a1 = _src([("system", venv_root / "bin" / "python")]).discover()[0]
            a2 = _src([("system", venv_root / "bin" / "python")]).discover()[0]
        assert a1.id == a2.id
        assert a1.id.startswith("python-pkg-")

    def test_asset_id_uses_sha256_not_builtin_hash(self, tmp_path: Path) -> None:
        """Subprocess test with PYTHONHASHSEED=12345 — same as P3.1/P3.2.
        Built-in hash() would vary; sha256 is stable."""
        venv_root = _make_fake_venv(tmp_path)
        python_bin = venv_root / "bin" / "python"

        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[{"name": "requests", "version": "2.31.0"}],
        ):
            expected_id = _src([("system", python_bin)]).discover()[0].id

        script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / "src")!r})
from pathlib import Path
from unittest.mock import patch
from claude_monitoring.attack_surface.discovery.sources.python_packages import (
    PythonPackagesSource,
)
with patch(
    "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
    return_value=[{{"name": "requests", "version": "2.31.0"}}],
):
    src = PythonPackagesSource(
        venv_candidates=[("system", Path({str(python_bin)!r}))]
    )
    a = src.discover()[0]
print(a.id)
"""
        env = dict(os.environ)
        env["PYTHONHASHSEED"] = "12345"
        result = subprocess.run(
            [sys.executable, "-c", script],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        assert result.stdout.strip() == expected_id, (
            "id varies under PYTHONHASHSEED — source is using built-in hash() instead of hashlib.sha256."
        )

    def test_same_package_two_venvs_distinct_ids(self, tmp_path: Path) -> None:
        """The same package installed in two different venvs produces
        TWO distinct assets (separate installations on disk)."""
        v1 = _make_fake_venv(tmp_path, "v1")
        v2 = _make_fake_venv(tmp_path, "v2")
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[{"name": "requests", "version": "2.31.0"}],
        ):
            assets = _src(
                [
                    ("v1", v1 / "bin" / "python"),
                    ("v2", v2 / "bin" / "python"),
                ]
            ).discover()
        ids = {a.id for a in assets}
        assert len(ids) == 2

    def test_version_NOT_in_digest_so_updates_upsert(self, tmp_path: Path) -> None:
        """Per MCP + P3.1 + P3.2 precedent: version excluded from digest
        so an upgrade produces the SAME id."""
        venv_root = _make_fake_venv(tmp_path)
        python_bin = venv_root / "bin" / "python"
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[{"name": "requests", "version": "2.31.0"}],
        ):
            a_v1 = _src([("system", python_bin)]).discover()[0]
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[{"name": "requests", "version": "2.32.0"}],
        ):
            a_v2 = _src([("system", python_bin)]).discover()[0]
        assert a_v1.id == a_v2.id, "version must NOT be in digest"
        assert a_v1.version != a_v2.version


# ---------------------------------------------------------------------------
# 6. Binary-trust boundary (Phase A §3a — load-bearing)
# ---------------------------------------------------------------------------


class TestBinaryTrustBoundary:
    """A discovered python binary outside the ratified prefixes
    (`Path.home()`, `/opt/homebrew/`, `/usr/local/`) MUST NOT be exec'd.
    Defends against a symlink-escape or a candidate path that slipped
    through default-candidate-generation by accident.
    """

    def test_default_candidates_only_yield_paths_under_ratified_prefixes(self) -> None:
        """All default-generated candidates are under Path.home() OR
        /opt/homebrew/ OR /usr/local/. Sanity check on the default
        generator — proves it doesn't leak arbitrary system paths."""
        from claude_monitoring.attack_surface.discovery.sources.python_packages import (
            _default_venv_candidates,
        )

        candidates = _default_venv_candidates()
        home = str(Path.home())
        for _label, py_bin in candidates:
            s = str(py_bin)
            assert (
                s.startswith(home) or s.startswith("/opt/homebrew") or s.startswith("/usr/local") or s == sys.executable
            ), f"candidate {s} is not under a ratified prefix"


# ---------------------------------------------------------------------------
# 7. Empirical gate
# ---------------------------------------------------------------------------


class TestEmpirical:
    def test_empirical_system_python_lists_at_least_pip_itself(self) -> None:
        """sys.executable's pip ALWAYS knows about itself ('pip' package).
        Smoke test the real subprocess path end-to-end (no mocks)."""
        # Use ONLY sys.executable; skip the default candidate list to
        # keep this test fast and deterministic.
        src = PythonPackagesSource(venv_candidates=[("system", Path(sys.executable))])
        assets = src.discover()
        assert len(assets) >= 1
        names = {a.current_state["package_name_normalized"] for a in assets}
        assert "pip" in names, (
            f"sys.executable's pip list should include 'pip' itself; got names: {sorted(names)[:10]}..."
        )


# ---------------------------------------------------------------------------
# 8. Registration in REGISTERED_SOURCES (P2.2-gate)
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_source_appears_in_mapping_registry(self) -> None:
        from claude_monitoring.attack_surface.ontology import mapping

        assert "python-packages" in mapping._REGISTRY

    def test_mapper_returns_frozenset(self) -> None:
        from claude_monitoring.attack_surface.asset import Asset
        from claude_monitoring.attack_surface.ontology.mapping import (
            map_python_package,
        )

        asset = Asset(
            id="python-pkg-test",
            type="python_package",
            parent_asset_id=None,
            name="requests",
            version="2.31.0",
            install_path="/tmp/x",
            source="python-packages",
            current_state={
                "venv_label": "system",
                "package_name_normalized": "requests",
            },
            discovered_at=time.time(),
        )
        result = map_python_package(asset)
        assert isinstance(result, frozenset)


# ---------------------------------------------------------------------------
# 9. Outcome reporting
# ---------------------------------------------------------------------------


class TestOutcomeReporting:
    def test_outcome_success_after_empty_run(self) -> None:
        src = _src([])
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_outcome_success_after_partial_skip(self, tmp_path: Path) -> None:
        v1 = _make_fake_venv(tmp_path, "bad")
        v2 = _make_fake_venv(tmp_path, "ok")

        def fake_list(python_bin):
            if "bad" in str(python_bin):
                raise RuntimeError("broken")
            return [{"name": "requests", "version": "2.31.0"}]

        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            side_effect=fake_list,
        ):
            src = _src(
                [
                    ("bad", v1 / "bin" / "python"),
                    ("ok", v2 / "bin" / "python"),
                ]
            )
            src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS


# ---------------------------------------------------------------------------
# 10. Coexistence with legacy supply_chain pip flow (regression net)
# ---------------------------------------------------------------------------


class TestCoexistenceWithLegacy:
    """Verifies P3.3 does NOT break the v0.2.1 supply_chain pip discovery
    path (which writes to environment_packages table) or any downstream
    that depends on supply_chain.get_pip_packages() / get_full_environment().

    The existing pins live at:
      - tests/test_supply_chain.py:448 test_get_pip_packages_uses_sys_executable
      - tests/test_vuln_scanner.py:336+369 (vuln_scanner ↔ supply_chain wiring)

    This test class adds an INTEGRATION pin: both flows must coexist in
    the same process without mutual interference (no monkey-patching of
    subprocess.run at import time, no module-level state collision).
    """

    def test_legacy_get_pip_packages_signature_unchanged(self) -> None:
        """The legacy function MUST keep its no-arg signature so existing
        callers (vuln_scanner.run_full_scan) continue to work without
        modification."""
        import inspect

        from claude_monitoring import supply_chain

        sig = inspect.signature(supply_chain.get_pip_packages)
        assert len(sig.parameters) == 0, (
            f"supply_chain.get_pip_packages() must keep its no-arg signature; got params: {list(sig.parameters)}"
        )

    def test_legacy_get_pip_packages_return_shape_unchanged(self) -> None:
        """The legacy function must still return list[{name,version,manager:'pip'}]."""
        from unittest.mock import patch

        from claude_monitoring import supply_chain

        def fake_run(cmd, **kw):
            class R:
                stdout = '[{"name": "requests", "version": "2.31.0"}]'

            return R()

        with patch("claude_monitoring.supply_chain.subprocess.run", side_effect=fake_run):
            result = supply_chain.get_pip_packages()
        assert result == [{"name": "requests", "version": "2.31.0", "manager": "pip"}]

    def test_both_flows_coexist_in_same_process(self, tmp_path: Path) -> None:
        """Invoke legacy AND new flows in the same process; both must
        succeed without mutual interference (no module-level state
        collision, no shared mocks leaking)."""
        from unittest.mock import patch

        from claude_monitoring import supply_chain

        def fake_run(cmd, **kw):
            class R:
                stdout = '[{"name": "requests", "version": "2.31.0"}]'

            return R()

        venv_root = _make_fake_venv(tmp_path)
        with patch("claude_monitoring.supply_chain.subprocess.run", side_effect=fake_run):
            legacy_result = supply_chain.get_pip_packages()

        with patch(
            "claude_monitoring.attack_surface.discovery.sources.python_packages.list_pip_packages",
            return_value=[{"name": "requests", "version": "2.31.0"}],
        ):
            new_assets = _src([("system", venv_root / "bin" / "python")]).discover()

        assert legacy_result == [{"name": "requests", "version": "2.31.0", "manager": "pip"}]
        assert len(new_assets) == 1
        assert new_assets[0].name == "requests"
        assert new_assets[0].source == "python-packages"


# ---------------------------------------------------------------------------
# 11. list_pip_packages helper contract (helpers.py)
# ---------------------------------------------------------------------------


class TestListPipPackagesHelper:
    """Pins the new helpers.list_pip_packages(python_bin) contract.
    The helper is the only place that knows the pip invocation shape;
    both P3.3 and the future legacy-cleanup PR will route through it."""

    def test_helper_is_importable_from_helpers_module(self) -> None:
        from claude_monitoring.attack_surface.discovery.helpers import (
            list_pip_packages,
        )

        assert callable(list_pip_packages)

    def test_helper_uses_argv_list_not_shell(self, tmp_path: Path) -> None:
        """The helper must call subprocess via safe_subprocess (argv list).
        Pins the launchd-safe invocation shape."""
        from claude_monitoring.attack_surface.discovery import helpers

        captured: list[list[str]] = []

        class R:
            returncode = 0
            stdout = '[{"name": "requests", "version": "2.31.0"}]'
            stderr = ""

        def fake_run(argv, **kw):
            captured.append(argv)
            assert kw.get("shell") is False, "shell=False is the security control"
            return R()

        with patch.object(helpers.subprocess, "run", side_effect=fake_run):
            packages = helpers.list_pip_packages(Path("/usr/bin/python3"))
        assert captured, "subprocess.run was never called"
        assert captured[0][0] == "/usr/bin/python3"
        assert captured[0][1:5] == ["-m", "pip", "list", "--format=json"]
        assert packages == [{"name": "requests", "version": "2.31.0"}]

    def test_helper_raises_on_nonzero_returncode(self) -> None:
        """A broken pip (e.g., no pip module) returns non-zero; the
        helper raises so the source can catch + skip per-venv."""
        from claude_monitoring.attack_surface.discovery import helpers

        class R:
            returncode = 1
            stdout = ""
            stderr = "No module named pip"

        with patch.object(helpers.subprocess, "run", return_value=R()), pytest.raises(RuntimeError):
            helpers.list_pip_packages(Path("/usr/bin/python3"))

    def test_helper_raises_on_malformed_json(self) -> None:
        from claude_monitoring.attack_surface.discovery import helpers

        class R:
            returncode = 0
            stdout = "{not json"
            stderr = ""

        with patch.object(helpers.subprocess, "run", return_value=R()):
            with pytest.raises(json.JSONDecodeError):
                helpers.list_pip_packages(Path("/usr/bin/python3"))
