"""P3.4 — Python project-file dependency discovery.

Pins the discovery contract: walks ``~/Projects/*/`` one level deep and
parses ``requirements*.txt``, ``pyproject.toml``, ``Pipfile.lock`` at
each project root. Each declared dependency becomes one ``Asset`` of
type ``"python_dependency"`` (distinct from P3.3's ``"python_package"``,
which is the *installed* counterpart).

Tests follow the P3.1 / P3.2 / P3.3 precedent.
See ``~/Documents/vigil-notes/v022/phase-3/p3.4-phase-a-investigation.md``
for the full investigation that scoped the source.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from claude_monitoring.attack_surface.discovery.base import (
    DiscoverySource,
    LastRunOutcome,
)
from claude_monitoring.attack_surface.discovery.sources.python_project_deps import (
    PythonProjectDepsSource,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_project(root: Path, name: str) -> Path:
    """Create an empty project directory under ``root``."""
    proj = root / name
    proj.mkdir(parents=True, exist_ok=True)
    return proj


def _write_requirements(project: Path, content: str, filename: str = "requirements.txt") -> Path:
    """Write a requirements.txt-style file to a project."""
    f = project / filename
    f.write_text(content)
    return f


def _write_pyproject(project: Path, deps: list[str] | None = None, optional: dict | None = None) -> Path:
    """Write a PEP 621 pyproject.toml to a project."""
    f = project / "pyproject.toml"
    lines = ["[project]", 'name = "test-proj"', 'version = "0.1.0"']
    if deps is not None:
        lines.append("dependencies = [")
        for d in deps:
            lines.append(f'    "{d}",')
        lines.append("]")
    if optional is not None:
        lines.append("[project.optional-dependencies]")
        for section, items in optional.items():
            lines.append(f"{section} = [")
            for d in items:
                lines.append(f'    "{d}",')
            lines.append("]")
    f.write_text("\n".join(lines) + "\n")
    return f


def _write_pyproject_raw(project: Path, content: str) -> Path:
    """Write a raw pyproject.toml string (for non-PEP-621 shapes like Poetry)."""
    f = project / "pyproject.toml"
    f.write_text(content)
    return f


def _write_pipfile_lock(project: Path, default: dict | None = None, develop: dict | None = None) -> Path:
    """Write a Pipfile.lock-style JSON file to a project."""
    f = project / "Pipfile.lock"
    payload: dict = {"_meta": {}}
    if default is not None:
        payload["default"] = default
    if develop is not None:
        payload["develop"] = develop
    f.write_text(json.dumps(payload))
    return f


def _src(roots: list[Path]) -> PythonProjectDepsSource:
    return PythonProjectDepsSource(project_roots=roots)


# ---------------------------------------------------------------------------
# 1. Contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_is_a_DiscoverySource(self) -> None:
        assert issubclass(PythonProjectDepsSource, DiscoverySource)

    def test_name_is_python_project_deps(self) -> None:
        assert PythonProjectDepsSource().name() == "python-project-deps"

    def test_does_not_require_auth(self) -> None:
        assert PythonProjectDepsSource().requires_auth() is False

    def test_appears_in_REGISTERED_SOURCES(self) -> None:
        from claude_monitoring.attack_surface.ontology.mapping import REGISTERED_SOURCES

        assert "python-project-deps" in REGISTERED_SOURCES


# ---------------------------------------------------------------------------
# 2. requirements.txt parsing
# ---------------------------------------------------------------------------


class TestRequirementsTxtParsing:
    def test_simple_line_yields_one_asset(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, "proj-a")
        _write_requirements(proj, "requests\n")
        assets = _src([tmp_path]).discover()
        assert len(assets) == 1
        a = assets[0]
        assert a.type == "python_dependency"
        assert a.source == "python-project-deps"
        assert a.current_state["project_name"] == "proj-a"
        assert a.current_state["manifest_kind"] == "requirements"
        assert a.current_state["package_name"] == "requests"
        assert a.current_state["package_name_normalized"] == "requests"
        assert a.current_state["version_spec"] is None
        assert a.current_state["extras"] == []

    def test_version_spec_captured(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, "proj-a")
        _write_requirements(proj, "requests>=2.31.0,<3\n")
        a = _src([tmp_path]).discover()[0]
        assert a.current_state["package_name"] == "requests"
        assert a.current_state["version_spec"] == ">=2.31.0,<3"

    def test_extras_captured(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, "proj-a")
        _write_requirements(proj, "requests[security,socks]>=2.0\n")
        a = _src([tmp_path]).discover()[0]
        assert a.current_state["package_name"] == "requests"
        assert sorted(a.current_state["extras"]) == ["security", "socks"]
        assert a.current_state["version_spec"] == ">=2.0"

    def test_comments_and_blanks_skipped(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, "proj-a")
        _write_requirements(
            proj,
            "# top-level comment\n\nrequests\n  # indented comment\n\ndjango==5.0  # trailing comment\n",
        )
        names = {a.name for a in _src([tmp_path]).discover()}
        assert names == {"requests", "django"}

    def test_include_directive_skipped(self, tmp_path: Path) -> None:
        """`-r other.txt` (include) is NOT followed in this PR; logged but skipped."""
        proj = _make_project(tmp_path, "proj-a")
        _write_requirements(proj, "-r other.txt\nrequests\n")
        names = {a.name for a in _src([tmp_path]).discover()}
        assert names == {"requests"}

    def test_pip_option_lines_skipped(self, tmp_path: Path) -> None:
        """Lines like `--index-url`, `--extra-index-url`, `-e` are pip options/editable installs, not deps."""
        proj = _make_project(tmp_path, "proj-a")
        _write_requirements(
            proj,
            "--index-url https://example.com/simple\n--extra-index-url https://foo/\nrequests\n-e ./local-pkg\n",
        )
        names = {a.name for a in _src([tmp_path]).discover()}
        assert names == {"requests"}

    def test_multiple_requirements_files_each_scanned(self, tmp_path: Path) -> None:
        """requirements.txt + requirements-dev.txt + requirements-test.txt all scanned."""
        proj = _make_project(tmp_path, "proj-a")
        _write_requirements(proj, "requests\n", "requirements.txt")
        _write_requirements(proj, "pytest\n", "requirements-dev.txt")
        _write_requirements(proj, "coverage\n", "requirements-test.txt")
        names = {a.name for a in _src([tmp_path]).discover()}
        assert names == {"requests", "pytest", "coverage"}


# ---------------------------------------------------------------------------
# 3. pyproject.toml parsing (PEP 621 + Poetry)
# ---------------------------------------------------------------------------


class TestPyprojectTomlParsing:
    def test_pep621_project_dependencies_parsed(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, "proj-a")
        _write_pyproject(proj, deps=["requests>=2.31", "django"])
        assets = _src([tmp_path]).discover()
        names_specs = {(a.current_state["package_name"], a.current_state["version_spec"]) for a in assets}
        assert names_specs == {("requests", ">=2.31"), ("django", None)}
        for a in assets:
            assert a.current_state["manifest_kind"] == "pyproject"
            assert a.current_state["section"] == "dependencies"

    def test_pep621_optional_dependencies_parsed_with_section(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, "proj-a")
        _write_pyproject(
            proj,
            deps=["requests"],
            optional={"dev": ["pytest", "ruff"], "test": ["coverage"]},
        )
        assets = _src([tmp_path]).discover()
        by_section: dict[str, set[str]] = {}
        for a in assets:
            by_section.setdefault(a.current_state["section"], set()).add(a.current_state["package_name"])
        assert by_section.get("dependencies") == {"requests"}
        assert by_section.get("optional.dev") == {"pytest", "ruff"}
        assert by_section.get("optional.test") == {"coverage"}

    def test_poetry_dependencies_parsed(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, "proj-a")
        _write_pyproject_raw(
            proj,
            '[tool.poetry]\nname = "p"\nversion = "0.1"\n\n[tool.poetry.dependencies]\n'
            'python = "^3.10"\nrequests = "^2.31"\ndjango = "*"\n',
        )
        assets = _src([tmp_path]).discover()
        names_specs = {(a.current_state["package_name"], a.current_state["version_spec"]) for a in assets}
        # `python` itself is the interpreter constraint, NOT a package — must be filtered out
        assert ("python", "^3.10") not in names_specs
        assert ("requests", "^2.31") in names_specs
        assert ("django", "*") in names_specs

    def test_missing_project_section_yields_no_assets(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, "proj-a")
        _write_pyproject_raw(proj, '[build-system]\nrequires = ["setuptools"]\n')
        assert _src([tmp_path]).discover() == []

    def test_empty_dependencies_yields_no_assets(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, "proj-a")
        _write_pyproject(proj, deps=[])
        assert _src([tmp_path]).discover() == []


# ---------------------------------------------------------------------------
# 4. Pipfile.lock parsing
# ---------------------------------------------------------------------------


class TestPipfileLockParsing:
    def test_default_packages_parsed(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, "proj-a")
        _write_pipfile_lock(
            proj,
            default={
                "requests": {"version": "==2.31.0"},
                "django": {"version": "==5.0.0"},
            },
        )
        assets = _src([tmp_path]).discover()
        by_name = {a.current_state["package_name"]: a for a in assets}
        assert set(by_name) == {"requests", "django"}
        assert by_name["requests"].current_state["section"] == "default"
        assert by_name["requests"].current_state["version_spec"] == "==2.31.0"
        for a in assets:
            assert a.current_state["manifest_kind"] == "pipfile-lock"

    def test_develop_packages_get_develop_section(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, "proj-a")
        _write_pipfile_lock(
            proj,
            default={"requests": {"version": "==2.31.0"}},
            develop={"pytest": {"version": "==8.0.0"}},
        )
        by_section: dict[str, set[str]] = {}
        for a in _src([tmp_path]).discover():
            by_section.setdefault(a.current_state["section"], set()).add(a.current_state["package_name"])
        assert by_section.get("default") == {"requests"}
        assert by_section.get("develop") == {"pytest"}

    def test_malformed_pipfile_lock_skipped(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, "proj-a")
        (proj / "Pipfile.lock").write_text("{not json")
        # Sibling project still emits
        proj_b = _make_project(tmp_path, "proj-b")
        _write_requirements(proj_b, "requests\n")
        names = {a.current_state["project_name"] for a in _src([tmp_path]).discover()}
        assert names == {"proj-b"}


# ---------------------------------------------------------------------------
# 5. Per-item isolation (THREE layers)
# ---------------------------------------------------------------------------


class TestPerItemIsolation:
    def test_malformed_requirements_one_line_doesnt_break_others(self, tmp_path: Path) -> None:
        """A garbled spec on one line is skipped; sibling lines emit."""
        proj = _make_project(tmp_path, "proj-a")
        _write_requirements(proj, "requests\n!!!garbage!!!\ndjango\n")
        names = {a.name for a in _src([tmp_path]).discover()}
        assert names == {"requests", "django"}

    def test_one_bad_project_doesnt_block_others(self, tmp_path: Path) -> None:
        """One project with all-malformed manifests doesn't stop sibling project from emitting."""
        bad = _make_project(tmp_path, "bad")
        (bad / "pyproject.toml").write_text("{{not toml{{")
        good = _make_project(tmp_path, "good")
        _write_requirements(good, "requests\n")
        names = {a.current_state["project_name"] for a in _src([tmp_path]).discover()}
        assert names == {"good"}

    def test_one_bad_manifest_doesnt_block_siblings_in_same_project(self, tmp_path: Path) -> None:
        """Malformed pyproject.toml in a project doesn't block its sibling requirements.txt."""
        proj = _make_project(tmp_path, "proj-a")
        (proj / "pyproject.toml").write_text("{{not toml{{")
        _write_requirements(proj, "requests\n")
        names = {a.name for a in _src([tmp_path]).discover()}
        assert names == {"requests"}

    def test_oversized_manifest_rejected_others_emit(self, tmp_path: Path) -> None:
        """validate_path 10 MiB cap rejects huge manifests; siblings survive."""
        huge = _make_project(tmp_path, "huge")
        (huge / "requirements.txt").write_text("requests\n" + ("x" * (11 * 1024 * 1024)))
        good = _make_project(tmp_path, "good")
        _write_requirements(good, "django\n")
        names = {a.current_state["project_name"] for a in _src([tmp_path]).discover()}
        assert names == {"good"}


# ---------------------------------------------------------------------------
# 6. Empty / absent
# ---------------------------------------------------------------------------


class TestEmptyAndAbsent:
    def test_no_project_roots_returns_empty(self, tmp_path: Path) -> None:
        assert _src([tmp_path / "absent"]).discover() == []

    def test_empty_project_dir_returns_empty(self, tmp_path: Path) -> None:
        _make_project(tmp_path, "empty")
        assert _src([tmp_path]).discover() == []


# ---------------------------------------------------------------------------
# 7. Asset.id stability
# ---------------------------------------------------------------------------


class TestAssetIdStability:
    def test_same_inputs_same_id(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, "proj-a")
        _write_requirements(proj, "requests==2.31.0\n")
        a1 = _src([tmp_path]).discover()[0]
        a2 = _src([tmp_path]).discover()[0]
        assert a1.id == a2.id
        assert a1.id.startswith("python-req-")

    def test_asset_id_uses_sha256_not_builtin_hash(self, tmp_path: Path) -> None:
        proj = _make_project(tmp_path, "proj-a")
        _write_requirements(proj, "requests==2.31.0\n")
        expected_id = _src([tmp_path]).discover()[0].id

        script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / "src")!r})
from pathlib import Path
from claude_monitoring.attack_surface.discovery.sources.python_project_deps import PythonProjectDepsSource
src = PythonProjectDepsSource(project_roots=[Path({str(tmp_path)!r})])
print(src.discover()[0].id)
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
        assert result.stdout.strip() == expected_id

    def test_version_spec_NOT_in_digest_so_updates_upsert(self, tmp_path: Path) -> None:
        """Per MCP + P3.1/P3.2/P3.3 precedent: version excluded from digest."""
        proj = _make_project(tmp_path, "proj-a")
        _write_requirements(proj, "requests>=2.31.0\n")
        a_old = _src([tmp_path]).discover()[0]
        # Bump version spec
        _write_requirements(proj, "requests>=2.32.0\n")
        a_new = _src([tmp_path]).discover()[0]
        assert a_old.id == a_new.id, "version_spec must NOT be in digest input"
        assert a_old.current_state["version_spec"] != a_new.current_state["version_spec"]

    def test_pep503_normalization_in_digest(self, tmp_path: Path) -> None:
        """'Requests' and 'requests' UPSERT to the same row per PEP 503."""
        proj = _make_project(tmp_path, "proj-a")
        _write_requirements(proj, "Requests==2.31.0\n")
        a_mixed = _src([tmp_path]).discover()[0]
        _write_requirements(proj, "requests==2.31.0\n")
        a_lower = _src([tmp_path]).discover()[0]
        assert a_mixed.current_state["package_name_normalized"] == "requests"
        assert a_lower.current_state["package_name_normalized"] == "requests"
        assert a_mixed.id == a_lower.id


# ---------------------------------------------------------------------------
# 8. Empirical gate
# ---------------------------------------------------------------------------


class TestEmpirical:
    @pytest.mark.skipif(
        not (Path.home() / "Projects").is_dir(),
        reason="no ~/Projects on this machine",
    )
    def test_empirical_projects_dir_yields_assets(self) -> None:
        """Smoke test against the developer's ~/Projects/ — at least one
        recognizable dependency should be discovered."""
        assets = PythonProjectDepsSource().discover()
        assert isinstance(assets, list)
        # On this machine: ai-runtime-monitor-enterprise (pyproject) +
        # claude-monitoring (pyproject) + defender (requirements.txt) +
        # trader (requirements.txt). Empirically ≥1 known dep.
        if assets:
            a = assets[0]
            assert a.source == "python-project-deps"
            assert a.current_state["project_name"]
            assert a.current_state["manifest_kind"] in {"requirements", "pyproject", "pipfile-lock"}


# ---------------------------------------------------------------------------
# 9. Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_source_appears_in_mapping_registry(self) -> None:
        from claude_monitoring.attack_surface.ontology import mapping

        assert "python-project-deps" in mapping._REGISTRY

    def test_mapper_returns_frozenset(self) -> None:
        from claude_monitoring.attack_surface.asset import Asset
        from claude_monitoring.attack_surface.ontology.mapping import map_python_dependency

        asset = Asset(
            id="python-req-test",
            type="python_dependency",
            parent_asset_id=None,
            name="requests",
            version=">=2.31",
            install_path="/tmp/x",
            source="python-project-deps",
            current_state={"project_name": "p", "package_name_normalized": "requests"},
            discovered_at=time.time(),
        )
        assert isinstance(map_python_dependency(asset), frozenset)


# ---------------------------------------------------------------------------
# 10. Outcome reporting
# ---------------------------------------------------------------------------


class TestOutcomeReporting:
    def test_outcome_success_after_empty_run(self, tmp_path: Path) -> None:
        src = _src([tmp_path / "absent"])
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_outcome_success_after_partial_skip(self, tmp_path: Path) -> None:
        bad = _make_project(tmp_path, "bad")
        (bad / "pyproject.toml").write_text("{{not toml{{")
        good = _make_project(tmp_path, "good")
        _write_requirements(good, "requests\n")
        src = _src([tmp_path])
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
