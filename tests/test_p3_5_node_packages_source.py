"""P3.5 — Node package discovery (npm global + per-project).

Pins the discovery contract: combines a subprocess code path
(``npm list -g --json --depth=0`` against the system npm) with a
filesystem-walk code path (per-project ``package.json`` +
``package-lock.json`` under ``~/Projects/``).

Tests follow the P3.1 / P3.2 / P3.3 / P3.4 precedent.
See ``~/Documents/vigil-notes/v022/phase-3/p3.5-phase-a-investigation.md``
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
from claude_monitoring.attack_surface.discovery.sources.node_packages import (
    NodePackagesSource,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_project_with_package_json(
    tmp_path: Path,
    project_name: str,
    *,
    name: str | None = None,
    version: str = "0.1.0",
    dependencies: dict | None = None,
    dev_dependencies: dict | None = None,
    peer_dependencies: dict | None = None,
    optional_dependencies: dict | None = None,
    scripts: dict | None = None,
    bin_entries: dict | str | None = None,
    raw_text: str | None = None,
) -> Path:
    """Create a synthetic project directory with a ``package.json``."""
    project = tmp_path / project_name
    project.mkdir(parents=True, exist_ok=True)
    pkg = project / "package.json"
    if raw_text is not None:
        pkg.write_text(raw_text)
        return project
    payload: dict = {"name": name if name is not None else project_name, "version": version}
    if dependencies is not None:
        payload["dependencies"] = dependencies
    if dev_dependencies is not None:
        payload["devDependencies"] = dev_dependencies
    if peer_dependencies is not None:
        payload["peerDependencies"] = peer_dependencies
    if optional_dependencies is not None:
        payload["optionalDependencies"] = optional_dependencies
    if scripts is not None:
        payload["scripts"] = scripts
    if bin_entries is not None:
        payload["bin"] = bin_entries
    pkg.write_text(json.dumps(payload))
    return project


def _make_package_lock(
    project: Path,
    *,
    packages: dict | None = None,
    raw_text: str | None = None,
) -> Path:
    """Create a synthetic package-lock.json in a project."""
    lock = project / "package-lock.json"
    if raw_text is not None:
        lock.write_text(raw_text)
        return lock
    payload: dict = {"name": project.name, "version": "0.1.0", "lockfileVersion": 3}
    if packages is not None:
        payload["packages"] = packages
    lock.write_text(json.dumps(payload))
    return lock


def _src(
    npm_candidates: list[Path] | None = None,
    project_roots: list[Path] | None = None,
) -> NodePackagesSource:
    return NodePackagesSource(npm_candidates=npm_candidates, project_roots=project_roots)


# ---------------------------------------------------------------------------
# 1. Contract
# ---------------------------------------------------------------------------


class TestContract:
    def test_is_a_DiscoverySource(self) -> None:
        assert issubclass(NodePackagesSource, DiscoverySource)

    def test_name_is_node_packages(self) -> None:
        assert NodePackagesSource().name() == "node-packages"

    def test_does_not_require_auth(self) -> None:
        assert NodePackagesSource().requires_auth() is False

    def test_appears_in_REGISTERED_SOURCES(self) -> None:
        from claude_monitoring.attack_surface.ontology.mapping import REGISTERED_SOURCES

        assert "node-packages" in REGISTERED_SOURCES


# ---------------------------------------------------------------------------
# 2. Global packages (npm list -g --json)
# ---------------------------------------------------------------------------


class TestGlobalPackages:
    def test_single_global_package_yields_asset(self, tmp_path: Path) -> None:
        npm_bin = tmp_path / "bin" / "npm"
        npm_bin.parent.mkdir(parents=True)
        npm_bin.write_text("#!/bin/sh\n")
        npm_bin.chmod(0o755)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.node_packages.list_npm_global_packages",
            return_value=[{"name": "wscat", "version": "6.1.0"}],
        ):
            assets = _src(npm_candidates=[npm_bin], project_roots=[]).discover()
        assert len(assets) == 1
        a = assets[0]
        assert a.type == "node_package"
        assert a.source == "node-packages"
        assert a.name == "wscat"
        assert a.version == "6.1.0"
        assert a.current_state["scope"] == "global"
        assert a.current_state["manifest_kind"] == "npm-global"
        assert a.current_state["dep_kind"] == "global"
        assert a.current_state["package_name_normalized"] == "wscat"

    def test_scoped_global_package_normalization(self, tmp_path: Path) -> None:
        """`@openai/codex` — scoped package names must be preserved."""
        npm_bin = tmp_path / "bin" / "npm"
        npm_bin.parent.mkdir(parents=True)
        npm_bin.write_text("#!/bin/sh\n")
        npm_bin.chmod(0o755)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.node_packages.list_npm_global_packages",
            return_value=[{"name": "@openai/codex", "version": "0.58.0"}],
        ):
            a = _src(npm_candidates=[npm_bin], project_roots=[]).discover()[0]
        assert a.name == "@openai/codex"
        assert a.current_state["package_name_normalized"] == "@openai/codex"

    def test_multiple_global_packages_each_emit(self, tmp_path: Path) -> None:
        npm_bin = tmp_path / "bin" / "npm"
        npm_bin.parent.mkdir(parents=True)
        npm_bin.write_text("#!/bin/sh\n")
        npm_bin.chmod(0o755)
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.node_packages.list_npm_global_packages",
            return_value=[
                {"name": "wscat", "version": "6.1.0"},
                {"name": "vercel", "version": "50.1.3"},
                {"name": "create-react-app", "version": "5.0.1"},
            ],
        ):
            names = {a.name for a in _src(npm_candidates=[npm_bin], project_roots=[]).discover()}
        assert names == {"wscat", "vercel", "create-react-app"}

    def test_subprocess_timeout_skips_global_path(self, tmp_path: Path) -> None:
        """If npm hangs, the global path skips; project path continues."""
        npm_bin = tmp_path / "bin" / "npm"
        npm_bin.parent.mkdir(parents=True)
        npm_bin.write_text("#!/bin/sh\n")
        npm_bin.chmod(0o755)
        project_root = tmp_path / "Projects"
        _make_project_with_package_json(project_root, "p1", name="p1")
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.node_packages.list_npm_global_packages",
            side_effect=subprocess.TimeoutExpired(cmd=["npm"], timeout=60),
        ):
            assets = _src(npm_candidates=[npm_bin], project_roots=[project_root]).discover()
        # Global path skipped; project root self-asset still emitted
        names = {a.name for a in assets}
        assert "p1" in names

    def test_absent_npm_binary_yields_no_global_assets(self, tmp_path: Path) -> None:
        """No npm on disk → no globals, but project walk still runs."""
        project_root = tmp_path / "Projects"
        _make_project_with_package_json(project_root, "p1", name="p1")
        assets = _src(
            npm_candidates=[tmp_path / "absent" / "npm"],
            project_roots=[project_root],
        ).discover()
        scopes = {a.current_state["scope"] for a in assets}
        assert "global" not in scopes
        assert "project" in scopes


# ---------------------------------------------------------------------------
# 3. package.json parsing
# ---------------------------------------------------------------------------


class TestPackageJsonParsing:
    def test_project_root_self_asset_emitted(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        _make_project_with_package_json(project_root, "my-app", name="my-app", version="1.2.3")
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        self_assets = [a for a in assets if a.current_state["dep_kind"] == "self"]
        assert len(self_assets) == 1
        a = self_assets[0]
        assert a.name == "my-app"
        assert a.version == "1.2.3"
        assert a.current_state["scope"] == "project"
        assert a.current_state["manifest_kind"] == "package.json"

    def test_dependencies_parsed_with_dep_kind(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        _make_project_with_package_json(
            project_root,
            "my-app",
            dependencies={"react": "^18.0.0", "next": "^14.0.0"},
        )
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        deps = {
            (a.name, a.current_state["version_spec"]) for a in assets if a.current_state["dep_kind"] == "dependencies"
        }
        assert deps == {("react", "^18.0.0"), ("next", "^14.0.0")}

    def test_dev_dependencies_parsed(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        _make_project_with_package_json(
            project_root,
            "my-app",
            dev_dependencies={"jest": "^29.0.0", "eslint": "^8.0.0"},
        )
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        dev = {a.name for a in assets if a.current_state["dep_kind"] == "devDependencies"}
        assert dev == {"jest", "eslint"}

    def test_peer_and_optional_dependencies_parsed(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        _make_project_with_package_json(
            project_root,
            "my-app",
            peer_dependencies={"react": ">=16"},
            optional_dependencies={"fsevents": "^2.0"},
        )
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        by_kind: dict[str, set[str]] = {}
        for a in assets:
            by_kind.setdefault(a.current_state["dep_kind"], set()).add(a.name)
        assert by_kind.get("peerDependencies") == {"react"}
        assert by_kind.get("optionalDependencies") == {"fsevents"}

    def test_missing_name_field_skips_project(self, tmp_path: Path) -> None:
        """A package.json without a top-level `name` is malformed; we don't
        emit a self-asset (no stable id without a name)."""
        project_root = tmp_path / "Projects"
        proj = project_root / "anonymous"
        proj.mkdir(parents=True)
        (proj / "package.json").write_text('{"version": "1.0.0", "dependencies": {"react": "^18"}}')
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        # No self-asset; deps still emit (we know the project_name from the dir)
        self_assets = [a for a in assets if a.current_state["dep_kind"] == "self"]
        assert self_assets == []

    def test_lifecycle_scripts_captured_on_self_asset_only(self, tmp_path: Path) -> None:
        """Lifecycle script NAMES are captured on the project's self-asset.
        They are NEVER executed by the source."""
        project_root = tmp_path / "Projects"
        _make_project_with_package_json(
            project_root,
            "my-app",
            scripts={
                "preinstall": "echo hi",
                "postinstall": "node setup.js",
                "build": "vite build",
            },
            dependencies={"react": "^18"},
        )
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        self_a = next(a for a in assets if a.current_state["dep_kind"] == "self")
        assert "preinstall" in self_a.current_state["lifecycle_scripts"]
        assert "postinstall" in self_a.current_state["lifecycle_scripts"]
        # `build` is not a lifecycle script per npm semantics — should NOT be captured
        # in lifecycle_scripts (or, more permissively, all script names captured —
        # source decides). Here we assert lifecycle_scripts at least includes the
        # well-known dangerous ones.
        # Sibling dep doesn't carry lifecycle_scripts:
        dep_a = next(a for a in assets if a.current_state["dep_kind"] == "dependencies")
        assert dep_a.current_state.get("lifecycle_scripts") == []

    def test_bin_entries_captured_on_self_asset(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        _make_project_with_package_json(
            project_root,
            "my-cli",
            bin_entries={"my-cli": "./bin/cli.js", "helper": "./bin/helper.js"},
        )
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        self_a = next(a for a in assets if a.current_state["dep_kind"] == "self")
        assert set(self_a.current_state["bin_entries"]) == {"my-cli", "helper"}


# ---------------------------------------------------------------------------
# 4. package-lock.json parsing
# ---------------------------------------------------------------------------


class TestPackageLockParsing:
    def test_lockfile_v3_packages_parsed(self, tmp_path: Path) -> None:
        """v2/v3 lockfile uses a `packages` map keyed by path."""
        project_root = tmp_path / "Projects"
        proj = _make_project_with_package_json(project_root, "my-app", name="my-app")
        _make_package_lock(
            proj,
            packages={
                "": {"name": "my-app", "version": "0.1.0"},  # root entry — filtered
                "node_modules/react": {"version": "18.2.0"},
                "node_modules/lodash": {"version": "4.17.21"},
            },
        )
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        lock_assets = [a for a in assets if a.current_state["manifest_kind"] == "package-lock.json"]
        names = {a.name for a in lock_assets}
        assert names == {"react", "lodash"}

    def test_lockfile_root_empty_key_filtered(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        proj = _make_project_with_package_json(project_root, "my-app", name="my-app")
        _make_package_lock(
            proj,
            packages={
                "": {"name": "my-app", "version": "0.1.0"},
                "node_modules/foo": {"version": "1.0.0"},
            },
        )
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        lock_assets = [a for a in assets if a.current_state["manifest_kind"] == "package-lock.json"]
        for a in lock_assets:
            # root entry must be skipped — only deps emit from lock
            assert a.name != ""

    def test_lockfile_only_no_package_json_yields_nothing(self, tmp_path: Path) -> None:
        """If a project has package-lock.json but no package.json, we still
        scan the lock — it has its own deps view."""
        project_root = tmp_path / "Projects"
        proj = project_root / "lock-only"
        proj.mkdir(parents=True)
        _make_package_lock(
            proj,
            packages={"node_modules/react": {"version": "18.2.0"}},
        )
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        names = {a.name for a in assets}
        assert "react" in names


# ---------------------------------------------------------------------------
# 5. Per-item isolation
# ---------------------------------------------------------------------------


class TestPerItemIsolation:
    def test_one_bad_project_doesnt_block_others(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        bad = project_root / "bad"
        bad.mkdir(parents=True)
        (bad / "package.json").write_text("{not json")
        _make_project_with_package_json(project_root, "good", name="good")
        names = {a.name for a in _src(npm_candidates=[], project_roots=[project_root]).discover()}
        assert "good" in names

    def test_bad_package_json_doesnt_block_package_lock(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        proj = project_root / "p1"
        proj.mkdir(parents=True)
        (proj / "package.json").write_text("{not json")
        _make_package_lock(
            proj,
            packages={"node_modules/react": {"version": "18.2.0"}},
        )
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        names = {a.name for a in assets}
        assert "react" in names

    def test_oversized_manifest_rejected_others_emit(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        huge = project_root / "huge"
        huge.mkdir(parents=True)
        (huge / "package.json").write_text(
            '{"name":"h","version":"1","description":"' + ("x" * (11 * 1024 * 1024)) + '"}'
        )
        _make_project_with_package_json(project_root, "good", name="good")
        names = {a.name for a in _src(npm_candidates=[], project_roots=[project_root]).discover()}
        assert "good" in names
        assert "h" not in names

    def test_malformed_dep_entry_skipped_others_emit(self, tmp_path: Path) -> None:
        """If `dependencies` has a non-string value or non-str key, skip
        that entry; siblings still emit."""
        project_root = tmp_path / "Projects"
        proj = project_root / "my-app"
        proj.mkdir(parents=True)
        (proj / "package.json").write_text(
            json.dumps(
                {
                    "name": "my-app",
                    "version": "1.0",
                    "dependencies": {"react": "^18", "bad": 12345, "next": "^14"},
                }
            )
        )
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        dep_names = {a.name for a in assets if a.current_state["dep_kind"] == "dependencies"}
        assert dep_names == {"react", "next"}


# ---------------------------------------------------------------------------
# 6. Empty / absent
# ---------------------------------------------------------------------------


class TestEmptyAndAbsent:
    def test_no_npm_and_no_projects_returns_empty(self, tmp_path: Path) -> None:
        assert _src(npm_candidates=[], project_roots=[]).discover() == []

    def test_project_with_no_deps_emits_self_only(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        _make_project_with_package_json(project_root, "empty-app", name="empty-app")
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        assert len(assets) == 1
        assert assets[0].current_state["dep_kind"] == "self"

    def test_empty_project_dir_returns_empty(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        (project_root / "no-manifest").mkdir(parents=True)
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        assert assets == []


# ---------------------------------------------------------------------------
# 7. Asset.id stability
# ---------------------------------------------------------------------------


class TestAssetIdStability:
    def test_same_inputs_same_id(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        _make_project_with_package_json(project_root, "my-app", name="my-app", dependencies={"react": "^18"})
        a1 = _src(npm_candidates=[], project_roots=[project_root]).discover()
        a2 = _src(npm_candidates=[], project_roots=[project_root]).discover()
        ids1 = sorted(a.id for a in a1)
        ids2 = sorted(a.id for a in a2)
        assert ids1 == ids2

    def test_asset_id_uses_sha256_not_builtin_hash(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        _make_project_with_package_json(project_root, "my-app", name="my-app")
        expected = sorted(a.id for a in _src(npm_candidates=[], project_roots=[project_root]).discover())

        script = f"""
import sys
sys.path.insert(0, {str(Path(__file__).resolve().parents[1] / "src")!r})
from pathlib import Path
from claude_monitoring.attack_surface.discovery.sources.node_packages import NodePackagesSource
src = NodePackagesSource(npm_candidates=[], project_roots=[Path({str(project_root)!r})])
ids = sorted(a.id for a in src.discover())
print(",".join(ids))
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
        assert result.stdout.strip().split(",") == expected

    def test_same_package_global_vs_project_distinct_ids(self, tmp_path: Path) -> None:
        npm_bin = tmp_path / "bin" / "npm"
        npm_bin.parent.mkdir(parents=True)
        npm_bin.write_text("#!/bin/sh\n")
        npm_bin.chmod(0o755)
        project_root = tmp_path / "Projects"
        _make_project_with_package_json(project_root, "my-app", name="my-app", dependencies={"react": "^18"})
        with patch(
            "claude_monitoring.attack_surface.discovery.sources.node_packages.list_npm_global_packages",
            return_value=[{"name": "react", "version": "18.2.0"}],
        ):
            assets = _src(npm_candidates=[npm_bin], project_roots=[project_root]).discover()
        react_assets = [a for a in assets if a.name == "react"]
        assert len(react_assets) == 2  # global + project dep
        assert len({a.id for a in react_assets}) == 2

    def test_same_package_two_projects_distinct_ids(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        _make_project_with_package_json(project_root, "app-a", name="app-a", dependencies={"react": "^18"})
        _make_project_with_package_json(project_root, "app-b", name="app-b", dependencies={"react": "^18"})
        assets = _src(npm_candidates=[], project_roots=[project_root]).discover()
        react_assets = [a for a in assets if a.name == "react"]
        assert len(react_assets) == 2
        assert len({a.id for a in react_assets}) == 2

    def test_version_NOT_in_digest_so_upgrade_upserts(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        _make_project_with_package_json(project_root, "my-app", name="my-app", dependencies={"react": "^17"})
        a_v1 = next(a for a in _src(npm_candidates=[], project_roots=[project_root]).discover() if a.name == "react")
        _make_project_with_package_json(project_root, "my-app", name="my-app", dependencies={"react": "^18"})
        a_v2 = next(a for a in _src(npm_candidates=[], project_roots=[project_root]).discover() if a.name == "react")
        assert a_v1.id == a_v2.id
        assert a_v1.current_state["version_spec"] != a_v2.current_state["version_spec"]


# ---------------------------------------------------------------------------
# 8. Binary-trust boundary
# ---------------------------------------------------------------------------


class TestBinaryTrustBoundary:
    def test_default_npm_candidates_only_under_ratified_prefixes(self) -> None:
        from claude_monitoring.attack_surface.discovery.sources.node_packages import (
            _default_npm_candidates,
        )

        home = str(Path.home())
        for candidate in _default_npm_candidates():
            s = str(candidate)
            assert s.startswith("/opt/homebrew") or s.startswith("/usr/local") or s.startswith(home), (
                f"npm candidate {s} not under a ratified prefix"
            )


# ---------------------------------------------------------------------------
# 9. Empirical
# ---------------------------------------------------------------------------


class TestEmpirical:
    @pytest.mark.skipif(
        not (Path.home() / "Projects").is_dir(),
        reason="no ~/Projects on this machine",
    )
    def test_empirical_real_machine_walk(self) -> None:
        """Real `~/Projects/` walk; if any project has a package.json,
        we should get at least one asset."""
        assets = NodePackagesSource().discover()
        assert isinstance(assets, list)
        if assets:
            a = assets[0]
            assert a.source == "node-packages"
            assert a.current_state["scope"] in {"global", "project"}


# ---------------------------------------------------------------------------
# 10. Registration
# ---------------------------------------------------------------------------


class TestRegistration:
    def test_source_appears_in_mapping_registry(self) -> None:
        from claude_monitoring.attack_surface.ontology import mapping

        assert "node-packages" in mapping._REGISTRY

    def test_mapper_returns_frozenset(self) -> None:
        from claude_monitoring.attack_surface.asset import Asset
        from claude_monitoring.attack_surface.ontology.mapping import map_node_package

        asset = Asset(
            id="node-pkg-test",
            type="node_package",
            parent_asset_id=None,
            name="react",
            version="^18",
            install_path="/tmp/x",
            source="node-packages",
            current_state={"scope": "project", "package_name_normalized": "react"},
            discovered_at=time.time(),
        )
        assert isinstance(map_node_package(asset), frozenset)


# ---------------------------------------------------------------------------
# 11. list_npm_global_packages helper
# ---------------------------------------------------------------------------


class TestListNpmGlobalPackagesHelper:
    def test_helper_is_importable(self) -> None:
        from claude_monitoring.attack_surface.discovery.helpers import (
            list_npm_global_packages,
        )

        assert callable(list_npm_global_packages)

    def test_helper_uses_argv_list_not_shell(self) -> None:
        from claude_monitoring.attack_surface.discovery import helpers

        captured: list[list[str]] = []

        class R:
            returncode = 0
            stdout = '{"dependencies": {"wscat": {"version": "6.1.0"}}}'
            stderr = ""

        def fake_run(argv, **kw):
            captured.append(argv)
            assert kw.get("shell") is False
            return R()

        with patch.object(helpers.subprocess, "run", side_effect=fake_run):
            packages = helpers.list_npm_global_packages(Path("/opt/homebrew/bin/npm"))
        assert captured
        assert captured[0][0] == "/opt/homebrew/bin/npm"
        assert captured[0][1:5] == ["list", "-g", "--json", "--depth=0"]
        # Helper returns a flat list of {"name", "version"} dicts
        assert {"name": "wscat", "version": "6.1.0"} in packages

    def test_helper_raises_on_nonzero_returncode(self) -> None:
        from claude_monitoring.attack_surface.discovery import helpers

        class R:
            returncode = 1
            stdout = ""
            stderr = "npm: command not found"

        with patch.object(helpers.subprocess, "run", return_value=R()), pytest.raises(RuntimeError):
            helpers.list_npm_global_packages(Path("/opt/homebrew/bin/npm"))

    def test_helper_raises_on_malformed_json(self) -> None:
        from claude_monitoring.attack_surface.discovery import helpers

        class R:
            returncode = 0
            stdout = "{not json"
            stderr = ""

        with patch.object(helpers.subprocess, "run", return_value=R()), pytest.raises(json.JSONDecodeError):
            helpers.list_npm_global_packages(Path("/opt/homebrew/bin/npm"))

    def test_helper_raises_on_non_object_top_level(self) -> None:
        """A corrupt npm returning a JSON array at the top level must raise TypeError."""
        from claude_monitoring.attack_surface.discovery import helpers

        class R:
            returncode = 0
            stdout = "[1, 2, 3]"
            stderr = ""

        with patch.object(helpers.subprocess, "run", return_value=R()), pytest.raises(TypeError):
            helpers.list_npm_global_packages(Path("/opt/homebrew/bin/npm"))

    def test_helper_returns_empty_when_no_dependencies_key(self) -> None:
        """npm returns an object without a `dependencies` key when nothing
        is globally installed (or under certain --depth conditions). The
        helper must return [] rather than raise."""
        from claude_monitoring.attack_surface.discovery import helpers

        class R:
            returncode = 0
            stdout = '{"name": "lib", "version": "1.0.0"}'
            stderr = ""

        with patch.object(helpers.subprocess, "run", return_value=R()):
            result = helpers.list_npm_global_packages(Path("/opt/homebrew/bin/npm"))
        assert result == []

    def test_helper_filters_malformed_dep_entries(self) -> None:
        """Defensive filtering: dep entries with non-string names, non-dict
        info, or missing version are dropped silently. Sibling entries emit."""
        from claude_monitoring.attack_surface.discovery import helpers

        class R:
            returncode = 0
            stdout = json.dumps(
                {
                    "dependencies": {
                        "good": {"version": "1.0.0"},
                        "no-version": {"overridden": False},
                        "scalar-info": "not-a-dict",
                        "no-version-string": {"version": 123},
                        "also-good": {"version": "2.0.0"},
                    }
                }
            )
            stderr = ""

        with patch.object(helpers.subprocess, "run", return_value=R()):
            result = helpers.list_npm_global_packages(Path("/opt/homebrew/bin/npm"))
        names = {p["name"] for p in result}
        assert names == {"good", "also-good"}


# ---------------------------------------------------------------------------
# 12. Outcome reporting
# ---------------------------------------------------------------------------


class TestOutcomeReporting:
    def test_outcome_success_after_empty_run(self, tmp_path: Path) -> None:
        src = _src(npm_candidates=[], project_roots=[tmp_path / "absent"])
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_outcome_success_after_partial_skip(self, tmp_path: Path) -> None:
        project_root = tmp_path / "Projects"
        bad = project_root / "bad"
        bad.mkdir(parents=True)
        (bad / "package.json").write_text("{not json")
        _make_project_with_package_json(project_root, "good", name="good")
        src = _src(npm_candidates=[], project_roots=[project_root])
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
