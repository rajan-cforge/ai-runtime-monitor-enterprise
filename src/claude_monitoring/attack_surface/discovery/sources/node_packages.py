"""Node package discovery — P3.5.

Combines a subprocess code path (``npm list -g --json --depth=0`` against
the system npm) with a filesystem-walk code path (per-project
``package.json`` + ``package-lock.json`` under ``~/Projects/``).

Each discovered package becomes one :class:`Asset` of type
``"node_package"``. ``current_state.scope`` distinguishes
``"global"`` vs ``"project"``, and ``current_state.dep_kind``
distinguishes the dep relationship (``"global"``, ``"self"``,
``"dependencies"``, ``"devDependencies"``, ``"peerDependencies"``,
``"optionalDependencies"``).

**Locked refs:**

- directive §3 P3.5 — "Node package discovery (global + per-detected-project).
  ``npm list -g --json`` + per-project ``package.json`` + ``package-lock.json``."
- memory ``project_v022_per_item_isolation.md`` — multi-layer per-item isolation
- memory ``project_asset_id_must_be_stable_digest.md`` — ``hashlib.sha256``,
  NOT Python's built-in ``hash()``
- memory ``project_billion_laughs_detonation_site.md`` — ``validate_path``
  10 MiB size cap on every manifest before read

**Source name:** ``"node-packages"`` (kebab-case).

**Asset.id digest input:**

- Global packages: ``sha256("npm-global"|name_normalized|node_modules_root)``
- Project packages: ``sha256(project_name|manifest_kind|name_normalized|spec_path)``

Both prefixed ``node-pkg-``. ``version`` is EXCLUDED so upgrades UPSERT
(matches MCP + all prior Phase-3 precedent). Lowercase normalization for
case-insensitive npm names.

**Binary-trust boundary (Phase A §3a — load-bearing, mirrors P3.3):**
the npm binary is discovered on disk and exec'd. Defense: candidate
generation is restricted to ratified prefixes (``/opt/homebrew/``,
``/usr/local/``, ``Path.home()``). A `shutil.which("npm")` fallback
that resolves outside ratified prefixes is dropped.

**Redaction:** NOT performed. ``package.json`` and ``package-lock.json``
carry structural metadata only. ``.npmrc`` (registry auth tokens) and
``.env*`` files are EXPLICITLY out of scope and must NOT be read.

**Lifecycle scripts:** captured as a list of NAME strings (e.g.,
``["preinstall", "postinstall"]``) on the project's self-asset. They
are NEVER executed by this source — they're data for P3.8 to flag.
"""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
import time
from pathlib import Path

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import DiscoverySource
from claude_monitoring.attack_surface.discovery.helpers import (
    list_npm_global_packages,
    validate_path,
)

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.node_packages")


SOURCE_NAME = "node-packages"
MAX_MANIFEST_MB = 10.0

# npm's well-known lifecycle script names per the npm docs. Other script
# keys in `scripts` are user-defined (e.g., "build", "dev") and not
# automatically run by `npm install` / `npm uninstall`. We surface the
# automatic ones explicitly because they are the code-execution risk.
_NPM_LIFECYCLE_SCRIPTS = frozenset(
    {
        "preinstall",
        "install",
        "postinstall",
        "prepublish",
        "preprepare",
        "prepare",
        "postprepare",
        "preuninstall",
        "uninstall",
        "postuninstall",
        "preversion",
        "version",
        "postversion",
        "pretest",
        "test",
        "posttest",
        "prestop",
        "stop",
        "poststop",
        "prestart",
        "start",
        "poststart",
        "prerestart",
        "restart",
        "postrestart",
        "preshrinkwrap",
        "shrinkwrap",
        "postshrinkwrap",
    }
)

# Ratified absolute prefixes for the npm binary-trust boundary.
_RATIFIED_NPM_PREFIXES = (
    Path("/opt/homebrew"),
    Path("/usr/local"),
    Path.home(),
)


def _is_under_ratified_prefix(candidate: Path) -> bool:
    """True iff ``candidate`` resolves under one of the ratified prefixes."""
    try:
        resolved = candidate.resolve()
    except OSError:
        return False
    for prefix in _RATIFIED_NPM_PREFIXES:
        try:
            resolved.relative_to(prefix)
            return True
        except ValueError:
            continue
    return False


def _default_npm_candidates() -> list[Path]:
    """Production defaults: well-known npm install locations, plus a
    `shutil.which` fallback gated by the ratified-prefix check."""
    candidates: list[Path] = []
    for static_path in (Path("/opt/homebrew/bin/npm"), Path("/usr/local/bin/npm")):
        if static_path.exists():
            candidates.append(static_path)
    which_result = shutil.which("npm")
    if which_result:
        which_path = Path(which_result)
        if _is_under_ratified_prefix(which_path) and which_path not in candidates:
            candidates.append(which_path)
    return candidates


def _default_project_roots() -> list[Path]:
    """Production defaults: scan ``~/Projects/`` one level deep."""
    return [Path.home() / "Projects"]


def _normalize_npm(name: str) -> str:
    """Case-insensitive normalization for digest stability. npm itself is
    case-sensitive in registry, but our digest key normalizes for the same
    reason PEP 503 does (avoid double-row on a case typo)."""
    return name.lower()


class NodePackagesSource(DiscoverySource):
    """Discovers Node.js packages: globally-installed (npm) + per-project
    ``package.json`` / ``package-lock.json`` declarations."""

    def __init__(
        self,
        npm_candidates: list[Path] | None = None,
        project_roots: list[Path] | None = None,
    ) -> None:
        """Args:
        npm_candidates: Optional override list of npm binary paths.
            Default is ``[/opt/homebrew/bin/npm, /usr/local/bin/npm]``
            plus a `shutil.which` fallback gated by ratified-prefix check.
        project_roots: Optional override list of project-root directories.
            Default is ``[~/Projects]``. Each root is walked depth-1.
        """
        self._npm_candidates = npm_candidates if npm_candidates is not None else _default_npm_candidates()
        self._project_roots = project_roots if project_roots is not None else _default_project_roots()

    def name(self) -> str:
        """Return the registered source identifier."""
        return SOURCE_NAME

    def requires_auth(self) -> bool:
        """Filesystem walk + npm subprocess; no authentication required."""
        return False

    def discover(self) -> list[Asset]:
        """Run the global path then the project path; return all assets."""
        assets: list[Asset] = []
        assets.extend(self._discover_global())
        assets.extend(self._discover_projects())
        return assets

    def _discover_global(self) -> list[Asset]:
        """Invoke ``npm list -g --json --depth=0`` against the first
        existing npm candidate. Per-item isolation: subprocess failures
        skip the global path without affecting the project walk."""
        out: list[Asset] = []
        for npm_bin in self._npm_candidates:
            try:
                if not npm_bin.exists():
                    continue
            except OSError:
                continue
            try:
                packages = list_npm_global_packages(npm_bin)
            except Exception as exc:
                logger.warning(
                    "node-packages: global path skipped (%s) — %s",
                    npm_bin,
                    exc,
                )
                return []
            # node_modules root inferred from npm path: e.g.,
            # /opt/homebrew/bin/npm → /opt/homebrew/lib/node_modules
            node_modules_root = str(npm_bin.parent.parent / "lib" / "node_modules")
            for pkg in packages:
                name = pkg.get("name")
                version = pkg.get("version")
                if not isinstance(name, str) or not isinstance(version, str):
                    continue
                out.append(
                    self._make_global_asset(
                        name=name,
                        version=version,
                        node_modules_root=node_modules_root,
                    )
                )
            return out  # first usable npm wins
        return out

    def _discover_projects(self) -> list[Asset]:
        """Walk each project root depth-1; parse package.json + package-lock.json."""
        out: list[Asset] = []
        for root in self._project_roots:
            try:
                if not root.is_dir():
                    continue
            except OSError:
                continue
            try:
                projects = sorted(root.iterdir())
            except OSError as exc:
                logger.warning("node-packages: cannot list %s — %s", root, exc)
                continue
            for project in projects:
                if project.name.startswith("."):
                    continue
                try:
                    if not project.is_dir():
                        continue
                except OSError:
                    continue
                out.extend(self._scan_project(project))
        return out

    def _scan_project(self, project: Path) -> list[Asset]:
        out: list[Asset] = []
        # package.json
        pkg_json = project / "package.json"
        if pkg_json.is_file():
            try:
                out.extend(self._parse_package_json(project, pkg_json))
            except Exception as exc:
                logger.warning(
                    "node-packages: skipping %s/package.json — %s",
                    project.name,
                    exc,
                )
        # package-lock.json
        lock = project / "package-lock.json"
        if lock.is_file():
            try:
                out.extend(self._parse_package_lock(project, lock))
            except Exception as exc:
                logger.warning(
                    "node-packages: skipping %s/package-lock.json — %s",
                    project.name,
                    exc,
                )
        return out

    @staticmethod
    def _read_capped(path: Path, *, root: Path) -> str:
        validate_path(path, root=root, check_size=True, max_size_mb=MAX_MANIFEST_MB)
        return path.read_text(errors="replace")

    def _parse_package_json(self, project: Path, pkg_json: Path) -> list[Asset]:
        raw = self._read_capped(pkg_json, root=project)
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise TypeError("package.json top-level is not an object")
        out: list[Asset] = []

        # Project self-asset (only if `name` present)
        self_name = data.get("name")
        if isinstance(self_name, str) and self_name:
            self_version = data.get("version")
            self_version = self_version if isinstance(self_version, str) else None
            scripts = data.get("scripts")
            if isinstance(scripts, dict):
                lifecycle_scripts = sorted(k for k in scripts if isinstance(k, str) and k in _NPM_LIFECYCLE_SCRIPTS)
            else:
                lifecycle_scripts = []
            bin_field = data.get("bin")
            if isinstance(bin_field, dict):
                bin_entries = sorted(k for k in bin_field if isinstance(k, str))
            elif isinstance(bin_field, str):
                # `"bin": "./cli.js"` form → single entry keyed by self_name
                bin_entries = [self_name]
            else:
                bin_entries = []
            out.append(
                self._make_project_asset(
                    project=project,
                    manifest_path=pkg_json,
                    manifest_kind="package.json",
                    name=self_name,
                    version_spec=self_version,
                    dep_kind="self",
                    lifecycle_scripts=lifecycle_scripts,
                    bin_entries=bin_entries,
                )
            )

        # Each dependency map → one asset per entry
        for field, dep_kind in (
            ("dependencies", "dependencies"),
            ("devDependencies", "devDependencies"),
            ("peerDependencies", "peerDependencies"),
            ("optionalDependencies", "optionalDependencies"),
        ):
            section = data.get(field)
            if not isinstance(section, dict):
                continue
            for name, spec in section.items():
                if not isinstance(name, str) or not isinstance(spec, str):
                    continue
                out.append(
                    self._make_project_asset(
                        project=project,
                        manifest_path=pkg_json,
                        manifest_kind="package.json",
                        name=name,
                        version_spec=spec,
                        dep_kind=dep_kind,
                        lifecycle_scripts=[],
                        bin_entries=[],
                    )
                )
        return out

    def _parse_package_lock(self, project: Path, lock: Path) -> list[Asset]:
        raw = self._read_capped(lock, root=project)
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise TypeError("package-lock.json top-level is not an object")
        out: list[Asset] = []
        packages = data.get("packages")
        if not isinstance(packages, dict):
            return out
        for key, info in packages.items():
            # Root entry is keyed by empty string per lockfile v2/v3 spec
            if key == "" or not isinstance(key, str):
                continue
            if not isinstance(info, dict):
                continue
            # Lockfile entries: key is e.g. "node_modules/react"; extract package name
            # as the last path segment (handles scoped packages too —
            # "node_modules/@scope/pkg" → "@scope/pkg" is the relevant identity).
            if "node_modules/" in key:
                _, _, after = key.partition("node_modules/")
                # Last "node_modules/" wins for nested deps
                while "node_modules/" in after:
                    _, _, after = after.partition("node_modules/")
                pkg_name = after
            else:
                pkg_name = key
            if not pkg_name:
                continue
            version = info.get("version")
            if not isinstance(version, str):
                continue
            out.append(
                self._make_project_asset(
                    project=project,
                    manifest_path=lock,
                    manifest_kind="package-lock.json",
                    name=pkg_name,
                    version_spec=version,
                    dep_kind="dependencies",
                    lifecycle_scripts=[],
                    bin_entries=[],
                )
            )
        return out

    @staticmethod
    def _make_global_asset(*, name: str, version: str, node_modules_root: str) -> Asset:
        name_normalized = _normalize_npm(name)
        digest_input = f"npm-global|{name_normalized}|{node_modules_root}"
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]
        asset_id = f"node-pkg-{digest}"
        return Asset(
            id=asset_id,
            type="node_package",
            parent_asset_id=None,
            name=name,
            version=version,
            install_path=node_modules_root,
            source=SOURCE_NAME,
            current_state={
                "scope": "global",
                "manifest_kind": "npm-global",
                "project_name": None,
                "manifest_path": None,
                "package_name": name,
                "package_name_normalized": name_normalized,
                "dep_kind": "global",
                "version_spec": version,
                "lifecycle_scripts": [],
                "bin_entries": [],
            },
            discovered_at=time.time(),
        )

    @staticmethod
    def _make_project_asset(
        *,
        project: Path,
        manifest_path: Path,
        manifest_kind: str,
        name: str,
        version_spec: str | None,
        dep_kind: str,
        lifecycle_scripts: list[str],
        bin_entries: list[str],
    ) -> Asset:
        name_normalized = _normalize_npm(name)
        spec_path = str(manifest_path)
        project_name = project.name
        digest_input = f"{project_name}|{manifest_kind}|{dep_kind}|{name_normalized}|{spec_path}"
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]
        asset_id = f"node-pkg-{digest}"
        return Asset(
            id=asset_id,
            type="node_package",
            parent_asset_id=None,
            name=name,
            version=version_spec,
            install_path=str(project),
            source=SOURCE_NAME,
            current_state={
                "scope": "project",
                "manifest_kind": manifest_kind,
                "project_name": project_name,
                "manifest_path": spec_path,
                "package_name": name,
                "package_name_normalized": name_normalized,
                "dep_kind": dep_kind,
                "version_spec": version_spec,
                "lifecycle_scripts": lifecycle_scripts,
                "bin_entries": bin_entries,
            },
            discovered_at=time.time(),
        )


__all__ = ["SOURCE_NAME", "NodePackagesSource"]
