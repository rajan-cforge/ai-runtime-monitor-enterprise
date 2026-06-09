"""Python project-file dependency discovery — P3.4.

Walks each configured project root one level deep and parses every
``requirements*.txt``, ``pyproject.toml``, and ``Pipfile.lock`` at each
project root. Each declared dependency becomes one :class:`Asset` of
type ``"python_dependency"``.

**Distinct from P3.3.** P3.3 (``python-packages``) captures what is
*installed* in a venv (pip's view). P3.4 (``python-project-deps``)
captures what is *declared* in a project's manifest (the source-of-truth
view). Cross-referencing them surfaces declared-but-not-installed and
installed-but-not-declared — both supply-chain signals P3.8 will read.

**Locked refs:**

- directive §3 P3.4 — "Python package discovery from project files.
  Parse ``requirements.txt``, ``pyproject.toml``, ``Pipfile.lock`` in
  detected project directories."
- memory ``project_v022_per_item_isolation.md`` — THREE layers of
  per-item try/except (per-project + per-manifest + per-line/per-package)
- memory ``project_asset_id_must_be_stable_digest.md`` — ``hashlib.sha256``,
  NOT Python's built-in ``hash()``
- memory ``project_billion_laughs_detonation_site.md`` — ``validate_path``
  10 MiB size cap on every manifest before read

**Source name:** ``"python-project-deps"`` (kebab-case, distinguishes
from P3.3's ``"python-packages"``).

**Asset.id digest input:**
``sha256(project_name|manifest_kind|name_normalized|spec_path)``.
``version_spec`` is intentionally EXCLUDED so a version-spec bump
UPSERTs the existing row (matches MCP + P3.1 + P3.2 + P3.3 precedent).
``name_normalized`` is PEP 503 lowercase so ``"Requests"`` and
``"requests"`` collapse to the same row.

**Detection scope (bounded):** depth-1 walk of each configured root
(default ``~/Projects/``). Each top-level subdir of the root is treated
as a project. NO recursive descent — monorepo support filed as a
follow-up.

**Redaction:** NOT performed. Declarative dependency files contain
public package names + version specs only. Comments in
``requirements.txt`` are stripped at parse time before any storage.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sys
import time
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover — exercised only on the 3.10 CI runner
    import tomli as tomllib

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import DiscoverySource
from claude_monitoring.attack_surface.discovery.helpers import validate_path

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.python_project_deps")


SOURCE_NAME = "python-project-deps"
"""Stable source identifier — matches the entry in
``ontology.mapping.REGISTERED_SOURCES``."""


MAX_MANIFEST_MB = 10.0
"""Size cap on each manifest before read."""


# PEP 503 normalization: lowercase + collapse runs of -_. to a single -
_PEP503_RE = re.compile(r"[-_.]+")


def _normalize_pep503(name: str) -> str:
    """PEP 503: lowercase; collapse runs of `-`, `_`, `.` to a single `-`."""
    return _PEP503_RE.sub("-", name.lower())


# Simple PEP 508 parser (regex-based; sufficient for discovery).
# Matches: <name>[extras]<spec> with optional whitespace.
#   name:    [A-Za-z][A-Za-z0-9_.-]*
#   extras:  [name1,name2,...] (inside square brackets)
#   spec:    rest of line (operator + version, e.g., >=2.0, ==1, ~=3.4)
_PEP508_RE = re.compile(
    r"""
    ^\s*
    (?P<name>[A-Za-z][A-Za-z0-9_.\-]*)
    (?:\s*\[\s*(?P<extras>[A-Za-z0-9_,\s.\-]+?)\s*\])?
    \s*
    (?P<spec>(?:[<>=!~][^;#@]+)?)
    """,
    re.VERBOSE,
)


def _default_project_roots() -> list[Path]:
    """Production defaults: scan ``~/Projects/`` one level deep."""
    return [Path.home() / "Projects"]


def _parse_pep508_line(line: str) -> tuple[str, str | None, list[str]] | None:
    """Parse a single PEP 508-ish line.

    Returns ``(name, version_spec, extras)`` or ``None`` if the line is
    not a recognizable dependency spec.

    Strips inline comments (``#...``). Drops env markers (``; python_version >= '3.10'``)
    and URL/path specs (``@ <url>``) from the version field.
    """
    # Strip inline comment
    comment_idx = line.find("#")
    if comment_idx >= 0:
        line = line[:comment_idx]
    line = line.strip()
    if not line:
        return None

    m = _PEP508_RE.match(line)
    if not m or not m.group("name"):
        return None
    name = m.group("name")
    extras_raw = m.group("extras")
    extras = [e.strip() for e in extras_raw.split(",")] if extras_raw else []
    extras = [e for e in extras if e]
    spec = m.group("spec").strip() or None
    # Reject pure-noise matches where the rest of the line wasn't consumed
    # cleanly (e.g., "!!!garbage!!!" — name won't match anyway, but defend).
    consumed = m.end()
    leftover = line[consumed:].strip()
    if leftover and not (leftover.startswith(";") or leftover.startswith("@") or leftover.startswith("#")):
        # Trailing junk that isn't a marker or URL — reject defensively
        return None
    return (name, spec, extras)


class PythonProjectDepsSource(DiscoverySource):
    """Discovers Python dependencies declared in project manifests."""

    def __init__(
        self,
        project_roots: list[Path] | None = None,
    ) -> None:
        """Args:
        project_roots: Optional override list of root directories to scan.
            Each root is walked depth-1; each subdir is treated as a project.
            Production passes ``None`` and the default is ``[~/Projects]``.
        """
        self._project_roots = project_roots if project_roots is not None else _default_project_roots()

    def name(self) -> str:
        """Return the registered source identifier."""
        return SOURCE_NAME

    def requires_auth(self) -> bool:
        """Filesystem walk; no authentication required."""
        return False

    def discover(self) -> list[Asset]:
        """Walk each project root, parse every manifest, emit one Asset per
        declared dependency.

        Per-item isolation at THREE layers:

        1. Per-project: a project whose entire manifest set is unparseable
           does not block sibling projects.
        2. Per-manifest: a malformed ``pyproject.toml`` does not block the
           same project's ``requirements.txt``.
        3. Per-line / per-package: a single bad spec or entry does not
           block sibling entries within the same manifest.
        """
        assets: list[Asset] = []
        for root in self._project_roots:
            try:
                if not root.is_dir():
                    logger.debug("python-project-deps: root %s absent; skipping", root)
                    continue
            except OSError as exc:
                logger.debug("python-project-deps: root %s probe failed (%s); skipping", root, exc)
                continue
            try:
                project_entries = sorted(root.iterdir())
            except OSError as exc:
                logger.warning("python-project-deps: cannot list %s — %s", root, exc)
                continue
            for project in project_entries:
                if project.name.startswith("."):
                    continue
                try:
                    if not project.is_dir():
                        continue
                except OSError:
                    continue
                assets.extend(self._scan_project(project))
        return assets

    def _scan_project(self, project: Path) -> list[Asset]:
        """Scan one project directory; parse all known manifest shapes."""
        out: list[Asset] = []
        # requirements*.txt — any matching file at project root
        try:
            req_files = sorted(project.glob("requirements*.txt"))
        except OSError as exc:
            logger.warning(
                "python-project-deps: cannot glob requirements in %s — %s",
                project,
                exc,
            )
            req_files = []
        for req in req_files:
            try:
                out.extend(self._parse_requirements_file(project, req))
            except Exception as exc:
                logger.warning(
                    "python-project-deps: skipping %s/%s — %s",
                    project.name,
                    req.name,
                    exc,
                )
        # pyproject.toml
        pyproj = project / "pyproject.toml"
        if pyproj.is_file():
            try:
                out.extend(self._parse_pyproject_file(project, pyproj))
            except Exception as exc:
                logger.warning(
                    "python-project-deps: skipping %s/pyproject.toml — %s",
                    project.name,
                    exc,
                )
        # Pipfile.lock
        pipfile_lock = project / "Pipfile.lock"
        if pipfile_lock.is_file():
            try:
                out.extend(self._parse_pipfile_lock(project, pipfile_lock))
            except Exception as exc:
                logger.warning(
                    "python-project-deps: skipping %s/Pipfile.lock — %s",
                    project.name,
                    exc,
                )
        return out

    @staticmethod
    def _read_capped(path: Path, *, root: Path) -> str:
        """Read a manifest file under the 10 MiB cap, using validate_path."""
        validate_path(path, root=root, check_size=True, max_size_mb=MAX_MANIFEST_MB)
        return path.read_text(errors="replace")

    def _parse_requirements_file(self, project: Path, req_file: Path) -> list[Asset]:
        raw = self._read_capped(req_file, root=project)
        assets: list[Asset] = []
        for raw_line in raw.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            # Skip pip option lines (-r, -e, --index-url, etc.) — not deps
            if line.startswith("-") or line.startswith("--"):
                continue
            try:
                parsed = _parse_pep508_line(line)
            except Exception as exc:
                logger.warning(
                    "python-project-deps: bad line in %s/%s — %s",
                    project.name,
                    req_file.name,
                    exc,
                )
                continue
            if parsed is None:
                continue
            name, spec, extras = parsed
            assets.append(
                self._make_asset(
                    project=project,
                    manifest_kind="requirements",
                    manifest_path=req_file,
                    name=name,
                    version_spec=spec,
                    extras=extras,
                    section=None,
                )
            )
        return assets

    def _parse_pyproject_file(self, project: Path, pyproj: Path) -> list[Asset]:
        raw = self._read_capped(pyproj, root=project)
        data = tomllib.loads(raw)
        if not isinstance(data, dict):
            raise TypeError("pyproject.toml top-level is not a table")
        assets: list[Asset] = []
        # PEP 621: [project.dependencies]
        proj_section = data.get("project")
        if isinstance(proj_section, dict):
            deps = proj_section.get("dependencies")
            if isinstance(deps, list):
                for entry in deps:
                    if not isinstance(entry, str):
                        continue
                    try:
                        parsed = _parse_pep508_line(entry)
                    except Exception:
                        continue
                    if parsed is None:
                        continue
                    name, spec, extras = parsed
                    assets.append(
                        self._make_asset(
                            project=project,
                            manifest_kind="pyproject",
                            manifest_path=pyproj,
                            name=name,
                            version_spec=spec,
                            extras=extras,
                            section="dependencies",
                        )
                    )
            optional = proj_section.get("optional-dependencies")
            if isinstance(optional, dict):
                for opt_section, opt_deps in optional.items():
                    if not isinstance(opt_section, str) or not isinstance(opt_deps, list):
                        continue
                    for entry in opt_deps:
                        if not isinstance(entry, str):
                            continue
                        try:
                            parsed = _parse_pep508_line(entry)
                        except Exception:
                            continue
                        if parsed is None:
                            continue
                        name, spec, extras = parsed
                        assets.append(
                            self._make_asset(
                                project=project,
                                manifest_kind="pyproject",
                                manifest_path=pyproj,
                                name=name,
                                version_spec=spec,
                                extras=extras,
                                section=f"optional.{opt_section}",
                            )
                        )
        # Poetry: [tool.poetry.dependencies]
        tool_section = data.get("tool")
        if isinstance(tool_section, dict):
            poetry = tool_section.get("poetry")
            if isinstance(poetry, dict):
                poetry_deps = poetry.get("dependencies")
                if isinstance(poetry_deps, dict):
                    for raw_name, spec_value in poetry_deps.items():
                        if not isinstance(raw_name, str):
                            continue
                        # Poetry uses 'python' as the interpreter constraint, not a package
                        if raw_name == "python":
                            continue
                        if isinstance(spec_value, str):
                            spec = spec_value
                        elif isinstance(spec_value, dict):
                            spec = spec_value.get("version") if isinstance(spec_value.get("version"), str) else None
                        else:
                            spec = None
                        assets.append(
                            self._make_asset(
                                project=project,
                                manifest_kind="pyproject",
                                manifest_path=pyproj,
                                name=raw_name,
                                version_spec=spec,
                                extras=[],
                                section="poetry.dependencies",
                            )
                        )
        return assets

    def _parse_pipfile_lock(self, project: Path, lock: Path) -> list[Asset]:
        raw = self._read_capped(lock, root=project)
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise TypeError("Pipfile.lock top-level is not an object")
        assets: list[Asset] = []
        for section in ("default", "develop"):
            packages = data.get(section)
            if not isinstance(packages, dict):
                continue
            for name, spec_data in packages.items():
                if not isinstance(name, str):
                    continue
                version_spec: str | None = None
                if isinstance(spec_data, dict):
                    v = spec_data.get("version")
                    if isinstance(v, str):
                        version_spec = v
                assets.append(
                    self._make_asset(
                        project=project,
                        manifest_kind="pipfile-lock",
                        manifest_path=lock,
                        name=name,
                        version_spec=version_spec,
                        extras=[],
                        section=section,
                    )
                )
        return assets

    @staticmethod
    def _make_asset(
        *,
        project: Path,
        manifest_kind: str,
        manifest_path: Path,
        name: str,
        version_spec: str | None,
        extras: list[str],
        section: str | None,
    ) -> Asset:
        name_normalized = _normalize_pep503(name)
        spec_path = str(manifest_path)
        project_name = project.name
        digest_input = f"{project_name}|{manifest_kind}|{name_normalized}|{spec_path}"
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]
        asset_id = f"python-req-{digest}"
        return Asset(
            id=asset_id,
            type="python_dependency",
            parent_asset_id=None,
            name=name,
            version=version_spec,
            install_path=str(project),
            source=SOURCE_NAME,
            current_state={
                "project_name": project_name,
                "manifest_kind": manifest_kind,
                "manifest_path": spec_path,
                "package_name": name,
                "package_name_normalized": name_normalized,
                "version_spec": version_spec,
                "extras": extras,
                "section": section,
            },
            discovered_at=time.time(),
        )


__all__ = ["SOURCE_NAME", "PythonProjectDepsSource"]
