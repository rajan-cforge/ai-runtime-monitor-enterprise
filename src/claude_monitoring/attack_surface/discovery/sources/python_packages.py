"""Python package discovery — P3.3.

Invokes ``<python_bin> -m pip list --format=json`` against the system
interpreter and each detected venv (canonical home paths, shallow
project-dir globs, pipenv / pyenv / conda venv roots). Each package
becomes one :class:`Asset` with stable id and venv attribution.

**Locked refs:**

- directive §3 P3.3 — "Python package discovery (global + per-detected-venv).
  pip list --format=json against system Python and detected venvs."
- memory ``project_v022_per_item_isolation.md`` — TWO layers of per-item
  try/except (per-venv + per-package)
- memory ``project_asset_id_must_be_stable_digest.md`` — ``hashlib.sha256``,
  NOT Python's built-in ``hash()``

**Source name:** ``"python-packages"`` (kebab-case; manager-agnostic so
future poetry/uv/pdm wiring extends this same source rather than
spawning new ones).

**Asset.id digest input:** ``sha256(venv_label|name_normalized|venv_path)``.
- ``venv_label`` distinguishes installations (``"system"``, ``"project:foo"``, etc.)
- ``name_normalized`` is the PEP 503 lowercase canonical name so
  ``"Requests"`` and ``"requests"`` collapse to the same row
- ``venv_path`` is the venv root (parent of ``bin/``); the python binary
  path itself would change across pyenv installs of the same Python
  version, but the venv root is stable
- ``version`` is intentionally EXCLUDED so an upgrade UPSERTs the
  existing row (matches MCP + P3.1 + P3.2 precedent)

**Binary-trust boundary (Phase A §3a — load-bearing).** Per-venv
scanning means we exec each detected ``<venv>/bin/python``. The
discovery candidate-generator restricts itself to ratified prefixes
(``Path.home()``, ``/opt/homebrew/``, ``/usr/local/``) so an arbitrary
filesystem path cannot be reached by default. ``~/Projects/*/venv/`` is
the riskiest channel — a malicious repo CAN drop a fake interpreter
there, but the trust delta is small: ``pip install`` from such a repo
can already execute arbitrary code, so simply listing its packages is
not the load-bearing risk. Boundary documented + filed follow-up issue
for user-opt-in project-dir scanning in a future PR.

**Redaction:** NOT performed. ``pip list --format=json`` output is
structural metadata only (package name, version, install location). No
env vars, no credentials, no PyPI tokens. Future maintainers: do NOT
add ``redact_secrets_in_env`` calls here unless a future field is
identified that carries user secrets.

**Coexistence with legacy supply_chain pip flow:** the v0.2.1
``supply_chain.get_pip_packages()`` continues to operate independently
against ``sys.executable``, writing to the ``environment_packages``
table. P3.3 is additive — it does NOT modify the legacy path. A
separate cleanup PR will eventually point the legacy function at the
new shared :func:`list_pip_packages` helper; Phase 4 absorbs
``supply_chain.py`` entirely.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from pathlib import Path

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import DiscoverySource
from claude_monitoring.attack_surface.discovery.helpers import list_pip_packages

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.python_packages")


SOURCE_NAME = "python-packages"
"""Stable source identifier — matches the entry in
``ontology.mapping.REGISTERED_SOURCES``."""


# PEP 503 normalization: lowercase + collapse runs of -_. to single -
_PEP503_RE = re.compile(r"[-_.]+")


def _normalize_pep503(name: str) -> str:
    """PEP 503: lowercase; collapse runs of `-`, `_`, `.` to a single `-`."""
    return _PEP503_RE.sub("-", name.lower())


def _default_venv_candidates() -> list[tuple[str, Path]]:
    """Production defaults: system interpreter + canonical venv locations
    under ratified prefixes (Path.home(), /opt/homebrew, /usr/local).

    Each entry is ``(venv_label, python_bin_path)``. The label is
    durable across rescans; the path is the absolute interpreter to
    invoke. Glob expansion is shallow (depth-1) for project / pipenv /
    pyenv / conda roots — no recursive walks.
    """
    import sys

    home = Path.home()
    candidates: list[tuple[str, Path]] = [("system", Path(sys.executable))]

    # Canonical user venv
    user_venv = home / ".venv" / "bin" / "python"
    if user_venv.exists():
        candidates.append(("home-venv", user_venv))

    # Project venvs — shallow glob
    projects = home / "Projects"
    if projects.is_dir():
        for proj in sorted(projects.iterdir()):
            if not proj.is_dir():
                continue
            for venv_dirname in (".venv", "venv", "env"):
                py = proj / venv_dirname / "bin" / "python"
                if py.exists():
                    candidates.append((f"project:{proj.name}", py))
                    break  # only one venv per project

    # Pipenv
    pipenv_root = home / ".local" / "share" / "virtualenvs"
    if pipenv_root.is_dir():
        for venv in sorted(pipenv_root.iterdir()):
            py = venv / "bin" / "python"
            if py.exists():
                candidates.append((f"pipenv:{venv.name}", py))

    # Pyenv versions
    pyenv_root = home / ".pyenv" / "versions"
    if pyenv_root.is_dir():
        for ver in sorted(pyenv_root.iterdir()):
            py = ver / "bin" / "python"
            if py.exists():
                candidates.append((f"pyenv:{ver.name}", py))

    # Conda envs (both miniconda + anaconda layouts)
    for conda_root in (home / "miniconda3" / "envs", home / "anaconda3" / "envs"):
        if conda_root.is_dir():
            for env in sorted(conda_root.iterdir()):
                py = env / "bin" / "python"
                if py.exists():
                    candidates.append((f"conda:{env.name}", py))

    return candidates


class PythonPackagesSource(DiscoverySource):
    """Discovers Python packages installed in the system interpreter and
    each detected venv."""

    def __init__(
        self,
        venv_candidates: list[tuple[str, Path]] | None = None,
    ) -> None:
        """Args:
        venv_candidates: Optional override list of ``(venv_label,
            python_bin_path)`` pairs. Production passes ``None`` and the
            default scans the system interpreter + canonical venv locations
            under ratified prefixes. Tests inject synthetic candidates.
        """
        self._venv_candidates = venv_candidates if venv_candidates is not None else _default_venv_candidates()

    def name(self) -> str:
        """Return the registered source identifier."""
        return SOURCE_NAME

    def requires_auth(self) -> bool:
        """Subprocess invocation; no authentication required."""
        return False

    def discover(self) -> list[Asset]:
        """Walk each configured venv candidate, run ``pip list --format=json``,
        emit one :class:`Asset` per package.

        Per-item isolation at TWO levels:

        1. Per-venv: subprocess timeout, non-zero returncode, JSON parse
           failure, or missing python binary → log + skip; sibling venvs
           continue.
        2. Per-package: a malformed pip-list entry (missing/non-str name
           or version) → skip; sibling packages still emit.
        """
        assets: list[Asset] = []
        for venv_label, python_bin in self._venv_candidates:
            try:
                if not python_bin.exists():
                    logger.debug(
                        "python-packages: %s — interpreter %s absent; skipping",
                        venv_label,
                        python_bin,
                    )
                    continue
            except OSError as exc:
                logger.debug(
                    "python-packages: %s — interpreter probe failed (%s); skipping",
                    venv_label,
                    exc,
                )
                continue
            try:
                packages = list_pip_packages(python_bin)
            except Exception as exc:
                logger.warning(
                    "python-packages: skipping %s (%s) — %s",
                    venv_label,
                    python_bin,
                    exc,
                )
                continue
            venv_root = python_bin.parent.parent  # <venv>/bin/python → <venv>
            for pkg in packages:
                try:
                    asset = self._make_asset(venv_label, python_bin, venv_root, pkg)
                except Exception as exc:
                    logger.warning(
                        "python-packages: skipping malformed entry in %s — %s",
                        venv_label,
                        exc,
                    )
                    continue
                if asset is not None:
                    assets.append(asset)
        return assets

    @staticmethod
    def _make_asset(
        venv_label: str,
        python_bin: Path,
        venv_root: Path,
        pkg: dict,
    ) -> Asset | None:
        """Build one :class:`Asset` from a single pip-list entry, or
        return ``None`` if the entry is malformed."""
        if not isinstance(pkg, dict):
            return None
        name = pkg.get("name")
        version = pkg.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            return None

        name_normalized = _normalize_pep503(name)
        venv_path_str = str(venv_root)
        digest_input = f"{venv_label}|{name_normalized}|{venv_path_str}"
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]
        asset_id = f"python-pkg-{digest}"

        return Asset(
            id=asset_id,
            type="python_package",
            parent_asset_id=None,
            name=name,
            version=version,
            install_path=venv_path_str,
            source=SOURCE_NAME,
            current_state={
                "venv_label": venv_label,
                "venv_path": venv_path_str,
                "python_executable": str(python_bin),
                "package_name": name,
                "package_name_normalized": name_normalized,
            },
            discovered_at=time.time(),
        )


__all__ = ["SOURCE_NAME", "PythonPackagesSource"]
