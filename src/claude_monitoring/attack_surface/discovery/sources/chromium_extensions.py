"""Chromium-family extension discovery — P3.2.

Walks ``~/Library/Application Support/<browser>/<profile>/Extensions/``
for Chrome, Edge, Brave, and Arc (all four are Chromium forks sharing
the identical extension layout). For each ``<ext-id>/<version>_<N>/manifest.json``
the risk-bearing fields (``permissions``, ``host_permissions``,
``content_scripts[].matches``, ``background.service_worker`` /
``background.scripts``, ``externally_connectable``, ``oauth2``) are
captured into ``Asset.current_state`` for P3.8's ontology mapping.

**Locked refs:**

- directive §3 P3.2 — "Parse Chrome extensions directory + manifest.json per extension"
- directive §7.2 — `CHROME_PERMISSION_MAP` example for P3.8 rules
- memory ``project_v022_per_item_isolation.md`` — THREE layers of per-item try/except
  (per-browser-root, per-profile, per-extension) because the chromium layout has one
  extra nesting level compared to P3.1
- memory ``project_asset_id_must_be_stable_digest.md`` — ``hashlib.sha256``, NOT
  Python's built-in ``hash()`` (``PYTHONHASHSEED`` randomization would break
  the ``first_seen`` UPSERT contract)
- memory ``project_billion_laughs_detonation_site.md`` — ``validate_path``
  size-caps every ``manifest.json`` read at 10 MiB before parse

**Source name:** ``"chromium-extensions"`` (kebab-case per existing convention).

**Asset.id digest input:** ``sha256(browser|profile|extension_id|install_path)`` —
``version`` is intentionally EXCLUDED so an extension upgrade UPSERTs the existing row
(matches the MCP / P3.1 precedent). ``browser`` and ``profile`` are in the digest so
the same extension installed in two browsers OR two profiles produces distinct assets
(separate installations on disk; one can be vulnerable while the other isn't).

**``install_path`` semantics:** the ext-id directory (NOT the version subdirectory).
Chrome keeps older version dirs on disk during update — install_path must be stable
across that churn so ``first_seen`` is preserved.

**Version-dir selection policy:** when multiple ``<version>_<N>`` subdirs coexist
under one ext-id (Chrome update window), the source picks the lexicographically latest
that contains ``manifest.json``. This matches the actually-active install Chrome will
launch.

**MV2 vs MV3 split:** in Manifest V2 manifests, URL patterns like ``"https://*/*"``
appear inside the ``permissions`` array alongside API permission strings. The source
splits them at parse time: entries containing ``://`` or wildcard ``*`` are collected
into ``mv2_host_permissions``; everything else stays in ``permissions``. MV3 manifests
cleanly separate the two, so the split is a no-op there.

**Redaction:** NOT performed. ``manifest.json`` carries structural metadata only
(permission declarations, capability strings, URL patterns) — not user-configured
values. Actual extension storage (OAuth tokens, login state for password manager
extensions, etc.) lives in ``Default/Preferences``, ``Default/Secure Preferences``,
and ``Default/Local Extension Settings/<ext-id>/`` (LevelDB). Those are EXPLICITLY
OUT OF SCOPE for P3.2 and must NOT be opened by this source. Future maintainers:
do NOT expand to Preferences without a separate PR + Rajan ratification.

**JSON parsing:** ``json.loads`` — no anchor/alias bomb risk in JSON. Deep
nesting (>1000 levels) could in theory raise ``RecursionError`` but the
per-extension ``try/except Exception`` catches it. The 10 MiB size cap on read
prevents extreme inputs from even reaching the parser.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import DiscoverySource
from claude_monitoring.attack_surface.discovery.helpers import validate_path

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.chromium_extensions")


SOURCE_NAME = "chromium-extensions"
"""Stable source identifier — matches the entry in
``ontology.mapping.REGISTERED_SOURCES``."""


MAX_MANIFEST_MB = 10.0
"""Size cap on each ``manifest.json`` before read (memory
``project_billion_laughs_detonation_site.md`` precedent)."""


DESCRIPTION_TRUNCATE = 500
"""``current_state.description`` is truncated to this many characters.
Extension descriptions can be multi-kilobyte; the field is not
security-relevant and we don't want unbounded storage."""


EXTENSIONS_SUBDIR = "Extensions"
"""Per-profile subdirectory name where Chromium browsers store extensions."""


MANIFEST_FILENAME = "manifest.json"


def _default_browser_roots() -> list[tuple[str, Path]]:
    """Production defaults: scan Chrome + Edge + Brave + Arc on macOS."""
    home = Path.home()
    app_support = home / "Library" / "Application Support"
    return [
        ("chrome", app_support / "Google" / "Chrome"),
        ("edge", app_support / "Microsoft Edge"),
        ("brave", app_support / "BraveSoftware" / "Brave-Browser"),
        ("arc", app_support / "Arc" / "User Data"),
    ]


def _split_mv2_permissions(raw: list[str]) -> tuple[list[str], list[str]]:
    """Split an MV2 ``permissions`` list into (api_perms, host_patterns).

    Entries containing ``://``, wildcard ``*``, or the literal
    ``<all_urls>`` match pattern are URL patterns (MV2 treats them as
    host permissions). Everything else is an API permission keyword.
    The split is a no-op for MV3 manifests because their
    ``permissions`` only contains API keywords.
    """
    api_perms: list[str] = []
    host_patterns: list[str] = []
    for entry in raw:
        if not isinstance(entry, str):
            continue
        if "://" in entry or "*" in entry or entry == "<all_urls>":
            host_patterns.append(entry)
        else:
            api_perms.append(entry)
    return api_perms, host_patterns


class ChromiumExtensionsSource(DiscoverySource):
    """Discovers Chrome, Edge, Brave, and Arc extensions in one pass."""

    def __init__(
        self,
        browser_roots: list[tuple[str, Path]] | None = None,
    ) -> None:
        """Args:
        browser_roots: Optional override list of ``(browser_label, path)``
            pairs. Production passes ``None`` and the default scans
            the four Chromium-family browser app-support dirs.
            Tests inject synthetic dirs.
        """
        self._browser_roots = browser_roots if browser_roots is not None else _default_browser_roots()

    def name(self) -> str:
        """Return the registered source identifier."""
        return SOURCE_NAME

    def requires_auth(self) -> bool:
        """Filesystem walk; no authentication required."""
        return False

    def discover(self) -> list[Asset]:
        """Walk each configured browser root, iterate profiles, parse every
        per-ext ``manifest.json``, emit one :class:`Asset` per valid extension.

        Per-item isolation at THREE levels (one deeper than P3.1 due to the
        browser → profile → ext nesting):

        1. Per-browser-root: a missing or unreadable root logs a debug line and
           moves on; sibling browsers still scan.
        2. Per-profile: a profile dir without an ``Extensions/`` subdir or
           with an OSError on listing is skipped; sibling profiles still scan.
        3. Per-extension: a malformed ``manifest.json`` logs a warning and
           is skipped; sibling extensions still emit.
        """
        assets: list[Asset] = []
        for browser_label, root in self._browser_roots:
            try:
                if not root.is_dir():
                    logger.debug("chromium-extensions: browser root %s absent; skipping", root)
                    continue
            except OSError as exc:
                logger.debug(
                    "chromium-extensions: browser root %s probe failed (%s); skipping",
                    root,
                    exc,
                )
                continue
            for profile_label, ext_id_dir in self._iter_extensions(browser_label, root):
                try:
                    asset = self._parse_extension(browser_label, profile_label, ext_id_dir)
                except Exception as exc:
                    logger.warning(
                        "chromium-extensions: skipping %s/%s/%s — %s",
                        browser_label,
                        profile_label,
                        ext_id_dir.name,
                        exc,
                    )
                    continue
                if asset is not None:
                    assets.append(asset)
        return assets

    @staticmethod
    def _iter_extensions(browser_label: str, root: Path):
        """Yield ``(profile_label, ext_id_dir)`` pairs under a browser root.

        Walks each profile directory under ``root`` that has an
        ``Extensions/`` subdir, then yields each ext-id directory under it.
        Hidden entries and non-directories are filtered. Sorted for
        deterministic test output.
        """
        try:
            profile_entries = sorted(root.iterdir())
        except OSError as exc:
            logger.warning("chromium-extensions: cannot list %s — %s", root, exc)
            return
        for profile_entry in profile_entries:
            if profile_entry.name.startswith("."):
                continue
            try:
                if not profile_entry.is_dir():
                    continue
            except OSError:
                continue
            extensions_dir = profile_entry / EXTENSIONS_SUBDIR
            try:
                if not extensions_dir.is_dir():
                    continue
            except OSError:
                continue
            try:
                ext_id_entries = sorted(extensions_dir.iterdir())
            except OSError as exc:
                logger.warning(
                    "chromium-extensions: cannot list %s/%s extensions — %s",
                    browser_label,
                    profile_entry.name,
                    exc,
                )
                continue
            for ext_id_entry in ext_id_entries:
                if ext_id_entry.name.startswith("."):
                    continue
                try:
                    if not ext_id_entry.is_dir():
                        continue
                except OSError:
                    continue
                yield (profile_entry.name, ext_id_entry)

    @staticmethod
    def _select_latest_version_dir(ext_id_dir: Path) -> Path | None:
        """Pick the lexicographically latest version subdir of ``ext_id_dir``
        that contains a ``manifest.json``. Returns ``None`` when no version
        dir has a manifest (e.g., abandoned cleanup state)."""
        try:
            entries = sorted(ext_id_dir.iterdir(), reverse=True)
        except OSError:
            return None
        for entry in entries:
            try:
                if not entry.is_dir():
                    continue
            except OSError:
                continue
            if (entry / MANIFEST_FILENAME).is_file():
                return entry
        return None

    @staticmethod
    def _parse_extension(browser_label: str, profile_label: str, ext_id_dir: Path) -> Asset | None:
        """Parse one extension's ``manifest.json``. Returns the Asset, or
        ``None`` when the ext should be skipped (no manifest in any
        version subdir)."""
        version_dir = ChromiumExtensionsSource._select_latest_version_dir(ext_id_dir)
        if version_dir is None:
            return None
        manifest_path = version_dir / MANIFEST_FILENAME
        # validate_path enforces the 10 MiB size cap. Use ext_id_dir as the
        # root so the validator confirms manifest.json is at the expected
        # depth (2 — version subdir + filename) — defends against
        # symlink-escape into elsewhere.
        validate_path(manifest_path, root=ext_id_dir, check_size=True, max_size_mb=MAX_MANIFEST_MB)
        raw = manifest_path.read_text(errors="replace")
        manifest = json.loads(raw)
        if not isinstance(manifest, dict):
            raise TypeError(f"manifest.json top-level is not a dict (got {type(manifest).__name__})")

        extension_id = ext_id_dir.name
        manifest_version = manifest.get("manifest_version")
        if not isinstance(manifest_version, int):
            manifest_version = 0  # defensive; treat unknown as 0
        name = manifest.get("name")
        if not isinstance(name, str):
            name = extension_id  # i18n placeholder allowed; fall back to id if missing/bad type
        version = manifest.get("version")
        version = version if isinstance(version, str) else None
        description = manifest.get("description")
        description = description if isinstance(description, str) else None
        if description is not None and len(description) > DESCRIPTION_TRUNCATE:
            description = description[:DESCRIPTION_TRUNCATE]

        raw_permissions = manifest.get("permissions")
        raw_permissions = raw_permissions if isinstance(raw_permissions, list) else []
        raw_permissions = [p for p in raw_permissions if isinstance(p, str)]
        if manifest_version == 2:
            permissions, mv2_host_permissions = _split_mv2_permissions(raw_permissions)
        else:
            permissions = list(raw_permissions)
            mv2_host_permissions = []

        host_permissions = manifest.get("host_permissions")
        host_permissions = host_permissions if isinstance(host_permissions, list) else []
        host_permissions = [h for h in host_permissions if isinstance(h, str)]

        optional_permissions = manifest.get("optional_permissions")
        optional_permissions = optional_permissions if isinstance(optional_permissions, list) else []
        optional_permissions = [p for p in optional_permissions if isinstance(p, str)]

        content_scripts = manifest.get("content_scripts")
        content_scripts = content_scripts if isinstance(content_scripts, list) else []
        matches_seen: set[str] = set()
        for cs in content_scripts:
            if not isinstance(cs, dict):
                continue
            matches = cs.get("matches")
            if not isinstance(matches, list):
                continue
            for m in matches:
                if isinstance(m, str):
                    matches_seen.add(m)
        content_scripts_matches = sorted(matches_seen)

        background = manifest.get("background")
        background = background if isinstance(background, dict) else {}
        has_background_service_worker = isinstance(background.get("service_worker"), str)
        has_background_scripts = isinstance(background.get("scripts"), list)

        externally_connectable_raw = manifest.get("externally_connectable")
        externally_connectable: list[str] | None
        if isinstance(externally_connectable_raw, dict):
            ec_matches = externally_connectable_raw.get("matches")
            externally_connectable = (
                [m for m in ec_matches if isinstance(m, str)] if isinstance(ec_matches, list) else None
            )
        else:
            externally_connectable = None

        oauth2_raw = manifest.get("oauth2")
        oauth2_scopes: list[str] | None
        if isinstance(oauth2_raw, dict):
            scopes = oauth2_raw.get("scopes")
            oauth2_scopes = [s for s in scopes if isinstance(s, str)] if isinstance(scopes, list) else None
        else:
            oauth2_scopes = None

        install_path = str(ext_id_dir)
        digest_input = f"{browser_label}|{profile_label}|{extension_id}|{install_path}"
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]
        asset_id = f"chrome-ext-{digest}"

        return Asset(
            id=asset_id,
            type="extension",
            parent_asset_id=None,
            name=name,
            version=version,
            install_path=install_path,
            source=SOURCE_NAME,
            current_state={
                "browser": browser_label,
                "profile": profile_label,
                "extension_id": extension_id,
                "manifest_version": manifest_version,
                "description": description,
                "permissions": permissions,
                "mv2_host_permissions": mv2_host_permissions,
                "host_permissions": host_permissions,
                "optional_permissions": optional_permissions,
                "content_scripts_matches": content_scripts_matches,
                "has_background_service_worker": has_background_service_worker,
                "has_background_scripts": has_background_scripts,
                "externally_connectable": externally_connectable,
                "oauth2_scopes": oauth2_scopes,
            },
            discovered_at=time.time(),
        )


__all__ = ["SOURCE_NAME", "ChromiumExtensionsSource"]
