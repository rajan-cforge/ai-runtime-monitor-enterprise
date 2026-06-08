"""VSCode / Cursor extension discovery — P3.1.

Walks ``~/.vscode/extensions/`` AND ``~/.cursor/extensions/`` (both hosts
covered by a single source per Phase A §5 — Cursor is a VSCode fork
using the identical extension layout). Per-extension ``package.json``
manifests are parsed; the risk-bearing fields (``activationEvents``,
``contributes.*``, ``extensionKind``, ``capabilities``, ``main``) are
captured into ``Asset.current_state`` for P3.8's ontology mapping.

**Locked refs:**

- directive §3 P3.1 — "Parse extensions.json + per-ext package.json"
- spec §5.2 — ontology categories that P3.8 will map to
- memory ``project_v022_per_item_isolation.md`` — two layers of per-item try/except:
  per-host-root (one missing dir doesn't block the other) AND per-extension-dir
  (one malformed package.json doesn't poison the rest)
- memory ``project_asset_id_must_be_stable_digest.md`` — ``hashlib.sha256``, NOT
  Python's built-in ``hash()`` (``PYTHONHASHSEED`` randomization would break
  the ``first_seen`` UPSERT contract)
- memory ``project_billion_laughs_detonation_site.md`` — ``validate_path``
  size-caps every ``package.json`` read at 10 MiB before parse

**Source name:** ``"vscode-extensions"`` (kebab-case per existing convention;
the directive's ``vscode_ext`` shorthand was informal).

**Asset.id digest input:** ``sha256(host|publisher|name|install_path)`` — version
is intentionally EXCLUDED so an extension upgrade UPSERTs the existing row
(matches the MCP server precedent). The ``host`` field is in the digest so the
same extension installed in BOTH VSCode and Cursor produces TWO distinct assets
(which is the correct behavior for separate installations).

**Redaction:** NOT performed. VSCode extension ``package.json`` manifests carry
structural metadata only (publisher, name, capability declarations) — not
user-configured values. Actual user settings live in
``~/.config/Code/User/settings.json`` which is out of scope for P3.1. Future
maintainers: do NOT add ``redact_secrets_in_env`` calls here unless a future
field is identified that carries user secrets.

**JSON parsing:** ``json.loads`` — no anchor/alias bomb risk in JSON. Deep
nesting (>1000 levels) could in theory raise ``RecursionError`` but the
per-extension ``try/except Exception`` catches it (``RecursionError`` IS an
``Exception`` subclass via ``RuntimeError``). The 10 MiB size cap on read
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

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.vscode_cursor_extensions")


SOURCE_NAME = "vscode-extensions"
"""Stable source identifier — matches the entry in
``ontology.mapping.REGISTERED_SOURCES``."""


MAX_PACKAGE_JSON_MB = 10.0
"""Size cap on each ``package.json`` before read (memory
``project_billion_laughs_detonation_site.md`` precedent — even though JSON
has no anchor/alias amplification, an oversized manifest can still DoS the
parser via recursion depth or memory)."""


DESCRIPTION_TRUNCATE = 500
"""``current_state.description`` is truncated to this many characters.
Extension descriptions can be multi-kilobyte; the field is not
security-relevant and we don't want unbounded storage."""


def _default_extensions_roots() -> list[tuple[str, Path]]:
    """Production defaults: scan both VSCode and Cursor user-extension dirs."""
    home = Path.home()
    return [
        ("vscode", home / ".vscode" / "extensions"),
        ("cursor", home / ".cursor" / "extensions"),
    ]


class VscodeCursorExtensionsSource(DiscoverySource):
    """Discovers VSCode and Cursor extensions in one pass."""

    def __init__(
        self,
        extensions_roots: list[tuple[str, Path]] | None = None,
    ) -> None:
        """Args:
        extensions_roots: Optional override list of ``(host_label, path)``
            pairs. Production passes ``None`` and the default scans
            ``~/.vscode/extensions`` + ``~/.cursor/extensions``. Tests
            inject synthetic dirs.
        """
        self._extensions_roots = extensions_roots if extensions_roots is not None else _default_extensions_roots()

    def name(self) -> str:
        return SOURCE_NAME

    def requires_auth(self) -> bool:
        return False

    def discover(self) -> list[Asset]:
        """Walk each configured host root, parse every per-ext ``package.json``,
        emit one :class:`Asset` per valid extension.

        Per-item isolation at two levels:

        1. Per-host-root: a missing or unreadable root logs a debug line and
           moves on; sibling roots still scan.
        2. Per-extension-dir: a malformed ``package.json`` logs a warning and
           is skipped; sibling extensions still emit.
        """
        assets: list[Asset] = []
        for host_label, root in self._extensions_roots:
            try:
                if not root.is_dir():
                    logger.debug("vscode-extensions: host root %s absent; skipping", root)
                    continue
            except OSError as exc:
                logger.debug("vscode-extensions: host root %s probe failed (%s); skipping", root, exc)
                continue
            for ext_dir in self._iter_extension_dirs(root):
                try:
                    asset = self._parse_extension(host_label, root, ext_dir)
                except Exception as exc:
                    logger.warning(
                        "vscode-extensions: skipping %s/%s — %s",
                        host_label,
                        ext_dir.name,
                        exc,
                    )
                    continue
                if asset is not None:
                    assets.append(asset)
        return assets

    @staticmethod
    def _iter_extension_dirs(root: Path):
        """Yield candidate extension directories under ``root``.

        Filters out the index file (``extensions.json``), hidden entries,
        and non-directories. Sorted for deterministic test output."""
        try:
            entries = sorted(root.iterdir())
        except OSError as exc:
            logger.warning("vscode-extensions: cannot list %s — %s", root, exc)
            return
        for entry in entries:
            if entry.name.startswith("."):
                continue
            try:
                if not entry.is_dir():
                    continue
            except OSError:
                continue
            yield entry

    @staticmethod
    def _parse_extension(host_label: str, root: Path, ext_dir: Path) -> Asset | None:
        """Parse one extension's ``package.json``. Returns the Asset, or
        ``None`` when the ext should be skipped (no manifest)."""
        pkg = ext_dir / "package.json"
        if not pkg.is_file():
            return None
        # validate_path enforces the 10 MiB size cap. Use ext_dir as the
        # root so the validator confirms `package.json` is at the expected
        # depth (1) — defends against symlink-escape into elsewhere.
        validate_path(pkg, root=ext_dir, check_size=True, max_size_mb=MAX_PACKAGE_JSON_MB)
        raw = pkg.read_text(errors="replace")
        manifest = json.loads(raw)
        if not isinstance(manifest, dict):
            raise TypeError(f"package.json top-level is not a dict (got {type(manifest).__name__})")

        publisher = manifest.get("publisher")
        name = manifest.get("name")
        if not isinstance(publisher, str) or not isinstance(name, str):
            raise TypeError("package.json missing publisher and/or name")

        version = manifest.get("version")
        version = version if isinstance(version, str) else None
        display_name = manifest.get("displayName")
        display_name = display_name if isinstance(display_name, str) else None
        description = manifest.get("description")
        description = description if isinstance(description, str) else None
        if description is not None and len(description) > DESCRIPTION_TRUNCATE:
            description = description[:DESCRIPTION_TRUNCATE]
        main = manifest.get("main")
        main = main if isinstance(main, str) else None
        browser = manifest.get("browser")
        browser = browser if isinstance(browser, str) else None
        activation_events = manifest.get("activationEvents")
        activation_events = activation_events if isinstance(activation_events, list) else []
        # Filter to string entries only (defensive against malformed)
        activation_events = [e for e in activation_events if isinstance(e, str)]
        extension_kind = manifest.get("extensionKind")
        extension_kind = extension_kind if isinstance(extension_kind, list) else None
        if extension_kind is not None:
            extension_kind = [k for k in extension_kind if isinstance(k, str)]
        capabilities = manifest.get("capabilities")
        capabilities = capabilities if isinstance(capabilities, dict) else None

        contributes = manifest.get("contributes")
        contributes = contributes if isinstance(contributes, dict) else {}
        contributes_keys = sorted(contributes.keys())
        contributes_commands: list[str] = []
        cmds = contributes.get("commands")
        if isinstance(cmds, list):
            for c in cmds:
                if isinstance(c, dict):
                    cid = c.get("command")
                    if isinstance(cid, str):
                        contributes_commands.append(cid)
        contributes_debug = bool(contributes.get("debuggers"))
        contributes_terminal = bool(contributes.get("terminal"))
        contributes_tasks = bool(contributes.get("taskDefinitions"))

        install_path = str(ext_dir)
        digest_input = f"{host_label}|{publisher}|{name}|{install_path}"
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]
        asset_id = f"vscode-ext-{digest}"
        extension_id = f"{publisher}.{name}"

        return Asset(
            id=asset_id,
            type="extension",
            parent_asset_id=None,
            name=display_name or name,
            version=version,
            install_path=install_path,
            source=SOURCE_NAME,
            current_state={
                "host": host_label,
                "publisher": publisher,
                "extension_id": extension_id,
                "display_name": display_name,
                "description": description,
                "main": main,
                "browser": browser,
                "activation_events": activation_events,
                "contributes_keys": contributes_keys,
                "contributes_commands": contributes_commands,
                "contributes_debug": contributes_debug,
                "contributes_terminal": contributes_terminal,
                "contributes_tasks": contributes_tasks,
                "extension_kind": extension_kind,
                "capabilities": capabilities,
            },
            discovered_at=time.time(),
        )


__all__ = ["SOURCE_NAME", "VscodeCursorExtensionsSource"]
