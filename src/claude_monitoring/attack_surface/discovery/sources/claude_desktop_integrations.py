"""Claude Desktop integrations beyond MCP — P3.7.

Parses ``~/Library/Application Support/Claude/claude_desktop_config.json``
for integration-relevant entries. Emits one :class:`Asset` per:

- enabled integration-toggle preference (e.g., ``coworkWebSearchEnabled: true``)
- filesystem-access preference (e.g., ``coworkUserFilesPath: "/Users/x/Claude"``)
- unknown top-level config key (forward-compat for future Anthropic
  integration shapes — Connectors today are server-side and not in the
  local config, but future shapes may land locally)

**Explicitly skipped:** ``mcpServers`` — already covered by P1.4's
``mcp-servers`` source. Documented inline + pinned by
``TestMcpServersExplicitlySkipped``.

**Load-bearing security boundary — allowlist, not denylist.** This
source opens exactly ONE file: ``claude_desktop_config.json``. Sibling
files in the Claude config dir (``buddy-tokens.json``, ``Cookies``,
``Cache/``, ``blob_storage/``, ``Local Storage/``, etc.) are out of
scope and CANNOT be reached by any code path in this module. The
pinning test ``test_source_opens_only_claude_desktop_config_json``
monkeypatches ``Path.open`` to detect any leak.

**Locked refs:**

- directive §3 P3.7 — "Claude Desktop integrations discovery beyond MCP
  servers. Parse config for connected integrations (Google Drive,
  GitHub, etc.)."
- memory ``project_v022_per_item_isolation.md``
- memory ``project_asset_id_must_be_stable_digest.md`` — ``hashlib.sha256``
- memory ``project_billion_laughs_detonation_site.md`` — ``validate_path``
  10 MiB size cap

**Source name:** ``"claude-desktop-integrations"``.

**Asset.id digest input:** ``sha256(integration_kind|integration_name_normalized|config_path)``.
The toggle's ``enabled`` state is EXCLUDED from the digest so a toggle
flipping from off to on yields a clean UPSERT (when emit-on-true semantics
later expand). Currently we only emit on ``true``, so a toggle flipping to
``false`` simply causes the asset to disappear from the next scan — the
orchestrator's "last_seen" delta handles that.

**Redaction:** NOT performed at source layer because the source skips
``mcpServers`` entirely (which is where env-shaped secrets live in this
file). The remaining captured fields are integration TOGGLES (booleans),
filesystem PATHS (no secrets), and forward-compat unknown values
(size-capped raw JSON; if a future Anthropic schema puts secrets in a
top-level key, this would need to be revisited).
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

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.claude_desktop_integrations")


SOURCE_NAME = "claude-desktop-integrations"
MAX_CONFIG_MB = 10.0
MAX_RAW_VALUE_BYTES = 10_000
"""Cap on the serialized ``current_state.raw_value`` for unknown_top_level
assets. Anything bigger is replaced with a truncation sentinel."""


CONFIG_FILENAME = "claude_desktop_config.json"


INTEGRATION_TOGGLE_KEYS: frozenset[str] = frozenset(
    {
        "coworkWebSearchEnabled",
        "coworkScheduledTasksEnabled",
        "ccdScheduledTasksEnabled",
    }
)
"""Known integration-toggle preference keys. Extensible: add new keys
here as Claude Desktop adds them."""


FILESYSTEM_ACCESS_KEYS: frozenset[str] = frozenset({"coworkUserFilesPath"})
"""Top-level config keys that grant Claude Desktop filesystem access."""


KNOWN_TOP_LEVEL_KEYS: frozenset[str] = frozenset({"mcpServers", "preferences"})
"""Top-level keys we explicitly DO NOT emit as unknown_top_level.

- ``mcpServers``: covered by P1.4's ``mcp-servers`` source. P3.7 skips entirely.
- ``preferences``: handled via the targeted ``INTEGRATION_TOGGLE_KEYS`` allowlist.
"""


def _default_config_paths() -> list[Path]:
    """Production defaults: macOS Claude Desktop config location."""
    home = Path.home()
    return [home / "Library" / "Application Support" / "Claude" / CONFIG_FILENAME]


class ClaudeDesktopIntegrationsSource(DiscoverySource):
    """Discovers Claude Desktop integrations beyond MCP servers."""

    def __init__(
        self,
        config_paths: list[Path] | None = None,
    ) -> None:
        """Args:
        config_paths: Optional override list of ``claude_desktop_config.json``
            paths. Default scans the macOS location. Tests inject synthetic
            paths.
        """
        self._config_paths = config_paths if config_paths is not None else _default_config_paths()

    def name(self) -> str:
        """Return the registered source identifier."""
        return SOURCE_NAME

    def requires_auth(self) -> bool:
        """Filesystem read of one allowlisted JSON file; no auth."""
        return False

    def discover(self) -> list[Asset]:
        """Parse each configured config-path's JSON; emit one Asset per
        integration toggle / filesystem-access / unknown top-level key.

        Per-item isolation at TWO layers:

        1. Per-config-path: missing file → silent skip; oversized or
           malformed → log + skip; siblings still scan.
        2. Per-entry: a non-bool toggle value or non-string filesystem
           path is skipped; sibling entries emit.
        """
        assets: list[Asset] = []
        for config_path in self._config_paths:
            try:
                if not config_path.is_file():
                    continue
            except OSError:
                continue
            try:
                # validate_path 10 MiB cap before read; root is the
                # config's parent so a symlink-escape into elsewhere
                # is rejected.
                validate_path(
                    config_path,
                    root=config_path.parent,
                    check_size=True,
                    max_size_mb=MAX_CONFIG_MB,
                )
                with config_path.open(encoding="utf-8", errors="replace") as fp:
                    data = json.load(fp)
            except Exception as exc:
                logger.warning(
                    "claude-desktop-integrations: skipping %s — %s",
                    config_path,
                    exc,
                )
                continue
            if not isinstance(data, dict):
                logger.warning(
                    "claude-desktop-integrations: %s top-level is not a dict",
                    config_path,
                )
                continue
            assets.extend(self._extract(config_path, data))
        return assets

    def _extract(self, config_path: Path, data: dict) -> list[Asset]:
        out: list[Asset] = []

        # --- preferences: integration toggles + filesystem access ---
        prefs = data.get("preferences")
        if isinstance(prefs, dict):
            for key, value in prefs.items():
                if not isinstance(key, str):
                    continue
                if key in INTEGRATION_TOGGLE_KEYS:
                    if isinstance(value, bool) and value:
                        out.append(
                            self._make_asset(
                                config_path=config_path,
                                kind="toggle",
                                name=key,
                                install_path=str(config_path),
                                extra_state={"enabled": True},
                            )
                        )

        # --- filesystem-access top-level keys ---
        for key in FILESYSTEM_ACCESS_KEYS:
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                out.append(
                    self._make_asset(
                        config_path=config_path,
                        kind="filesystem_access",
                        name=key,
                        install_path=value,
                        extra_state={"filesystem_path": value},
                    )
                )

        # --- unknown top-level keys (forward-compat) ---
        for key, value in data.items():
            if not isinstance(key, str):
                continue
            if key in KNOWN_TOP_LEVEL_KEYS or key in FILESYSTEM_ACCESS_KEYS:
                continue
            raw_value = self._cap_raw_value(value)
            out.append(
                self._make_asset(
                    config_path=config_path,
                    kind="unknown_top_level",
                    name=key,
                    install_path=str(config_path),
                    extra_state={"raw_value": raw_value},
                )
            )
        return out

    @staticmethod
    def _cap_raw_value(value: object) -> object:
        """Cap the JSON-serialized size of an unknown top-level value.
        Anything over MAX_RAW_VALUE_BYTES is replaced with a sentinel
        carrying the original byte length."""
        try:
            serialized = json.dumps(value)
        except (TypeError, ValueError):
            return {"__truncated__": True, "reason": "non-serializable"}
        if len(serialized) > MAX_RAW_VALUE_BYTES:
            return {"__truncated__": True, "size_bytes": len(serialized)}
        return value

    @staticmethod
    def _make_asset(
        *,
        config_path: Path,
        kind: str,
        name: str,
        install_path: str,
        extra_state: dict,
    ) -> Asset:
        name_normalized = name.lower()
        config_path_str = str(config_path)
        digest_input = f"{kind}|{name_normalized}|{config_path_str}"
        digest = hashlib.sha256(digest_input.encode("utf-8")).hexdigest()[:16]
        asset_id = f"claude-int-{digest}"
        current_state: dict = {
            "integration_kind": kind,
            "integration_name_normalized": name_normalized,
            "config_path": config_path_str,
            "enabled": None,
            "filesystem_path": None,
            "raw_value": None,
        }
        current_state.update(extra_state)
        return Asset(
            id=asset_id,
            type="claude_desktop_integration",
            parent_asset_id=None,
            name=name,
            version=None,
            install_path=install_path,
            source=SOURCE_NAME,
            current_state=current_state,
            discovered_at=time.time(),
        )


__all__ = [
    "FILESYSTEM_ACCESS_KEYS",
    "INTEGRATION_TOGGLE_KEYS",
    "KNOWN_TOP_LEVEL_KEYS",
    "SOURCE_NAME",
    "ClaudeDesktopIntegrationsSource",
]
