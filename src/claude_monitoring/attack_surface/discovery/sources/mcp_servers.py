"""`McpServersSource` — discovers MCP server registrations.

Phase A: ``~/Documents/vigil-notes/v022/phase-1/p1.4/phase-a-investigation.md`` §2.
Spec §4.2 (EASY tier).

**C3 source — secret-path attention.** MCP configs store
``env: {GITHUB_TOKEN: "ghp_..."}``-style secrets that MUST be
redacted before storage in ``Asset.current_state``. This source
is the primary consumer of :func:`redact_secrets_in_env`; any
code change that bypasses redaction is a security-control
regression.

**Three config surfaces (empirical 2026-06-05):**

1. Claude Desktop: ``~/Library/Application Support/Claude/claude_desktop_config.json``
2. Claude Code: ``~/.claude.json`` — top-level ``mcpServers`` plus
   per-project ``projects.<project_path>.mcpServers``
3. Cursor: ``~/.cursor/mcp.json``

**Per-item isolation contract — two layers:**

1. Per-config: malformed JSON, oversize, IOError → log WARNING,
   continue to next config; one bad file CANNOT zero out the
   batch.
2. Per-server within a config: missing ``command``, server entry
   is not a dict, redaction raises → log WARNING, continue to
   next server within the same config.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from pathlib import Path

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import DiscoverySource
from claude_monitoring.attack_surface.discovery.helpers import (
    redact_secrets_in_env,
    validate_path,
)

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.mcp_servers")


_DEFAULT_CONFIG_PATHS: list[Path] = [
    Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
    Path.home() / ".claude.json",
    Path.home() / ".cursor" / "mcp.json",
]


class McpServersSource(DiscoverySource):
    """Enumerates MCP servers across Claude Desktop, Claude Code, Cursor."""

    DEFAULT_TIMEOUT_SEC = 30
    MAX_FILE_SIZE_MB = 10

    def __init__(self, config_paths: list[Path] | None = None) -> None:
        self.config_paths: list[Path] = (
            [Path(p) for p in config_paths] if config_paths is not None else list(_DEFAULT_CONFIG_PATHS)
        )

    def name(self) -> str:
        """Source identifier per spec §4.2."""
        return "mcp-servers"

    def requires_auth(self) -> bool:
        """No credentials required; pure local config parse."""
        return False

    def discover(self) -> list[Asset]:
        """Iterate config paths; emit assets with two-layer per-item isolation."""
        assets: list[Asset] = []
        scan_time = time.time()
        for config in self.config_paths:
            try:
                config_assets = self._scan_config(config, scan_time)
            except Exception as exc:
                logger.warning("skipping MCP config %s: %s", config, exc)
                continue
            assets.extend(config_assets)
        return assets

    def _scan_config(self, config: Path, scan_time: float) -> list[Asset]:
        """Parse one config file, emit assets per server, with per-server isolation."""
        if not config.is_file():
            # Missing file = config surface not present (e.g. Cursor not
            # installed). Silent normal flow.
            return []
        # validate_path enforces the size cap before we read the bytes.
        validate_path(config, root=config.parent, check_size=True, max_size_mb=self.MAX_FILE_SIZE_MB)
        raw = config.read_text(errors="replace")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"malformed JSON in {config.name}: {exc}") from exc
        if not isinstance(payload, dict):
            return []
        # Top-level mcpServers (Claude Desktop, Cursor, Claude Code global)
        assets: list[Asset] = list(
            self._iter_server_entries(payload.get("mcpServers"), config, scan_time, scope="global")
        )
        # Claude Code per-project: projects.<path>.mcpServers
        projects = payload.get("projects")
        if isinstance(projects, dict):
            for project_path, project_entry in projects.items():
                if not isinstance(project_entry, dict):
                    continue
                project_servers = project_entry.get("mcpServers")
                assets.extend(self._iter_server_entries(project_servers, config, scan_time, scope=str(project_path)))
        return assets

    def _iter_server_entries(
        self,
        servers: object,
        config: Path,
        scan_time: float,
        *,
        scope: str,
    ) -> list[Asset]:
        """Iterate the `{name: {command, args, env}}` dict, isolating per-server failures."""
        if not isinstance(servers, dict):
            return []
        out: list[Asset] = []
        for server_name, entry in servers.items():
            try:
                asset = self._build_server_asset(server_name, entry, config, scan_time, scope)
            except Exception as exc:
                logger.warning("skipping MCP server %s in %s: %s", server_name, config.name, exc)
                continue
            if asset is not None:
                out.append(asset)
        return out

    def _build_server_asset(
        self,
        server_name: str,
        entry: object,
        config: Path,
        scan_time: float,
        scope: str,
    ) -> Asset | None:
        if not isinstance(entry, dict):
            raise TypeError(f"server entry {server_name!r} is not a dict")
        command = entry.get("command")
        if not isinstance(command, str) or not command.strip():
            raise ValueError(f"server entry {server_name!r} missing string `command`")
        args = entry.get("args") if isinstance(entry.get("args"), list) else []
        env_raw = entry.get("env") if isinstance(entry.get("env"), dict) else None
        # Secret-path: redact_secrets_in_env BEFORE storing.
        env_redacted = redact_secrets_in_env(env_raw) if env_raw is not None else None
        current_state: dict = {
            "scope": scope,
            "config_path": str(config),
            "command": command,
            "args": [a for a in args if isinstance(a, str)],
        }
        if env_redacted is not None:
            current_state["env"] = env_redacted
        # id is a stable digest of (config_path, scope, server_name) — Asset
        # spec drift 2 requires id stability across daemon restarts so the
        # UPSERT path preserves first_seen. Python's built-in hash() is
        # PYTHONHASHSEED-randomized per process; sha256 is deterministic.
        key = f"{config}|{scope}|{server_name}".encode()
        asset_id = f"mcp-server-{hashlib.sha256(key).hexdigest()[:16]}"
        return Asset(
            id=asset_id,
            type="mcp_server",
            parent_asset_id=None,
            name=server_name,
            version=None,
            install_path=str(config),
            source=self.name(),
            current_state=current_state,
            discovered_at=scan_time,
        )
