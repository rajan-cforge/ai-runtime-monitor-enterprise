"""`AIToolVersionsSource` — CLI version probes for known AI tools.

Per spec §4.2 + P1.4 Phase A §6. C2 source: pure ``<cli> --version`` probes;
no structured input; no secrets. Per-item isolation contract honored —
one bad probe does NOT poison the batch.

**Info.plist and npm package.json strategies DEFERRED** to the later C3
batch (they parse structured attacker-controllable input). P1.4-minimal
ships CLI-binary probes only.

**Empirical baseline (Rajan's machine 2026-06-05):** claude 2.1.165,
gh 2.86.0, ollama 0.18.2.
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from typing import TypedDict

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import DiscoverySource
from claude_monitoring.attack_surface.discovery.helpers import safe_subprocess

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.ai_tool_versions")


class _ToolSpec(TypedDict, total=True):
    name: str
    argv: list[str]
    version_regex: str


KNOWN_TOOLS: list[_ToolSpec] = [
    {"name": "claude", "argv": ["claude", "--version"], "version_regex": r"(\d+\.\d+\.\d+)"},
    {"name": "gh", "argv": ["gh", "--version"], "version_regex": r"gh version (\d+\.\d+\.\d+)"},
    {"name": "ollama", "argv": ["ollama", "--version"], "version_regex": r"(\d+\.\d+\.\d+)"},
]


class AIToolVersionsSource(DiscoverySource):
    """CLI-binary `--version` probes for known AI tools."""

    DEFAULT_TIMEOUT_SEC = 30

    def __init__(self, known_tools: list[_ToolSpec] | None = None) -> None:
        # No super().__init__() needed — DiscoverySource has none post-Fix 2;
        # _last_run_outcome is a class-level default.
        self._known_tools = known_tools if known_tools is not None else KNOWN_TOOLS

    def name(self) -> str:
        """Source identifier per spec §4.2."""
        return "ai-tool-versions"

    def requires_auth(self) -> bool:
        """No credentials — CLI ``--version`` probes only."""
        return False

    def discover(self) -> list[Asset]:
        """Probe every entry in ``KNOWN_TOOLS`` via ``<argv> --version``."""
        assets: list[Asset] = []
        scan_time = time.time()
        for tool in self._known_tools:
            try:
                asset = self._probe(tool, scan_time)
            except Exception as exc:
                logger.warning("ai-tool-versions: skipping %s: %s", tool["name"], exc)
                continue
            if asset is not None:
                assets.append(asset)
        return assets

    def _probe(self, tool: _ToolSpec, scan_time: float) -> Asset | None:
        name = tool["name"]
        argv = tool["argv"]
        regex = tool["version_regex"]
        try:
            result = safe_subprocess(argv, timeout=self.DEFAULT_TIMEOUT_SEC)
        except FileNotFoundError:
            # Tool not installed — silent normal flow.
            return None
        except subprocess.TimeoutExpired:
            logger.warning("ai-tool-versions: %s --version timed out", name)
            return None
        if result.returncode != 0:
            logger.warning(
                "ai-tool-versions: %s --version exited %d; stderr: %s",
                name,
                result.returncode,
                (result.stderr or "")[:200],
            )
            return None
        match = re.search(regex, result.stdout)
        if match is None:
            logger.warning(
                "ai-tool-versions: %s --version output did not match regex; raw: %r",
                name,
                result.stdout[:200],
            )
            return None
        version = match.group(1)
        return Asset(
            id=f"ai-tool-{name}",
            type="ai_tool",
            parent_asset_id=None,
            name=name,
            version=version,
            install_path=None,
            source="ai-tool-versions",
            current_state={"raw_version_output": result.stdout[:200].rstrip()},
            discovered_at=scan_time,
        )
