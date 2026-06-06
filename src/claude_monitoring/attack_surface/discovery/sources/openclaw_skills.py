"""`OpenClawSkillsSource` — discovers OpenClaw skills.

Phase A: ``~/Documents/vigil-notes/v022/phase-1/p1.4/phase-a-investigation.md`` §3.

C3 source — same SKILL.md+YAML-frontmatter shape as Claude Code
skills, but with two roots:

- Bundled (Homebrew/npm-installed):
  ``/opt/homebrew/lib/node_modules/openclaw/skills/<skill>/SKILL.md``
- User workspace:
  ``~/.openclaw/workspace/skills/<skill>/SKILL.md``

Ephemeral sandbox skills under ``~/.openclaw/sandboxes/*/skills/``
are deferred per Phase A — they're noisy and per-session.

**Empirical baseline (Rajan's machine 2026-06-05):** ≥10 bundled
skills (apple-notes, bear-notes, gh-issues, ...); 2 user skills
(clawguard, clawmemory).
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import DiscoverySource
from claude_monitoring.attack_surface.discovery.helpers import (
    safe_yaml_load,
    validate_path,
)

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.openclaw_skills")


_DEFAULT_ROOTS: list[Path] = [
    Path("/opt/homebrew/lib/node_modules/openclaw/skills"),
    Path.home() / ".openclaw" / "workspace" / "skills",
]


class OpenClawSkillsSource(DiscoverySource):
    """Enumerates OpenClaw skills across bundled + user-workspace roots."""

    DEFAULT_TIMEOUT_SEC = 30
    MAX_FILE_SIZE_MB = 10

    def __init__(self, skill_roots: list[Path] | None = None) -> None:
        self.skill_roots: list[Path] = (
            [Path(p) for p in skill_roots] if skill_roots is not None else list(_DEFAULT_ROOTS)
        )

    def name(self) -> str:
        """Source identifier per spec §4.2."""
        return "openclaw-skills"

    def requires_auth(self) -> bool:
        """No credentials required; pure local filesystem walk."""
        return False

    def discover(self) -> list[Asset]:
        """Walk each skill_root; emit one asset per SKILL.md under per-item isolation."""
        assets: list[Asset] = []
        scan_time = time.time()
        for root in self.skill_roots:
            if not root.is_dir():
                # Absent root → that surface not installed; normal flow.
                continue
            for entry in sorted(root.iterdir()):
                try:
                    asset = self._build_asset(entry, root, scan_time)
                except Exception as exc:
                    logger.warning("skipping openclaw skill %s under %s: %s", entry.name, root, exc)
                    continue
                if asset is not None:
                    assets.append(asset)
        return assets

    def _build_asset(self, skill_dir: Path, root: Path, scan_time: float) -> Asset | None:
        validate_path(skill_dir, root=root, max_depth=2)
        if not skill_dir.is_dir():
            return None
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.is_file():
            raise ValueError(f"SKILL.md missing in {skill_dir.name}")
        validate_path(skill_md, root=root, max_depth=3, check_size=True, max_size_mb=self.MAX_FILE_SIZE_MB)
        content = skill_md.read_text(errors="replace")
        frontmatter = _extract_frontmatter(content)
        parsed: dict = {}
        if frontmatter is not None:
            loaded = safe_yaml_load(frontmatter)
            if isinstance(loaded, dict):
                parsed = loaded
        current_state: dict = {
            "root": str(root),
            "frontmatter_name": parsed.get("name") if isinstance(parsed.get("name"), str) else None,
            "description": parsed.get("description") if isinstance(parsed.get("description"), str) else None,
        }
        # id is a stable digest of (root, skill_name) — same skill name in
        # bundled vs workspace yields distinct ids; identical across daemon
        # restarts. sha256 (not built-in hash()) because PYTHONHASHSEED is
        # randomized per process and would break the UPSERT first_seen
        # preservation contract (Asset spec drift 2).
        key = f"{root}|{skill_dir.name}".encode()
        asset_id = f"openclaw-skill-{hashlib.sha256(key).hexdigest()[:16]}"
        return Asset(
            id=asset_id,
            type="ai_tool",
            parent_asset_id=None,
            name=skill_dir.name,
            version=None,
            install_path=str(skill_dir),
            source=self.name(),
            current_state=current_state,
            discovered_at=scan_time,
        )


def _extract_frontmatter(content: str) -> str | None:
    if not content.startswith("---"):
        return None
    rest = content[3:]
    if rest.startswith("\n"):
        rest = rest[1:]
    closing = rest.find("\n---")
    if closing == -1:
        return None
    return rest[:closing]
