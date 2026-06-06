"""`ClaudeCodeSkillsSource` — discovers user-installed Claude Code skills.

Phase A: ``~/Documents/vigil-notes/v022/phase-1/p1.4/phase-a-investigation.md`` §1.
Spec §4.2 (EASY tier discovery sources).

C3 source — parses YAML frontmatter from user-installable
``SKILL.md`` files. The user-installable surface makes this
attacker-controlled structured input even though no secrets are
expected; the same `safe_yaml_load` anchor/alias caps that defend
the MCP / OpenClaw sources apply here.

**Empirical baseline (Rajan's machine 2026-06-05):** ≥4 skills
under ``~/.claude/skills/codebase-memory-{exploring,quality,
reference,tracing}/SKILL.md``.

**Scope (Phase A defaults):**

- Walks ``~/.claude/skills/<name>/SKILL.md`` only.
- Does NOT walk ``~/.claude/agents/`` (absent today; v2 follow-up).
- Does NOT walk plugin-bundled skills under
  ``~/.claude/plugins/data/*/skills/`` (deferred to v2 per Phase
  A — multiplicity + ownership-attribution still under discussion).
"""

from __future__ import annotations

import logging
import time
from pathlib import Path

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import DiscoverySource
from claude_monitoring.attack_surface.discovery.helpers import (
    safe_yaml_load,
    validate_path,
)

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.claude_code_skills")


_DEFAULT_SKILLS_ROOT: Path = Path.home() / ".claude" / "skills"


class ClaudeCodeSkillsSource(DiscoverySource):
    """Enumerates Claude Code skills under ``~/.claude/skills/``."""

    DEFAULT_TIMEOUT_SEC = 30
    MAX_FILE_SIZE_MB = 10

    def __init__(self, skills_root: Path | None = None) -> None:
        # Resolve default lazily so home-dir changes during test runs don't
        # bind a stale path at import time.
        self.skills_root: Path = Path(skills_root) if skills_root is not None else _DEFAULT_SKILLS_ROOT

    def name(self) -> str:
        """Source identifier per spec §4.2."""
        return "claude-code-skills"

    def requires_auth(self) -> bool:
        """No credentials required; pure local filesystem walk."""
        return False

    def discover(self) -> list[Asset]:
        """Enumerate skill subdirs, parsing each SKILL.md under per-item isolation."""
        if not self.skills_root.is_dir():
            # Root absent → Claude Code never installed, or skills dir
            # never created. Silent normal flow.
            return []
        assets: list[Asset] = []
        scan_time = time.time()
        for entry in sorted(self.skills_root.iterdir()):
            try:
                asset = self._build_asset(entry, scan_time)
            except Exception as exc:
                logger.warning("skipping skill %s: %s", entry.name, exc)
                continue
            if asset is not None:
                assets.append(asset)
        return assets

    def _build_asset(self, skill_dir: Path, scan_time: float) -> Asset | None:
        """Parse one skill dir's SKILL.md and emit an Asset.

        Raises on any policy violation (validate_path size/traversal,
        safe_yaml_load bomb rejection) so the caller's per-item
        try/except can isolate the failure.
        """
        # Validate the dir is within root (catches symlink escape).
        validate_path(skill_dir, root=self.skills_root, max_depth=2)
        if not skill_dir.is_dir():
            return None
        skill_md = skill_dir / "SKILL.md"
        if not skill_md.is_file():
            raise ValueError(f"SKILL.md missing in {skill_dir.name}")
        # Validate the file is within root + size-cap before reading.
        validate_path(skill_md, root=self.skills_root, max_depth=3, check_size=True, max_size_mb=self.MAX_FILE_SIZE_MB)
        content = skill_md.read_text(errors="replace")
        frontmatter = _extract_frontmatter(content)
        parsed: dict = {}
        if frontmatter is not None:
            # safe_yaml_load enforces anchor/alias caps; bomb → ValueError
            loaded = safe_yaml_load(frontmatter)
            if isinstance(loaded, dict):
                parsed = loaded
        current_state: dict = {
            "frontmatter_name": parsed.get("name") if isinstance(parsed.get("name"), str) else None,
            "description": parsed.get("description") if isinstance(parsed.get("description"), str) else None,
        }
        return Asset(
            id=f"claude-code-skill-{skill_dir.name}",
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
    """Return the YAML frontmatter block, or None when absent.

    Frontmatter convention: file starts with ``---\\n``, then YAML,
    then a closing ``---\\n``. Anything else returns None.
    """
    if not content.startswith("---"):
        return None
    # Strip the leading marker line and search for the closing marker.
    rest = content[3:]
    # Skip the newline after the opening ---
    if rest.startswith("\n"):
        rest = rest[1:]
    closing = rest.find("\n---")
    if closing == -1:
        return None
    return rest[:closing]
