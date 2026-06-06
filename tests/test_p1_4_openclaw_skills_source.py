"""P1.4 C3 batch — `OpenClawSkillsSource` tests.

C3 source — parses `SKILL.md` YAML frontmatter under two roots:

1. ``/opt/homebrew/lib/node_modules/openclaw/skills/`` — bundled
   (npm-installed via Homebrew)
2. ``~/.openclaw/workspace/skills/`` — user workspace

Shape is identical to the Claude Code skills source; tests are
the same shape adapted for the dual-root iteration.

Empirical baseline (Rajan's machine 2026-06-05): dozens of bundled
skills (`1password`, `apple-notes`, ...); 2 user skills
(`clawguard`, `clawmemory`).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from claude_monitoring.attack_surface.discovery.base import LastRunOutcome
from claude_monitoring.attack_surface.discovery.sources.openclaw_skills import (
    OpenClawSkillsSource,
)

_VALID_SKILL_MD = """---
name: my-skill
description: An OpenClaw test skill.
---

# Body
"""


def _make_skill(root: Path, name: str, content: str = _VALID_SKILL_MD) -> Path:
    skill_dir = root / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(content)
    return skill_dir


class TestOpenClawSkillsSourceContract:
    def test_name_is_openclaw_skills(self) -> None:
        assert OpenClawSkillsSource().name() == "openclaw-skills"

    def test_requires_auth_is_false(self) -> None:
        assert OpenClawSkillsSource().requires_auth() is False


class TestOpenClawSkillsDualRoot:
    def test_bundled_and_workspace_aggregate(self, tmp_path: Path) -> None:
        """Skills under both roots are merged into a single result set."""
        bundled = tmp_path / "bundled" / "skills"
        workspace = tmp_path / "workspace" / "skills"
        _make_skill(bundled, "bundled-a")
        _make_skill(bundled, "bundled-b")
        _make_skill(workspace, "workspace-x")
        src = OpenClawSkillsSource(skill_roots=[bundled, workspace])
        result = src.run_with_safety()
        assert len(result) == 3
        assert {a.name for a in result} == {"bundled-a", "bundled-b", "workspace-x"}
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_one_root_absent_other_root_still_yields_assets(self, tmp_path: Path) -> None:
        """If bundled root absent (no Homebrew install), workspace skills still emit."""
        absent = tmp_path / "absent"
        present = tmp_path / "present" / "skills"
        _make_skill(present, "only-workspace")
        src = OpenClawSkillsSource(skill_roots=[absent, present])
        result = src.run_with_safety()
        assert len(result) == 1
        assert result[0].name == "only-workspace"

    def test_same_name_in_both_roots_yields_distinct_ids(self, tmp_path: Path) -> None:
        """Same skill name in bundled + workspace → 2 distinct assets."""
        bundled = tmp_path / "bundled" / "skills"
        workspace = tmp_path / "workspace" / "skills"
        _make_skill(bundled, "clawmemory")
        _make_skill(workspace, "clawmemory")
        src = OpenClawSkillsSource(skill_roots=[bundled, workspace])
        result = src.run_with_safety()
        assert len(result) == 2
        ids = [a.id for a in result]
        assert len(set(ids)) == 2


class TestOpenClawSkillsHappyPath:
    def test_skill_metadata_persisted(self, tmp_path: Path) -> None:
        bundled = tmp_path / "bundled" / "skills"
        _make_skill(bundled, "my-skill")
        src = OpenClawSkillsSource(skill_roots=[bundled])
        result = src.run_with_safety()
        assert len(result) == 1
        state = result[0].current_state
        assert state.get("description") == "An OpenClaw test skill."

    def test_every_asset_has_expected_contract(self, tmp_path: Path) -> None:
        bundled = tmp_path / "bundled" / "skills"
        _make_skill(bundled, "a")
        _make_skill(bundled, "b")
        src = OpenClawSkillsSource(skill_roots=[bundled])
        result = src.run_with_safety()
        for asset in result:
            assert asset.source == "openclaw-skills"
            assert asset.type == "ai_tool"
            assert asset.version is None


class TestOpenClawSkillsPerItemIsolation:
    def test_one_skill_missing_skill_md(self, tmp_path: Path, caplog) -> None:
        root = tmp_path / "skills"
        _make_skill(root, "good")
        (root / "no-skill-md").mkdir(parents=True)
        src = OpenClawSkillsSource(skill_roots=[root])
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.openclaw_skills"):
            result = src.run_with_safety()
        assert len(result) == 1
        assert result[0].name == "good"

    def test_oversized_skill_md_rejected(self, tmp_path: Path, caplog) -> None:
        root = tmp_path / "skills"
        _make_skill(root, "good")
        oversized_dir = root / "oversized"
        oversized_dir.mkdir(parents=True)
        (oversized_dir / "SKILL.md").write_text("a" * (11 * 1024 * 1024))
        src = OpenClawSkillsSource(skill_roots=[root])
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.openclaw_skills"):
            result = src.run_with_safety()
        assert len(result) == 1
        assert result[0].name == "good"


class TestOpenClawSkillsDefaultRoots:
    def test_default_roots_include_bundled_and_workspace(self) -> None:
        src = OpenClawSkillsSource()
        paths_str = [str(p) for p in src.skill_roots]
        assert any("openclaw/skills" in p for p in paths_str)
        assert any(".openclaw/workspace/skills" in p for p in paths_str)


class TestOpenClawSkillsEmpirical:
    def test_real_openclaw_skills_root_yields_assets(self) -> None:
        """Empirical (CLAUDE.md §9). Skip when no roots present."""
        src = OpenClawSkillsSource()
        if not any(p.is_dir() for p in src.skill_roots):
            pytest.skip("no OpenClaw skill roots present on this machine")
        result = src.run_with_safety()
        # ≥1 skill if at least one root is present
        assert len(result) >= 1
        for asset in result:
            assert asset.name
            assert asset.source == "openclaw-skills"
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
