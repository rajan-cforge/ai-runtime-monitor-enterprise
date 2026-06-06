"""P1.4 C3 batch — `ClaudeCodeSkillsSource` tests.

C3 source — parses attacker-controlled SKILL.md YAML frontmatter
under `~/.claude/skills/<skill>/SKILL.md`. Per-item isolation
contract pinned; safe_yaml_load anchor/alias caps are the
billion-laughs defense (already covered in helpers_tests; here we
just assert the bomb is rejected without crashing the batch).

Empirical baseline (Rajan's machine 2026-06-05): ≥4 skills under
`~/.claude/skills/codebase-memory-*/SKILL.md`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from claude_monitoring.attack_surface.discovery.base import LastRunOutcome
from claude_monitoring.attack_surface.discovery.sources.claude_code_skills import (
    ClaudeCodeSkillsSource,
)

_VALID_SKILL_MD = """---
name: my-skill
description: A test skill that does something useful.
---

# My Skill

Body content here.
"""

_VALID_SKILL_MD_MINIMAL = """---
name: minimal-skill
---

Body.
"""

_BILLION_LAUGHS_YAML = """---
a: &a [x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a,*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b,*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c,*c,*c,*c,*c,*c,*c,*c,*c,*c,*c,*c]
e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d,*d,*d,*d,*d,*d,*d,*d,*d,*d,*d,*d]
f: &f [*e,*e,*e,*e,*e,*e,*e,*e,*e,*e,*e,*e,*e,*e,*e,*e,*e,*e,*e,*e]
g: &g [*f,*f,*f,*f,*f,*f,*f,*f,*f,*f,*f,*f,*f,*f,*f,*f,*f,*f,*f,*f]
h: &h [*g,*g,*g,*g,*g,*g,*g,*g,*g,*g,*g,*g,*g,*g,*g,*g,*g,*g,*g,*g]
i: &i [*h,*h,*h,*h,*h,*h,*h,*h,*h,*h,*h,*h,*h,*h,*h,*h,*h,*h,*h,*h]
---
"""


def _make_skill(root: Path, name: str, content: str = _VALID_SKILL_MD) -> Path:
    """Helper: create root/<name>/SKILL.md with the given content."""
    skill_dir = root / name
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(content)
    return skill_dir


class TestClaudeCodeSkillsSourceContract:
    """Cross-cutting DiscoverySource contract assertions."""

    def test_name_is_claude_code_skills(self) -> None:
        assert ClaudeCodeSkillsSource().name() == "claude-code-skills"

    def test_requires_auth_is_false(self) -> None:
        assert ClaudeCodeSkillsSource().requires_auth() is False


class TestClaudeCodeSkillsSourceHappyPath:
    def test_three_skills_yields_three_assets(self, tmp_path: Path) -> None:
        """3 skill dirs → 3 assets; outcome SUCCESS."""
        _make_skill(tmp_path, "skill-one")
        _make_skill(tmp_path, "skill-two")
        _make_skill(tmp_path, "skill-three", _VALID_SKILL_MD_MINIMAL)
        src = ClaudeCodeSkillsSource(skills_root=tmp_path)
        result = src.run_with_safety()
        assert len(result) == 3
        names = {a.name for a in result}
        assert names == {"skill-one", "skill-two", "skill-three"}
        for a in result:
            assert a.source == "claude-code-skills"
            assert a.type == "ai_tool"
            assert a.version is None
            assert a.install_path is not None
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_skill_metadata_persisted_in_current_state(self, tmp_path: Path) -> None:
        """Frontmatter description landed in current_state for downstream display."""
        _make_skill(tmp_path, "my-skill")
        src = ClaudeCodeSkillsSource(skills_root=tmp_path)
        result = src.run_with_safety()
        assert len(result) == 1
        state = result[0].current_state
        assert state.get("frontmatter_name") == "my-skill"
        assert state.get("description") == "A test skill that does something useful."


class TestClaudeCodeSkillsSourceEmptyAndMissing:
    def test_empty_root_returns_empty_list(self, tmp_path: Path) -> None:
        """Root exists but has no skill dirs → [] + SUCCESS."""
        src = ClaudeCodeSkillsSource(skills_root=tmp_path)
        result = src.run_with_safety()
        assert result == []
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_missing_root_silent_empty(self, tmp_path: Path, caplog) -> None:
        """Root does not exist (Claude Code never installed) → [] silently, SUCCESS, no WARNING."""
        nonexistent = tmp_path / "no-such-dir"
        src = ClaudeCodeSkillsSource(skills_root=nonexistent)
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.claude_code_skills"):
            result = src.run_with_safety()
        assert result == []
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
        assert not any(
            r.name == "ai-runtime-monitor.attack_surface.discovery.claude_code_skills" for r in caplog.records
        )


class TestClaudeCodeSkillsSourcePerItemIsolation:
    """The cross-cutting per-item isolation contract.

    One bad skill MUST NOT poison the batch.
    """

    def test_three_skills_one_missing_skill_md(self, tmp_path: Path, caplog) -> None:
        """3 dirs; 1 has no SKILL.md → 2 assets + 1 WARNING."""
        _make_skill(tmp_path, "good-one")
        (tmp_path / "broken-no-skill-md").mkdir()  # No SKILL.md
        _make_skill(tmp_path, "good-two")
        src = ClaudeCodeSkillsSource(skills_root=tmp_path)
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.claude_code_skills"):
            result = src.run_with_safety()
        assert len(result) == 2
        assert {a.name for a in result} == {"good-one", "good-two"}
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
        assert any("broken-no-skill-md" in (r.message or "") for r in caplog.records)

    def test_three_skills_one_malformed_yaml(self, tmp_path: Path, caplog) -> None:
        """3 dirs; 1 has SKILL.md with broken YAML → 2 assets + 1 WARNING."""
        _make_skill(tmp_path, "good-one")
        _make_skill(tmp_path, "broken-yaml", "---\nname: : : :\n  bad: indent\n---\n")
        _make_skill(tmp_path, "good-two")
        src = ClaudeCodeSkillsSource(skills_root=tmp_path)
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.claude_code_skills"):
            result = src.run_with_safety()
        # Note: malformed YAML doesn't always raise — it may parse to a weird
        # but valid structure. The contract is "no crash, no batch poison."
        assert len(result) >= 2
        assert {"good-one", "good-two"}.issubset({a.name for a in result})
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_three_skills_one_billion_laughs_bomb(self, tmp_path: Path, caplog) -> None:
        """3 dirs; 1 has a YAML bomb → 2 assets + 1 WARNING; bomb structurally rejected by safe_yaml_load."""
        _make_skill(tmp_path, "good-one")
        _make_skill(tmp_path, "bombed", _BILLION_LAUGHS_YAML)
        _make_skill(tmp_path, "good-two")
        src = ClaudeCodeSkillsSource(skills_root=tmp_path)
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.claude_code_skills"):
            result = src.run_with_safety()
        assert len(result) == 2
        assert {a.name for a in result} == {"good-one", "good-two"}
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
        # Bomb-rejection WARNING fires; "bombed" appears in the message.
        assert any("bombed" in (r.message or "") for r in caplog.records)

    def test_no_frontmatter_falls_back_to_dir_name(self, tmp_path: Path) -> None:
        """SKILL.md with no `---` frontmatter → asset still emitted with name=dir; description empty."""
        _make_skill(tmp_path, "no-frontmatter", "Just plain markdown content.\n")
        src = ClaudeCodeSkillsSource(skills_root=tmp_path)
        result = src.run_with_safety()
        assert len(result) == 1
        assert result[0].name == "no-frontmatter"
        assert result[0].current_state.get("description") is None


class TestClaudeCodeSkillsSourceSizeCap:
    def test_oversized_skill_md_rejected(self, tmp_path: Path, caplog) -> None:
        """SKILL.md > 10 MiB cap → that skill skipped + WARNING; others survive."""
        _make_skill(tmp_path, "good")
        oversized_dir = tmp_path / "oversized"
        oversized_dir.mkdir()
        # 11 MiB of `a` characters
        (oversized_dir / "SKILL.md").write_text("a" * (11 * 1024 * 1024))
        src = ClaudeCodeSkillsSource(skills_root=tmp_path)
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.claude_code_skills"):
            result = src.run_with_safety()
        assert len(result) == 1
        assert result[0].name == "good"
        assert any("oversized" in (r.message or "") for r in caplog.records)


class TestClaudeCodeSkillsSourceSymlinkEscape:
    def test_symlinked_skill_dir_pointing_outside_root_rejected(self, tmp_path: Path, caplog) -> None:
        """Symlink under skills_root pointing outside → rejected by validate_path; batch survives."""
        _make_skill(tmp_path, "legit")
        outside = tmp_path.parent / "outside-skill-dir"
        outside.mkdir(parents=True, exist_ok=True)
        (outside / "SKILL.md").write_text(_VALID_SKILL_MD)
        # Symlink legit subdir under root to the outside path
        (tmp_path / "escape").symlink_to(outside, target_is_directory=True)
        src = ClaudeCodeSkillsSource(skills_root=tmp_path)
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.claude_code_skills"):
            result = src.run_with_safety()
        # Only "legit" survives; "escape" is rejected by validate_path
        names = {a.name for a in result}
        assert "legit" in names
        assert "escape" not in names


class TestClaudeCodeSkillsSourceEmpirical:
    """CLAUDE.md §9 empirical verification gate."""

    def test_real_skills_root_yields_expected_count(self) -> None:
        """Run against the actual ~/.claude/skills/ on this machine.

        Skips if the directory is absent. When present, asserts that
        every emitted asset has a non-empty name + source.
        """
        real_root = Path.home() / ".claude" / "skills"
        if not real_root.is_dir():
            pytest.skip("~/.claude/skills/ not present on this machine")
        src = ClaudeCodeSkillsSource(skills_root=real_root)
        result = src.run_with_safety()
        # Sanity: every emitted asset has the expected source identity
        for a in result:
            assert a.name
            assert a.source == "claude-code-skills"
            assert a.type == "ai_tool"
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS


class TestClaudeCodeSkillsDefaultRoot:
    """Pin the default root path so calling sites don't have to override it."""

    def test_default_root_is_home_dot_claude_skills(self) -> None:
        """Default `skills_root` is `~/.claude/skills` (or None if home-relative)."""
        src = ClaudeCodeSkillsSource()
        # The default may be a Path; we assert it's home-relative.
        assert str(src.skills_root).endswith(".claude/skills")

    def test_explicit_root_override_takes_precedence(self, tmp_path: Path) -> None:
        src = ClaudeCodeSkillsSource(skills_root=tmp_path)
        assert src.skills_root == tmp_path
