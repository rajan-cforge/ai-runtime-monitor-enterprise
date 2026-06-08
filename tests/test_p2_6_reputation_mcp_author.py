"""MCP author curator-list reputation client — offline, no network."""

from __future__ import annotations

from pathlib import Path

from claude_monitoring.attack_surface.reputation.mcp_author import (
    MCPAuthorReputationClient,
)
from claude_monitoring.attack_surface.reputation.types import (
    ReputationSignal,
    UnavailableReason,
)


def _write_curator(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "mcp-trusted-authors.yaml"
    path.write_text(content)
    return path


_VALID_YAML = """
commands:
  - claude-mcp
  - npx
package_patterns:
  - "@modelcontextprotocol/server-*"
  - "@anthropic-ai/*"
"""


class TestCommandMatch:
    def test_exact_command_match_marks_verified(self, tmp_path: Path) -> None:
        client = MCPAuthorReputationClient(_write_curator(tmp_path, _VALID_YAML))
        result = client.lookup(command="claude-mcp", first_arg=None)
        assert result.signal is ReputationSignal.MCP_AUTHOR_UNVERIFIED
        assert result.present is True

    def test_unknown_command_falls_through_to_pattern(self, tmp_path: Path) -> None:
        client = MCPAuthorReputationClient(_write_curator(tmp_path, _VALID_YAML))
        result = client.lookup(command="strange-runner", first_arg=None)
        assert result.present is False


class TestPackagePatternMatch:
    def test_modelcontextprotocol_pattern_matches(self, tmp_path: Path) -> None:
        client = MCPAuthorReputationClient(_write_curator(tmp_path, _VALID_YAML))
        result = client.lookup(
            command="strange-runner",  # doesn't match Pass 1
            first_arg="@modelcontextprotocol/server-filesystem",
        )
        assert result.present is True

    def test_anthropic_ai_pattern_matches(self, tmp_path: Path) -> None:
        client = MCPAuthorReputationClient(_write_curator(tmp_path, _VALID_YAML))
        result = client.lookup(command="x", first_arg="@anthropic-ai/some-server")
        assert result.present is True

    def test_unrelated_package_is_unverified(self, tmp_path: Path) -> None:
        client = MCPAuthorReputationClient(_write_curator(tmp_path, _VALID_YAML))
        result = client.lookup(command="x", first_arg="@somebody-else/mcp")
        assert result.present is False


class TestBothFieldsMissing:
    def test_both_none_returns_unverified(self, tmp_path: Path) -> None:
        client = MCPAuthorReputationClient(_write_curator(tmp_path, _VALID_YAML))
        result = client.lookup(command=None, first_arg=None)
        # Defensive default: cannot verify if neither field is present
        assert result.present is False


class TestLoadFailures:
    """Fail-CLOSED — defensive default is unverified-with-reason."""

    def test_missing_file_returns_unavailable(self, tmp_path: Path) -> None:
        client = MCPAuthorReputationClient(tmp_path / "nonexistent.yaml")
        result = client.lookup(command="claude-mcp", first_arg=None)
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED

    def test_malformed_yaml_returns_unavailable(self, tmp_path: Path) -> None:
        path = _write_curator(tmp_path, "not: valid: yaml: [")
        client = MCPAuthorReputationClient(path)
        result = client.lookup(command="x", first_arg="y")
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED

    def test_wildcard_pattern_forbidden(self, tmp_path: Path) -> None:
        """A `*` pattern would trust everything — defensive default
        if anyone tries this."""
        path = _write_curator(
            tmp_path,
            'commands: []\npackage_patterns:\n  - "*"\n',
        )
        client = MCPAuthorReputationClient(path)
        result = client.lookup(command="x", first_arg="anything")
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED


class TestShippedCuratorListLoads:
    """The actual shipped curator list at config/mcp-trusted-authors.yaml
    must load without error."""

    def test_default_path_loads(self) -> None:
        client = MCPAuthorReputationClient()
        # Trigger load
        result = client.lookup(command="claude-mcp", first_arg=None)
        assert result.reason is None  # not failed
        assert result.present is True  # claude-mcp is in the shipped list

    def test_modelcontextprotocol_server_matches_shipped_pattern(self) -> None:
        client = MCPAuthorReputationClient()
        result = client.lookup(
            command="npx",
            first_arg="@modelcontextprotocol/server-filesystem",
        )
        assert result.present is True
