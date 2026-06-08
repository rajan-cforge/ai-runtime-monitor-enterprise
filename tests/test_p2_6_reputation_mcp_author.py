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
privileged_commands:
  - claude-mcp
generic_runners:
  - npx
  - uvx
package_patterns:
  - "@modelcontextprotocol/server-*"
  - "@anthropic-ai/*"
"""


class TestPass1PrivilegedCommandStandaloneTrust:
    """`privileged_commands` carry standalone trust — verify with no Pass 2."""

    def test_privileged_command_match_verifies(self, tmp_path: Path) -> None:
        client = MCPAuthorReputationClient(_write_curator(tmp_path, _VALID_YAML))
        result = client.lookup(command="claude-mcp", first_arg=None)
        assert result.signal is ReputationSignal.MCP_AUTHOR_UNVERIFIED
        assert result.present is True

    def test_unrecognized_command_alone_is_unverified(self, tmp_path: Path) -> None:
        client = MCPAuthorReputationClient(_write_curator(tmp_path, _VALID_YAML))
        result = client.lookup(command="strange-runner", first_arg=None)
        assert result.present is False


class TestPass2GenericRunnerRequiresPackagePattern:
    """Architect-pass BLOCKER #1 fix: `generic_runners` (npx/uvx/python/…)
    do NOT verify on command alone. The package the runner executes
    (``args[0]``) must ALSO match a curated pattern."""

    def test_generic_runner_with_curated_package_verifies(self, tmp_path: Path) -> None:
        client = MCPAuthorReputationClient(_write_curator(tmp_path, _VALID_YAML))
        result = client.lookup(
            command="npx",
            first_arg="@modelcontextprotocol/server-filesystem",
        )
        assert result.present is True

    def test_generic_runner_with_uncurated_package_is_unverified(
        self, tmp_path: Path
    ) -> None:
        """The adversarial case — npx + evil-package MUST NOT verify."""
        client = MCPAuthorReputationClient(_write_curator(tmp_path, _VALID_YAML))
        result = client.lookup(command="npx", first_arg="evil-package")
        assert result.present is False, (
            "command in generic_runners alone must NOT verify; "
            "the runner must combine with a curated package pattern"
        )

    def test_generic_runner_with_no_args_is_unverified(self, tmp_path: Path) -> None:
        """No package to match → cannot complete Pass 2."""
        client = MCPAuthorReputationClient(_write_curator(tmp_path, _VALID_YAML))
        result = client.lookup(command="uvx", first_arg=None)
        assert result.present is False


class TestPackagePatternRequiresGenericRunner:
    """A curated package pattern alone — without a recognized runner —
    does not verify. The shape is "known runner + known package."""

    def test_pattern_match_with_unknown_command_is_unverified(self, tmp_path: Path) -> None:
        client = MCPAuthorReputationClient(_write_curator(tmp_path, _VALID_YAML))
        result = client.lookup(
            command="strange-runner",
            first_arg="@modelcontextprotocol/server-filesystem",
        )
        assert result.present is False

    def test_unrelated_package_is_unverified(self, tmp_path: Path) -> None:
        client = MCPAuthorReputationClient(_write_curator(tmp_path, _VALID_YAML))
        result = client.lookup(command="npx", first_arg="@somebody-else/mcp")
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
            'privileged_commands: []\ngeneric_runners: []\npackage_patterns:\n  - "*"\n',
        )
        client = MCPAuthorReputationClient(path)
        result = client.lookup(command="x", first_arg="anything")
        assert result.present is None
        assert result.reason is UnavailableReason.LOOKUP_FAILED

    def test_load_failure_latches_no_repeated_critical_log(
        self, tmp_path: Path, caplog
    ) -> None:
        """Architect-pass STRONG #2 fix: a failed load logs CRITICAL once,
        not once per asset. The `_load_failed` latch prevents re-reading
        the file on every lookup."""
        client = MCPAuthorReputationClient(tmp_path / "nonexistent.yaml")
        with caplog.at_level("CRITICAL"):
            # 5 lookups against a missing file — should log CRITICAL once
            for _ in range(5):
                result = client.lookup(command="claude-mcp", first_arg=None)
                assert result.reason is UnavailableReason.LOOKUP_FAILED
        critical_count = sum(1 for r in caplog.records if r.levelname == "CRITICAL")
        assert critical_count == 1, (
            f"expected CRITICAL log exactly once across 5 lookups, got {critical_count}"
        )


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
