"""P1.4 C3 batch — `McpServersSource` tests.

C3 source with **secret-path attention** — parses MCP server config
files that contain `env: {TOKEN: "..."}` style secrets. Three
config surfaces:

1. Claude Desktop ``~/Library/Application Support/Claude/claude_desktop_config.json``
2. Claude Code ``~/.claude.json`` — top-level ``mcpServers`` AND per-project
   ``projects.<project_path>.mcpServers``
3. Cursor ``~/.cursor/mcp.json``

**Secret-path test contract (Phase A §4.G):** the `redact_secrets_in_env`
mock-and-assert-called pattern fires on every server with an `env`
dict. Bypassing redaction is a test-failing offense.

**Per-item isolation contract — two layers:**
- Per-config: bad JSON / missing file / oversized → log + continue
- Per-server in a config: missing `command`, redaction failure → log + continue
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest import mock

import pytest

from claude_monitoring.attack_surface.discovery.base import LastRunOutcome
from claude_monitoring.attack_surface.discovery.sources.mcp_servers import (
    McpServersSource,
)


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload))
    return path


def _claude_desktop_config(tmp: Path, payload: dict) -> Path:
    return _write_json(tmp / "claude_desktop" / "claude_desktop_config.json", payload)


def _claude_code_config(tmp: Path, payload: dict) -> Path:
    return _write_json(tmp / "claude_code" / ".claude.json", payload)


def _cursor_config(tmp: Path, payload: dict) -> Path:
    return _write_json(tmp / "cursor" / "mcp.json", payload)


class TestMcpServersSourceContract:
    def test_name_is_mcp_servers(self) -> None:
        assert McpServersSource().name() == "mcp-servers"

    def test_requires_auth_is_false(self) -> None:
        assert McpServersSource().requires_auth() is False


class TestMcpServersSourceHappyPath:
    def test_one_server_in_claude_desktop_yields_one_asset(self, tmp_path: Path) -> None:
        config = _claude_desktop_config(
            tmp_path,
            {
                "mcpServers": {
                    "talosai": {
                        "command": "node",
                        "args": ["/path/to/talosai/server.js"],
                        "env": {"TALOSAI_API_URL": "https://api.talosai.com", "TALOSAI_API_KEY": "sk-secret-xyz"},
                    }
                }
            },
        )
        src = McpServersSource(config_paths=[config])
        result = src.run_with_safety()
        assert len(result) == 1
        asset = result[0]
        assert asset.source == "mcp-servers"
        assert asset.type == "mcp_server"
        assert asset.name == "talosai"
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_three_configs_each_with_one_server_yields_three_assets(self, tmp_path: Path) -> None:
        c1 = _claude_desktop_config(tmp_path, {"mcpServers": {"a": {"command": "a"}}})
        c2 = _claude_code_config(tmp_path, {"mcpServers": {"b": {"command": "b"}}})
        c3 = _cursor_config(tmp_path, {"mcpServers": {"c": {"command": "c"}}})
        src = McpServersSource(config_paths=[c1, c2, c3])
        result = src.run_with_safety()
        assert len(result) == 3
        assert {a.name for a in result} == {"a", "b", "c"}

    def test_claude_code_per_project_servers_are_enumerated(self, tmp_path: Path) -> None:
        """Claude Code ~/.claude.json has top-level + projects.<path>.mcpServers."""
        cfg = _claude_code_config(
            tmp_path,
            {
                "mcpServers": {"global-server": {"command": "g"}},
                "projects": {
                    "/Users/x/proj-a": {"mcpServers": {"proj-a-server": {"command": "a"}}},
                    "/Users/x/proj-b": {"mcpServers": {"proj-b-server": {"command": "b"}}},
                },
            },
        )
        src = McpServersSource(config_paths=[cfg])
        result = src.run_with_safety()
        names = {a.name for a in result}
        assert names == {"global-server", "proj-a-server", "proj-b-server"}


class TestMcpServersSourceSecretRedaction:
    """Secret-path attention — redaction is mandatory."""

    def test_token_key_name_redacted_in_current_state(self, tmp_path: Path) -> None:
        """`TALOSAI_API_KEY` matches the name-based redaction rule → value hidden."""
        config = _claude_desktop_config(
            tmp_path,
            {
                "mcpServers": {
                    "talosai": {
                        "command": "node",
                        "env": {
                            "TALOSAI_API_URL": "https://api.talosai.com",
                            "TALOSAI_API_KEY": "sk-supersecret-xyz",
                        },
                    }
                }
            },
        )
        src = McpServersSource(config_paths=[config])
        result = src.run_with_safety()
        env = result[0].current_state.get("env", {})
        # API_KEY redacted; API_URL preserved
        assert env.get("TALOSAI_API_KEY") != "sk-supersecret-xyz"
        assert "REDACTED" in env.get("TALOSAI_API_KEY", "")
        assert env.get("TALOSAI_API_URL") == "https://api.talosai.com"

    def test_token_value_pattern_redacted(self, tmp_path: Path) -> None:
        """A GitHub `ghp_...` token value triggers value-based redaction even when name is plain."""
        config = _claude_desktop_config(
            tmp_path,
            {
                "mcpServers": {
                    "gh-mcp": {
                        "command": "gh-mcp",
                        "env": {"PLAIN_NAME": "ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"},
                    }
                }
            },
        )
        src = McpServersSource(config_paths=[config])
        result = src.run_with_safety()
        env = result[0].current_state.get("env", {})
        assert "REDACTED" in env.get("PLAIN_NAME", "")

    def test_redact_secrets_in_env_is_actually_called(self, tmp_path: Path) -> None:
        """**Bypassing redaction is a test-fail.** Patch redact_secrets_in_env
        and assert it was invoked for the server with env."""
        config = _claude_desktop_config(
            tmp_path,
            {"mcpServers": {"s": {"command": "c", "env": {"FOO": "bar"}}}},
        )
        src = McpServersSource(config_paths=[config])
        with mock.patch(
            "claude_monitoring.attack_surface.discovery.sources.mcp_servers.redact_secrets_in_env",
            wraps=lambda d: {"WATERMARK": "yes"},
        ) as redact_mock:
            result = src.run_with_safety()
        assert redact_mock.called
        # Watermark proves the patched function's output was actually
        # stored — not just called and ignored.
        assert result[0].current_state.get("env") == {"WATERMARK": "yes"}

    def test_no_env_dict_no_redaction_call(self, tmp_path: Path) -> None:
        """Server with no `env` → redact_secrets_in_env NOT called for that server."""
        config = _claude_desktop_config(
            tmp_path,
            {"mcpServers": {"no-env": {"command": "c"}}},
        )
        src = McpServersSource(config_paths=[config])
        with mock.patch(
            "claude_monitoring.attack_surface.discovery.sources.mcp_servers.redact_secrets_in_env",
        ) as redact_mock:
            result = src.run_with_safety()
        assert len(result) == 1
        assert not redact_mock.called


class TestMcpServersSourceEmptyAndMissing:
    def test_empty_paths_list_yields_empty_assets(self) -> None:
        src = McpServersSource(config_paths=[])
        result = src.run_with_safety()
        assert result == []
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_missing_config_file_silent_skip(self, tmp_path: Path, caplog) -> None:
        nonexistent = tmp_path / "no-such" / "config.json"
        src = McpServersSource(config_paths=[nonexistent])
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.mcp_servers"):
            result = src.run_with_safety()
        assert result == []
        # Missing config = "not installed" = silent normal flow
        assert not any(
            r.name == "ai-runtime-monitor.attack_surface.discovery.mcp_servers" and r.levelname == "WARNING"
            for r in caplog.records
        )

    def test_config_without_mcp_servers_key_yields_empty(self, tmp_path: Path) -> None:
        """`~/.claude.json` is 63 KB of user state but no `mcpServers` → []; not an error."""
        cfg = _claude_code_config(tmp_path, {"some_other_key": "value"})
        src = McpServersSource(config_paths=[cfg])
        result = src.run_with_safety()
        assert result == []


class TestMcpServersSourcePerItemIsolation:
    """Two-layer per-item isolation contract."""

    def test_one_bad_config_does_not_poison_others(self, tmp_path: Path, caplog) -> None:
        """3 configs; 1 has malformed JSON → assets from other 2; 1 WARNING."""
        c1 = _claude_desktop_config(tmp_path, {"mcpServers": {"good-a": {"command": "a"}}})
        bad = tmp_path / "claude_code" / ".claude.json"
        bad.parent.mkdir(parents=True, exist_ok=True)
        bad.write_text("{not valid json")
        c3 = _cursor_config(tmp_path, {"mcpServers": {"good-c": {"command": "c"}}})
        src = McpServersSource(config_paths=[c1, bad, c3])
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.mcp_servers"):
            result = src.run_with_safety()
        names = {a.name for a in result}
        assert names == {"good-a", "good-c"}
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
        assert any("json" in (r.message or "").lower() for r in caplog.records)

    def test_one_bad_server_does_not_poison_others_in_same_config(self, tmp_path: Path, caplog) -> None:
        """One config with 3 servers; 1 has no command → 2 assets + 1 WARNING."""
        c = _claude_desktop_config(
            tmp_path,
            {
                "mcpServers": {
                    "good-a": {"command": "a"},
                    "broken": "this-is-a-string-not-a-dict",
                    "good-c": {"command": "c"},
                }
            },
        )
        src = McpServersSource(config_paths=[c])
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.mcp_servers"):
            result = src.run_with_safety()
        names = {a.name for a in result}
        assert names == {"good-a", "good-c"}
        assert any("broken" in (r.message or "") for r in caplog.records)

    def test_oversized_config_rejected_others_survive(self, tmp_path: Path, caplog) -> None:
        """Config > 10 MiB → that config skipped + WARNING; other configs still scanned."""
        good = _claude_desktop_config(tmp_path, {"mcpServers": {"survivor": {"command": "s"}}})
        oversized = tmp_path / "cursor" / "mcp.json"
        oversized.parent.mkdir(parents=True, exist_ok=True)
        # 11 MiB of `a` characters → not valid JSON but the size cap fires first
        oversized.write_text("a" * (11 * 1024 * 1024))
        src = McpServersSource(config_paths=[good, oversized])
        with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.mcp_servers"):
            result = src.run_with_safety()
        assert {a.name for a in result} == {"survivor"}


class TestMcpServersAssetIdUniqueness:
    """Asset.id digests (config_path, scope, server_name) so the same MCP
    name in Claude Desktop AND Cursor AND Claude Code yields 3 distinct
    assets — AND the id is stable across daemon restarts (sha256, not
    PYTHONHASHSEED-randomized built-in hash())."""

    def test_same_name_across_configs_yields_distinct_ids(self, tmp_path: Path) -> None:
        same_name = "codebase-memory-mcp"
        c1 = _claude_desktop_config(tmp_path, {"mcpServers": {same_name: {"command": "x"}}})
        c2 = _claude_code_config(tmp_path, {"mcpServers": {same_name: {"command": "x"}}})
        c3 = _cursor_config(tmp_path, {"mcpServers": {same_name: {"command": "x"}}})
        src = McpServersSource(config_paths=[c1, c2, c3])
        result = src.run_with_safety()
        ids = [a.id for a in result]
        assert len(ids) == 3
        assert len(set(ids)) == 3, f"expected 3 distinct ids, got {ids}"

    def test_id_is_stable_across_processes_with_different_pythonhashseed(self, tmp_path: Path) -> None:
        """**C1 regression pin.** Asset.id must be a stable digest so the
        UPSERT path's `first_seen` preservation works across daemon
        restarts. Spawn a subprocess with PYTHONHASHSEED=12345 and assert
        the id matches the in-process id (which runs under a different
        seed)."""
        import os
        import subprocess
        import sys

        config_path = _claude_desktop_config(
            tmp_path,
            {"mcpServers": {"stable-name": {"command": "x"}}},
        )
        in_process = McpServersSource(config_paths=[config_path]).run_with_safety()
        assert len(in_process) == 1
        in_process_id = in_process[0].id

        subprocess_script = (
            "import sys, json\n"
            f"sys.path.insert(0, {str(Path.cwd() / 'src')!r})\n"
            "from claude_monitoring.attack_surface.discovery.sources.mcp_servers import McpServersSource\n"
            "from pathlib import Path\n"
            f"r = McpServersSource(config_paths=[Path({str(config_path)!r})]).run_with_safety()\n"
            "print(r[0].id)\n"
        )
        env = os.environ.copy()
        env["PYTHONHASHSEED"] = "12345"
        result = subprocess.run(
            [sys.executable, "-c", subprocess_script],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
        assert result.returncode == 0, f"subprocess failed: {result.stderr}"
        subprocess_id = result.stdout.strip()
        assert subprocess_id == in_process_id, (
            f"Asset.id is process-unstable: in-process={in_process_id!r} subprocess={subprocess_id!r}"
        )


class TestMcpServersRedactRaiseIsolation:
    """H2 — if redact_secrets_in_env raises on one server, the other
    servers in the same config still emit. Two-layer per-item isolation
    contract at the redact-failure layer."""

    def test_redact_raise_on_one_server_others_survive(self, tmp_path: Path, caplog) -> None:
        config = _claude_desktop_config(
            tmp_path,
            {
                "mcpServers": {
                    "good-a": {"command": "a", "env": {"X": "y"}},
                    "explodes": {"command": "e", "env": {"WILL": "raise"}},
                    "good-c": {"command": "c", "env": {"Z": "w"}},
                }
            },
        )

        def selective_redact(env_dict: dict) -> dict:
            if env_dict.get("WILL") == "raise":
                raise RuntimeError("simulated redaction failure")
            return {k: "OK" for k in env_dict}

        src = McpServersSource(config_paths=[config])
        with mock.patch(
            "claude_monitoring.attack_surface.discovery.sources.mcp_servers.redact_secrets_in_env",
            side_effect=selective_redact,
        ):
            with caplog.at_level("WARNING", logger="ai-runtime-monitor.attack_surface.discovery.mcp_servers"):
                result = src.run_with_safety()
        names = {a.name for a in result}
        assert names == {"good-a", "good-c"}, f"unexpected: {names}"
        assert any("explodes" in (r.message or "") for r in caplog.records)


class TestMcpServersDefaultPaths:
    def test_default_paths_resolve_to_known_locations(self) -> None:
        """Default config_paths point at the three Phase A surfaces."""
        src = McpServersSource()
        paths_str = [str(p) for p in src.config_paths]
        assert any("claude_desktop_config.json" in p for p in paths_str)
        assert any(".claude.json" in p for p in paths_str)
        assert any("mcp.json" in p and ".cursor" in p for p in paths_str)


class TestMcpServersSourceEmpirical:
    """Empirical gate — runs against this machine's real config files.

    Skips if none are present. When present, asserts that no
    raw secret string leaks into Asset.current_state.env.
    """

    def test_no_secret_value_leaks_in_current_state(self) -> None:
        src = McpServersSource()
        if not any(p.is_file() for p in src.config_paths):
            pytest.skip("no MCP config files present on this machine")
        result = src.run_with_safety()
        for asset in result:
            env = asset.current_state.get("env") or {}
            for k, v in env.items():
                # If the key looks token-shaped, the value MUST be a
                # redaction sentinel; never the literal secret.
                upper_k = k.upper()
                if any(
                    suffix in upper_k for suffix in ("_TOKEN", "_KEY", "_SECRET", "_PASSWORD")
                ) or upper_k.startswith("AUTH_"):
                    # H1: tightened — if redaction is bypassed, v could be
                    # a non-string (e.g., int PORT). Assert isinstance first
                    # so the AssertionError carries the real failure context
                    # rather than a TypeError masking a leak.
                    assert isinstance(v, str) and "REDACTED" in v, (
                        f"secret leak or redact bypass: {asset.name} {k}={v!r}"
                    )
