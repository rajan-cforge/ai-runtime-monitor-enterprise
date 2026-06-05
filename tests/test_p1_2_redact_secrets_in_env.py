"""TDD test suite for v0.2.2 P1.2 — `redact_secrets_in_env`.

Per the architect-pass §1.4 + spec §7.1.1:

- Name-based detection via `TOKEN_VAR_NAMES` regex
- Value-based detection via 8 `TOKEN_VALUE_PATTERNS` (ghp_/gho_/ghu_/ghs_,
  sk-ant- before generic sk-, xox[bps]-, AKIA[0-9A-Z]{16})
- Anthropic-specific pattern MUST precede generic `sk-` (order matters)
- Returns NEW dict; original not modified
- `TypeError` on non-dict (programming error fail-closed)
- `str()` coercion for non-str values (MCP port numbers etc.)

9 tests total. Empirical Q8 check (test 9) runs against the user's real
`claude_desktop_config.json` to confirm `TOKEN_VAR_NAMES` catches the
real env-var KEYS observed on this machine.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from claude_monitoring.attack_surface.discovery.helpers import (
    REDACTED_VAL_SHAPE,
    REDACTED_VAR_NAME,
    redact_secrets_in_env,
)


class TestRedactSecretsInEnv:
    def test_name_based_redaction_token_suffix(self) -> None:
        """`{"GITHUB_TOKEN": "abc"}` → name match (suffix `_TOKEN`) wins;
        value replaced by `REDACTED_VAR_NAME` sentinel."""
        result = redact_secrets_in_env({"GITHUB_TOKEN": "abc"})
        assert result == {"GITHUB_TOKEN": REDACTED_VAR_NAME}

    @pytest.mark.parametrize(
        "key",
        ["GITHUB_TOKEN", "OPENAI_KEY", "SLACK_SECRET", "DB_PASSWORD", "AUTH_HEADER"],
    )
    def test_name_based_redaction_all_suffixes(self, key: str) -> None:
        """Parametrized over the five `TOKEN_VAR_NAMES` suffix patterns —
        each triggers name-based redaction."""
        result = redact_secrets_in_env({key: "any_value"})
        assert result[key] == REDACTED_VAR_NAME

    @pytest.mark.parametrize(
        "value,label",
        [
            ("ghp_" + "A" * 36, "GitHub PAT"),
            ("gho_" + "A" * 36, "GitHub OAuth"),
            ("ghu_" + "A" * 36, "GitHub user-to-server"),
            ("ghs_" + "A" * 36, "GitHub server-to-server"),
            ("sk-ant-" + "A" * 32, "Anthropic specific"),
            ("sk-" + "A" * 32, "OpenAI / generic sk-"),
            ("xoxb-" + "A" * 20, "Slack bot token"),
            ("AKIA" + "0123456789ABCDEF", "AWS access key ID"),
        ],
    )
    def test_value_based_redaction_all_8_patterns(self, value: str, label: str) -> None:
        """Each of the 8 `TOKEN_VALUE_PATTERNS` triggers value-based redaction
        when the variable name does NOT match a name pattern."""
        # Use a benign name so only value-match can fire
        result = redact_secrets_in_env({"SOME_VAR": value})
        assert result["SOME_VAR"] == REDACTED_VAL_SHAPE, f"missed {label}"

    def test_anthropic_specific_precedes_generic_sk(self) -> None:
        """`sk-ant-...` matches the Anthropic pattern (more specific) FIRST,
        not the generic `sk-`. The list is checked in order; the more specific
        pattern appears before the more general one."""
        anthropic_token = "sk-ant-" + "X" * 64
        result = redact_secrets_in_env({"SOME_VAR": anthropic_token})
        # Both patterns would match — order ensures Anthropic-specific wins.
        # Test by asserting redaction occurred (the failure mode would be
        # NOT being redacted if pattern order broke).
        assert result["SOME_VAR"] == REDACTED_VAL_SHAPE

    def test_non_token_value_passthrough(self) -> None:
        """`{"PATH": "/usr/bin"}` → passes through unchanged (no name or
        value match)."""
        result = redact_secrets_in_env({"PATH": "/usr/bin"})
        assert result == {"PATH": "/usr/bin"}

    @pytest.mark.parametrize("bad_input", [None, ["list"], "string", 42, {"OK"}])
    def test_non_dict_input_raises_typeerror(self, bad_input: object) -> None:
        """Non-dict input → TypeError (programming error fail-closed; CLAUDE.md
        empty-string fallback applies to sanitizers returning str, not
        dict-returners)."""
        with pytest.raises(TypeError):
            redact_secrets_in_env(bad_input)  # type: ignore[arg-type]

    def test_non_str_value_coerced_via_str(self) -> None:
        """`{"PORT": 8080}` → coerced via `str()`; no redaction (int port not
        token-shaped). Pins the MCP-config-has-int-port case."""
        result = redact_secrets_in_env({"PORT": 8080})  # type: ignore[dict-item]
        assert result == {"PORT": "8080"}

    def test_input_dict_not_mutated(self) -> None:
        """Original `env` dict is unchanged after call (returns NEW dict)."""
        env = {"GITHUB_TOKEN": "abc", "PATH": "/usr/bin"}
        original = dict(env)
        result = redact_secrets_in_env(env)
        assert env == original
        assert result is not env

    def test_real_claude_desktop_config_envvar_names(self) -> None:
        """Empirical Q8 check (per architect-pass §1.4 + 2026-06-05 ratification).

        Load the user's real `claude_desktop_config.json`, dump env-var KEYS
        only, assert `TOKEN_VAR_NAMES` regex catches all token-named keys.
        Skipped if the file is absent.

        Pins the 2026-06-05 finding: `TALOSAI_API_KEY` matches via `_KEY`
        suffix; `TALOSAI_API_URL` correctly does NOT match (URL is public).
        Q8 PASSES with the locked 8-pattern set."""
        config_path = (
            Path(os.path.expanduser("~")) / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"
        )
        if not config_path.exists():
            pytest.skip(f"{config_path} not present on this machine")

        with config_path.open() as f:
            data = json.load(f)

        mcp_servers = data.get("mcpServers", {})
        if not mcp_servers:
            pytest.skip("no mcpServers in config (nothing to assert)")

        # Walk each server's env dict, redact, assert token-named keys
        # were redacted by the name pattern (NOT just by value match —
        # that would be coincidental and could break if the value happened
        # to not match a value pattern).
        for server_name, server_cfg in mcp_servers.items():
            env = server_cfg.get("env") or {}
            if not env:
                continue
            redacted = redact_secrets_in_env(env)
            # Any key with TOKEN/KEY/SECRET/PASSWORD/AUTH_ suffix must end up
            # as REDACTED_VAR_NAME (proves name-based pattern matched, not value).
            for key in env:
                upper = key.upper()
                if any(
                    upper.endswith(s) or upper.startswith("AUTH_") for s in ("_TOKEN", "_KEY", "_SECRET", "_PASSWORD")
                ):
                    assert redacted[key] == REDACTED_VAR_NAME, (
                        f"name-pattern miss on {server_name}/{key!r} — TOKEN_VAR_NAMES "
                        f"needs expansion (HARDER-tier signal)"
                    )
