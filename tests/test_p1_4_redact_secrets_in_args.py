"""TDD test suite for `redact_secrets_in_args` — the P1.4 args-redaction helper.

Filed per Rajan's 2026-06-06 PR #87 review catch: MCP `args` carry
tokens (`["--token", "ghp_..."]`, `["--api-key=sk-..."]`) and would
leak the same secret class as a missed env-redaction. The env-value
patterns are anchored and miss the embedded `--flag=token` form, so
the args path needs its own helper rather than reusing
`redact_secrets_in_env`.

Two shapes:

- Standalone: the arg IS a token → wholesale REDACTED_VAL_SHAPE
- Embedded: `--flag=token` → prefix `--flag=` preserved, RHS redacted
"""

from __future__ import annotations

import pytest

from claude_monitoring.attack_surface.discovery.helpers import (
    REDACTED_VAL_SHAPE,
    redact_secrets_in_args,
)


class TestStandaloneTokenArgs:
    """Anchored token patterns match the whole arg."""

    def test_github_personal_access_token(self) -> None:
        args = ["--token", "ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"]
        result = redact_secrets_in_args(args)
        assert result == ["--token", REDACTED_VAL_SHAPE]

    def test_anthropic_token(self) -> None:
        args = ["sk-ant-secrettokenvalueXXXXXXXXXXXXXXXXX"]
        result = redact_secrets_in_args(args)
        assert result == [REDACTED_VAL_SHAPE]

    def test_aws_access_key(self) -> None:
        args = ["AKIAIOSFODNN7EXAMPLE"]
        result = redact_secrets_in_args(args)
        assert result == [REDACTED_VAL_SHAPE]

    def test_slack_token(self) -> None:
        args = ["xoxb-1234567890-abcdefghij-ABCDEFG"]
        result = redact_secrets_in_args(args)
        assert result == [REDACTED_VAL_SHAPE]


class TestEmbeddedFlagEqualsTokenArgs:
    """`--flag=token` — the env-value anchored patterns would miss these
    without the explicit `=` split."""

    def test_github_token_after_equals(self) -> None:
        args = ["--token=ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"]
        result = redact_secrets_in_args(args)
        assert result == [f"--token={REDACTED_VAL_SHAPE}"]

    def test_anthropic_token_after_equals(self) -> None:
        args = ["--api-key=sk-ant-secrettokenvalueXXXXXXXXXXXXXXXXX"]
        result = redact_secrets_in_args(args)
        assert result == [f"--api-key={REDACTED_VAL_SHAPE}"]

    def test_flag_prefix_with_no_secret_preserved(self) -> None:
        """`--port=8080` is not a secret — must pass through unchanged."""
        args = ["--port=8080"]
        result = redact_secrets_in_args(args)
        assert result == ["--port=8080"]


class TestMixedArgs:
    def test_only_token_args_redacted_others_pass_through(self) -> None:
        args = [
            "--verbose",
            "--config",
            "/etc/mcp.conf",
            "AKIAIOSFODNN7EXAMPLE",
            "--debug",
        ]
        result = redact_secrets_in_args(args)
        assert result == ["--verbose", "--config", "/etc/mcp.conf", REDACTED_VAL_SHAPE, "--debug"]

    def test_empty_list_returns_empty_list(self) -> None:
        assert redact_secrets_in_args([]) == []

    def test_non_string_elements_coerced_via_str(self) -> None:
        """Per the docstring: `str()` coerces non-str inputs."""
        result = redact_secrets_in_args(["plain", 8080])
        assert result == ["plain", "8080"]


class TestErrorPath:
    def test_non_list_raises_typeerror(self) -> None:
        with pytest.raises(TypeError):
            redact_secrets_in_args("not a list")  # type: ignore[arg-type]


class TestNoMutation:
    def test_original_list_not_mutated(self) -> None:
        original = ["--token", "ghp_abcdefghijklmnopqrstuvwxyz1234567890ABCD"]
        snapshot = list(original)
        _ = redact_secrets_in_args(original)
        assert original == snapshot


class TestNotFalsePositives:
    """Plain CLI args that LOOK like they might match must NOT be redacted."""

    def test_short_strings_not_redacted(self) -> None:
        """Token patterns require minimum lengths (e.g., 32+ for sk-...).
        Short strings starting with `sk-` are NOT tokens."""
        args = ["sk-short"]
        assert redact_secrets_in_args(args) == ["sk-short"]

    def test_partial_aws_key_not_redacted(self) -> None:
        """AWS access key is exactly 20 chars; shorter doesn't match."""
        args = ["AKIA1234"]
        assert redact_secrets_in_args(args) == ["AKIA1234"]
