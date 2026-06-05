"""TDD test suite for v0.2.2 P1.2 — safe helpers.

Per the architect-pass at `~/Documents/vigil-notes/v022/phase-1/p1.2/architect-pass.md`:

- `safe_yaml_load`: three-layer DoS defense (byte cap, anchor cap, alias cap)
- `safe_subprocess`: hardcoded `shell=False`, argv list only, CompletedProcess return
- `validate_path`: raise-on-policy-violation; legitimate symlinks within root preserved

The billion-laughs defense thresholds (`MAX_YAML_ANCHORS = 10`,
`MAX_YAML_ALIASES = 15`) are data-derived per Rajan's 2026-06-05
threshold correction — see architect-pass §1.1 ADD-1 detonation tables.
Tests pin the exact thresholds against the gap between sane configs
(0-5 anchors, 0-10 aliases) and the smallest detonating bomb
(wide-shallow level=2 at 3 anchors + 21 aliases; narrow-deep level=10
at 11 anchors + 21 aliases).

54 tests total across this file + `test_p1_2_redact_secrets_in_env.py`.
"""

from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from unittest import mock

import pytest

# ---------------------------------------------------------------------------
# Imports under test. Phase B: fails at collection (ModuleNotFoundError).
# Phase C: lands the helpers module, all tests turn green.
# ---------------------------------------------------------------------------
from claude_monitoring.attack_surface.discovery.helpers import (
    MAX_YAML_ALIASES,
    MAX_YAML_ANCHORS,
    MAX_YAML_INPUT_BYTES,
    safe_subprocess,
    safe_yaml_load,
    validate_path,
)

# ---------------------------------------------------------------------------
# Group 1 — TestSafeYamlLoad (9 tests)
# ---------------------------------------------------------------------------


def _make_bomb_yaml(levels: int, width: int = 10) -> str:
    """Construct a billion-laughs YAML with N levels of width-fold alias expansion.

    Per Rajan's 2026-06-05 detonation analysis:
    - 10-wide level=N: N+1 anchors, 10*N + 1 aliases. Output expands 10x per level.
    - 2-wide level=N: N+1 anchors, 2*N + 1 aliases. Output expands 2x per level.
    """
    lines = ["a0: &a0 'leaf'"]
    for i in range(1, levels + 1):
        refs = ", ".join([f"*a{i - 1}"] * width)
        lines.append(f"a{i}: &a{i} [{refs}]")
    lines.append(f"top: *a{levels}")
    return "\n".join(lines) + "\n"


class TestSafeYamlLoad:
    def test_valid_yaml_dict_returns_dict(self) -> None:
        """Happy path — simple mapping parses to a dict."""
        assert safe_yaml_load("key: value") == {"key": "value"}

    def test_valid_yaml_list_returns_list(self) -> None:
        """Happy path — block sequence parses to a list."""
        assert safe_yaml_load("- item") == ["item"]

    def test_bytes_input_supported(self) -> None:
        """Production hardening — `bytes` input accepted (directive sketch was str-only;
        MCP configs may be read as bytes before decoding)."""
        assert safe_yaml_load(b"key: value") == {"key": "value"}

    def test_empty_string_returns_none(self) -> None:
        """Empty / whitespace-only is NOT an error — returns None."""
        assert safe_yaml_load("") is None
        assert safe_yaml_load("   \n  ") is None

    def test_invalid_yaml_raises_yaml_error(self) -> None:
        """Syntactically invalid YAML → yaml.YAMLError. Caller (per-item isolation)
        catches and skips the bad file."""
        import yaml

        with pytest.raises(yaml.YAMLError):
            safe_yaml_load("{bad: [yaml")

    def test_unsafe_constructor_raises_constructor_error(self) -> None:
        """`!!python/object/apply:` payload pointing at a builtin → ConstructorError
        (subclass of YAMLError). Pins safe_load (not load) is used."""
        import yaml

        with pytest.raises(yaml.YAMLError):
            safe_yaml_load("!!python/object/apply:builtins.eval ['1+1']")

    def test_oversized_input_raises_value_error_before_parse(self) -> None:
        """ADD-1 layer 1 — input over `MAX_YAML_INPUT_BYTES` (10 MiB) → ValueError
        raised BEFORE `yaml.safe_load` is invoked."""
        oversized = b"a: 1\n" * (MAX_YAML_INPUT_BYTES // 5 + 1)
        with mock.patch("yaml.safe_load") as mock_load:
            with pytest.raises(ValueError, match="exceeds"):
                safe_yaml_load(oversized)
            mock_load.assert_not_called()

    def test_over_anchor_count_raises_before_parse(self) -> None:
        """ADD-1 layer 2 — YAML containing > MAX_YAML_ANCHORS (10) `&` anchors
        → ValueError raised by pre-parse scan; yaml.safe_load is NEVER invoked.

        Threshold derived empirically: rejects narrow-deep level=10+ (11 anchors)
        per architect-pass §1.1 ADD-1 detonation table."""
        # Construct YAML with 11 anchors (MAX_YAML_ANCHORS + 1)
        text = "\n".join([f"a{i}: &anchor{i} 'leaf'" for i in range(MAX_YAML_ANCHORS + 1)])
        with mock.patch("yaml.safe_load") as mock_load:
            with pytest.raises(ValueError, match="anchor"):
                safe_yaml_load(text)
            mock_load.assert_not_called()

    def test_over_alias_count_raises_before_parse(self) -> None:
        """ADD-1 layer 2 — YAML containing > MAX_YAML_ALIASES (15) `*` aliases
        → ValueError before parse; same mock assertion.

        Threshold derived empirically: rejects wide-shallow level=2+ (21 aliases)
        AND narrow-deep level=10+ (21 aliases) — every detonating shape observed."""
        # Construct YAML with 16 aliases (MAX_YAML_ALIASES + 1)
        refs = ", ".join(["*a0"] * (MAX_YAML_ALIASES + 1))
        text = f"a0: &a0 'leaf'\nrefs: [{refs}]\n"
        with mock.patch("yaml.safe_load") as mock_load:
            with pytest.raises(ValueError, match="alias"):
                safe_yaml_load(text)
            mock_load.assert_not_called()

    def test_gap_boundary_pass_just_under_fail_just_over(self) -> None:
        """Rajan's 2026-06-05 data-derived threshold validation.

        At-cap YAML (anchors=10, aliases=15) parses AND serializes via json.dumps
        in < 50ms. Then over-cap by one in each dimension: rejected before parse.

        Pins 'the cap sits in the gap between sane configs and the smallest
        detonating bomb' — guards against the threshold drifting back to round
        numbers like 100 in future maintenance."""
        # At-cap (MUST pass): 10 anchors, 15 aliases.
        # Construct with 1 root anchor + 9 reuse anchors = 10 anchors;
        # alias each reuse anchor + 6 refs to root = 15 aliases.
        at_cap_lines = ["root: &root 'r'"]
        for i in range(1, 10):  # anchors 1-9 (total 10 with root)
            at_cap_lines.append(f"a{i}: &a{i} 'leaf{i}'")
        # 15 aliases: reference each a1..a9 + 6 more *root
        alias_list = [f"*a{i}" for i in range(1, 10)] + ["*root"] * 6
        at_cap_lines.append(f"refs: [{', '.join(alias_list)}]")
        at_cap = "\n".join(at_cap_lines) + "\n"
        # Verify counts
        import re

        n_anchors = len(re.findall(r"&[A-Za-z_][\w]*", at_cap))
        n_aliases = len(re.findall(r"\*[A-Za-z_][\w]*", at_cap))
        assert n_anchors == MAX_YAML_ANCHORS, f"setup error: {n_anchors} anchors, expected {MAX_YAML_ANCHORS}"
        assert n_aliases == MAX_YAML_ALIASES, f"setup error: {n_aliases} aliases, expected {MAX_YAML_ALIASES}"
        # At-cap MUST parse AND serialize under 50ms
        start = time.monotonic()
        parsed = safe_yaml_load(at_cap)
        serialized = json.dumps(parsed)
        elapsed = time.monotonic() - start
        assert elapsed < 0.05, f"at-cap pipeline took {elapsed * 1000:.1f}ms — bomb at threshold?"
        assert len(serialized) < 10_000, f"at-cap json output {len(serialized)} bytes — too inflated?"

        # Over-cap by one anchor (11): rejected
        over_anchor_lines = at_cap_lines[:-1] + ["extra: &extra 'x'", at_cap_lines[-1]]
        over_anchor = "\n".join(over_anchor_lines) + "\n"
        with pytest.raises(ValueError, match="anchor"):
            safe_yaml_load(over_anchor)

        # Over-cap by one alias (16): rejected
        over_alias_lines = at_cap_lines[:-1] + [f"refs: [{', '.join(alias_list + ['*root'])}]"]
        over_alias = "\n".join(over_alias_lines) + "\n"
        with pytest.raises(ValueError, match="alias"):
            safe_yaml_load(over_alias)


# ---------------------------------------------------------------------------
# Group 2 — TestSafeSubprocess (7 tests)
# ---------------------------------------------------------------------------


class TestSafeSubprocess:
    def test_happy_path_echo(self) -> None:
        """`safe_subprocess(["echo", "hi"])` → CompletedProcess with returncode=0,
        stdout='hi\\n'."""
        result = safe_subprocess(["echo", "hi"])
        assert result.returncode == 0
        assert result.stdout == "hi\n"

    def test_non_zero_exit_returns_completed_process_with_warning(self, caplog) -> None:
        """`["false"]` → CompletedProcess with returncode=1; WARNING logged with argv[0]."""
        with caplog.at_level("WARNING"):
            result = safe_subprocess(["false"])
        assert result.returncode == 1
        assert any("false" in rec.message for rec in caplog.records)

    def test_empty_argv_raises_value_error(self) -> None:
        """`[]` → ValueError immediately; no subprocess spawned."""
        with pytest.raises(ValueError, match="argv"):
            safe_subprocess([])

    def test_non_str_argv_element_raises_value_error(self) -> None:
        """`["echo", 42]` → ValueError immediately; no subprocess spawned."""
        with pytest.raises(ValueError, match="str"):
            safe_subprocess(["echo", 42])  # type: ignore[list-item]

    def test_timeout_raises_timeout_expired(self) -> None:
        """Slow subprocess + timeout=0.1 → subprocess.TimeoutExpired."""
        with pytest.raises(subprocess.TimeoutExpired):
            safe_subprocess(["sleep", "5"], timeout=0.1)

    def test_missing_executable_raises_filenotfounderror(self) -> None:
        """`["no_such_executable_xyzzy"]` → FileNotFoundError. Sources catch this
        for 'tool not installed' detection."""
        with pytest.raises(FileNotFoundError):
            safe_subprocess(["no_such_executable_xyzzy_2026"])

    def test_shell_false_enforced_via_mock(self) -> None:
        """unittest.mock inspection of underlying subprocess.run call — asserts
        shell=False kwarg regardless of argv content. Pins Q5 security control."""
        with mock.patch("subprocess.run") as mock_run:
            mock_run.return_value = subprocess.CompletedProcess(args=["echo"], returncode=0, stdout="", stderr="")
            safe_subprocess(["echo", "--shell", "bash"])
        # The hardcoded shell=False kwarg is the sole security control.
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs.get("shell") is False


# ---------------------------------------------------------------------------
# Group 3 — TestValidatePath (11 tests)
# ---------------------------------------------------------------------------


class TestValidatePath:
    def test_path_within_root_returns_resolved_path(self, tmp_path: Path) -> None:
        """Happy path — direct child of root returns resolved absolute Path."""
        child = tmp_path / "subdir"
        child.mkdir()
        result = validate_path(child, tmp_path)
        assert result == child.resolve()

    def test_legitimate_symlink_within_root_allowed(self, tmp_path: Path) -> None:
        """Q4 — symlink in root pointing to file in root → returns resolved Path.
        Preserves `~/.vscode` symlink-as-root patterns."""
        target = tmp_path / "real_dir"
        target.mkdir()
        link = tmp_path / "link_to_real"
        link.symlink_to(target)
        result = validate_path(link, tmp_path)
        assert result == target.resolve()

    def test_symlink_escaping_root_raises_value_error(self, tmp_path: Path, tmp_path_factory) -> None:
        """Q4 — symlink in root pointing OUTSIDE root → ValueError. Caught by
        `is_relative_to` after `resolve(strict=True)`."""
        outside = tmp_path_factory.mktemp("outside_root")
        link = tmp_path / "escape_link"
        link.symlink_to(outside)
        with pytest.raises(ValueError, match=r"outside|traversal"):
            validate_path(link, tmp_path)

    def test_dotdot_traversal_raises_value_error(self, tmp_path: Path, tmp_path_factory) -> None:
        """`path = root / ".." / "other"` → resolves outside root → ValueError."""
        outside = tmp_path_factory.mktemp("traversal_target")
        traversal = tmp_path / ".." / outside.name
        with pytest.raises(ValueError, match=r"outside|traversal"):
            validate_path(traversal, tmp_path)

    def test_absolute_path_outside_root_raises_value_error(self, tmp_path: Path, tmp_path_factory) -> None:
        """NEW post-Phase-B-review — absolute path (not via .. or symlink) → ValueError.

        Distinct attack vector from #4/#5 even though functionally covered by
        is_relative_to. Pins that the check IS reached via this code path."""
        outside = tmp_path_factory.mktemp("absolute_outside")
        # Direct absolute path, not constructed via traversal
        with pytest.raises(ValueError, match=r"outside|traversal"):
            validate_path(outside, tmp_path)

    def test_exact_max_depth_allowed(self, tmp_path: Path) -> None:
        """Path at depth = max_depth → returns Path."""
        depth = 3
        deep = tmp_path
        for i in range(depth):
            deep = deep / f"d{i}"
        deep.mkdir(parents=True)
        result = validate_path(deep, tmp_path, max_depth=depth)
        assert result == deep.resolve()

    def test_over_max_depth_raises_value_error(self, tmp_path: Path) -> None:
        """Path at depth = max_depth + 1 → ValueError."""
        max_depth = 2
        deep = tmp_path
        for i in range(max_depth + 1):
            deep = deep / f"d{i}"
        deep.mkdir(parents=True)
        with pytest.raises(ValueError, match="depth"):
            validate_path(deep, tmp_path, max_depth=max_depth)

    def test_oversized_file_raises_when_check_size_true(self, tmp_path: Path) -> None:
        """File > max_size_mb with check_size=True → ValueError; with check_size=False
        → returns Path (cap is opt-in)."""
        big = tmp_path / "big.txt"
        big.write_bytes(b"x" * (2 * 1024 * 1024))  # 2 MiB
        # Default (check_size=False) — passes
        assert validate_path(big, tmp_path, max_size_mb=1.0) == big.resolve()
        # check_size=True — fails
        with pytest.raises(ValueError, match="size"):
            validate_path(big, tmp_path, max_size_mb=1.0, check_size=True)

    def test_nonexistent_path_raises_filenotfounderror(self, tmp_path: Path) -> None:
        """Q3 + P1.4 usage note — missing path → FileNotFoundError. Sources catch
        this as 'no assets,' normal flow (not an error)."""
        missing = tmp_path / "does_not_exist"
        with pytest.raises(FileNotFoundError):
            validate_path(missing, tmp_path)

    def test_nonexistent_root_raises_filenotfounderror(self, tmp_path: Path) -> None:
        """Missing root → FileNotFoundError (e.g., `~/.claude/skills/` on a
        Claude-Code-less machine)."""
        path = tmp_path / "any"
        path.mkdir()
        missing_root = tmp_path / "no_such_root"
        with pytest.raises(FileNotFoundError):
            validate_path(path, missing_root)

    def test_path_is_root_itself_returns_root(self, tmp_path: Path) -> None:
        """Edge — `validate_path(root, root)` → returns resolved root (depth 0)."""
        assert validate_path(tmp_path, tmp_path) == tmp_path.resolve()


# ---------------------------------------------------------------------------
# Group 4 — TestHelpersModuleSurface (3 tests)
# ---------------------------------------------------------------------------


class TestHelpersModuleSurface:
    def test_module_exposes_locked_constants(self) -> None:
        """`MAX_YAML_INPUT_BYTES`, `MAX_YAML_ANCHORS`, `MAX_YAML_ALIASES`,
        `REDACTED_VAR_NAME`, `REDACTED_VAL_SHAPE` are module-level constants
        (testability + audit clarity).

        Specific values pinned per architect-pass §1.1 ADD-1 (data-derived
        2026-06-05): 10 MiB / 10 anchors / 15 aliases."""
        from claude_monitoring.attack_surface.discovery import helpers

        assert helpers.MAX_YAML_INPUT_BYTES == 10 * 1024 * 1024
        assert helpers.MAX_YAML_ANCHORS == 10, (
            "Threshold drift detected — see architect-pass §1.1 ADD-1 detonation table"
        )
        assert helpers.MAX_YAML_ALIASES == 15, (
            "Threshold drift detected — see architect-pass §1.1 ADD-1 detonation table"
        )
        assert isinstance(helpers.REDACTED_VAR_NAME, str)
        assert isinstance(helpers.REDACTED_VAL_SHAPE, str)

    def test_module_exposes_all_four_helpers(self) -> None:
        """All four helpers are importable from `helpers` directly."""
        from claude_monitoring.attack_surface.discovery.helpers import (
            redact_secrets_in_env,
            safe_subprocess,
            safe_yaml_load,
            validate_path,
        )

        assert callable(safe_yaml_load)
        assert callable(safe_subprocess)
        assert callable(validate_path)
        assert callable(redact_secrets_in_env)

    def test_helpers_reexported_from_discovery_package(self) -> None:
        """`from claude_monitoring.attack_surface.discovery import safe_yaml_load`
        works (re-export convenience for source authors)."""
        from claude_monitoring.attack_surface.discovery import (
            redact_secrets_in_env,
            safe_subprocess,
            safe_yaml_load,
            validate_path,
        )

        assert callable(safe_yaml_load)
        assert callable(safe_subprocess)
        assert callable(validate_path)
        assert callable(redact_secrets_in_env)
