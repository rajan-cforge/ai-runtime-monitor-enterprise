"""Safe input-handling primitives for discovery sources.

Architect-pass: ``~/Documents/vigil-notes/v022/phase-1/p1.2/architect-pass.md``
Spec source: ``~/Documents/vigil-notes/v022-attack-surface-feature-spec-v1-LOCKED.md`` §4.7, §7.1.1, §7.2

Four helpers consumed exclusively by v0.2.2 discovery sources:

- :func:`safe_yaml_load` — `yaml.safe_load` with three-layer DoS defense
  (byte cap + anchor count cap + alias count cap). The anchor/alias caps
  are the bomb-specific defense; per the 2026-06-05 empirical detonation
  analysis (architect-pass §1.1 ADD-1), `yaml.safe_load` itself is bounded
  via PyYAML's shared-reference graph, but `json.dumps` (which P1.3
  persistence calls on `Asset.current_state`) unfolds the shared refs
  and detonates. The caps stop the bomb structurally before `safe_load`
  runs.

- :func:`safe_subprocess` — `subprocess.run` with hardcoded `shell=False`.
  Argv list only; non-list / non-str argv raises `ValueError`. Returns
  the full `CompletedProcess` (sources need return codes to distinguish
  "tool not installed" / "tool returned error" / "success").

- :func:`validate_path` — resolves and verifies a path falls within
  `root`. Symlink escape, ``..`` traversal, absolute-path-outside-root,
  depth, and optional size are all checked. Raises `ValueError` on
  policy violation; `FileNotFoundError` on missing path (sources catch
  this as "no assets" — normal flow for optional configs).

- :func:`redact_secrets_in_env` — name-based + value-based redaction of
  env-var dicts. 8 token-value patterns; 5 token-name suffixes. Source
  authors MUST call this on any env dict before storing in
  `Asset.current_state`.

**Module-level constants** (testability + audit clarity):

- ``MAX_YAML_INPUT_BYTES = 10 MiB``
- ``MAX_YAML_ANCHORS = 10`` (data-derived 2026-06-05; see architect-pass
  §1.1 ADD-1 detonation table)
- ``MAX_YAML_ALIASES = 15`` (data-derived 2026-06-05)
- ``TOKEN_VAR_NAMES`` regex (`.*(_TOKEN|_KEY|_SECRET|_PASSWORD|AUTH_.*)$`)
- ``TOKEN_VALUE_PATTERNS`` 8-element list
- ``REDACTED_VAR_NAME``, ``REDACTED_VAL_SHAPE`` sentinel strings
"""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from subprocess import CompletedProcess

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.helpers")


# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

MAX_YAML_INPUT_BYTES: int = 10 * 1024 * 1024
"""Byte cap on YAML input. Catches oversized configs (e.g., 50 MB file
uploaded by mistake) but does NOT catch billion-laughs bombs, which are
typically <1 KB. The anchor/alias caps are the bomb-specific defense."""

MAX_YAML_ANCHORS: int = 10
"""Maximum `&` anchor count permitted in YAML input. Sane configs run
0-5 anchors; bombs at narrow-deep level=10 have 11 anchors. Threshold
10 leaves 2x margin over sane and rejects narrow-deep bombs."""

MAX_YAML_ALIASES: int = 15
"""Maximum `*` alias count permitted in YAML input. Sane configs run
0-10 aliases; the smallest detonating wide-shallow bomb (level=2) has
21 aliases; narrow-deep level=10 has 21 aliases. Threshold 15 rejects
every detonating shape observed in the 2026-06-05 empirical run."""

_YAML_ANCHOR_PATTERN: re.Pattern[str] = re.compile(r"&[A-Za-z_][\w]*")
_YAML_ALIAS_PATTERN: re.Pattern[str] = re.compile(r"\*[A-Za-z_][\w]*")


TOKEN_VAR_NAMES: re.Pattern[str] = re.compile(r".*(_TOKEN|_KEY|_SECRET|_PASSWORD|AUTH_.*)$", re.IGNORECASE)
"""Env-var name suffix patterns. Either the name match OR a value match
(see TOKEN_VALUE_PATTERNS) triggers redaction."""

TOKEN_VALUE_PATTERNS: list[re.Pattern[str]] = [
    # GitHub token family (all four prefixes)
    re.compile(r"^ghp_[A-Za-z0-9]{36,}"),
    re.compile(r"^gho_[A-Za-z0-9]{36,}"),
    re.compile(r"^ghu_[A-Za-z0-9]{36,}"),
    re.compile(r"^ghs_[A-Za-z0-9]{36,}"),
    # Anthropic-specific MUST precede generic sk- (more specific first)
    re.compile(r"^sk-ant-[A-Za-z0-9\-_]{32,}"),
    # OpenAI / generic sk-
    re.compile(r"^sk-[A-Za-z0-9]{32,}"),
    # Slack tokens
    re.compile(r"^xox[bps]-[A-Za-z0-9\-]+"),
    # AWS access key ID (exact 20-char format)
    re.compile(r"^AKIA[0-9A-Z]{16}$"),
]

REDACTED_VAR_NAME: str = "[REDACTED — token-shaped variable name]"
REDACTED_VAL_SHAPE: str = "[REDACTED — token-shaped value]"


# ---------------------------------------------------------------------------
# safe_yaml_load
# ---------------------------------------------------------------------------


def safe_yaml_load(text: str | bytes) -> dict | list | None:
    """Parse YAML with `yaml.safe_load` under three-layer DoS defense.

    Args:
        text: YAML source as `str` or `bytes`.

    Returns:
        Parsed dict / list / scalar / None per `yaml.safe_load`. Empty or
        whitespace-only input returns `None`.

    Raises:
        ValueError: If `text` exceeds `MAX_YAML_INPUT_BYTES`, or contains
            more than `MAX_YAML_ANCHORS` `&` anchors, or more than
            `MAX_YAML_ALIASES` `*` aliases.
        yaml.YAMLError: If `text` is not valid YAML, or contains an
            unsafe constructor (e.g., `!!python/object/apply:` — raises
            `yaml.constructor.ConstructorError`, a YAMLError subclass).
        TypeError: If `text` is neither `str` nor `bytes`.
    """
    if text is None:
        raise TypeError("safe_yaml_load: text must be str or bytes, got None")
    if not isinstance(text, (str, bytes)):
        raise TypeError(f"safe_yaml_load: text must be str or bytes, got {type(text).__name__}")

    # Layer 1: byte cap (DoS protection against oversized configs)
    if len(text) > MAX_YAML_INPUT_BYTES:
        raise ValueError(
            f"safe_yaml_load: input exceeds {MAX_YAML_INPUT_BYTES // (1024 * 1024)} MiB cap ({len(text)} bytes)"
        )

    # Empty / whitespace-only short-circuit (not an error)
    if not text:
        return None
    if isinstance(text, str):
        if not text.strip():
            return None
        text_for_scan = text
    else:
        # bytes — try utf-8 decode for the regex scan; fall back to latin-1
        # which never fails (we only need to count single-byte sigils).
        try:
            text_for_scan = text.decode("utf-8")
        except UnicodeDecodeError:
            text_for_scan = text.decode("latin-1")
        if not text_for_scan.strip():
            return None

    # Layers 2-3: anchor + alias count caps (bomb-specific defense)
    anchor_matches = _YAML_ANCHOR_PATTERN.findall(text_for_scan)
    if len(anchor_matches) > MAX_YAML_ANCHORS:
        raise ValueError(
            f"safe_yaml_load: YAML contains {len(anchor_matches)} anchors — "
            f"exceeds bomb-resistance threshold (MAX_YAML_ANCHORS={MAX_YAML_ANCHORS})"
        )
    alias_matches = _YAML_ALIAS_PATTERN.findall(text_for_scan)
    if len(alias_matches) > MAX_YAML_ALIASES:
        raise ValueError(
            f"safe_yaml_load: YAML contains {len(alias_matches)} aliases — "
            f"exceeds bomb-resistance threshold (MAX_YAML_ALIASES={MAX_YAML_ALIASES})"
        )

    import yaml

    return yaml.safe_load(text)


# ---------------------------------------------------------------------------
# safe_subprocess
# ---------------------------------------------------------------------------


def safe_subprocess(
    argv: list[str],
    timeout: float = 30.0,
    *,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> CompletedProcess[str]:
    """Run a subprocess with argv list only; never `shell=True`.

    `shell=False` is hardcoded — the sole security control. Argv must be
    a non-empty list of `str`; non-list / empty / non-str element raises
    `ValueError` immediately, before any subprocess is spawned.

    Args:
        argv: Command and args. First element is executable; non-empty
            list of str required.
        timeout: Wall-clock timeout. Default 30s (matches
            `DiscoverySource.DEFAULT_TIMEOUT_SEC`).
        cwd: Working directory; `None` inherits.
        env: Subprocess env. Callers MUST have applied
            :func:`redact_secrets_in_env` to any dict derived from
            config files BEFORE passing.

    Returns:
        `subprocess.CompletedProcess[str]` with stdout / stderr captured
        as `str` (`text=True` hardcoded).

    Raises:
        ValueError: If `argv` is empty, not a list, or contains non-str.
        FileNotFoundError: If `argv[0]` is not on PATH (sources catch
            this for "tool not installed" detection).
        subprocess.TimeoutExpired: If subprocess exceeds `timeout`.
    """
    if not isinstance(argv, list) or not argv:
        raise ValueError("safe_subprocess: argv must be a non-empty list")
    if not all(isinstance(a, str) for a in argv):
        raise ValueError("safe_subprocess: every element of argv must be str")

    result = subprocess.run(
        argv,
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
        env=env,
    )
    if result.returncode != 0:
        logger.warning(
            "safe_subprocess: %s exited %d; stderr: %s",
            argv[0],
            result.returncode,
            (result.stderr or "")[:200],
        )
    return result


# ---------------------------------------------------------------------------
# validate_path
# ---------------------------------------------------------------------------


def validate_path(
    path: Path | str,
    root: Path | str,
    *,
    max_depth: int = 10,
    max_size_mb: float = 10.0,
    check_size: bool = False,
) -> Path:
    """Resolve `path` and verify it falls within `root`.

    Symlink escape, `..` traversal, absolute-path-outside-root, and depth
    are all caught. Optional size cap fires only when `check_size=True`.

    Args:
        path: Candidate path (`str` or `Path`).
        root: Expected root directory (`str` or `Path`).
        max_depth: Max directory depth relative to `root`. Default 10.
        max_size_mb: Max file size in MiB. Only checked when
            `check_size=True`.
        check_size: When True, stat the resolved path and enforce
            `max_size_mb`. Set True when about to read the file's
            contents; False when validating before recursing.

    Returns:
        Resolved absolute `Path` within `root`.

    Raises:
        ValueError: If resolved path is outside `root`, exceeds
            `max_depth`, or (with `check_size=True`) exceeds
            `max_size_mb`.
        FileNotFoundError: If `path` or `root` does not exist on disk.
            P1.4 sources catch this as "no assets" normal flow for
            optional configs.
    """
    resolved = Path(path).resolve(strict=True)
    resolved_root = Path(root).resolve(strict=True)

    if not resolved.is_relative_to(resolved_root):
        raise ValueError(f"validate_path: {resolved} is outside root {resolved_root} (possible traversal)")

    relative_parts = resolved.relative_to(resolved_root).parts
    if len(relative_parts) > max_depth:
        raise ValueError(f"validate_path: path depth {len(relative_parts)} exceeds max_depth={max_depth}")

    if check_size and resolved.is_file():
        size_mb = resolved.stat().st_size / (1024 * 1024)
        if size_mb > max_size_mb:
            raise ValueError(f"validate_path: file size {size_mb:.1f}MB exceeds max_size_mb={max_size_mb}")

    return resolved


# ---------------------------------------------------------------------------
# list_pip_packages — `pip list --format=json` against a chosen interpreter
# ---------------------------------------------------------------------------


def list_pip_packages(python_bin: Path | str) -> list[dict]:
    """Run ``<python_bin> -m pip list --format=json`` and return the parsed list.

    The argv shape (`[..., "-m", "pip", "list", "--format=json"]`) is
    pinned by the P3.3 source and the legacy
    ``supply_chain.get_pip_packages`` regression test
    (``tests/test_supply_chain.py:448``). Centralizing it here keeps any
    future invocation-shape change in one place.

    Launchd-safe: callers pass an absolute interpreter path; no PATH
    lookup is performed. The ``safe_subprocess`` primitive enforces
    ``shell=False``.

    Args:
        python_bin: Absolute path to the Python interpreter. The caller
            is responsible for `validate_path`-ing this against a
            ratified prefix BEFORE invocation — `list_pip_packages` does
            NOT itself enforce a binary-trust boundary (see P3.3
            Phase A §3a for the boundary contract).

    Returns:
        Parsed JSON list (e.g., ``[{"name": "...", "version": "..."}, ...]``).
        Caller filters / normalizes downstream.

    Raises:
        RuntimeError: If pip exits non-zero (broken pip, missing module,
            etc.). Sources catch this for per-venv isolation.
        json.JSONDecodeError: If stdout is not valid JSON (corrupt pip,
            unexpected output). Sources catch this for per-venv isolation.
        subprocess.TimeoutExpired: If pip hangs (30s default; propagated
            from `safe_subprocess`).
        ValueError: From `safe_subprocess` if argv validation fails.
    """
    import json

    result = safe_subprocess(
        [str(python_bin), "-m", "pip", "list", "--format=json"],
        timeout=30.0,
    )
    if result.returncode != 0:
        raise RuntimeError(f"pip list exited {result.returncode}: {(result.stderr or '')[:200]}")
    parsed = json.loads(result.stdout)
    if not isinstance(parsed, list):
        raise TypeError(f"pip list returned non-list top level: got {type(parsed).__name__}")
    return parsed


# ---------------------------------------------------------------------------
# list_npm_global_packages — `npm list -g --json --depth=0`
# ---------------------------------------------------------------------------


def list_npm_global_packages(npm_bin: Path | str) -> list[dict]:
    """Run ``<npm_bin> list -g --json --depth=0`` and return a flat list of
    ``{"name", "version"}`` dicts.

    The argv shape (``[..., "list", "-g", "--json", "--depth=0"]``) is
    pinned by the P3.5 source. ``--depth=0`` avoids npm's transitive
    resolution (which can be huge and slow on cold cache). Centralizing
    here keeps the invocation shape in one place.

    npm's raw output shape is:
    ``{"name": "...", "dependencies": {"<pkg>": {"version": "..."}, ...}}``
    This helper flattens the ``dependencies`` map into the list shape every
    other discovery helper returns, so the source can iterate uniformly.

    Launchd-safe: callers pass an absolute path; no PATH lookup is performed.
    The ``safe_subprocess`` primitive enforces ``shell=False``. Timeout is
    60s because npm can be slow on cold cache.

    Args:
        npm_bin: Absolute path to the npm executable. The caller is
            responsible for `validate_path`-ing this against a ratified
            prefix BEFORE invocation — `list_npm_global_packages` does NOT
            itself enforce a binary-trust boundary.

    Returns:
        Flat list of ``{"name": str, "version": str}`` dicts. Caller
        filters / normalizes downstream.

    Raises:
        RuntimeError: If npm exits non-zero.
        json.JSONDecodeError: If stdout is not valid JSON.
        TypeError: If npm returns something other than an object at the
            top level.
        subprocess.TimeoutExpired: If npm hangs (60s default).
        ValueError: From `safe_subprocess` if argv validation fails.
    """
    import json

    result = safe_subprocess(
        [str(npm_bin), "list", "-g", "--json", "--depth=0"],
        timeout=60.0,
    )
    if result.returncode != 0:
        raise RuntimeError(f"npm list exited {result.returncode}: {(result.stderr or '')[:200]}")
    parsed = json.loads(result.stdout)
    if not isinstance(parsed, dict):
        raise TypeError(f"npm list returned non-object top level: got {type(parsed).__name__}")
    deps = parsed.get("dependencies")
    if not isinstance(deps, dict):
        return []
    out: list[dict] = []
    for name, info in deps.items():
        if not isinstance(name, str):
            continue
        version: str | None = None
        if isinstance(info, dict):
            v = info.get("version")
            if isinstance(v, str):
                version = v
        if version is None:
            continue
        out.append({"name": name, "version": version})
    return out


# ---------------------------------------------------------------------------
# redact_secrets_in_env
# ---------------------------------------------------------------------------


def redact_secrets_in_env(env: dict) -> dict:
    """Return a new dict with token-shaped values replaced by sentinels.

    Detection signals (either triggers redaction):

    - Key name matches `TOKEN_VAR_NAMES` (`_TOKEN` / `_KEY` / `_SECRET`
      / `_PASSWORD` / `AUTH_*` suffix, case-insensitive) → value replaced
      by `REDACTED_VAR_NAME`.
    - Value matches any of the 8 `TOKEN_VALUE_PATTERNS` → value replaced
      by `REDACTED_VAL_SHAPE`. The Anthropic-specific `sk-ant-` pattern
      precedes the generic `sk-` in the list; order matters.

    Source authors MUST call this on any env-var dict (e.g., MCP
    server `env` map) before storing in `Asset.current_state`.

    Args:
        env: Dict of env-var name → value. Non-str values are coerced
            via `str()` (MCP configs may have int port numbers).

    Returns:
        New dict; original `env` is not mutated.

    Raises:
        TypeError: If `env` is not a dict (programming error; CLAUDE.md
            empty-string fallback applies to sanitizers returning `str`,
            not dict-returners).
    """
    if not isinstance(env, dict):
        raise TypeError(f"redact_secrets_in_env: expected dict, got {type(env).__name__}")

    redacted: dict[str, str] = {}
    for key, value in env.items():
        str_key = str(key)
        str_val = str(value)
        if TOKEN_VAR_NAMES.match(str_key):
            redacted[str_key] = REDACTED_VAR_NAME
        elif any(p.match(str_val) for p in TOKEN_VALUE_PATTERNS):
            redacted[str_key] = REDACTED_VAL_SHAPE
        else:
            redacted[str_key] = str_val
    return redacted


# ---------------------------------------------------------------------------
# redact_secrets_in_args
# ---------------------------------------------------------------------------


def redact_secrets_in_args(args: list[str]) -> list[str]:
    """Return a new list with token-shaped CLI args replaced by sentinels.

    MCP server configs commonly pass tokens as command-line arguments
    rather than as ``env`` map entries (e.g., ``"args": ["--token",
    "ghp_..."]`` or ``"args": ["--api-key=sk-ant-..."]``). Storing args
    verbatim in ``Asset.current_state`` would leak secrets the same way
    a missed env-redaction would — same control class, different field.

    Two redaction shapes:

    - **Standalone token**: the arg IS a token (e.g., ``"ghp_xyz..."``)
      → replaced wholesale with ``REDACTED_VAL_SHAPE``. The 8
      ``TOKEN_VALUE_PATTERNS`` are anchored, so a `re.match` against
      the arg fires only on the standalone form.

    - **Embedded ``--flag=token`` token**: the arg has the form
      ``"--name=value"`` and ``value`` matches a token pattern → the
      prefix ``"--name="`` is preserved (so the flag name is still
      visible in the audit trail) and the RHS is replaced.

    Args:
        args: List of CLI argv strings. Non-str elements are coerced
            via ``str()``.

    Returns:
        New list; original ``args`` is not mutated.

    Raises:
        TypeError: If ``args`` is not a list.
    """
    if not isinstance(args, list):
        raise TypeError(f"redact_secrets_in_args: expected list, got {type(args).__name__}")
    out: list[str] = []
    for raw in args:
        s = str(raw)
        # Standalone: anchored token pattern matches the whole arg.
        if any(p.match(s) for p in TOKEN_VALUE_PATTERNS):
            out.append(REDACTED_VAL_SHAPE)
            continue
        # Embedded: --flag=value where value is a token. The env-style
        # anchored patterns would miss this without the explicit split.
        if "=" in s:
            prefix, value = s.split("=", 1)
            if any(p.match(value) for p in TOKEN_VALUE_PATTERNS):
                out.append(f"{prefix}={REDACTED_VAL_SHAPE}")
                continue
        out.append(s)
    return out
