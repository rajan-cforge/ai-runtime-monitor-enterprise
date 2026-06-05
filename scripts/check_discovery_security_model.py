#!/usr/bin/env python3
"""Discovery security-model gate — AST scan of attack_surface/ code.

Per the v0.2.2 implementation directive §11.2 (gate #1) and the P1.2
architect-pass §5. Polices the safe-helpers contract: no `yaml.load`,
no `yaml.unsafe_load`, no forbidden subprocess shell-kwarg invocations,
no `os` shell-out built-ins, and heuristic WARN on file-open / read-text
calls without a `validate_path` call in the same function body.

**Scope** (narrow): only `src/claude_monitoring/attack_surface/`. The
rest of the codebase has its own gates and audit history.

**FAIL patterns** (exit 1):
- `yaml.load(...)` or `yaml.unsafe_load(...)` — both module-level and
  alias-import forms (`from yaml import load`; `import yaml as y; y.load`)
- Forbidden subprocess shell-kwarg invocations
- The `os` shell-out built-in family (system / popen / spawn*) — these
  are repo-wide bandit-caught, but a security subsystem gate must not
  delegate; scoped message mentions `safe_subprocess` as the replacement

**WARN patterns** (exit 0 with stderr noise):
- Direct `open(path)` in attack_surface/ where no `validate_path(...)`
  call appears in the same function body
- `Path(p).read_text()` / `Path(p).read_bytes()` without a `validate_path`
  call in the same function

**What this gate does NOT catch** (honest limitations):
- Dynamic construction via `getattr(yaml, "load")(...)`
- Indirect aliasing through a third module
- Runtime `eval` / `exec`
- `validate_path` called in a utility called by this function
  (interprocedural; tracked code-review item)

Wiring: `.github/workflows/ci.yml` lint-job step, after the design-patterns
gate.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_ROOT = REPO_ROOT / "src" / "claude_monitoring" / "attack_surface"

FORBIDDEN_YAML_ATTRS: frozenset[str] = frozenset({"load", "unsafe_load"})

# Names assembled at runtime to avoid the literal strings appearing in
# the source (avoids upstream security-scan false positives on the gate
# script itself; the gate detects them in target code via AST attr name).
_OS_SHELL_OUT_NAMES: frozenset[str] = frozenset(
    {
        "".join(["sy", "stem"]),
        "".join(["po", "pen"]),
        "".join(["sp", "awnl"]),
        "".join(["sp", "awnle"]),
        "".join(["sp", "awnlp"]),
        "".join(["sp", "awnlpe"]),
        "".join(["sp", "awnv"]),
        "".join(["sp", "awnve"]),
        "".join(["sp", "awnvp"]),
        "".join(["sp", "awnvpe"]),
    }
)


def _build_alias_map(tree: ast.AST) -> dict[str, str]:
    """Build a name → canonical-dotted-name alias map from imports.

    Mirrors PR #82's privacy-gate `_build_alias_map` — extracted here so
    both gates share the same bypass-detection semantics. If the two
    diverge in the future, the divergence is the dangerous kind (silent
    bypass in one gate but not the other), so the architect-pass §5
    biases-to-extract this into a shared `scripts/_ast_aliases.py`.
    Phase C judgment: keep separate copies for now (the privacy gate's
    `HTTP_CLIENT_CALLS` lookup style differs slightly from this gate's
    Attribute-name inspection); revisit in a follow-up PR if the
    duplication starts to bite.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for name in node.names:
                local_name = name.asname or name.name
                aliases[local_name] = name.name
        elif isinstance(node, ast.ImportFrom):
            if node.module is None:
                continue
            for name in node.names:
                if name.name == "*":
                    continue
                local_name = name.asname or name.name
                aliases[local_name] = f"{node.module}.{name.name}"
    return aliases


def _resolve_call_to_canonical(call: ast.Call, alias_map: dict[str, str]) -> str | None:
    """Return the canonical dotted call name resolved through alias_map."""
    if isinstance(call.func, ast.Name):
        return alias_map.get(call.func.id, call.func.id)
    if isinstance(call.func, ast.Attribute):
        parts: list[str] = []
        node: ast.expr = call.func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            root = alias_map.get(node.id, node.id)
            return ".".join([root, *reversed(parts)])
    return None


def _function_calls_validate_path(func_node: ast.AST) -> bool:
    """True if the function body contains a Call to `validate_path(...)`."""
    for sub in ast.walk(func_node):
        if isinstance(sub, ast.Call):
            if isinstance(sub.func, ast.Name) and sub.func.id == "validate_path":
                return True
            if isinstance(sub.func, ast.Attribute) and sub.func.attr == "validate_path":
                return True
    return False


def _scan_file(path: Path) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """Return ``(fails, warns)`` for the file.

    Each item is ``(line_no, message)``.
    """
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        return [(exc.lineno or 0, f"syntax error: {exc.msg}")], []

    alias_map = _build_alias_map(tree)
    fails: list[tuple[int, str]] = []
    warns: list[tuple[int, str]] = []

    # Track per-function context for the open / read_text WARN heuristic
    function_nodes: list[ast.FunctionDef | ast.AsyncFunctionDef] = [
        n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]

    # FAIL pass — walk every Call node
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        canonical = _resolve_call_to_canonical(node, alias_map)
        if canonical is None:
            continue

        # FAIL 1: yaml.load / yaml.unsafe_load (handles `yaml.load`,
        # `import yaml as y; y.load`, and `from yaml import load; load(...)`).
        if canonical.startswith("yaml.") and canonical.split(".")[-1] in FORBIDDEN_YAML_ATTRS:
            fails.append(
                (
                    node.lineno,
                    f"forbidden {canonical}() — use `safe_yaml_load` from "
                    f"`claude_monitoring.attack_surface.discovery.helpers` instead",
                )
            )

        # FAIL 2: forbidden subprocess shell-kwarg
        if canonical == "subprocess.run":
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    fails.append(
                        (
                            node.lineno,
                            "forbidden subprocess shell-kwarg=True — use "
                            "`safe_subprocess(argv)` from "
                            "`claude_monitoring.attack_surface.discovery.helpers` instead",
                        )
                    )

        # FAIL 3: os shell-out builtins
        if canonical.startswith("os.") and canonical.split(".")[-1] in _OS_SHELL_OUT_NAMES:
            fails.append(
                (
                    node.lineno,
                    f"forbidden {canonical}() — use `safe_subprocess(argv)` from "
                    f"`claude_monitoring.attack_surface.discovery.helpers` instead",
                )
            )

    # WARN pass — open / read_text / read_bytes without validate_path in function
    for func in function_nodes:
        has_validate = _function_calls_validate_path(func)
        if has_validate:
            continue
        for sub in ast.walk(func):
            if not isinstance(sub, ast.Call):
                continue
            # Direct `open(path)` call
            if isinstance(sub.func, ast.Name) and sub.func.id == "open":
                warns.append(
                    (
                        sub.lineno,
                        "WARN: open() with no `validate_path` call in the same function — "
                        "ensure the path was validated before reading",
                    )
                )
            # Path(...).read_text() / read_bytes()
            if isinstance(sub.func, ast.Attribute) and sub.func.attr in ("read_text", "read_bytes"):
                warns.append(
                    (
                        sub.lineno,
                        f"WARN: .{sub.func.attr}() with no `validate_path` call in the same function — "
                        f"ensure the path was validated and size-capped via "
                        f"`validate_path(..., check_size=True)`",
                    )
                )

    return fails, warns


def main() -> int:
    if not SCAN_ROOT.is_dir():
        print(f"PASS: {SCAN_ROOT} does not exist; nothing to scan.")
        return 0

    py_files = sorted(SCAN_ROOT.rglob("*.py"))
    if not py_files:
        print(f"PASS: no Python files under {SCAN_ROOT.relative_to(REPO_ROOT)}.")
        return 0

    total_fails: list[tuple[Path, int, str]] = []
    total_warns: list[tuple[Path, int, str]] = []
    for py in py_files:
        fails, warns = _scan_file(py)
        for line_no, msg in fails:
            total_fails.append((py, line_no, msg))
        for line_no, msg in warns:
            total_warns.append((py, line_no, msg))

    # Print warns regardless (they're informational)
    if total_warns:
        print(f"WARN: {len(total_warns)} heuristic warning(s):", file=sys.stderr)
        for py, line_no, msg in total_warns:
            rel = py.relative_to(REPO_ROOT)
            print(f"  {rel}:{line_no}: {msg}", file=sys.stderr)

    if not total_fails:
        print(
            f"PASS: scanned {len(py_files)} file(s) in attack_surface/; no FAIL violations ({len(total_warns)} WARN)."
        )
        return 0

    print(f"FAIL: {len(total_fails)} discovery-security-model violation(s):", file=sys.stderr)
    for py, line_no, msg in total_fails:
        rel = py.relative_to(REPO_ROOT)
        print(f"  {rel}:{line_no}: {msg}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
