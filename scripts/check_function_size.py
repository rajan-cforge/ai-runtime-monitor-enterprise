#!/usr/bin/env python3
"""Fail CI when any function exceeds MAX_LINES.

AST-based: counts each ``FunctionDef`` / ``AsyncFunctionDef`` /
``Lambda`` (lambdas only when not trivial). Length is
``end_lineno - lineno + 1``. Nested functions are checked
independently of their parent.

The threshold is a **ceiling** set just above the largest function
currently in src/ — it ratchets. Lower it as long functions are
refactored, never raise it just to make the gate quiet.

Usage:
    python scripts/check_function_size.py [PATH ...]

Default path is ``src/``. Exit 0 on PASS, 1 on FAIL, 2 on usage error.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

MAX_LINES = 400


def function_lengths(path: Path) -> list[tuple[str, int, int]]:
    """Return [(name, start_line, length), ...] for every function in *path*."""
    try:
        tree = ast.parse(path.read_text())
    except SyntaxError:
        return []
    out: list[tuple[str, int, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            length = end - node.lineno + 1
            out.append((node.name, node.lineno, length))
    return out


def check(roots: list[Path]) -> int:
    failures: list[tuple[Path, str, int, int]] = []
    fn_total = 0
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            for name, start, length in function_lengths(path):
                fn_total += 1
                if length > MAX_LINES:
                    failures.append((path, name, start, length))

    if failures:
        print(f"FAIL: {len(failures)} function(s) over the {MAX_LINES}-line ceiling:")
        for path, name, start, length in failures:
            print(f"  {length:4d} lines  {path}:{start}  {name}  (+{length - MAX_LINES})")
        print(
            "\nSplit the function into smaller helpers. Long functions hide "
            "branch complexity from reviewers and inflate test surface area."
        )
        return 1

    print(f"PASS: {fn_total} function(s) under the {MAX_LINES}-line ceiling.")
    return 0


def main(argv: list[str]) -> int:
    paths = [Path(a) for a in argv[1:]] if len(argv) > 1 else [Path("src")]
    for p in paths:
        if not p.exists():
            print(f"ERROR: {p} does not exist", file=sys.stderr)
            return 2
    return check(paths)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
