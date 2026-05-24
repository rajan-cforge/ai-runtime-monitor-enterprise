#!/usr/bin/env python3
"""Fail CI when any source file exceeds MAX_LINES.

The threshold is a **ceiling**, set just above the current state of the
codebase so it ratchets — not a target. Lower it as monitor.py is
split (M6) and as new modules naturally land smaller.

Skips comments-only and blank lines? No. The point is to gate total
file size including comments; a 5000-line file is hard to navigate
regardless of comment ratio. We measure raw line count.

Usage:
    python scripts/check_file_size.py [PATH ...]

Default path is ``src/``. Exit 0 on PASS, 1 on FAIL (any file over the
threshold), 2 on usage error.
"""

from __future__ import annotations

import sys
from pathlib import Path

MAX_LINES = 5500


def file_line_count(path: Path) -> int:
    """Number of lines in the file, counted by ``\\n``."""
    with path.open("rb") as f:
        return sum(1 for _ in f)


def check(roots: list[Path]) -> int:
    failures: list[tuple[Path, int]] = []
    total = 0
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            total += 1
            n = file_line_count(path)
            if n > MAX_LINES:
                failures.append((path, n))

    if failures:
        print(f"FAIL: {len(failures)} file(s) over the {MAX_LINES}-line ceiling:")
        for path, n in failures:
            print(f"  {n:5d} lines  {path}  (+{n - MAX_LINES})")
        print(
            "\nAdd new code to a separate module or split this one. "
            "The ceiling is a ratchet — bump only after a split lands, "
            "never to make the gate stop firing."
        )
        return 1

    print(f"PASS: {total} file(s) under the {MAX_LINES}-line ceiling.")
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
