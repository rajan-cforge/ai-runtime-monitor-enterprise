#!/usr/bin/env python3
"""Project-specific AST design-pattern checks beyond what ruff provides.

Walks every `.py` file under ``src/claude_monitoring/`` and reports
violations of the patterns codified in ``CLAUDE.md`` (Mandatory /
Forbidden patterns). Existing violations are baselined in
``scripts/check_design_patterns_baseline.txt`` — the baseline is
meant to **shrink** over time, never grow. New violations not in the
baseline fail the build.

Usage:
    python scripts/check_design_patterns.py             # check vs baseline
    python scripts/check_design_patterns.py --update-baseline   # rewrite baseline

Exit codes:
    0  all checks pass (or all violations are in the baseline)
    1  one or more new violations found
    2  usage error
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src" / "claude_monitoring"
BASELINE_PATH = PROJECT_ROOT / "scripts" / "check_design_patterns_baseline.txt"


class DesignPatternChecker(ast.NodeVisitor):
    """Walk one module's AST collecting (lineno, message) violations."""

    def __init__(self, filepath: Path) -> None:
        self.filepath = filepath
        self.violations: list[tuple[int, str]] = []
        self.in_dashboard_handler = False

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        was_in_handler = self.in_dashboard_handler
        if node.name == "DashboardHandler":
            self.in_dashboard_handler = True
        self.generic_visit(node)
        self.in_dashboard_handler = was_in_handler

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # Public function must have a docstring (CLAUDE.md mandatory pattern).
        if not node.name.startswith("_") and not ast.get_docstring(node):
            self.violations.append((node.lineno, f"public function '{node.name}' missing docstring"))

        # Dashboard handler methods must call verify_token or annotate # auth-exempt.
        if self.in_dashboard_handler and node.name.startswith("_handle_"):
            calls = [n for n in ast.walk(node) if isinstance(n, ast.Call)]
            has_auth = any(
                (isinstance(c.func, ast.Attribute) and c.func.attr == "verify_token")
                or (isinstance(c.func, ast.Name) and c.func.id == "verify_token")
                for c in calls
            )
            has_skip = any(
                isinstance(n, ast.Constant) and isinstance(n.value, str) and "auth-exempt" in n.value
                for n in ast.walk(node)
            )
            if not has_auth and not has_skip:
                self.violations.append(
                    (
                        node.lineno,
                        f"handler '{node.name}' must call verify_token or annotate # auth-exempt",
                    )
                )

        # Mutable default arguments (CLAUDE.md forbidden pattern).
        for default in node.args.defaults:
            if isinstance(default, (ast.List, ast.Dict, ast.Set)):
                self.violations.append((node.lineno, f"function '{node.name}' has mutable default argument"))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        # Bare except — already on the CLAUDE.md forbidden list.
        if node.type is None:
            self.violations.append((node.lineno, "bare 'except:' clause (use 'except Exception:' at minimum)"))
        # Empty `except Exception: pass` silently swallows errors.
        if (
            isinstance(node.type, ast.Name)
            and node.type.id == "Exception"
            and len(node.body) == 1
            and isinstance(node.body[0], ast.Pass)
        ):
            self.violations.append((node.lineno, "empty 'except Exception: pass' (silently swallowing errors)"))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        # subprocess.*(shell=True) — CLAUDE.md forbidden pattern.
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            mod = node.func.value.id
            fn = node.func.attr
            if mod == "subprocess" and fn in ("run", "call", "check_output", "check_call", "Popen"):
                for kw in node.keywords:
                    if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                        self.violations.append((node.lineno, f"subprocess.{fn}(shell=True) — use argv list instead"))
            # requests.*(verify=False) — CLAUDE.md forbidden pattern.
            if mod == "requests" and fn in ("get", "post", "put", "delete", "patch", "head", "request"):
                for kw in node.keywords:
                    if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                        self.violations.append(
                            (node.lineno, f"requests.{fn}(verify=False) — TLS verification disabled")
                        )

        self.generic_visit(node)


def collect_violations(targets: list[Path]) -> list[str]:
    """Return list of violations as `relpath:lineno: msg` strings, sorted."""
    out: list[str] = []
    for filepath in sorted(targets):
        if filepath.name.startswith("test_"):
            continue
        try:
            tree = ast.parse(filepath.read_text())
        except SyntaxError as e:
            out.append(f"{filepath.relative_to(PROJECT_ROOT)}:{e.lineno}: syntax error")
            continue
        checker = DesignPatternChecker(filepath)
        checker.visit(tree)
        rel = filepath.relative_to(PROJECT_ROOT)
        for lineno, msg in checker.violations:
            out.append(f"{rel}:{lineno}: {msg}")
    return sorted(out)


def load_baseline() -> set[str]:
    """Read the baseline file; return set of normalized violation lines.

    Lines beginning with `#` or empty are treated as comments and skipped.
    """
    if not BASELINE_PATH.exists():
        return set()
    out: set[str] = set()
    for line in BASELINE_PATH.read_text().splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        out.add(s)
    return out


def write_baseline(violations: list[str]) -> None:
    """Rewrite the baseline file from the current violation set."""
    header = (
        "# Design-pattern violations existing on main as of the enforcement-PR landing.\n"
        "# The baseline shrinks over time — never grows. To remove an entry, fix the\n"
        "# violation in source. To remove an entry across multiple PRs, batch via a\n"
        "# dedicated cleanup PR rather than re-running --update-baseline silently.\n"
        "#\n"
        "# Generated by: scripts/check_design_patterns.py --update-baseline\n"
        "#\n"
    )
    BASELINE_PATH.write_text(header + "\n".join(violations) + ("\n" if violations else ""))


def main(argv: list[str]) -> int:
    update = "--update-baseline" in argv[1:]
    if update and len(argv) > 2:
        print(f"Usage: {argv[0]} [--update-baseline]", file=sys.stderr)
        return 2

    targets = list(SRC_DIR.rglob("*.py"))
    found = collect_violations(targets)

    if update:
        write_baseline(found)
        print(f"Baseline updated: {len(found)} violations recorded at {BASELINE_PATH.relative_to(PROJECT_ROOT)}")
        return 0

    baseline = load_baseline()
    new = [v for v in found if v not in baseline]
    healed = sorted(baseline - set(found))

    if healed:
        print("Note: violations cleaned up since baseline (consider running --update-baseline):")
        for h in healed:
            print(f"  - {h}")

    if new:
        print(f"FAIL: {len(new)} new design-pattern violation(s) not in baseline:")
        for v in new:
            print(f"  {v}")
        print(
            "\nFix the violation, or — if it represents a legitimate exception — add a\n"
            "narrow inline `# noqa-design: <rule>` annotation (not yet implemented) or\n"
            "discuss adding it to the baseline in PR review."
        )
        return 1

    print(f"PASS: {len(found)} violation(s), all in baseline (baseline shrinks over time, never grows).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
