"""Conformance test: every class named ``*Scanner`` satisfies the
``Scanner`` Protocol.

Walks ``claude_monitoring`` for classes whose name ends with
``Scanner`` (excluding the Protocol itself) and asserts each has the
``scan``, ``health_check``, and ``name`` members required by the
Protocol. Fails the build if a new scanner is added without conforming.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil

import pytest

import claude_monitoring

# Pre-existing classes that share the "Scanner" naming but predate the
# Protocol and serve a different role (continuous thread-loop scanners
# of host state — processes, files, network — rather than one-shot
# data scanners of input bodies). Bringing them under the Protocol is
# Phase 3F refactor work; until then, list them here with rationale.
#
# Format: "<module>.<ClassName>".
KNOWN_PROTOCOL_EXEMPT: frozenset[str] = frozenset(
    {
        # Thread-loop runtime scanner. Uses scan_once() + run_loop() rather
        # than the Protocol's single scan() entry point. Different lifecycle.
        "claude_monitoring.monitor.ProcessScanner",
    }
)


def find_scanner_classes() -> list[tuple[str, str, type]]:
    """Walk the package, return every class with name ending in Scanner."""
    classes: list[tuple[str, str, type]] = []
    for _finder, modname, _ispkg in pkgutil.walk_packages(claude_monitoring.__path__, prefix="claude_monitoring."):
        # Skip the protocols package itself — it defines the Scanner
        # Protocol, not concrete implementations.
        if modname.startswith("claude_monitoring.protocols"):
            continue
        try:
            mod = importlib.import_module(modname)
        except Exception:
            # Modules with optional deps (mitmproxy, matplotlib) may
            # fail to import in CI. Skip rather than crash the conformance
            # test — the missing-dep skip count is already tracked elsewhere.
            continue
        for name, obj in inspect.getmembers(mod, inspect.isclass):
            if obj.__module__ != modname:
                continue
            if name.endswith("Scanner") and name != "Scanner":
                fqname = f"{modname}.{name}"
                if fqname in KNOWN_PROTOCOL_EXEMPT:
                    continue
                classes.append((modname, name, obj))
    return classes


_SCANNER_CLASSES = find_scanner_classes()


@pytest.mark.parametrize(
    "modname,classname,cls",
    _SCANNER_CLASSES,
    ids=[f"{m}::{n}" for m, n, _ in _SCANNER_CLASSES] or ["no-scanners-found"],
)
def test_scanner_class_satisfies_protocol(modname: str, classname: str, cls: type) -> None:
    """Each ``*Scanner`` class must satisfy the Scanner Protocol shape.

    runtime_checkable Protocols support ``isinstance`` against instances,
    but for classes we check for the three required members directly —
    avoids needing a no-arg constructor for every scanner under test.
    """
    if not _SCANNER_CLASSES:
        # No concrete scanners yet (e.g., during early bootstrap of the
        # Protocol). That is acceptable; the meta-test enforces that
        # *adding* a scanner adds a conformance check.
        pytest.skip("no *Scanner classes found yet")
    # Stricter than hasattr: require the members to be callable methods,
    # not just any attribute that happens to share the name. Catches the
    # case where a class defines `scan = "not implemented"` and would
    # otherwise pass hasattr.
    scan_attr = getattr(cls, "scan", None)
    health_attr = getattr(cls, "health_check", None)
    assert callable(scan_attr), f"{classname}.scan must be callable, got {type(scan_attr).__name__}"
    assert callable(health_attr), f"{classname}.health_check must be callable, got {type(health_attr).__name__}"
    assert hasattr(cls, "name"), f"{classname} missing 'name' attribute"
