#!/usr/bin/env python3
"""Ontology mapping completeness gate — directive §11.2.

**Q5 ratification (2026-06-06): STRUCTURAL completeness only.** Every
:class:`DiscoverySource` MUST have a corresponding entry in
``ontology.mapping._REGISTRY``. A mapper that returns
``frozenset()`` is acceptable — the gate enforces existence, not
functional output. A functional gate would contradict the Q1
ratification (zero-tag asset is valid and lands at INFO band per
spec §6.5).

**Failure mode this catches:** a new discovery source ships in a PR
but the author forgets to add the corresponding mapper. The
orchestrator + persistence accept the new asset, but every instance
ends up at INFO band silently because the dispatcher returns
``frozenset()`` for unknown sources. This gate makes the omission
fail CI rather than disappear into the bug backlog.

**Scope:** the gate iterates every ``DiscoverySource`` subclass under
``src/claude_monitoring/attack_surface/discovery/sources/`` and
checks each ``name()`` against ``REGISTERED_SOURCES``. Subclasses
that exist purely as helpers (not registered with the orchestrator)
should subclass differently (e.g., add a ``_ABSTRACT_BASE`` marker
when the time comes); none exist in Phase 2.

Exit codes:
- 0 — all registered sources have a mapper (PASS)
- 1 — at least one source missing OR registry has phantoms (FAIL)
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
import sys
from pathlib import Path

# Ensure src/ is importable when invoked from repo root
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from claude_monitoring.attack_surface.discovery.base import DiscoverySource  # noqa: E402
from claude_monitoring.attack_surface.ontology.mapping import REGISTERED_SOURCES  # noqa: E402


def _discover_source_classes() -> list[type[DiscoverySource]]:
    """Walk `attack_surface.discovery.sources` and collect every
    concrete `DiscoverySource` subclass."""
    import claude_monitoring.attack_surface.discovery.sources as sources_pkg

    classes: list[type[DiscoverySource]] = []
    for _finder, module_name, _ispkg in pkgutil.iter_modules(sources_pkg.__path__):
        full_name = f"{sources_pkg.__name__}.{module_name}"
        mod = importlib.import_module(full_name)
        for attr in dir(mod):
            obj = getattr(mod, attr)
            if not (isinstance(obj, type) and issubclass(obj, DiscoverySource) and obj is not DiscoverySource):
                continue
            # Skip abstract intermediates (e.g., a future `FileBasedSource`
            # helper). They're not orchestrator-registered and don't need
            # an ontology mapper.
            if inspect.isabstract(obj):
                continue
            # Skip re-exports: only count classes defined IN a sources module.
            if obj.__module__ != full_name:
                continue
            classes.append(obj)
    return classes


def main() -> int:
    source_classes = _discover_source_classes()
    if not source_classes:
        print("FAIL: no DiscoverySource subclasses found under attack_surface/discovery/sources/")
        return 1

    failures: list[str] = []
    real_source_names: set[str] = set()
    for cls in source_classes:
        try:
            instance = cls()
        except Exception as exc:
            failures.append(f"{cls.__module__}.{cls.__name__}: cannot instantiate ({exc!r})")
            continue
        try:
            name = instance.name()
        except Exception as exc:
            failures.append(f"{cls.__module__}.{cls.__name__}: cannot read name() ({exc!r})")
            continue
        real_source_names.add(name)
        if name not in REGISTERED_SOURCES:
            failures.append(
                f"{cls.__module__}.{cls.__name__} (name={name!r}): no mapping function in ontology.mapping._REGISTRY"
            )

    # Inverse check: any phantoms in the registry without a corresponding source class
    phantoms = REGISTERED_SOURCES - real_source_names
    for ph in sorted(phantoms):
        failures.append(
            f"ontology.mapping._REGISTRY has phantom entry {ph!r} (no DiscoverySource subclass produces this name)"
        )

    if failures:
        print(f"FAIL: ontology completeness gate found {len(failures)} issue(s):")
        for f in failures:
            print(f"  - {f}")
        return 1

    print(
        f"PASS: ontology mapping completeness — {len(source_classes)} discovery source(s), "
        f"{len(REGISTERED_SOURCES)} registered mapper(s)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
