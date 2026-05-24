"""Meta-test: every Protocol exported from ``claude_monitoring.protocols``
has a corresponding conformance test file under ``tests/architecture/``.

If a new Protocol is added and no ``test_<name>_conformance.py`` exists,
this test fails — forcing the author to either write the conformance
test or remove the Protocol export.

Placeholder modules (``collector.py``, ``detector.py``) are intentionally
NOT exported from ``__init__.__all__`` yet, so the inventory check
doesn't fire on them. When their Protocols are defined and exported,
the meta-test will demand a conformance file alongside.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from claude_monitoring import protocols


def _is_protocol_class(obj: object) -> bool:
    """True iff *obj* is a typing.Protocol subclass (i.e. an interface)."""
    if not inspect.isclass(obj):
        return False
    # typing.Protocol marks subclasses with _is_protocol = True.
    return getattr(obj, "_is_protocol", False) is True


def test_every_protocol_has_conformance_test() -> None:
    """For each Protocol exported from ``protocols``, there must be a
    test file ``tests/architecture/test_<lowercase>_conformance.py``.
    """
    test_dir = Path(__file__).parent

    protocol_names = [name for name in protocols.__all__ if _is_protocol_class(getattr(protocols, name))]

    # If you add a new Protocol, add a conformance test alongside it.
    assert protocol_names, "expected at least one Protocol exported from claude_monitoring.protocols"

    missing: list[str] = []
    for name in protocol_names:
        expected_test = test_dir / f"test_{name.lower()}_conformance.py"
        if not expected_test.exists():
            missing.append(f"{name} → {expected_test.name}")

    assert not missing, "Protocol(s) without conformance tests: " + ", ".join(missing)


def test_data_classes_in_protocols_module_not_treated_as_protocols() -> None:
    """``Finding`` and ``ScannerHealth`` are dataclasses, not Protocols.

    They live in the protocols module because they're the wire types
    that Protocols transact in, but they don't need conformance tests
    of their own. This test guards against accidental misclassification.
    """
    # `Finding` and `ScannerHealth` should NOT be flagged as Protocols.
    assert not _is_protocol_class(protocols.Finding)
    assert not _is_protocol_class(protocols.ScannerHealth)
    # `Scanner` SHOULD be.
    assert _is_protocol_class(protocols.Scanner)


def test_every_exported_name_resolves() -> None:
    """Sanity: every name in ``__all__`` resolves to a real attribute.

    Catches the case where someone adds a name to ``__all__`` but
    forgets to import it, which would crash at first ``from
    claude_monitoring.protocols import X``.

    Avoids ``typing.get_type_hints`` here because resolving PEP 604
    annotations (``float | None``) under Python 3.9 raises at runtime
    even with ``from __future__ import annotations`` — the future
    import only defers parsing, not evaluation.
    """
    for name in protocols.__all__:
        obj = getattr(protocols, name)
        assert obj is not None, f"protocols.__all__ lists {name!r} but it's None"
