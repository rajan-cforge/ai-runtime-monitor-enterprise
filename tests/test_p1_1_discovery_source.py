"""TDD test suite for v0.2.2 P1.1 — DiscoverySource contract surface.

Per Rajan's Phase A approval (2026-06-04), P1.1 ships the contract surface
ONLY: Asset dataclass + DiscoverySource ABC + run_with_safety + timeout
helper. Persistence-layer tests (Asset ↔ assets-row mapping for drifts
1/2/4) move to P1.3.

Locked Phase A decisions exercised by these tests:

- Asset dataclass invariants: `current_state` and `source` have no
  default; construction without either raises TypeError. JSON round-trip
  on `current_state: dict` is preserved.
- DiscoverySource ABC: three abstract methods (`name`, `requires_auth`,
  `discover`) enforced by Python's `abc.ABC` machinery; missing override
  → cannot instantiate.
- `run_with_safety`: happy-path → returns discover() result; cap-exceeded
  → truncated to ``MAX_ASSETS_PER_SOURCE``; timeout-exceeded → ``[]``;
  uncaught exception → ``[]`` (sources never raise to the orchestrator);
  must be callable from worker threads (locks the thread-safe timeout
  mechanism — ``concurrent.futures``, not ``signal.alarm``).
- Class constants overridable per subclass; base class unchanged.

Total: 16 tests across 4 classes. All fail initially with
``ModuleNotFoundError: claude_monitoring.attack_surface`` (the module
doesn't exist yet); Phase C lands the implementation that turns each
test green.
"""

from __future__ import annotations

import json
import threading
import time

import pytest

# Imports under test. Phase B: this fails at collection time
# (ModuleNotFoundError). Phase C: lands the package, all tests turn green.
from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import DiscoverySource


def _make_asset(name: str, **overrides) -> Asset:
    """Test-only Asset factory with sensible defaults so individual tests
    only call out the field they care about."""
    defaults = {
        "id": f"id-{name}",
        "type": "ai_tool",
        "parent_asset_id": None,
        "name": name,
        "version": None,
        "install_path": None,
        "source": "test-source",
        "current_state": {},
        "discovered_at": 0.0,
    }
    defaults.update(overrides)
    return Asset(**defaults)


# ---------------------------------------------------------------------------
# Group 1 — Asset dataclass invariants (P1.1 guard tests per dispatch)
# ---------------------------------------------------------------------------


class TestAssetDataclassInvariants:
    def test_asset_requires_current_state(self) -> None:
        """No default. Construction without current_state fails at the
        application boundary. (The DB-layer half — INSERT without
        current_state — moves to P1.3 per the scope cut.)"""
        with pytest.raises(TypeError):
            Asset(
                id="x",
                type="ai_tool",
                parent_asset_id=None,
                name="claude",
                version=None,
                install_path=None,
                source="ai_apps",
                # current_state intentionally missing
                discovered_at=0.0,
            )  # type: ignore[call-arg]

    def test_asset_requires_source(self) -> None:
        """No default. Construction without source fails."""
        with pytest.raises(TypeError):
            Asset(
                id="x",
                type="ai_tool",
                parent_asset_id=None,
                name="claude",
                version=None,
                install_path=None,
                # source intentionally missing
                current_state={"a": 1},
                discovered_at=0.0,
            )  # type: ignore[call-arg]

    def test_asset_current_state_explicit_none_rejected(self) -> None:
        """``current_state=None`` is rejected at construction.

        TypeError-on-missing (Python's no-default enforcement, covered by
        :meth:`test_asset_requires_current_state`) does NOT cover the
        case where a discovery-source author explicitly passes
        ``current_state=None`` thinking it means "no inspectable state."
        The correct sentinel is empty dict ``{}``. Without this guard,
        None propagates silently to the P1.3 persistence adapter and
        crashes inside ``json.dumps`` far from the construction site.
        """
        with pytest.raises(ValueError, match="current_state"):
            Asset(
                id="x",
                type="ai_tool",
                parent_asset_id=None,
                name="claude",
                version=None,
                install_path=None,
                source="ai_apps",
                current_state=None,  # type: ignore[arg-type]
                discovered_at=0.0,
            )

    def test_asset_current_state_json_round_trip(self) -> None:
        """current_state: dict survives json.dumps → json.loads with
        equality preserved. Pins the contract that current_state is JSON-
        serializable arbitrary nested structures (per spec §7.1 doc:
        "serializable; permissions, scope, native config excerpt")."""
        original = {
            "permissions": ["read", "write"],
            "host_permissions": ["<all_urls>"],
            "nested": {"x": 1, "y": "two", "z": None},
            "list_of_dicts": [{"a": 1}, {"b": 2}],
        }
        # 1. JSON round-trips
        serialized = json.dumps(original)
        restored = json.loads(serialized)
        assert restored == original
        # 2. The dataclass holds the dict literally (not a serialized string)
        asset = _make_asset("test", current_state=original)
        assert asset.current_state == original
        assert isinstance(asset.current_state, dict)

    def test_asset_defaults_and_optionals(self) -> None:
        """is_vigil_component defaults to False; the four Optional fields
        accept None without complaint."""
        asset = _make_asset("test")
        assert asset.is_vigil_component is False
        assert asset.parent_asset_id is None
        assert asset.version is None
        assert asset.install_path is None


# ---------------------------------------------------------------------------
# Group 2 — DiscoverySource ABC contract
# ---------------------------------------------------------------------------


class TestDiscoverySourceContract:
    def test_cannot_instantiate_abstract_class(self) -> None:
        """abc.ABC enforcement — DiscoverySource itself is not instantiable."""
        with pytest.raises(TypeError, match="abstract"):
            DiscoverySource()  # type: ignore[abstract]

    def test_subclass_missing_name_cannot_instantiate(self) -> None:
        class Partial(DiscoverySource):
            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return []

        with pytest.raises(TypeError, match="abstract"):
            Partial()  # type: ignore[abstract]

    def test_subclass_missing_requires_auth_cannot_instantiate(self) -> None:
        class Partial(DiscoverySource):
            def name(self) -> str:
                return "x"

            def discover(self) -> list[Asset]:
                return []

        with pytest.raises(TypeError, match="abstract"):
            Partial()  # type: ignore[abstract]

    def test_subclass_missing_discover_cannot_instantiate(self) -> None:
        class Partial(DiscoverySource):
            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

        with pytest.raises(TypeError, match="abstract"):
            Partial()  # type: ignore[abstract]

    def test_concrete_subclass_instantiates_and_responds(self) -> None:
        class Concrete(DiscoverySource):
            def name(self) -> str:
                return "test-source"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return [_make_asset("a")]

        src = Concrete()
        assert src.name() == "test-source"
        assert src.requires_auth() is False
        assert len(src.discover()) == 1


# ---------------------------------------------------------------------------
# Group 3 — run_with_safety (the concrete wrapper)
# ---------------------------------------------------------------------------


class TestRunWithSafety:
    def test_happy_path_returns_discover_result(self) -> None:
        sample = [_make_asset("a"), _make_asset("b")]

        class Src(DiscoverySource):
            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return sample

        result = Src().run_with_safety()
        assert result == sample

    def test_enforces_max_assets_per_source_cap(self) -> None:
        """Subclass returns 100 assets but MAX cap is 5 → result truncated
        to 5. Documents the cap-enforcement contract for the orchestrator."""

        class Src(DiscoverySource):
            MAX_ASSETS_PER_SOURCE = 5

            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return [_make_asset(str(i)) for i in range(100)]

        result = Src().run_with_safety()
        assert len(result) == 5
        # First 5 are preserved (order matters for debugging — earliest
        # discovered first).
        assert [a.name for a in result] == ["0", "1", "2", "3", "4"]

    def test_timeout_returns_empty_list(self) -> None:
        """discover() that runs longer than DEFAULT_TIMEOUT_SEC → []."""

        class Src(DiscoverySource):
            DEFAULT_TIMEOUT_SEC = 0.1  # very short for test runtime

            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                time.sleep(2.0)  # well past the 0.1s timeout
                return [_make_asset("never")]

        start = time.monotonic()
        result = Src().run_with_safety()
        elapsed = time.monotonic() - start
        assert result == []
        # The wrapper returns within ~timeout + small overhead, NOT after
        # the full 2s sleep. Allow 1s ceiling for executor overhead.
        assert elapsed < 1.0, f"timeout did not return early (took {elapsed:.2f}s)"

    def test_generic_exception_returns_empty_list(self) -> None:
        """ANY uncaught exception from discover() → []. Sources never raise
        to the orchestrator — that's the universal failure signal contract."""

        class Src(DiscoverySource):
            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                raise RuntimeError("oh no the upstream API crashed")

        result = Src().run_with_safety()
        assert result == []

    def test_thread_safe_callable_from_worker_thread(self) -> None:
        """Locks the timeout-mechanism decision: must be ``concurrent.futures``
        (or equivalent thread-safe), NOT ``signal.alarm``. The orchestrator
        (P1.3) calls run_with_safety from worker threads; if the impl used
        ``signal.signal``/``signal.alarm`` it would raise
        ``ValueError: signal only works in main thread`` from any worker."""
        results: list[list[Asset]] = []
        errors: list[BaseException] = []

        class Src(DiscoverySource):
            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return [_make_asset("from-worker")]

        def worker() -> None:
            try:
                results.append(Src().run_with_safety())
            except BaseException as exc:
                errors.append(exc)

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=10)

        assert errors == [], (
            f"run_with_safety raised in worker thread (likely signal-based timeout?): {errors[0]!r}" if errors else ""
        )
        assert len(results) == 1
        assert len(results[0]) == 1
        assert results[0][0].name == "from-worker"


# ---------------------------------------------------------------------------
# Group 4 — Class-level constants (override pattern)
# ---------------------------------------------------------------------------


class TestClassConstants:
    def test_default_class_constants_match_spec(self) -> None:
        """Locked per spec §4.7 / directive §7.1."""
        assert DiscoverySource.DEFAULT_TIMEOUT_SEC == 30
        assert DiscoverySource.MAX_ASSETS_PER_SOURCE == 1000
        assert DiscoverySource.MAX_FILE_SIZE_MB == 10
        assert DiscoverySource.MAX_TRAVERSAL_DEPTH == 10

    def test_subclass_can_override_constants_without_affecting_base(self) -> None:
        """Per-source overrides leave the base class untouched."""

        class Src(DiscoverySource):
            DEFAULT_TIMEOUT_SEC = 60
            MAX_ASSETS_PER_SOURCE = 500

            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return []

        assert Src.DEFAULT_TIMEOUT_SEC == 60
        assert Src.MAX_ASSETS_PER_SOURCE == 500
        # Base class unchanged
        assert DiscoverySource.DEFAULT_TIMEOUT_SEC == 30
        assert DiscoverySource.MAX_ASSETS_PER_SOURCE == 1000
