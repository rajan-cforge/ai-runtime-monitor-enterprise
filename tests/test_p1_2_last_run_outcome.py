"""Tests for the `last_run_outcome()` contract extension.

P1.2 lands an additive method on `DiscoverySource` per Rajan's
2026-06-05 ratification (Decision 2). The orchestrator (P1.3) reads
this AFTER `run_with_safety` returns to distinguish a clean zero from
a crash — without it, the audit log cannot tell those apart.

C4-attention tests per architect-pass: this is the contract surface
that future P1.3 tests assert against. Cannot drift silently.
"""

from __future__ import annotations

import threading
import time

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.base import (
    DiscoverySource,
    LastRunOutcome,
)


def _make_asset(name: str) -> Asset:
    return Asset(
        id=f"id-{name}",
        type="ai_tool",
        parent_asset_id=None,
        name=name,
        version=None,
        install_path=None,
        source="test-source",
        current_state={},
        discovered_at=0.0,
    )


class TestLastRunOutcomeEnumShape:
    def test_enum_contains_five_locked_values(self) -> None:
        """LastRunOutcome has exactly 5 values per Decision 2 ratification:
        UNCALLED, SUCCESS, TIMEOUT, ERROR, CAPPED."""
        assert {m.name for m in LastRunOutcome} == {
            "UNCALLED",
            "SUCCESS",
            "TIMEOUT",
            "ERROR",
            "CAPPED",
        }

    def test_enum_values_are_lowercase_strings(self) -> None:
        """Enum value strings are lowercase — pins the
        `outcome.value → audit JSON failure_kind` mapping that P1.5 uses
        (Phase A §3.3 sketch uses lowercase 'timeout'/'exception')."""
        assert LastRunOutcome.SUCCESS.value == "success"
        assert LastRunOutcome.TIMEOUT.value == "timeout"
        assert LastRunOutcome.ERROR.value == "error"
        assert LastRunOutcome.CAPPED.value == "capped"
        assert LastRunOutcome.UNCALLED.value == "uncalled"


class TestLastRunOutcomeStateMachine:
    def test_initial_state_uncalled(self) -> None:
        """Before any `run_with_safety` call, outcome is UNCALLED."""

        class Src(DiscoverySource):
            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return []

        src = Src()
        assert src.last_run_outcome() == LastRunOutcome.UNCALLED

    def test_happy_path_sets_success(self) -> None:
        """`discover()` returning cleanly with assets → SUCCESS."""

        class Src(DiscoverySource):
            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return [_make_asset("a")]

        src = Src()
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_clean_zero_sets_success(self) -> None:
        """`discover()` returning empty list cleanly → SUCCESS. Empty
        + SUCCESS = 'no assets on this machine,' a valid result."""

        class Src(DiscoverySource):
            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return []

        src = Src()
        result = src.run_with_safety()
        assert result == []
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS, (
            "clean zero MUST be distinguishable from crash — orchestrator audit relies on this"
        )

    def test_timeout_sets_timeout(self) -> None:
        """`discover()` exceeding `DEFAULT_TIMEOUT_SEC` → TIMEOUT."""

        class Src(DiscoverySource):
            DEFAULT_TIMEOUT_SEC = 0.1

            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                time.sleep(2.0)
                return []

        src = Src()
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.TIMEOUT

    def test_exception_sets_error(self) -> None:
        """`discover()` raising any uncaught Exception → ERROR."""

        class Src(DiscoverySource):
            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                raise RuntimeError("boom")

        src = Src()
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.ERROR

    def test_cap_truncation_sets_capped(self) -> None:
        """`discover()` returning > MAX_ASSETS_PER_SOURCE → CAPPED (per
        architect-pass §1.3 enum). Pins truncation visibility."""

        class Src(DiscoverySource):
            MAX_ASSETS_PER_SOURCE = 3

            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return [_make_asset(str(i)) for i in range(10)]

        src = Src()
        result = src.run_with_safety()
        assert len(result) == 3
        assert src.last_run_outcome() == LastRunOutcome.CAPPED

    def test_exact_cap_sets_success_not_capped(self) -> None:
        """Returning EXACTLY MAX_ASSETS_PER_SOURCE → SUCCESS (boundary).
        CAPPED fires only when result was truncated (count > cap)."""

        class Src(DiscoverySource):
            MAX_ASSETS_PER_SOURCE = 3

            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return [_make_asset(str(i)) for i in range(3)]

        src = Src()
        result = src.run_with_safety()
        assert len(result) == 3
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS


class TestLastRunOutcomeFootgunResistance:
    """Per Rajan's 2026-06-05 base.py review: a subclass that overrides
    __init__ WITHOUT calling super().__init__() must STILL return
    UNCALLED from last_run_outcome(), not raise AttributeError.

    The fix is to keep `_last_run_outcome` as a class-level default
    attribute, NOT an instance attribute set by DiscoverySource.__init__.
    Then run_with_safety creates an instance attribute that shadows the
    class default; subclasses that skip super().__init__() still get the
    UNCALLED class default via attribute lookup.
    """

    def test_subclass_skipping_super_init_still_returns_uncalled(self) -> None:
        """The footgun: a subclass overrides __init__ without calling
        super().__init__(). `last_run_outcome()` must STILL return UNCALLED."""

        class BadlyInitialised(DiscoverySource):
            def __init__(self) -> None:
                # Intentionally NO super().__init__() — the footgun pattern
                self.subclass_local = 1

            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return []

        instance = BadlyInitialised()
        # Must NOT raise AttributeError
        assert instance.last_run_outcome() == LastRunOutcome.UNCALLED

    def test_subclass_skipping_super_init_still_updates_outcome_on_run(self) -> None:
        """And the outcome MUST still update after `run_with_safety` — i.e.,
        the class-attribute default doesn't break the assignment path."""

        class BadlyInitialised(DiscoverySource):
            def __init__(self) -> None:
                self.subclass_local = 1

            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return [_make_asset("a")]

        instance = BadlyInitialised()
        instance.run_with_safety()
        assert instance.last_run_outcome() == LastRunOutcome.SUCCESS


class TestLastRunOutcomeContract:
    def test_run_with_safety_return_type_unchanged(self) -> None:
        """Decision 2 ratification: `run_with_safety` STILL returns
        `list[Asset]`, NOT a tuple or rich object. The universal
        empty-list signal stays intact for simple callers."""

        class Src(DiscoverySource):
            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return [_make_asset("a")]

        result = Src().run_with_safety()
        assert isinstance(result, list)
        assert all(isinstance(a, Asset) for a in result)

    def test_state_persists_across_multiple_calls(self) -> None:
        """`last_run_outcome()` reflects the MOST RECENT call. A SUCCESS
        followed by an ERROR shows ERROR."""

        class Src(DiscoverySource):
            counter = 0

            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                Src.counter += 1
                if Src.counter > 1:
                    raise RuntimeError("subsequent calls fail")
                return [_make_asset("a")]

        src = Src()
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.ERROR

    def test_thread_safe_read_after_worker_resolves(self) -> None:
        """Decision 2: read from any thread that observes the
        completion of `run_with_safety`; future-resolution barrier
        establishes ordering. Pins the worker-thread read scenario."""

        class Src(DiscoverySource):
            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return [_make_asset("from-worker")]

        src = Src()
        outcomes: list[LastRunOutcome] = []

        def worker() -> None:
            src.run_with_safety()
            outcomes.append(src.last_run_outcome())

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=10)
        assert outcomes == [LastRunOutcome.SUCCESS]
