"""P1.3 File 1 — TestLastRunOutcomeContract (C4-attention).

12 tests pinning the merged P1.2 `LastRunOutcome` contract per Rajan's
2026-06-05 reconciliation. Tests 1, 2, 9, 11 reconciled against the
merged 5-value enum (NOT the original 4-value+None stale draft); test 12
pins the §8 str-mixin amendment for JSON serialization.

**Read discipline locked here:** `outcome.value` (NEVER `str(member)`)
per the version-independence note in the LastRunOutcome docstring.
"""

from __future__ import annotations

import inspect
import json
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


# ---------------------------------------------------------------------------
# File 1 — TestLastRunOutcomeContract (12 tests, reconciled per 2026-06-05)
# ---------------------------------------------------------------------------


class TestLastRunOutcomeContract:
    def test_last_run_outcome_enum_has_five_values_including_uncalled(self) -> None:
        """Test 1 RECONCILED — merged P1.2 contract has 5 values incl UNCALLED."""
        assert {m.name for m in LastRunOutcome} == {
            "UNCALLED",
            "SUCCESS",
            "TIMEOUT",
            "ERROR",
            "CAPPED",
        }
        # §8 amendment: str-mixin enum (JSON-friendly via outcome.value).
        assert issubclass(LastRunOutcome, str)

    def test_last_run_outcome_initial_state_is_uncalled(self) -> None:
        """Test 2 RECONCILED — pre-call returns UNCALLED, NOT None.
        Non-optional return is the merged contract; UNCALLED is the
        auditable "registered-but-never-ran" state."""

        class Src(DiscoverySource):
            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return []

        src = Src()
        assert src.last_run_outcome() == LastRunOutcome.UNCALLED
        assert src.last_run_outcome() is not None

    def test_last_run_outcome_after_happy_path_is_success(self) -> None:
        """Test 3 — clean discover with assets → SUCCESS."""

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

    def test_last_run_outcome_after_timeout_is_timeout(self) -> None:
        """Test 4 — discover exceeds DEFAULT_TIMEOUT_SEC → TIMEOUT."""

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

    def test_last_run_outcome_after_generic_exception_is_error(self) -> None:
        """Test 5 — uncaught Exception → ERROR."""

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

    def test_last_run_outcome_after_cap_truncation_is_capped(self) -> None:
        """Test 6 — discover returned MAX_ASSETS_PER_SOURCE+1 → CAPPED."""

        class Src(DiscoverySource):
            MAX_ASSETS_PER_SOURCE = 3

            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return [_make_asset(str(i)) for i in range(10)]

        src = Src()
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.CAPPED

    def test_last_run_outcome_at_exactly_cap_is_success(self) -> None:
        """Test 7 — boundary: exactly MAX_ASSETS_PER_SOURCE → SUCCESS.
        CAPPED only fires when we actually dropped at least one asset."""

        class Src(DiscoverySource):
            MAX_ASSETS_PER_SOURCE = 3

            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return [_make_asset(str(i)) for i in range(3)]

        src = Src()
        src.run_with_safety()
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_last_run_outcome_run_with_safety_return_type_unchanged(self) -> None:
        """Test 8 — run_with_safety still returns list[Asset]. Pins
        Decision 2: universal empty-list signal stays intact."""
        sig = inspect.signature(DiscoverySource.run_with_safety)
        ann = sig.return_annotation
        # post-`from __future__ import annotations` — annotation is the string form
        assert "list[Asset]" in str(ann) or ann is list

    def test_last_run_outcome_set_after_discover_returns_not_before(self) -> None:
        """Test 9 RECONCILED — during-call read returns UNCALLED, NOT None.
        The write happens after the call resolves; the during-call read
        sees the class-default UNCALLED."""
        stashed: list[LastRunOutcome] = []

        class Src(DiscoverySource):
            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                # While discover is running, read our own outcome —
                # state hasn't been written yet (write happens after
                # _with_timeout returns).
                stashed.append(self.last_run_outcome())
                return [_make_asset("a")]

        src = Src()
        src.run_with_safety()
        assert stashed == [LastRunOutcome.UNCALLED]
        # After the call: SUCCESS
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_last_run_outcome_readable_from_other_thread_after_future_resolves(self) -> None:
        """Test 10 — main thread reads outcome AFTER worker's
        run_with_safety completes. Thread-safety via future-resolution
        happens-before; no threading.Lock needed."""

        class Src(DiscoverySource):
            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                return [_make_asset("from-worker")]

        src = Src()
        result: list[LastRunOutcome] = []

        def worker() -> None:
            src.run_with_safety()
            result.append(src.last_run_outcome())

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join(timeout=10)
        assert result == [LastRunOutcome.SUCCESS]
        # Main thread can also read the same value post-join
        assert src.last_run_outcome() == LastRunOutcome.SUCCESS

    def test_last_run_outcome_baseexception_propagates_and_does_not_set(self) -> None:
        """Test 11 RECONCILED — BaseException propagates; outcome remains
        UNCALLED (NOT None) on first call. Pins: write never executes
        because BaseException is intentionally not swallowed."""
        import pytest

        class Src(DiscoverySource):
            def name(self) -> str:
                return "x"

            def requires_auth(self) -> bool:
                return False

            def discover(self) -> list[Asset]:
                raise KeyboardInterrupt("user pressed Ctrl-C")

        src = Src()
        with pytest.raises(KeyboardInterrupt):
            src.run_with_safety()
        # Outcome remains UNCALLED — the write path never executed.
        assert src.last_run_outcome() == LastRunOutcome.UNCALLED

    def test_last_run_outcome_value_is_json_serializable_via_str_mixin(self) -> None:
        """Test 12 NEW — §8 amendment pin: json.dumps(member) serializes
        directly to the lowercase value string via str-mixin. P1.5 audit
        can use either `outcome.value` or `json.dumps(outcome)` without a
        mapping layer.

        **Read discipline locked**: use `outcome.value`, NEVER `str(member)`
        — `str()` returns the enum repr on Python 3.10/3.11 (only 3.12+
        returns the value)."""
        for outcome in LastRunOutcome:
            # json.dumps direct works via str-mixin
            assert json.dumps(outcome) == f'"{outcome.value}"', (
                f"json.dumps({outcome.name}) regression — str-mixin broken?"
            )
            # outcome.value is the canonical read form
            assert isinstance(outcome.value, str)
            assert outcome.value == outcome.name.lower()
            # Equality with bare string (str-mixin semantics)
            assert outcome == outcome.value
