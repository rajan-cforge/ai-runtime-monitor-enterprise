"""P2.2 — Derived ontology signals + extensible derivation registry.

**Spec §5.4 formula (verbatim):**

    data_exfiltration_capable =
        (secrets_access OR file_system_read)
        AND
        (network_unrestricted OR network_scoped)

Pure function over ``frozenset[OntologyCategory]``. No
``current_state`` introspection, no env/args inspection — a Boolean
over the already-computed base tag set.

**Rajan steer 2026-06-07 (verbatim):** "the thing to get right is
that it composes from the base tags exactly per the spec formula
and never short-circuits to a default."

The test contract pins both:

1. **Spec-formula exactness.** All 16 boolean combinations across
   the four input flags are exercised. The function's truth-table
   matches the spec verbatim.
2. **No short-circuit default.** The function never silently returns
   False on missing input or a typing oddity — it computes the
   formula on whatever set it was given. A test using ``frozenset()``
   confirms the formula evaluates to False (correctly), NOT a
   "I don't know" default.

Extensibility: a derived-rule registry shape supports future
additions (e.g., a hypothetical ``privilege_escalation_capable =
code_execution AND system_modification``) without restructuring.
P2.2 ships exactly one rule per spec §5.4.

**Spec §6.5 edge-case property pinned:** "Asset with
`data_exfiltration_capable` derived tag: Permission breadth gets +1
category counted." This falls out automatically as long as the
derived tag is added to ``ontology_tags`` BEFORE downstream
permission_breadth computation (P2.3). The test pins that
``apply_derived`` returns the UNION, not just the derived overlay.
"""

from __future__ import annotations

from itertools import product

import pytest

from claude_monitoring.attack_surface.ontology.categories import (
    DERIVED_CATEGORIES,
    OntologyCategory,
)
from claude_monitoring.attack_surface.ontology.derived import (
    DERIVED_RULES,
    apply_derived,
    derive_data_exfiltration_capable,
)

# ---------------------------------------------------------------------------
# data_exfiltration_capable — truth table per spec §5.4
# ---------------------------------------------------------------------------


class TestDataExfiltrationCapableFormula:
    """Exercise all 16 boolean combinations of the four input flags."""

    @pytest.mark.parametrize(
        "secrets_access,file_system_read,network_unrestricted,network_scoped",
        list(product([False, True], repeat=4)),
    )
    def test_truth_table_matches_spec(
        self,
        secrets_access: bool,
        file_system_read: bool,
        network_unrestricted: bool,
        network_scoped: bool,
    ) -> None:
        """Spec §5.4: ``(secrets_access OR file_system_read) AND
        (network_unrestricted OR network_scoped)``. The function must
        match this exactly across all 16 input combinations."""
        tags: set[OntologyCategory] = set()
        if secrets_access:
            tags.add(OntologyCategory.SECRETS_ACCESS)
        if file_system_read:
            tags.add(OntologyCategory.FILE_SYSTEM_READ)
        if network_unrestricted:
            tags.add(OntologyCategory.NETWORK_UNRESTRICTED)
        if network_scoped:
            tags.add(OntologyCategory.NETWORK_SCOPED)
        expected = (secrets_access or file_system_read) and (network_unrestricted or network_scoped)
        actual = derive_data_exfiltration_capable(frozenset(tags))
        assert actual is expected, (
            f"truth-table mismatch: secrets={secrets_access}, fs_read={file_system_read}, "
            f"net_unrestricted={network_unrestricted}, net_scoped={network_scoped}: "
            f"expected {expected}, got {actual}"
        )


class TestNoShortCircuitDefault:
    """The function never silently returns a default — it computes the
    formula on whatever set it was given."""

    def test_empty_input_returns_false_not_undefined(self) -> None:
        """``frozenset()`` is a valid input; the formula evaluates to
        ``False`` (both disjuncts are False, AND short-circuits). The
        function returns ``False`` — never ``None``, never raises, never
        a "don't know" sentinel."""
        result = derive_data_exfiltration_capable(frozenset())
        assert result is False

    def test_input_with_only_unrelated_tags_returns_false(self) -> None:
        """A set containing ``shell_execute`` and ``code_execution``
        (neither side of the formula) → ``False``. The function does NOT
        skip computation."""
        result = derive_data_exfiltration_capable(
            frozenset({OntologyCategory.SHELL_EXECUTE, OntologyCategory.CODE_EXECUTION})
        )
        assert result is False

    def test_input_with_only_secrets_no_network_returns_false(self) -> None:
        """Half the formula true (secrets_access) but no network side → False.
        The function does NOT default to True on the presence of any risky
        tag — it computes both disjuncts."""
        result = derive_data_exfiltration_capable(frozenset({OntologyCategory.SECRETS_ACCESS}))
        assert result is False

    def test_input_with_only_network_no_secrets_or_fs_returns_false(self) -> None:
        result = derive_data_exfiltration_capable(frozenset({OntologyCategory.NETWORK_UNRESTRICTED}))
        assert result is False


class TestReturnContract:
    def test_returns_bool_not_truthy_thing(self) -> None:
        """Must be a plain ``bool``, not ``None``/``0``/``""``/some sentinel.
        Pin so downstream callers don't accidentally rely on truthy-vs-falsy
        instead of identity."""
        result = derive_data_exfiltration_capable(
            frozenset({OntologyCategory.SECRETS_ACCESS, OntologyCategory.NETWORK_UNRESTRICTED})
        )
        assert result is True
        assert isinstance(result, bool)

    def test_does_not_mutate_input_set(self) -> None:
        """The input frozenset is immutable, but pin that the function
        does not return a different aliased set or otherwise side-effect."""
        input_set = frozenset({OntologyCategory.SECRETS_ACCESS, OntologyCategory.NETWORK_UNRESTRICTED})
        snapshot = frozenset(input_set)
        derive_data_exfiltration_capable(input_set)
        assert input_set == snapshot


# ---------------------------------------------------------------------------
# Extensible registry — DERIVED_RULES
# ---------------------------------------------------------------------------


class TestDerivedRulesRegistry:
    """P2.2 ships exactly one derived rule (per spec §5.4). The registry
    shape supports future additions without restructuring."""

    def test_registry_contains_data_exfiltration_capable_rule(self) -> None:
        assert OntologyCategory.DATA_EXFILTRATION_CAPABLE in DERIVED_RULES

    def test_registry_has_exactly_one_rule_in_v022(self) -> None:
        """Spec §5.4 names exactly one derived category. P2.0 declared
        ``DERIVED_CATEGORIES = {DATA_EXFILTRATION_CAPABLE}`` to pin this.
        The registry must agree."""
        assert len(DERIVED_RULES) == 1

    def test_registry_keys_match_derived_categories_set(self) -> None:
        """The registry's key set must exactly equal the DERIVED_CATEGORIES
        partition from categories.py. Drift in either direction breaks the
        Phase 2 contract."""
        assert set(DERIVED_RULES.keys()) == DERIVED_CATEGORIES

    def test_registry_values_are_callables(self) -> None:
        for cat, rule in DERIVED_RULES.items():
            assert callable(rule), f"{cat.value!r} rule is not callable"

    def test_load_time_invariant_holds(self) -> None:
        """The derived module asserts at import time that
        ``set(DERIVED_RULES) == DERIVED_CATEGORIES``. If this test runs at
        all, the import succeeded, which means the assertion held. This
        test exists as documentation that the load-time check is part of
        the contract — a future refactor that removes it should fail this
        test by removing the test along with the check."""
        from claude_monitoring.attack_surface.ontology import derived as derived_mod

        source = open(derived_mod.__file__).read()
        # The exact assertion string the load-time check uses
        assert "if set(DERIVED_RULES) != DERIVED_CATEGORIES:" in source, (
            "load-time invariant removed; rule-registry / category-partition drift now silent"
        )


# ---------------------------------------------------------------------------
# apply_derived — runs all derived rules and returns the union
# ---------------------------------------------------------------------------


class TestApplyDerived:
    """``apply_derived`` runs every registered rule over the base tag set
    and returns the union (base ∪ any-derived-that-fired). This is the
    orchestrator-facing entry point — runs once over the union of all
    per-source tags AFTER per-source mapping completes."""

    def test_adds_data_exfiltration_capable_when_formula_satisfied(self) -> None:
        base = frozenset({OntologyCategory.SECRETS_ACCESS, OntologyCategory.NETWORK_UNRESTRICTED})
        result = apply_derived(base)
        assert OntologyCategory.DATA_EXFILTRATION_CAPABLE in result
        # Base tags preserved
        assert OntologyCategory.SECRETS_ACCESS in result
        assert OntologyCategory.NETWORK_UNRESTRICTED in result

    def test_does_not_add_when_formula_not_satisfied(self) -> None:
        base = frozenset({OntologyCategory.SECRETS_ACCESS})
        result = apply_derived(base)
        assert OntologyCategory.DATA_EXFILTRATION_CAPABLE not in result
        assert result == base

    def test_returns_frozenset(self) -> None:
        result = apply_derived(frozenset())
        assert isinstance(result, frozenset)

    def test_empty_base_returns_empty(self) -> None:
        """No base tags + no formula satisfied → empty output. Pin so a
        future bug that silently emits derived tags on empty input fails."""
        result = apply_derived(frozenset())
        assert result == frozenset()

    def test_preserves_unrelated_tags(self) -> None:
        """Tags outside the formula's input domain (e.g., shell_execute)
        must pass through unchanged."""
        base = frozenset(
            {
                OntologyCategory.SHELL_EXECUTE,
                OntologyCategory.CODE_EXECUTION,
                OntologyCategory.SECRETS_ACCESS,
                OntologyCategory.NETWORK_UNRESTRICTED,
            }
        )
        result = apply_derived(base)
        assert OntologyCategory.SHELL_EXECUTE in result
        assert OntologyCategory.CODE_EXECUTION in result
        # And the derived tag is added
        assert OntologyCategory.DATA_EXFILTRATION_CAPABLE in result

    def test_idempotent(self) -> None:
        """Running apply_derived twice produces the same result. Important
        because the orchestrator might re-run derivation as the union of
        per-source tags is recomputed."""
        base = frozenset({OntologyCategory.FILE_SYSTEM_READ, OntologyCategory.NETWORK_SCOPED})
        once = apply_derived(base)
        twice = apply_derived(once)
        assert once == twice


# ---------------------------------------------------------------------------
# Spec §6.5 edge case — permission_breadth +1
# ---------------------------------------------------------------------------


class TestSpec_6_5_PermissionBreadthCountsDerivedTag:
    """Spec §6.5: 'Asset with `data_exfiltration_capable` derived tag:
    Permission breadth gets +1 category counted.'

    The Phase A analysis noted this falls out automatically if
    apply_derived adds the tag to the set BEFORE permission_breadth
    computes. This test pins the precondition: the derived tag lands in
    the SAME frozenset the downstream P2.3 scorer will count.
    """

    def test_derived_tag_in_result_increments_len_by_one(self) -> None:
        """When the formula fires, len(result) == len(base) + 1 (assuming
        no derived tag was already present, which mappers structurally
        cannot emit — pinned by P2.0's TestMapperReturnContract)."""
        base = frozenset(
            {
                OntologyCategory.SECRETS_ACCESS,
                OntologyCategory.NETWORK_UNRESTRICTED,
            }
        )
        result = apply_derived(base)
        assert len(result) == len(base) + 1


# ---------------------------------------------------------------------------
# Cross-cutting: never emits non-derived categories
# ---------------------------------------------------------------------------


class TestNeverEmitsNonDerivedCategories:
    """apply_derived never adds a BASE category that wasn't already in the
    input set — only DERIVED categories are introduced."""

    def test_only_derived_categories_added(self) -> None:
        from claude_monitoring.attack_surface.ontology.categories import (
            BASE_CATEGORIES,
        )

        base = frozenset({OntologyCategory.SECRETS_ACCESS, OntologyCategory.NETWORK_UNRESTRICTED})
        result = apply_derived(base)
        added = result - base
        # Everything added must be a DERIVED category
        assert added.issubset(DERIVED_CATEGORIES)
        # And specifically, no BASE category was added
        assert not (added & BASE_CATEGORIES)
