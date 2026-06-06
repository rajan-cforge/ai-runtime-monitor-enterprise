"""P2.0 — `OntologyCategory` enum + module-level category sets.

Per spec §5.2 the 10 starting ontology categories. Per spec §5.4 exactly
one category (`data_exfiltration_capable`) is DERIVED — computed from
other tags rather than mapped per-source. P2.0 declares the categories
and the BASE/DERIVED partition; P2.2 lands the derivation logic.
"""

from __future__ import annotations

import enum

from claude_monitoring.attack_surface.ontology.categories import (
    BASE_CATEGORIES,
    CATEGORIES,
    DERIVED_CATEGORIES,
    OntologyCategory,
)

# Spec §5.2 — locked vocabulary
_SPEC_CATEGORY_VALUES = {
    "file_system_read",
    "file_system_write",
    "shell_execute",
    "network_unrestricted",
    "network_scoped",
    "secrets_access",
    "code_execution",
    "data_exfiltration_capable",
    "system_modification",
    "inter_tool_communication",
}


class TestOntologyCategoryEnum:
    def test_exactly_ten_categories_per_spec_5_2(self) -> None:
        assert len(OntologyCategory) == 10

    def test_values_match_spec_5_2_vocabulary(self) -> None:
        observed = {member.value for member in OntologyCategory}
        assert observed == _SPEC_CATEGORY_VALUES

    def test_categories_frozenset_matches_enum(self) -> None:
        assert frozenset(OntologyCategory) == CATEGORIES

    def test_categories_is_frozenset(self) -> None:
        """Immutable so a mapper cannot accidentally mutate the global set."""
        assert isinstance(CATEGORIES, frozenset)

    def test_str_mixin_enables_direct_json_serialization(self) -> None:
        """OntologyCategory inherits from `str` so json.dumps(member)
        emits the exact lowercase value string, version-stable
        regardless of Python's 3.10/3.11 vs 3.12+ `str(member)` divergence
        (json.dumps takes the str-mixin path, not str())."""
        import json

        # Exact-match assertion (tightened per architect-pass M3):
        # str-mixin is the load-bearing property. A test that only checked
        # `"shell_execute" in encoded` would pass even if the mixin were
        # accidentally removed — this one would not.
        assert json.dumps(OntologyCategory.SHELL_EXECUTE) == '"shell_execute"'

    def test_str_mixin_class_inheritance(self) -> None:
        assert issubclass(OntologyCategory, str)
        assert issubclass(OntologyCategory, enum.Enum)


class TestDerivedVsBasePartition:
    def test_data_exfiltration_capable_is_derived(self) -> None:
        """Spec §5.4: `data_exfiltration_capable` is computed from
        other tags, not mapped per-source. P2.2 lands the derivation."""
        assert OntologyCategory.DATA_EXFILTRATION_CAPABLE in DERIVED_CATEGORIES

    def test_only_one_derived_category_in_v022(self) -> None:
        """Spec §5.4 names exactly one derived category. P2.0 ships only
        this one; the registry shape is extensible (P2.2 concern), but
        the enum constants land here."""
        assert frozenset({OntologyCategory.DATA_EXFILTRATION_CAPABLE}) == DERIVED_CATEGORIES

    def test_base_categories_are_complement_of_derived(self) -> None:
        assert BASE_CATEGORIES == CATEGORIES - DERIVED_CATEGORIES

    def test_base_plus_derived_equals_all(self) -> None:
        assert BASE_CATEGORIES | DERIVED_CATEGORIES == CATEGORIES

    def test_base_and_derived_are_disjoint(self) -> None:
        assert not (BASE_CATEGORIES & DERIVED_CATEGORIES)

    def test_base_categories_has_nine_members(self) -> None:
        assert len(BASE_CATEGORIES) == 9
