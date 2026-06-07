"""Derived ontology signals — spec §5.4.

A DERIVED ontology category is one computed from the BASE tag set,
not mapped per-source. Spec §5.4 names exactly one in v0.2.2:

    data_exfiltration_capable =
        (secrets_access OR file_system_read)
        AND
        (network_unrestricted OR network_scoped)

Per-source mappers (P2.0 + P2.1) emit only BASE categories. The
orchestrator runs :func:`apply_derived` once over the union of all
per-source tags AFTER per-source mapping completes — derivation is
its own pass, not inline per-source.

**Design (Phase A §2 + Rajan 2026-06-07 steer):** the derivation
registry shape supports future derived signals (e.g., a hypothetical
``privilege_escalation_capable = code_execution AND
system_modification``) without restructuring. P2.2 ships exactly one
rule per spec §5.4 — the registry is not gold-plated, just
extensible.

**The thing to get right (Rajan, P2.1 review):** the formula
composes from the base tags exactly per the spec, and the function
never short-circuits to a default. ``frozenset()`` input is valid
and evaluates to ``False`` per the formula — NOT a "don't know"
sentinel.

**Spec §6.5 edge-case property:** "Asset with
``data_exfiltration_capable`` derived tag: Permission breadth gets
+1 category counted." This falls out automatically as long as the
derived tag is added to ``ontology_tags`` BEFORE downstream
``permission_breadth`` computation (P2.3). :func:`apply_derived`
returns the UNION, so the +1 is structurally guaranteed.
"""

from __future__ import annotations

from collections.abc import Callable

from claude_monitoring.attack_surface.ontology.categories import (
    DERIVED_CATEGORIES,
    OntologyCategory,
)


def derive_data_exfiltration_capable(tags: frozenset[OntologyCategory]) -> bool:
    """Spec §5.4 verbatim formula.

    Args:
        tags: Frozenset of BASE ontology categories already mapped by
            per-source rules. The function is pure — no side effects
            on the input set.

    Returns:
        ``True`` iff ``(secrets_access OR file_system_read) AND
        (network_unrestricted OR network_scoped)``. Returns ``False``
        on empty input and on inputs containing only unrelated tags;
        never returns ``None`` or raises.
    """
    has_secret_source = OntologyCategory.SECRETS_ACCESS in tags or OntologyCategory.FILE_SYSTEM_READ in tags
    has_network_exit = OntologyCategory.NETWORK_UNRESTRICTED in tags or OntologyCategory.NETWORK_SCOPED in tags
    return has_secret_source and has_network_exit


DERIVED_RULES: dict[OntologyCategory, Callable[[frozenset[OntologyCategory]], bool]] = {
    OntologyCategory.DATA_EXFILTRATION_CAPABLE: derive_data_exfiltration_capable,
}
"""Extensible registry: derived category → predicate over the base tag set.

P2.2 ships exactly one entry per spec §5.4. The registry's key set
MUST equal :data:`DERIVED_CATEGORIES` (pinned both at module-load
time and by ``test_registry_keys_match_derived_categories_set``) —
drift in either direction breaks the Phase 2 contract.

Future derived signals (Phase 3+ may add e.g.
``privilege_escalation_capable``) drop into this dict without
restructuring :func:`apply_derived` or any caller."""


# Module-load invariant — fail loudly at import time if the registry
# drifts from the declared DERIVED_CATEGORIES partition. The runtime
# check pairs with the test-time check for belt-and-suspenders.
if set(DERIVED_RULES) != DERIVED_CATEGORIES:
    raise RuntimeError(
        f"DERIVED_RULES keys {sorted(c.value for c in DERIVED_RULES)} "
        f"do not match DERIVED_CATEGORIES {sorted(c.value for c in DERIVED_CATEGORIES)}; "
        "Phase 2 derivation contract violated — see ontology/categories.py and ontology/derived.py."
    )


def apply_derived(base_tags: frozenset[OntologyCategory]) -> frozenset[OntologyCategory]:
    """Run every registered derived rule over ``base_tags``; return the
    union of base ∪ any derived tag whose predicate fired.

    The orchestrator-facing entry point. Called ONCE over the union of
    all per-source tags after per-source mapping completes — derivation
    is its own pass, not inline per-source (Phase A §2 design).

    Args:
        base_tags: The union of all per-source-mapped BASE categories
            for a single asset.

    Returns:
        Frozenset containing the input ``base_tags`` plus every derived
        category whose predicate evaluated ``True``.

    Properties pinned by tests:

    - **Idempotent**: ``apply_derived(apply_derived(x)) == apply_derived(x)``.
    - **Additive**: never removes a base tag, never adds a non-derived tag.
    - **Empty-safe**: ``apply_derived(frozenset()) == frozenset()``.
    """
    additions: set[OntologyCategory] = set()
    for derived_cat, rule in DERIVED_RULES.items():
        if rule(base_tags):
            additions.add(derived_cat)
    if not additions:
        return base_tags
    return base_tags | additions


__all__ = [
    "DERIVED_RULES",
    "apply_derived",
    "derive_data_exfiltration_capable",
]
