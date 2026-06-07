"""The 10 ontology categories — spec §5.2 locked vocabulary.

Per spec §5.4 exactly one category (``data_exfiltration_capable``)
is DERIVED — computed by :mod:`derived` from the base tag set. The
remaining 9 are BASE categories, each mapped per-source by entries
in :mod:`mapping`.

**str-mixin (matches `LastRunOutcome` + `Severity` precedent).**
``OntologyCategory`` inherits from ``str`` so ``json.dumps(member)``
serializes directly to the lowercase value string. Persistence
(P2.3 / future) stores ``member.value``; cross-version-safe via
``.value``, never ``str(member)``.

**Q1 + Q5 ratifications (2026-06-06):** an asset with zero tags is
legitimate (Q1 → INFO band). Every registered discovery source has a
mapping function but a function MAY return ``frozenset()`` (Q5
structural completeness, not functional).
"""

from __future__ import annotations

import enum


class OntologyCategory(str, enum.Enum):
    """The 10 spec §5.2 ontology categories.

    Read discipline: use ``member.value`` to obtain the lowercase
    string; ``str(member)`` returns the enum repr on Python 3.10/3.11
    and the value only on 3.12+.
    """

    FILE_SYSTEM_READ = "file_system_read"
    """Read files outside own data dir."""

    FILE_SYSTEM_WRITE = "file_system_write"
    """Write files outside own data dir."""

    SHELL_EXECUTE = "shell_execute"
    """Execute shell commands / subprocesses."""

    NETWORK_UNRESTRICTED = "network_unrestricted"
    """Network requests to arbitrary hosts."""

    NETWORK_SCOPED = "network_scoped"
    """Network requests to a declared host allow-list. Dormant in
    Phase 2 — no Phase-1 source declares scoped hosts."""

    SECRETS_ACCESS = "secrets_access"
    """Read credentials, tokens, cookies, or other named secrets."""

    CODE_EXECUTION = "code_execution"
    """Execute arbitrary code in the host AI agent's process."""

    DATA_EXFILTRATION_CAPABLE = "data_exfiltration_capable"
    """**DERIVED** (spec §5.4): ``(secrets_access OR file_system_read)
    AND (network_unrestricted OR network_scoped)``. Computed by
    :mod:`derived` from the base tag set; per-source mappers in
    :mod:`mapping` MUST NOT emit this tag directly."""

    SYSTEM_MODIFICATION = "system_modification"
    """Change system settings, install software, modify privileged
    state. Dormant in Phase 2 — no Phase-1 source declares system
    modification permissions."""

    INTER_TOOL_COMMUNICATION = "inter_tool_communication"
    """Talk to other AI tools / services. The MCP protocol is itself
    this category by definition; every discovered MCP server is
    tagged with this category."""


CATEGORIES: frozenset[OntologyCategory] = frozenset(OntologyCategory)
"""All 10 categories. Immutable so a downstream caller cannot
mutate the global set."""


DERIVED_CATEGORIES: frozenset[OntologyCategory] = frozenset({OntologyCategory.DATA_EXFILTRATION_CAPABLE})
"""Categories computed from other tags (spec §5.4). P2.0 ships
exactly one: ``data_exfiltration_capable``. The set is extensible
(future PRs may add derived signals) but no others are spec-named."""


BASE_CATEGORIES: frozenset[OntologyCategory] = CATEGORIES - DERIVED_CATEGORIES
"""The 9 per-source-mappable categories. Per-source mappers in
:mod:`mapping` may emit any subset of these; never the derived ones."""


__all__ = [
    "BASE_CATEGORIES",
    "CATEGORIES",
    "DERIVED_CATEGORIES",
    "OntologyCategory",
]
