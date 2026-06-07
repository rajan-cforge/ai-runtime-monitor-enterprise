"""Ontology — per-spec §5 category vocabulary and per-source mapping.

P2.0 lands:

- :mod:`categories` — the 10 ontology categories (spec §5.2) and the
  BASE / DERIVED partition (spec §5.4).
- :mod:`mapping` — per-source mapping registry. Six mappers for the
  six merged Phase-1 sources; identity-only sources legitimately
  return ``frozenset()`` per the Q5 structural-completeness
  ratification (2026-06-06).

Phase-2 follow-ups:

- **P2.1** — MCP scored multi-signal mapping (directive §7.3.2).
  Lives in :mod:`mapping` alongside the simple keyword map but
  ships in its own PR per Q4 ratification.
- **P2.2** — :mod:`derived` for ``data_exfiltration_capable``
  computed from the base tag set (spec §5.4).
"""

from __future__ import annotations
