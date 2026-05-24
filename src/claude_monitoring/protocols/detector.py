"""Detector Protocol — placeholder.

A Detector inspects a single event (or a stream of events) for
patterns of interest: sensitive-data leakage, supply-chain risk,
prompt-injection attempts, etc.

This Protocol is intentionally a placeholder. The current detector
surface lives across ``sensitive.py``, ``supply_chain.py``,
``threat_intel.py``, and ``vuln_scanner.py`` with subtly different
shapes. Once unified, this module will define:

    class Detector(Protocol):
        name: str
        def detect(self, event: Event) -> list[Finding]: ...
        def health_check(self) -> DetectorHealth: ...

Unifying those four modules belongs to a Phase 3F refactor, not
this PR.

Until then, this module exists so the architect-reviewer agent
can reference the planned Protocol when reviewing detector-adjacent
changes and ask "should this conform to the upcoming Detector
contract?"
"""

from __future__ import annotations
