"""Collector Protocol — placeholder.

A Collector captures events from an external source (JSONL session
file, mitmproxy flow, browser-extension push) and normalizes them
into the project's event schema.

This Protocol is intentionally a placeholder. It will be defined
when the collector layer is unified (currently scattered across
``JSONLSessionWatcher``, ``BrowserIngest`` handlers, and the
``mitmproxy`` addon). Once unified, this module will define:

    class Collector(Protocol):
        name: str
        def start(self) -> None: ...
        def stop(self) -> None: ...
        def health_check(self) -> CollectorHealth: ...

Adding it now requires reshaping the three existing call sites,
which belongs to a Phase 3F refactor, not this PR.

Until then, this module exists so the architect-reviewer agent
can reference the planned Protocol when reviewing collector-adjacent
changes and ask "should this conform to the upcoming Collector
contract?"
"""

from __future__ import annotations
