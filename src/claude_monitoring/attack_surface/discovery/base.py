"""DiscoverySource ABC — the contract every Phase 1-3 source implements.

Spec source: ``~/Documents/vigil-notes/v022-attack-surface-feature-spec-v1-LOCKED.md`` §7.2
Architect-pass ratification: ``~/Documents/vigil-notes/v022/phase-1/p1.1/architect-pass.md``

Subclasses implement three abstract methods (``name``, ``requires_auth``,
``discover``) and inherit :meth:`run_with_safety`, which the orchestrator
(P1.3) is the ONLY caller of in production code paths. Sources never
raise to the orchestrator — :meth:`run_with_safety` converts every failure
mode (timeout, uncaught exception, over-cap) into a graceful return so a
single bad source can never crash a scan.

Class constants (overridable per subclass; base values locked at P1.1):

- ``DEFAULT_TIMEOUT_SEC = 30`` — wall-clock budget for ``discover()``.
- ``MAX_ASSETS_PER_SOURCE = 1000`` — truncation cap to prevent memory
  blow-up from a runaway source.
- ``MAX_FILE_SIZE_MB = 10`` — advisory: sources that read manifest files
  (package.json, mcp-config.json) MUST self-enforce this.
- ``MAX_TRAVERSAL_DEPTH = 10`` — advisory: sources that walk directories
  MUST self-enforce this.

The two advisory caps are advertised but NOT enforced by
:meth:`run_with_safety` — they're per-source knobs because what they bound
(file reads, directory walks) is per-source-implementation. The two
enforced caps (timeout, max-assets) are universal and live in the wrapper.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from claude_monitoring.attack_surface.asset import Asset
from claude_monitoring.attack_surface.discovery.timeout import _with_timeout

logger = logging.getLogger("ai-runtime-monitor.attack_surface.discovery.base")


class DiscoverySource(ABC):
    """Abstract base class for v0.2.2 attack-surface discovery sources.

    Subclass contract:

    1. Override the three abstract methods. Concrete behaviour is the
       source's responsibility; the base class enforces no schema beyond
       return types.
    2. Optionally override any of the four class constants to tighten or
       loosen per-source limits. The base class values are the locked
       defaults; subclass overrides leave the base class untouched.
    3. Callers (the orchestrator in P1.3) invoke :meth:`run_with_safety`,
       never :meth:`discover` directly. ``run_with_safety`` is the trust
       boundary that converts any source-side failure into ``[]``.

    Thread-safety: :meth:`run_with_safety` is safe to call from worker
    threads. The timeout helper uses :mod:`concurrent.futures` (NOT
    :mod:`signal`), which is the locked decision per architect-pass §4 —
    ``signal.alarm`` only works on the main thread and would crash the
    orchestrator's worker-thread call path.
    """

    DEFAULT_TIMEOUT_SEC: float = 30
    """Wall-clock budget for ``discover()``. Exceeded → ``[]``."""

    MAX_ASSETS_PER_SOURCE: int = 1000
    """Truncation cap on the list returned by ``discover()``. Enforced by
    :meth:`run_with_safety` via list slicing (preserves order — earliest
    discovered assets are kept; trailing assets are dropped)."""

    MAX_FILE_SIZE_MB: int = 10
    """Advisory cap on any single file a source reads. Per-source
    implementations MUST self-enforce; the base class does not police
    file I/O."""

    MAX_TRAVERSAL_DEPTH: int = 10
    """Advisory cap on directory-traversal depth. Per-source
    implementations MUST self-enforce; the base class does not police
    filesystem walks."""

    @abstractmethod
    def name(self) -> str:
        """Stable, unique identifier for this source.

        Used as the ``Asset.source`` value for every asset this source
        produces, and as the log/metric key for orchestrator telemetry.
        Convention: lowercase, hyphen-separated (e.g. ``"ai-apps"``,
        ``"chrome-extensions"``, ``"npm-packages"``).
        """

    @abstractmethod
    def requires_auth(self) -> bool:
        """Whether this source needs credentials to operate.

        ``True`` if the source talks to an external API that needs an
        API key, OAuth token, or session cookie. The orchestrator uses
        this to skip auth-required sources on unauthenticated scans.
        Phase 1 sources (EASY tier — filesystem walks, ``ollama list``,
        PID enumeration) all return ``False``.
        """

    @abstractmethod
    def discover(self) -> list[Asset]:
        """Enumerate assets and return them.

        Implementations may raise. :meth:`run_with_safety` catches every
        exception and returns ``[]``. Implementations may also exceed
        :attr:`MAX_ASSETS_PER_SOURCE`; :meth:`run_with_safety` truncates.
        Implementations may exceed :attr:`DEFAULT_TIMEOUT_SEC`;
        :meth:`run_with_safety` aborts the call and returns ``[]``.
        """

    def run_with_safety(self) -> list[Asset]:
        """Invoke :meth:`discover` under the orchestrator-facing contract.

        Guarantees, in order:

        1. **Timeout**: ``discover()`` is wrapped with a
           :attr:`DEFAULT_TIMEOUT_SEC` wall-clock budget. Exceeded →
           empty list. The hung worker thread is abandoned (documented
           limitation of the thread-based timeout); subsequent calls
           still work.
        2. **Universal exception swallow**: ANY uncaught :class:`Exception`
           subclass from ``discover()`` is logged and converted to an
           empty list — the orchestrator never sees a source-raised
           :class:`Exception`. Note: :class:`BaseException`-only
           subclasses (:class:`KeyboardInterrupt`, :class:`SystemExit`,
           :class:`GeneratorExit`) are intentionally **not** swallowed
           and propagate unchanged. A source raising one of those is a
           shutdown signal, not a discovery failure.
        3. **Cap enforcement**: results are sliced to
           :attr:`MAX_ASSETS_PER_SOURCE`. Order is preserved (earliest
           discovered assets win) so the truncation is deterministic
           and debuggable.

        Returns:
            List of :class:`Asset`, length ≤ :attr:`MAX_ASSETS_PER_SOURCE`.
            Empty list on timeout or exception.
        """
        try:
            result = _with_timeout(self.discover, self.DEFAULT_TIMEOUT_SEC)
        except TimeoutError:
            logger.warning(
                "discovery source %s exceeded %ss timeout; returning empty result",
                self.name(),
                self.DEFAULT_TIMEOUT_SEC,
            )
            return []
        except Exception as exc:
            # Universal failure signal: sources never propagate to the
            # orchestrator. Log at WARNING — the orchestrator decides
            # whether absent results are a problem in aggregate.
            logger.warning(
                "discovery source %s raised %s: %s; returning empty result",
                self.name(),
                type(exc).__name__,
                exc,
            )
            return []
        return result[: self.MAX_ASSETS_PER_SOURCE]
