# DiscoverySource Contract (v0.2.2+)

**Status:** v1.0 — introduced in v0.2.2 P1.1 (`feat/v022-p1.1-discovery-source-interface`)
**Authoritative implementation:** `src/claude_monitoring/attack_surface/discovery/base.py`
**Contract ratification:** `~/Documents/vigil-notes/v022/phase-1/p1.1/architect-pass.md`
**Spec source:** `~/Documents/vigil-notes/v022-attack-surface-feature-spec-v1-LOCKED.md` §7

This document is the user-facing contract for the v0.2.2 attack-surface
discovery layer. The architect-pass document (linked above) is the locked
contract for the *implementation*; this doc is for downstream consumers
(Phase 1-3 PR authors registering concrete sources, the Phase 1.3
orchestrator implementer, and future Vigil contributors reading the
codebase).

---

## 1. Purpose

The attack-surface feature (v0.2.2 Phases 1-5) discovers AI tooling
installed on a developer's machine, maps it onto the Vigil ontology
(Phase 2), correlates it with CVE data (Phase 4), and presents it in the
dashboard (Phases 7-8). The discovery layer is the input boundary: every
asset Vigil knows about flows through a `DiscoverySource`.

P1.1 lands the *contract surface*: the `Asset` dataclass + the
`DiscoverySource` ABC + the `run_with_safety` orchestration entry point
+ the thread-safe timeout helper. Concrete sources (filesystem walks,
`ollama list`, PID enumeration, registry inspection, …) are registered
against this contract in Phases 1.2 onward.

---

## 2. The two artifacts

P1.1 ships exactly two public types:

| Type | File | Purpose |
|---|---|---|
| `Asset` | `src/claude_monitoring/attack_surface/asset.py` | The unit of discovery — the data record a source produces |
| `DiscoverySource` | `src/claude_monitoring/attack_surface/discovery/base.py` | The abstract base class every concrete source subclasses |

Plus one internal helper used only by `DiscoverySource`:

| Helper | File | Purpose |
|---|---|---|
| `_with_timeout` | `src/claude_monitoring/attack_surface/discovery/timeout.py` | Thread-safe wall-clock timeout for arbitrary callables |

---

## 3. The `Asset` dataclass

```python
@dataclass
class Asset:
    id: str
    type: str                       # 'ai_tool' | 'extension' | 'mcp_server' | 'integration' | 'dependency'
    parent_asset_id: Optional[str]  # None at the root of a tool tree
    name: str
    version: Optional[str]          # None when the source can't determine it
    install_path: Optional[str]     # None for non-filesystem assets
    source: str                     # name() of the producing source — non-empty
    current_state: dict             # JSON-serializable; empty dict allowed; None rejected
    discovered_at: float            # time.time() at discovery
    is_vigil_component: bool = False
```

### Contract invariants

1. **`current_state` is required.** Empty dict is allowed (some
   discovery types may produce an asset without inspectable state) but
   `None` is rejected. Persistence will `json.dumps` on write,
   `json.loads` on read (Phase 1.3 lands the adapter).

2. **`source` is required and non-empty after strip.** Enforced at the
   application boundary by `__post_init__` (the `assets.source` column
   is nullable in the P0.2 schema, so this dataclass guard is the
   permanent non-empty enforcement point).

3. **`version=None` is the only correct signal for "unresolvable."**
   Sources MUST NOT fabricate `"unknown"` strings — `None` is the
   "the source couldn't determine" sentinel.

4. **`discovered_at` is "this scan saw it"**, not "first-ever sighting."
   The persistence layer (Phase 1.3) uses it to populate `first_seen`,
   `last_seen`, and `last_scanned` per the locked drift-2 disposition:
   on insert all three columns are set from `discovered_at`; on
   re-observation `first_seen` is preserved by `ON CONFLICT`, only
   `last_seen` and `last_scanned` are updated.

5. **`is_vigil_component=True`** marks Vigil-internal components (daemon,
   extension, dashboard). These are de-prioritized in risk scoring and
   hidden in the default UI view.

6. **Orchestrator-owned columns are off-limits to sources.** The four
   columns `ontology_tags`, `risk_score`, `risk_band`, `risk_factors`
   live in the `assets` table but are NEVER populated by sources —
   they're filled in by Phase 2 (ontology engine + risk scoring).
   `Asset` does not even expose them; that's intentional.

### JSON `current_state` payloads

`current_state` is the discovery source's chance to record the asset's
inspectable configuration: permissions, scope, native config excerpt,
manifest fragments, anything JSON-serializable. The persistence layer
serializes via `json.dumps`. Examples:

```python
# A Chrome extension source might emit:
current_state = {
    "permissions": ["tabs", "storage", "<all_urls>"],
    "host_permissions": ["https://*/*"],
    "manifest_version": 3,
}

# A local-process source might emit:
current_state = {
    "pid": 12345,
    "executable_path": "/Applications/Claude.app/Contents/MacOS/Claude",
    "open_tcp_ports": [443, 9080],
}

# A source with no inspectable state is fine emitting:
current_state = {}
```

---

## 4. The `DiscoverySource` ABC

```python
class DiscoverySource(ABC):
    DEFAULT_TIMEOUT_SEC: float = 30
    MAX_ASSETS_PER_SOURCE: int = 1000
    MAX_FILE_SIZE_MB: int = 10
    MAX_TRAVERSAL_DEPTH: int = 10

    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def requires_auth(self) -> bool: ...

    @abstractmethod
    def discover(self) -> list[Asset]: ...

    def run_with_safety(self) -> list[Asset]: ...
```

### The three abstract methods

| Method | Returns | Contract |
|---|---|---|
| `name()` | `str` | Stable, unique source identifier. Convention: lowercase, hyphen-separated. Used as `Asset.source` for every asset this source produces and as the orchestrator's telemetry key. |
| `requires_auth()` | `bool` | `True` iff the source needs credentials (API key, OAuth token, session cookie). The orchestrator uses this to skip auth-required sources on unauthenticated scans. Phase 1 sources all return `False`. |
| `discover()` | `list[Asset]` | Enumerate assets. May raise. May exceed `MAX_ASSETS_PER_SOURCE`. May exceed `DEFAULT_TIMEOUT_SEC`. `run_with_safety` handles all three. |

### The four class constants

| Constant | Default | Who enforces |
|---|---|---|
| `DEFAULT_TIMEOUT_SEC` | `30` | `run_with_safety` (universal) |
| `MAX_ASSETS_PER_SOURCE` | `1000` | `run_with_safety` (universal) |
| `MAX_FILE_SIZE_MB` | `10` | Subclass self-enforces (advisory) |
| `MAX_TRAVERSAL_DEPTH` | `10` | Subclass self-enforces (advisory) |

Subclass overrides leave the base class untouched. The two **advisory**
caps (`MAX_FILE_SIZE_MB`, `MAX_TRAVERSAL_DEPTH`) are advertised but NOT
policed by the wrapper — sources that read manifest files or walk
directories MUST self-enforce, because the things they bound (file
reads, traversal walks) are implementation-internal.

### `run_with_safety()` — the orchestrator-facing contract

`run_with_safety` is the **only** method the orchestrator (P1.3) calls
in production code paths. It provides three guarantees, in order:

1. **Wall-clock timeout** — `discover()` is wrapped with a
   `DEFAULT_TIMEOUT_SEC` budget. Exceeded → empty list. The hung
   worker thread is abandoned (documented limitation; see §6).
2. **Universal exception swallow** — ANY uncaught `Exception` subclass
   from `discover()` is logged and converted to an empty list. Note:
   `BaseException`-only subclasses (`KeyboardInterrupt`, `SystemExit`,
   `GeneratorExit`) are intentionally **not** swallowed and propagate
   unchanged — a source raising one of those is a shutdown signal, not
   a discovery failure.
3. **Cap enforcement** — results are sliced to
   `MAX_ASSETS_PER_SOURCE`. Order is preserved (earliest discovered
   assets win) so truncation is deterministic and debuggable.

The empty-list-on-failure pattern is the **universal failure signal**
contract: orchestrator code that branches on "did this source produce
anything?" sees the same answer for "timed out," "crashed," and
"genuinely found nothing." Forcing the orchestrator to distinguish
between failure modes is intentional non-goal — that information is
in the logs.

---

## 5. Registering a new source — the minimum example

```python
from claude_monitoring.attack_surface import Asset, DiscoverySource
import time

class OllamaListSource(DiscoverySource):
    """Discover locally-installed Ollama models via `ollama list`."""

    def name(self) -> str:
        return "ollama-list"

    def requires_auth(self) -> bool:
        return False  # ollama binary is local

    def discover(self) -> list[Asset]:
        # Real impl: subprocess.run(["ollama", "list"], ...)
        # Per CLAUDE.md: argv list, never shell=True.
        return [
            Asset(
                id="ollama-llama3",
                type="ai_tool",
                parent_asset_id=None,
                name="llama3:8b",
                version="8b",
                install_path="~/.ollama/models/...",
                source=self.name(),
                current_state={"size_bytes": 4_700_000_000},
                discovered_at=time.time(),
            ),
        ]
```

The orchestrator (P1.3) instantiates the source, calls
`run_with_safety()`, and persists the resulting assets to the `assets`
table.

---

## 6. Thread-safety and the timeout decision

`run_with_safety` is safe to call from worker threads. The orchestrator
(P1.3) parallelizes source execution across a thread pool; if
`run_with_safety` weren't thread-safe, the whole orchestration model
would break.

The thread-safety property is load-bearing on the **choice of timeout
mechanism**. The architect-pass §4 locked decision is
`concurrent.futures.ThreadPoolExecutor`, NOT `signal.alarm`. Rationale:

> `signal.alarm` and `signal.signal` are **main-thread only** in CPython.
> They raise `ValueError: signal only works in main thread` when called
> from any non-main thread. The orchestrator calls `run_with_safety`
> from worker threads, so a signal-based timeout would crash on every
> call.

### Known limitation

A thread-based timeout returns control to the caller after
`timeout_sec` elapses but **cannot force-kill a hung function**. If a
`discover()` implementation hangs in a CPU loop or a blocking I/O call
without its own timeout, the worker thread keeps running until the OS
reaps the process. Subsequent `run_with_safety` calls work fine (each
gets a fresh executor); the hung thread just accumulates in process
memory.

For genuinely hard-hang-prone sources, the architect-pass §8 forward-
extension plan (subprocess isolation) is the only true interrupt. P1.1
does not ship subprocess timeouts — the discovery sources in scope for
Phase 1 (EASY tier — directory listing, `ollama list`, PID enumeration)
have well-bounded runtimes.

---

## 7. The four locked drifts (Asset ↔ `assets` row)

The `Asset` dataclass and the `assets` DB table (P0.2 schema) are
*near* parity, with four documented drifts handled by the persistence
adapter (lands in P1.3, not P1.1):

| # | Drift | Disposition |
|---|---|---|
| 1 | `assets.source` is nullable in DDL; dataclass requires non-empty | Dataclass `__post_init__` guard is the permanent non-empty enforcement point. Persistence layer also rejects empty strings before INSERT. |
| 2 | DDL has separate `first_seen` / `last_seen` / `last_scanned`; dataclass has only `discovered_at` | Insert-time values lock: first INSERT sets all three from `discovered_at`. Re-observation preserves `first_seen` via `ON CONFLICT`; updates only `last_seen` and `last_scanned`. |
| 3 | DDL has `ontology_tags` / `risk_score` / `risk_band` / `risk_factors` columns; dataclass does not expose them | Orchestrator-owned; sources never see them. Phase 2 (ontology engine + risk scoring) is the only writer. |
| 4 | DDL stores `is_vigil_component` as `INTEGER` (0/1); dataclass uses `bool` | Persistence layer applies a `bool ↔ INTEGER 0/1` adapter at write/read time. |

All four drift dispositions are ratified in architect-pass §3 and land
in the P1.3 persistence layer. P1.1 does not ship persistence — only
the in-memory contract.

---

## 8. Forward-extension plan (not in P1.1)

The architect-pass §8 documents three future-extension points kept
out of P1.1 scope:

- **C.1 `AuthRequirement` value object** — replaces the boolean
  `requires_auth()` with a structured `{kind, scopes, redactor}` record
  when a real auth-required source lands. Serializable; uses a redactor
  registry so secrets never enter logs.
- **C.2 `AsyncDiscoverySource`** — a parallel async ABC for sources
  that do many network I/O calls. Sync bridge for non-loop callers only;
  the orchestrator picks the variant per source.
- **C.3 `discover_partial()`** — a streaming variant for sources that
  produce assets incrementally, with a cumulative MAX cap so partial
  results aren't a cap-bypass.

None of these block P1.2 onward; they're forward compatibility scaffolding
ratified during the P1.1 contract design so the eventual extension is a
straight subclass, not a breaking change.

---

## 9. Where things live

- `src/claude_monitoring/attack_surface/__init__.py` — re-exports `Asset`
  and `DiscoverySource`
- `src/claude_monitoring/attack_surface/asset.py` — `Asset` dataclass
- `src/claude_monitoring/attack_surface/discovery/__init__.py` —
  re-exports `DiscoverySource`
- `src/claude_monitoring/attack_surface/discovery/base.py` —
  `DiscoverySource` ABC + `run_with_safety`
- `src/claude_monitoring/attack_surface/discovery/timeout.py` —
  thread-safe `_with_timeout` helper
- `tests/test_p1_1_discovery_source.py` — 16-test contract suite
