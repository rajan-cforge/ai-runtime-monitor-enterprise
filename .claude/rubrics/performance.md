# Performance review rubric

Applied by `performance-reviewer` on every PR. The reviewer picks 3-5 highest-impact items — never enumerates the full list.

## Section A: Algorithmic complexity

- No O(n²) loops where O(n log n) or O(n) is achievable
- Repeated work outside the loop where possible
- Membership tests against sets, not lists
- Sorted data accessed with `bisect`, not linear scan

## Section B: Hot paths in Vigil

When reviewing a diff, identify whether any changed lines fall into one of these hot paths. If they do, scrutinize harder. If not, only flag glaring issues.

**Current hot paths:**

- `src/claude_monitoring/monitor.py` — `DashboardHandler` HTTP request handling: every HTTP request
- `src/claude_monitoring/monitor.py::JSONLSessionWatcher` — continuous JSONL tailing
- `src/claude_monitoring/sync.py` — event processing loop: every captured tool call (when `sync.py` is in active use)
- `src/claude_monitoring/sensitive.py`, `supply_chain.py`, `threat_intel.py`, `vuln_scanner.py` — detector surface: every event / install command / text body

**Planned hot paths (do not exist in `src/` yet — add when the directories land):**

- `src/claude_monitoring/collectors/` — every tool-call collector path
- `src/claude_monitoring/detectors/` — unified sensitive-data and supply-chain scanners
- `src/claude_monitoring/extension_scanner/` — moderate (every scan invocation)

In hot paths, check:
- No regex compilation inside the loop (compile once at module load, reuse)
- No JSON parse/dumps when dict access would suffice
- No file I/O per-iteration if cacheable
- No network calls per-iteration without batching
- No logging at INFO level for high-frequency events (use DEBUG)

## Section C: Resource management

- All file handles closed (context manager)
- All sockets closed (context manager or explicit close)
- All threads/processes joined or daemonized intentionally
- Unbounded lists/dicts in long-lived objects flagged

## Section D: Async correctness

- No blocking I/O in async functions (use `aiofiles`, `httpx` async)
- No `asyncio.sleep` with non-trivial duration in tests (mock it)
- No CPU-bound work in event loop without `run_in_executor`

## Section E: Memory patterns

- Generators over lists where downstream only iterates
- No accumulation of all results when streaming would work
- Large strings constructed via `"".join(parts)`, not `s += part`

## Section F: Database / external calls

- No N+1 queries (fetch all, then process)
- No per-row commits when batch commit would work
- Connection pooling for high-frequency external calls

## Section G: Python footguns

- No mutable default arguments
- No `setdefault` when `dict.get(k, default)` exists
- No repeated `json.dumps` of same object (cache)
- No `deepcopy` when shallow copy or immutable would suffice
