# Claude Code Orientation — Vigil

## Project identity

This is Vigil (formerly AI Runtime Monitor), an endpoint security product for AI developers.
Repo: ai-runtime-monitor-enterprise. Open source under Apache 2.0.

## Mandatory patterns

Use these patterns. Do not deviate without explicit user approval.

- **Constant-time comparison** for all credential and token checks: `hmac.compare_digest`. Never `==` for tokens.
- **Parameterized SQL queries** always. No string concatenation, no f-strings, no `%` formatting in SQL.
- **Context-aware HTML escaping** in dashboard.html. Use `escHtml`, `escAttr`, `escJs`, `escUrl` — never bare `esc()`.
- **Subprocess argv lists** for all subprocess calls. Never `shell=True`. For osascript, use the argv form.
- **Fail-closed sentinels** for sanitization. On any error, return "" (empty string) not the raw input.
- **chmod 600/700** enforcement on all sensitive files and directories. Use `security.enforce_permissions`.
- **NameConstraints on CA generation**. Never generate a CA without `permitted_subtrees`.
- **`from __future__ import annotations`** at the top of every Python file (for forward references).
- **Type hints** on every public function parameter and return value.
- **Docstrings** on every public function with at least one line describing purpose.

## Forbidden patterns

Never introduce these. If existing code has them, propose a fix in a separate PR.

- `eval()` or `exec()` on any user-provided data
- `pickle.load` or `yaml.unsafe_load` on any data
- `subprocess.run(..., shell=True)` for any reason
- SQL queries with `%s` interpolation or `f"SELECT ... {variable}"`
- `requests.post(url, verify=False)` — never disable TLS verification
- Bare `except:` clauses without re-raising or explicit handling
- `print()` for diagnostic output in production code paths (use `logger.*`)
- Module-level mutable state without explicit testing affordances
- Imports with side effects (e.g., importing a module that monkey-patches stdlib)
- New endpoints in `DashboardHandler` that don't call `verify_token`

## Pre-implementation checklist

Before writing any non-trivial code:

1. Read the relevant `docs/spec/functional/<module>.md` if it exists
2. Identify the trust boundary the change crosses (see `docs/spec/THREAT-MODEL.md`)
3. Identify the data classification of any data the change handles (see `docs/spec/DATA-CLASSIFICATION.md`)
4. If touching a Scanner, verify the `protocols/scanner.py` Protocol is satisfied
5. If touching authentication, update `docs/spec/functional/security.md`
6. If touching the API, update `docs/spec/openapi.yaml` AND `docs/spec/API-CONTRACTS.md`
7. If adding a new dependency, document the rationale in `docs/spec/dependency-rationale.md`
8. If the change is non-trivial, write a design doc at `docs/design/<feature>.md` before implementing
9. **Empirical verification before merge for any external-tool flag or invocation change.** For any architectural claim about how a tool, library, or OS actually behaves, empirical verification is mandatory BEFORE implementation begins. The verification is a short test (`lsof`, `curl`, `ps`, `strace`, `dtrace`, file existence, or equivalent) that runs the actual behaviour on the actual installed version and observes the result. If the architect agent cannot design such a test, the architect must explicitly state this limitation and propose an alternative verification path. This discipline applies to: socket behaviour, kernel calls, library config options, CLI flag semantics, process lifecycle behaviour, file system semantics, network stack behaviour, anything where the installed version's behaviour may differ from documentation or prior versions. Precedent: PR #73 shipped on a HIGH-confidence architect claim about macOS `IPV6_V6ONLY=0` that was correct for raw Python sockets but false for mitmproxy 12.x's listening socket — breaking IPv4 capture in production. 30 seconds of `lsof | curl` would have caught it. See Issue #75 and `~/Documents/vigil-notes/v021-sprint-status-2026-06-02.md` for the full failure analysis.

## Hot paths

These code paths are performance-critical. Do not add allocations or I/O inside them without measurement.

- `DashboardHandler.do_GET` and per-route handlers — every dashboard refresh hits multiple
- `JSONLSessionWatcher.run_loop` — high-frequency during active Claude Code sessions
- `ClaudeWatchAddon.response` — every intercepted HTTPS response
- `utils.scan_sensitive` — runs on every captured message body
- `utils.is_ai_process` — runs on every psutil process iter

## Source-honesty rules

When a requirement or spec is referenced but doesn't exist:
- Log it as "not yet authored" in the relevant doc
- Never invent the missing requirement
- Never proceed as if the requirement exists

When implementation reveals an architectural decision not previously documented:
- Mark it as "derived" in the relevant spec
- Surface it for explicit user ratification before merging

When a spec exists and code diverges from it:
- Either update the spec (explicit revision PR) OR revert the divergence
- Never silently leave spec and code disagreeing

## Design doc trigger criteria

Write a `docs/design/<feature>.md` before implementing if any of these are true:

- The change adds a new module
- The change crosses a trust boundary (new endpoint, new external API, new IPC)
- The change modifies the database schema
- The change adds a new external dependency
- The change touches the auth, masking, sanitization, or CA generation code
- The change is expected to take more than 100 lines

The design doc should cover: motivation, proposed approach, alternatives considered, threat surface,
and verification plan.

## Criticality classification

Every PR description must include a criticality level. **Criticality is the
stricter of two axes: security sensitivity and architectural blast radius.**
A PR is C4 if it is C4 on either axis — neither axis is subordinated.

- **C0** — docs-only, no code paths affected
- **C1** — tests or scripts, no production behavior
- **C2** — feature addition, no security implication
- **C3** — feature with security implication or hot-path touch
- **C4** — auth, secrets, crypto, or trust boundary, OR a change to how Vigil
  fundamentally operates

C3 and C4 PRs require human diff review even if all agents pass.

Note for v0.2.2 sprint PRs: the implementation directive
(`~/Documents/vigil-notes/v022-implementation-directive-v1-LOCKED.md` §5)
defers to this scale rather than redefining it. If a PR is C4 on either
axis under the union, classify and treat it as C4.

## Where things live

- Source code: `src/claude_monitoring/`
- Tests: `tests/`
- Specs: `docs/spec/`
- Architecture: `docs/ARCHITECTURE.md`
- SSDLC controls: `docs/SSDLC_ENFORCEMENT.md`
- Agent rubrics: `.claude/rubrics/`
- Agent definitions: `.claude/agents/`
- Quality gate scripts: `scripts/check_*.py`
- Local-only operational notes: `~/Documents/vigil-notes/` (NOT in repo)
