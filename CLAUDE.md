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

**Human diff review — keyed to the security axis, not the tier label (2026-06-08).**
Human diff review is required when a PR is C4 on the **security axis** — it touches
(a) auth / credential or token comparison / session / access-control routes;
(b) crypto / CA generation / signing / key material;
(c) secret handling / redaction / the sanitization path; or
(d) a NEW outbound data flow carrying findings/captured content off-box, or a new trust
boundary that receives data.

A PR that is high-tier only on the **architecture / blast-radius axis** (hot path, large
diff, new sub-package, first/Nth outbound *enrichment* call) does NOT require human review,
provided ALL of: (i) the architect-pass ran and its findings were folded; (ii) all relevant
CI gates are green; (iii) the vigil-loop verdict is APPROVE on the judge's independent
re-read; (iv) empirical-ratchet evidence is present; (v) no R0 keystone item is touched.
Otherwise → human review. Safe default: if unsure whether a change touches a security
surface (a)–(d), treat it as security-C4 → human review.

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

## vigil-notes judge/executor loop (compaction-durable)

When working a v0.2.2 sprint PR you are the **executor** in the vigil-notes loop;
Claude Desktop is the **judge**. The full protocol is the rulebook at
`~/Documents/vigil-notes/v022/CONTRACT.md`. This section exists so the loop survives
context compaction — it is re-loaded from this file, not from chat history.

**Re-hydration — do this at the start of every task AND immediately after any context
compaction, before taking any action:**

1. Re-read `~/Documents/vigil-notes/v022/CONTRACT.md` and this section.
2. Re-read `~/Documents/vigil-notes/v022/STATUS.md` to recover the active task, attempt,
   phase, last verdict, and carry-forwards. Your conversation history is NOT the source
   of truth after a compaction — these files are.

**Per PR:** run Phase A → B → C (architect-pass for C3/C4), then submit and act on the
verdict using `~/Documents/vigil-notes/v022/scripts/executor-loop.sh`
(`submit` → `wait` → act). Verdicts: `APPROVE` / `APPROVE-WITH-FIX` / `CHANGES` /
`NEEDS-RAJAN` (CONTRACT §6). Keep `STATUS.md` current and append one line per cycle to
`work-log/`.

**Merge gate (mechanical):** a `pre-push` hook blocks pushing a `feat/v022-pX.Y*`
branch unless an `APPROVE`/`APPROVE-WITH-FIX` verdict for that taskid exists in the
vigil-notes loop. Install it once with `make install-vigil-hook`. Do not set
`VIGIL_LOOP_OVERRIDE` to bypass it except for an intentional WIP push you will not turn
into a PR.
