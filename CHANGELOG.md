# Changelog

## [0.2.2] — unreleased

### Removed

- **`sync.py` + control-plane client surface.** The control plane (server half) was removed from the public repo in PR #110 (2026-06-09); this PR removes the corresponding client half. Removed: `src/claude_monitoring/sync.py` (365 lines: SyncAgent thread + _sanitize_payload sanitizer + watermark logic), `tests/test_sync.py`, `tests/test_sync_sanitize.py`, `monitor.py` sync-agent startup block, `--control-plane` + `--cp-api-key` CLI flags + their `start_monitoring()` params. **All captured data stays local. No daemon-side outbound sync surface.** The feature returns later as a properly-designed enterprise control plane with its own design doc and PRs.
  - **Trust-boundary B3 (Daemon ↔ Control Plane) deleted.** Threat model renumbered: old B4→new B3, old B5→new B4, old B6→new B5, old B7→new B6. `docs/spec/THREAT-MODEL.md` §5 (B3 STRIDE) deleted entirely; all cross-references in ARCHITECTURE.md, SECURITY-MANIFEST.md, DATA-CLASSIFICATION.md, spec/README.md, openapi.yaml, dependency-rationale.md updated.
  - **SECURITY-MANIFEST.md ASVS status changes** (architect-pass mandated source-honesty):
    - V2.4.1 (bcrypt for endpoint keys): IMPLEMENTED → **N/A**
    - V5.2.2 (sanitize unstructured data): IMPLEMENTED → **PARTIAL** (HTML escaping survives; structured-payload sanitization removed)
    - V6.4.2 (encryption in transit): IMPLEMENTED → **PARTIAL** (mitmproxy TLS path survives; outbound sync removed)
    - V9.1.1 (TLS 1.2+): IMPLEMENTED → **PARTIAL** (same rationale)
    - V2.7.6 (auth state never logged): IMPLEMENTED, evidence repointed to `security.py::verify_token`
    - V14.5.1 (HTTP method restrictions), A02, A07: evidence cleaned of sync references
  - **Schema:** `sync_state` table left dormant (lazily `CREATE TABLE IF NOT EXISTS`, no migration file existed). Users who ran `--control-plane` retain a dormant table; default DBs never had it. The future enterprise control plane will introduce its own versioned schema.
  - **Load-bearing pin tests** in `tests/test_no_sync_surface.py` (14 tests): grep-zero across src/ + tests/ for `SyncAgent`/`cp_url`/`_sanitize_payload`/`--control-plane`/etc.; file-absence (incl. `docs/spec/functional/sync.md` non-existence pin added in a2); import-raises-ModuleNotFoundError; threading-enumerate runtime check; `check_privacy_no_telemetry.py` still green.
  - **Spec doc scrub (a2 follow-up to judge CHANGES).** `docs/spec/functional/sync.md` deleted (archived to `~/Documents/vigil-notes/repo-hygiene/removed-2026-06/`). Present-tense control-plane prose reworded in `docs/spec/functional/db.md` (sync_state framed as dormant table only), `docs/spec/functional/monitor.md` (outbound scope clarified), `docs/spec/API-CONTRACTS.md` (HTTPS, `/api/fleet/*`, ingest references now explicitly planned-v1.0), `docs/spec/DATA-CLASSIFICATION.md` (log example switched off SyncAgent), `docs/spec/PRD.md:15` (control-plane lead-in reframed as planned tier). `.github/spec-requirements.yaml`'s `sync-sanitization-changes` rule and `.github/pull_request_template.md`'s C3 caller-audit section removed (both keyed to deleted symbols). Trust-boundary §2 list and §8 residual-risk table extended to include B6 (Discovery), correcting a pre-existing boundary-count omission flagged by the judge.

### Added

- **P3.8 — Ontology mapping bodies wired for all 8 Phase-3 sources.** Replaces the structural-only `frozenset()` placeholders with real rule bodies for VSCode/Cursor extensions, Chromium extensions, Python packages + project deps, Node packages, Homebrew AI tools, and Claude Desktop integrations. The identity-only sources (`ollama-models`, `ai-tool-versions`, `ai-apps-info-plist`), skill sources (`claude-code-skills`, `openclaw-skills`), and the already-complete `mcp-servers` scored mapper are unchanged.
  - Chrome extension permission map now emits `SECRETS_ACCESS` (cookies/identity/browsingData), `SHELL_EXECUTE` (debugger/nativeMessaging), `NETWORK_UNRESTRICTED` (webRequest, wildcard host permissions), `NETWORK_SCOPED` (specific-origin host permissions — first wiring of this category), `SYSTEM_MODIFICATION` (management/contentSettings — first wiring), `CODE_EXECUTION` (background service worker / scripts), `FILE_SYSTEM_READ` (tabs/history/bookmarks/`<all_urls>` content scripts), and `FILE_SYSTEM_WRITE` (downloads). **R6 ratification (2026-06-09):** `nativeMessaging` co-emits `{SHELL_EXECUTE, INTER_TOOL_COMMUNICATION}` because the IPC channel to native host programs is itself an inter-tool protocol; `INTER_TOOL_COMMUNICATION`'s docstring is updated to cover non-MCP IPC.
  - VSCode/Cursor: `main` non-null → `CODE_EXECUTION`; `contributes_debug/terminal/tasks` → `SHELL_EXECUTE`; `extension_kind` contains `"workspace"` → `{FILE_SYSTEM_READ, FILE_SYSTEM_WRITE}`. Web-only extensions (browser-set, main-null) do NOT emit `CODE_EXECUTION`.
  - Python (installed + project-deps) and Node packages: narrow hand-curated package-name → capability hint tables (`requests`/`boto3`/`paramiko`/`cryptography`/`openai`/`anthropic`; `axios`/`shelljs`/`execa`/`@anthropic-ai/sdk`/etc.).
  - Node: lifecycle scripts OR bin entries on a self-asset (R3 — `dep_kind == "self"`) → `CODE_EXECUTION`.
  - Homebrew AP-4 taxonomy split: LLM HTTP servers (`ollama`/`llama`) → `{CODE_EXECUTION, NETWORK_UNRESTRICTED}`; GPU runtimes (`cuda`/`rocm`) → `CODE_EXECUTION` only; ML frameworks (`pytorch`/`tensorflow`/`jax`) → `CODE_EXECUTION` only; API client CLIs (`openai`/`anthropic`) → `NETWORK_UNRESTRICTED`. R4 ratification: declared capability per spec §6.6.
  - Claude Desktop integrations: `coworkWebSearchEnabled` → `NETWORK_UNRESTRICTED`; `coworkScheduledTasksEnabled` and `ccdScheduledTasksEnabled` → `CODE_EXECUTION` (R5 ratification); `filesystem_access` kind → `{FILE_SYSTEM_READ, FILE_SYSTEM_WRITE}`; `unknown_top_level` kind → empty (forward-compat capture, UI renders as "Not yet classified").
  - `categories.py` docstrings updated: `NETWORK_SCOPED` and `SYSTEM_MODIFICATION` are no longer "Dormant in Phase 2".
  - **Authorized deferral of directive §7.3.3** (`config/package-capability-hints.yaml` inlined instead per AP-3) and **§5.6** (unmapped Chrome permissions log at INFO instead of carrying an `unknown_permission` tag, per AP-5) — both logged in `~/Documents/vigil-notes/v022/directive-gap-log.md`.
  - `TestDerivedTagProhibition` parametric test gains 12 positive-case fixtures (AP-2 architect-pass condition) so the derived-tag prohibition is no longer pinned trivially by empty-`current_state` fixtures.
  - End-to-end integration: `cookies + <all_urls>` on a Chrome extension correctly derives `DATA_EXFILTRATION_CAPABLE` via `derived.py`.
  - **Operator-surprise expectations on first post-merge scan:** the Anthropic Claude browser extension on developer machines will jump to HIGH/CRITICAL (it has `nativeMessaging + debugger + <all_urls> + content_scripts(<all_urls>)`); any Chrome extension with `cookies + <all_urls>` will derive `DATA_EXFILTRATION_CAPABLE`; locally-installed Ollama formula jumps to HIGH on the supply-chain side (`{CODE_EXECUTION, NETWORK_UNRESTRICTED}`). All accurate, not regressions.

- **Dashboard dual-stack loopback hotfix (PR #108).** Fixes Chrome's `localhost` → `::1` Happy Eyeballs resolution returning `ERR_CONNECTION_REFUSED` against the IPv4-only dashboard listener. `LoopbackDualStackServer` wraps two `ReusableHTTPServer` instances — one on `127.0.0.1`, one on `[::1]` — preserving the localhost-only security invariant (no all-interfaces binding). Same class of bug as issue #75 (mitmproxy IPv4-only) — dashboard-side counterpart to PR #76.

## [0.2.1] — 2026-06-03

### Fixed

- **Streaming response bodies from Anthropic Messages API are now correctly captured by the proxy addon (PR — issue #65).** Previously silently dropped due to a dispatch bug: the response hook used `raw.startswith("data:")` to decide between SSE and JSON parsers, which matched OpenAI SSE but missed Anthropic SSE (which leads with `event: message_start\n...`). The SSE parser was never reached for Anthropic streams; the JSON fallback raised `json.JSONDecodeError`; the bare `except: pass` silently swallowed the error. Affects all proxy-captured Claude Desktop, ChatGPT Desktop, Cursor, and streaming Claude Code sessions. Non-streaming responses were unaffected. The new dispatch uses `Content-Type: text/event-stream` as the canonical signal with a body-sniff fallback covering both `event:` (Anthropic) and `data:` (OpenAI) prefixes. The bare `except: pass` is replaced with a two-tier handler: expected parse failures log at WARNING; anything else logs at ERROR with full traceback. Historical rows with empty content cannot be backfilled.

- **`ai-monitor --status` capture matrix now reflects live evidence, not a static `sys_proxy` boolean.** Pre-fix the three desktop-AI-app rows (Claude Desktop / ChatGPT Desktop / Cursor) all printed `✅ Proxy (full capture)` whenever the user enabled system proxy, regardless of whether those apps were actually routing through the proxy or whether content was being decrypted. Ground-truth verification on 2026-06-01 proved this label was false — all three apps showed ✅ in `--status` while their chat messages produced zero captured rows. The replacement combines two live signals — does the app have an ESTABLISHED TCP connection to `127.0.0.1:9080`, and are there decrypted content rows (`input_tokens > 0`) from the app's expected host in the last hour — into one of four verdicts: `✅ Proxy verified — N rows captured last hour`, `⚠ Reaches proxy, no decrypted content (host may not be in allow_hosts)`, `❌ System proxy on but app routing direct (IPv6 / plugin-helper bypass)`, or `❌ Process only (system proxy disabled)`. The matrix now distinguishes Claude Desktop's IPv6 bypass (#70), ChatGPT Desktop's allow_hosts exclusion (#71), and Cursor's plugin-helper bypass with distinct, actionable labels.

- **Reverted IPv6 dual-stack listener change (PR #74 reverts PR #73) due to mitmproxy 12.x setting `IPV6_V6ONLY=1`, which made the IPv4 listener inaccessible.** PR #73 added `--listen-host ::` to the mitmdump cmdline on the assumption that macOS BSD default `IPV6_V6ONLY=0` would yield a single dual-stack socket. Empirical test on the installed mitmproxy 12.2.3 showed the assumption was wrong: mitmproxy 12.x explicitly sets `IPV6_V6ONLY=1` when an explicit listen host is passed, collapsing the bind to IPv6-only. macOS system proxy is always configured at an IPv4 host (`networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 9080`), so all apps relying on system proxy got `Connection refused` after PR #73 merged. PR #74 restores the pre-PR-73 code; mitmproxy 12.x's default behaviour (no explicit `--listen-host`) binds BOTH IPv4 *:port and IPv6 *:port sockets, which is the working state. Issue #70 (Claude Desktop IPv6 bypass) remains open pending alternative approach — likely setting a second IPv6 system proxy via `networksetup` rather than changing the mitmproxy listener. A new empirical regression test in `tests/test_lifecycle.py::TestMitmdumpDualStackOnMacOS` runs a real mitmdump subprocess and asserts BOTH listeners are present; any future regression of this shape will fail at CI time instead of in production.

- **Response/request parsers now defend against non-dict JSON bodies.** Surfaced by the new ERROR-level logger added in the SSE dispatch fix above: `parse_response_body` was raising `AttributeError: 'NoneType' object has no attribute 'get'` when `json.loads(raw)` returned Python `None` (the body was the JSON literal `null`). All five JSON parsers (`parse_response_body`, `parse_openai_response`, `parse_google_response`, `parse_request_body`, `parse_openai_request`) now return the record unchanged when `body` is not a dict. Same defensive pattern across the response and request sides; the type annotation `body: dict` now matches runtime behaviour. Content fill rate for `/v1/messages` rows trended from 13% (pre-fix) to 82% (post-SSE-fix) and should climb further toward the legitimate ceiling with this guard in place.

### Documentation

- **README capture matrix and roadmap rewritten for accuracy.** Desktop AI app coverage (Claude Desktop, ChatGPT Desktop, Cursor) is documented with known limitations and the v0.3 architectural path forward (Apple Network Extension framework). Capture coverage claims match `--status` output verbatim (the four-verdict strings — `✅ JSONL + Proxy`, `⚠ Reaches proxy, no decrypted content (host may not be in allow_hosts)`, `❌ System proxy on but app routing direct (IPv6 / plugin-helper bypass)` — appear in the README's first-run "Expect" block character-for-character from `status.py`). New "Honest capture matrix" section lays out per-surface coverage (Full / Partial / Envelope-only) with the mechanism, the specific v0.2.1 limitation, and the typical live `--status` verdict. Top tagline reframed to lead with honesty and local/open positioning. `docs/spec/THREAT-MODEL.md` Boundary B4 explicitly frames the macOS Electron capture gaps as routing-layer bypass (the OS doesn't send the traffic to the boundary), not boundary-violation (the boundary's NameConstraints / no-modification / masking / auto-purge invariants are intact for every flow the proxy does intercept). `docs/spec/functional/security.md` §13 and `docs/ARCHITECTURE.md` §7 Layer 3 carry the same framing.

### Notes

- This sprint adopted empirical verification of architectural claims as a permanent SSDLC discipline (CLAUDE.md §9). The discipline is what produced the honest framing now in the README. Two examples from the sprint that the documentation pattern is responding to: PR #73 (mitmproxy IPv6 listener) was reverted by PR #74 after a real-subprocess regression test surfaced an `IPV6_V6ONLY=1` interaction that mitmproxy 12.x's documentation alone had not flagged; the PAC routing investigation rejected three candidate architectures (dual-host `networksetup`, scutil/SCPreferences, `file://` PAC for Electron main process) based on empirical evidence — lsof socket observations, controlled Swift `URLSession` tests, and live Claude Desktop process inspection — before recommending the v0.3 Network Extension pivot. The cost of these empirical checks (5-30 minutes each) saved at least one production revert cycle and re-baselined the roadmap with verified ground truth.

## [0.2.0] — 2026-05-28

Verified end-to-end on two machines (primary + new laptop) before release. Capture matrix confirmed working for: Claude Code JSONL sessions, browser AI on claude.ai / chatgpt.com / gemini.google.com via the Chrome extension, full HTTPS proxy interception for routed CLI tools, process / filesystem / network observation.

### Fixed (post-audit launch blockers)

- **Bug 8 — wizard regenerates CA on every `--setup` invocation (PR #58).** `--setup` is now idempotent. The wizard reuses an existing valid cert (parseable PEM, NameConstraints match current `AI_PROXY_DOMAINS`, not expired within a 30-day buffer) instead of overwriting it. Closes the "trust applied to cert A, --setup rotates to cert B, verifier reports B as untrusted" loop that prevented the documented recovery path from converging. New `--regenerate-ca` flag for the explicit force-regen case.
- **Bug 2 — osascript trust silently fails on macOS Sequoia+ (PR #59).** Root cause: `osascript "do shell script ... with administrator privileges"` runs root but lacks GUI session ownership; `SecTrustSettingsSetTrustSettings` returns `errSecInteractionNotAllowed` and the `security` binary exits 0 anyway. Apple DTS-confirmed; the `authorizationdb` workaround is SIP-protected dead on Sequoia. Fix: `trust_ca_cert_with_fallback` orchestrates a two-attempt strategy — osascript first (still works on Monterey/Ventura), then a terminal-sudo fallback that prints the exact `sudo security add-trusted-cert` command and polls `verify_ca_trusted` every 2s for up to 120s. Enter triggers an immediate recheck; Ctrl-C skips. Non-tty / CI returns False immediately without hanging on input.
- **PR #51 verified on two machines.** `AI_PROXY_DOMAINS = AI_API_DOMAINS` invariant confirmed: claude.ai / gemini.google.com / chatgpt.com all load with their real upstream certs (Let's Encrypt / Google Trust Services), not Vigil's CA. Selective SSL inspection working as designed; browser UI sites captured by the Chrome extension exclusively.

### Documentation accuracy (post-audit)

- **README install model switched to clone + venv + `pip install -e .` (PR #60).** No PyPI / pipx path for v0.2 — same flow for end users, security engineers, and contributors. Published-package install scoped to v0.3 alongside the privileged macOS helper.
- **README capability claims audited and reframed (PR #60).** Cost claim narrowed: per-message cost surfaces only for Claude Code sessions (read from the cost field Claude Code writes into its own JSONL); per-call dollar cost for non-Claude-Code traffic is v0.3 roadmap. Browser AI claim narrowed: verified end-to-end for claude.ai / chatgpt.com / gemini.google.com; coded support for perplexity.ai / copilot.microsoft.com / deepseek.com with verification in progress. "Zero configuration" softened to "set up once, captures continuously." `claude-watch` removed from the main README's flag table; full reference moved to new `docs/CLAUDE-WATCH.md` with explicit "when NOT to use claude-watch" warnings.
- **Dashboard cost card relabeled (PR #62).** "Est. Total Cost" → "Claude Code Spend / From session logs" — matches the README's honest cost framing. Same numeric source, more accurate label.

### Fixed (dashboard auth)

- **Export functions returning 401 (PR #61).** Root cause: the dashboard monkey-patches `window.fetch` to auto-attach the session token, but four call sites used `window.open` / `window.location.href` / `<a href>` — full-page navigations that bypass the fetch interceptor. Affected: CSV/JSON exports, Weekly Report HTML, Weekly Report Markdown, SBOM export. Fix: new `window.withAuthToken(url)` helper inside the same IIFE; all four call sites wrap their URL with it before navigating.

### Brand

### Brand renamed

- Renamed product from "AI Runtime Monitor" to **Vigil**. Package name (`ai-runtime-monitor`) and module name (`claude_monitoring`) preserved for v0.2.0 — module rename deferred to v0.3.

### Added

- **`ai-monitor --version`** CLI flag with three-step version resolution (importlib.metadata → setuptools_scm → static fallback).
- **`ai-monitor --no-proxy`** opt-out for environments without a trusted Vigil CA. `--with-proxy` is preserved as a no-op for backwards-compat.
- **First-run setup wizard** (`ai-monitor --setup`) now includes a Step 4 browser-extension install prompt; 5-step wizard end-to-end.
- **Pre-flight checks** at `--start` time. If mitmproxy is missing the daemon exits 2 with an actionable message; if the CA isn't trusted in the System keychain admin trust settings the daemon exits 3.
- **`--status` allow_hosts visibility** — shows the active mitmdump allow-hosts pattern and flags regressions to the PR #51 invariant.
- **CA trust verification** (`security.verify_ca_trusted`) — `Literal`-typed `TrustVerificationCode` reports the keychain state with an actionable recovery hint.

### Changed

- **mitmproxy** moved from the `[watch]` optional extra to the base dependency. `pip install ai-runtime-monitor` now ships a fully-functional product. `[watch]` retained as an empty no-op alias for backwards-compat; removal slated for v0.3.
- **Python floor** bumped to **3.10** (mitmproxy 10+ dropped 3.9 support).
- **`AI_PROXY_DOMAINS = AI_API_DOMAINS`** — mitmdump's `--allow-hosts` regex now contains only AI API endpoints; browser UI sites (claude.ai, chatgpt.com, gemini.google.com, perplexity.ai) are captured by the Chrome extension exclusively. Closes a class of dashboard-only false positives.
- **`_classify_browser_service`** uses exact / proper-subdomain hostname matching (`_matches(host, domain)`) instead of bare `in host` substring checks. Closes CodeQL `py/incomplete-url-substring-sanitization` findings on `watch.py`.

### Security

- Audit-driven launch hygiene: `SECURITY.md` comprehensive refresh, response-process SLA table, links to threat model and data classification.
- Comprehensive 2026-05-26 enterprise-readiness audit; findings folded into the launch sprint (this release).
- Slack-webhook test fixture rewritten to use `EXAMPLE`/`PLACEHOLDER` tokens that match the validator regex shape but cannot trigger secret scanning.

### Documentation

- README rebrand and four-badge row (CI, license, PyPI, Python).
- Threat-model coverage matrix: 11 verified T-codes, 13 verification-pending — full enumeration in `vigil-notes/threat-model-coverage-2026-05-27.md`.
- New design docs: `docs/spec/SSL_INSPECTION.md`, `docs/spec/SUPPLY_CHAIN_DESIGN.md`.

### Internal

- Project conventions captured: synthetic-fixtures rule, CodeQL Pattern A (Literal-typed state codes) and Pattern B (rationale + UI dismissal), three cycle-1 patterns (dead-branch preservation, threshold-grounded-in-upstream, coverage via testable invariants).

## [0.1.0] - 2026-03-04

### Added
- Three-layer monitoring: network (JSONL transcript tailing), filesystem (watchdog), process (psutil)
- SQLite event store with WAL mode for concurrent reads
- Web dashboard on port 9081 with Session Explorer, Live Feed, Analytics, System, and Alerts tabs
- Sensitive data detection (DLP): AWS keys, GitHub tokens, private keys, JWTs, credit cards, SSNs, and more
- Cost estimation and burn rate forecasting with subscription plan detection
- Browser AI activity tracking via Chrome history
- Network connection monitoring with hostname resolution
- File activity monitoring for AI agent working directories
- Export to JSON and NDJSON (SIEM-compatible)
- `claude-watch` proxy-based traffic interceptor for deep API-level monitoring
- CLI entry points: `ai-monitor` and `claude-watch`
- macOS LaunchAgent install/uninstall support
