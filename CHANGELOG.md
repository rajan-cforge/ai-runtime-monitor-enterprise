# Changelog

## [0.2.0] — Unreleased

### Brand

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
