# Threat Model — AI Runtime Monitor (Vigil) v0.2

**Last updated:** 2026-05-24
**Methodology:** STRIDE
**Scope:** Local daemon + dashboard + control plane integration
**Status:** v0.2 launch candidate

This document analyzes threats to the AI Runtime Monitor across its trust boundaries. Each section identifies the boundary, enumerates STRIDE categories, lists current mitigations, and documents residual risks.

## 1. Scope and assumptions

### 1.1 In scope

- Local daemon process (`ai-monitor`) running on the developer's machine
- Local dashboard HTTP server on `localhost:9081`
- mitmproxy addon (`claude-watch`) on `localhost:9080` when proxy is enabled
- SQLite database at `~/claude_watch_output/monitor.db`
- Custom CA certificate generation and trust management
- Sync agent communication with the control plane (over HTTPS to a remote server)
- Browser extension communication with the daemon (v0.2.1)

### 1.2 Out of scope

- Vulnerabilities in the underlying operating system, Python interpreter, or third-party libraries (tracked via pip-audit; not a threat model concern)
- Threats to the AI agent processes themselves (Claude Code, Cursor, etc.) — Vigil observes them; it does not protect them from compromise. (Note: B6 (planned v0.3, §8) partially revisits this — v0.3 adds provenance verification and policy enforcement for agent identity, though Vigil still does not attempt to harden the agents' internals.)
- Threats to the Anthropic, OpenAI, Google, etc. APIs that AI agents talk to
- Physical security of the developer's machine
- Network-level attacks on the developer's home or office network (mitigated by HTTPS endpoints upstream, not Vigil)

### 1.3 Threat actors considered

- **Curious developer** — the person who installed Vigil, trying to inspect or extract data
- **Local malware** — code running as the same user as the daemon, with access to the user's home directory
- **Local non-privileged user** — another user on the same machine without root
- **Network adversary on local network** — someone on the same LAN as the developer
- **Compromised AI agent** — Claude Code or similar that has been prompt-injected or has installed a malicious tool
- **Compromised control plane** — the upstream server has been breached
- **Compromised dependency** — a Python package in Vigil's dependency tree has been backdoored

## 2. Trust boundaries

The system crosses five trust boundaries today, with a sixth (B6: Agent Identity) planned for v0.3. Each is analyzed below.

```
┌─────────────────────────────────────────────────────────────────────┐
│ Developer's machine                                                 │
│                                                                     │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────────────┐  │
│  │ AI agents   │ →  │ Vigil daemon │ →  │ SQLite DB             │  │
│  │ (untrusted) │    │              │    │ ~/claude_watch_output │  │
│  └─────────────┘    └───────┬──────┘    └───────────────────────┘  │
│                             │                                       │
│  ┌─────────────┐            │            ┌───────────────────────┐  │
│  │ Browser ext │ ─────────→ │ ←──────── │ Dashboard UI          │  │
│  │ (untrusted) │            │            │ http://localhost:9081 │  │
│  └─────────────┘            │            └───────────────────────┘  │
│                             │                                       │
└─────────────────────────────┼───────────────────────────────────────┘
                              │
                              │ HTTPS + bearer token
                              ▼
                    ┌───────────────────┐
                    │ Control plane     │
                    │ (remote server)   │
                    └───────────────────┘
```

Five boundaries today, with a sixth planned for v0.3:

- **B1: User ↔ Dashboard** (browser to local HTTP server)
- **B2: Daemon ↔ Database** (process to file system)
- **B3: Daemon ↔ Control Plane** (local to remote, over HTTPS)
- **B4: Proxy ↔ AI APIs** (intercept TLS termination)
- **B5: Browser Extension ↔ Daemon** (extension to local HTTP)
- **B6: Agent Identity** (claimed vs. verified agent provenance — planned v0.3; see §8)

## 3. Boundary B1: User ↔ Dashboard

### 3.1 Spoofing

**T1.1: Attacker impersonates the user to the dashboard.**

- *Vector:* Local malware reads the dashboard token from `~/claude_watch_output/.dashboard_token` and authenticates as the user.
- *Mitigation:* File is chmod 600 (owner-only). On macOS, FileVault encrypts the disk at rest. Browser-extension capture of the token requires either reading the file (chmod 600 blocks this) or scraping localStorage (origin-isolated to the localhost dashboard).
- *Residual risk:* Malware running as the user can read the token. This is the standard threat model for local credentials; defense requires OS-level controls (FileVault, SIP) and EDR (CrowdStrike, etc.) outside Vigil's scope.

### 3.2 Tampering

**T1.2: Attacker injects content into the dashboard.**

- *Vector:* Stored XSS via injected text in session data (e.g., AI agent processed an attacker-controlled prompt; the prompt text shows up in the dashboard's Session Explorer).
- *Mitigation:* Four context-aware escape helpers (`escHtml`, `escAttr`, `escJs`, `escUrl`) used at every interpolation site. The Phase 3A C2 fix migrated all known call sites to the appropriate helper.
- *Residual risk:* New code that uses bare `esc()` or string concatenation can reintroduce XSS. Mitigated by code review, the architect-reviewer agent's rubric, and (post-PR #20) a planned regex-based CI check that fails when `dashboard.html` contains `esc(` outside the alias definition.

### 3.3 Repudiation

**T1.3: User denies an action they performed in the dashboard.**

- *Vector:* User configures an alert exclusion or purges data, then claims they didn't.
- *Mitigation:* Dashboard does not support destructive write operations in v0.2. All writes go through the CLI (`ai-monitor --purge`, etc.) which is logged locally.
- *Residual risk:* CLI commands don't generate immutable audit logs in v0.2. v1.0 fleet dashboard will add audit logging.

### 3.4 Information disclosure

**T1.4: Dashboard exposes sensitive data to unauthorized viewers.**

- *Vector:* User leaves the dashboard open; family member or coworker reads sensitive credentials displayed on screen.
- *Mitigation:* Plaintext credentials are masked on display (first 4 + asterisks + last 4 chars). Token comparison is constant-time. Auto-purge strips plaintext after 30 days.
- *Residual risk:* Non-credential sensitive data (project names, prompts, file paths) is shown in plaintext. This is by design — the dashboard's value depends on showing this.

### 3.5 Denial of service

**T1.5: Local process consumes dashboard resources to make it unresponsive.**

- *Vector:* Curious or malicious user spams `/api/feed` to drown out the legitimate browser.
- *Mitigation:* None in v0.2. The localhost-only default and single-user assumption make this low-priority.
- *Residual risk:* No rate limiting. Acceptable for v0.2; v1.0 will add per-token rate limits.

### 3.6 Elevation of privilege

**T1.6: Unauthenticated request reaches a privileged endpoint.**

- *Vector:* Attacker discovers a path that doesn't check the bearer token.
- *Mitigation:* Every API endpoint goes through `DashboardHandler` which enforces token authentication. The C1-FOLLOWUP investigation in Phase 3A specifically verified this end-to-end with curl tests outside the dashboard's monkey-patched fetch.
- *Residual risk:* New endpoints added without the auth wrapper. Mitigated by code review, the architect-reviewer rubric, and (planned) a custom AST check that flags new handler methods missing the auth decorator.

## 4. Boundary B2: Daemon ↔ Database

### 4.1 Spoofing / Tampering

**T2.1: Local malware modifies the SQLite database to hide evidence.**

- *Vector:* Malware drops events from the `sensitive_data` table to cover its tracks.
- *Mitigation:* Database file is chmod 600. SQLite WAL mode means concurrent writes from outside the daemon would corrupt the journal. v0.3 will add SQLCipher encryption-at-rest.
- *Residual risk:* Malware with the user's privileges can read and modify the DB. Defense-in-depth via signed releases (planned v0.3) and integrity checks on critical tables (post-launch).

### 4.2 Information disclosure

**T2.2: Database leaks sensitive plaintext.**

- *Vector:* Old rows contain plaintext credentials that should have been masked.
- *Mitigation:* Sensitive-data scanner masks at insert time (`security.py::mask_value`). Auto-purge strips plaintext fragments from rows older than 30 days. Both mechanisms run on every startup and on a daily schedule.
- *Residual risk:* New code paths that insert plaintext bypassing the masker. Mitigated by code review, the sync.py `_sanitize_payload` defense-in-depth check, and the upcoming custom AST check that flags `INSERT` statements with text fields not passing through a sanitizer.

### 4.3 Denial of service

**T2.3: Database grows unbounded, fills disk.**

- *Vector:* Long-running daemon with high-volume AI agent activity.
- *Mitigation:* Auto-purge of plaintext after 30 days reduces row size. There is no row-count limit in v0.2.
- *Residual risk:* Sufficient activity over months could exceed disk space. Addressed in v0.3 by adding configurable retention policies and a `--cleanup` command.

## 5. Boundary B3: Daemon ↔ Control Plane

### 5.1 Spoofing

**T3.1: Attacker impersonates the daemon to the control plane.**

- *Vector:* Stolen `X-API-Key` (fleet key) or `X-Endpoint-Key` (per-endpoint key) used to send fake telemetry.
- *Mitigation:* Endpoint key is verified server-side against a bcrypt hash. Fleet API key is per-organization. HTTPS prevents network interception.
- *Residual risk:* If both keys are stolen (e.g., from a compromised endpoint), the attacker can send arbitrary data. Server-side anomaly detection (planned v1.0) will catch volume/pattern anomalies.

**T3.2: Daemon connects to a malicious server.**

- *Vector:* DNS hijack or compromised TLS PKI redirects the daemon to an attacker's server.
- *Mitigation:* Standard TLS verification with system trust store. Control plane URL is configurable but defaults to a known endpoint.
- *Residual risk:* TLS PKI compromise (rare but possible). Defense via certificate pinning (planned v1.0 for Enterprise tier).

### 5.2 Tampering

**T3.3: Attacker modifies data in transit.**

- *Vector:* MITM on the network between daemon and control plane.
- *Mitigation:* HTTPS with TLS 1.2+. Standard.
- *Residual risk:* Negligible with modern TLS.

### 5.3 Information disclosure (THE BIG ONE)

**T3.4: Daemon leaks plaintext credentials to the control plane.**

- *Vector:* Historical DB rows (pre-masking) or new code paths bypass the masker; the sync agent posts plaintext to the control plane.
- *Mitigation:* The sync agent runs `_sanitize_payload` as defense-in-depth on every outbound request. This recursively walks the payload, scans every field in `_SANITIZE_TEXT_FIELDS` for sensitive patterns, and masks any matches inline. The C3 audit fix changed this from fail-open to fail-closed: any error in the masker returns "" (empty string), not the raw value. The sanitizer also strips control characters and truncates oversized fields to prevent tunneling.
- *Residual risk:* A field name not in `_SANITIZE_TEXT_FIELDS` could leak data. Adding new fields requires updating the set. Mitigated by the sync test suite which uses synthetic plaintext inputs and asserts they're masked at the boundary.

### 5.4 Repudiation

**T3.5: Control plane disputes whether an endpoint sent data.**

- *Vector:* Compliance or legal investigation requires proof of what was sent.
- *Mitigation:* Server-side logging of all `/api/v1/ingest` requests with timestamps, source IP, and payload hashes.
- *Residual risk:* Server logs are server-side; daemon-side proof is limited to its local `~/.vigil-antfood-state` and similar diagnostic files (not designed as audit logs).

### 5.5 Denial of service

**T3.6: Daemon overwhelms the control plane with sync requests.**

- *Vector:* Bug in the sync agent causes runaway retries.
- *Mitigation:* Exponential backoff in `SyncAgent._sync_loop` (1 → 2 → 4 → ... → 60 seconds). Server-side rate limiting (planned v1.0).
- *Residual risk:* If many endpoints exhibit the same bug, they could collectively DoS the control plane.

### 5.6 Elevation of privilege

**T3.7: Compromised endpoint sends data attributed to another organization.**

- *Vector:* Endpoint key reuse across orgs, or org_id spoofing in the payload.
- *Mitigation:* Endpoint key is bcrypt-verified server-side; org_id is derived from the verified key, not from the payload.
- *Residual risk:* Per the TalosAI audit (referenced in the development history): server-side `KNOWN_CUSTOMER_ACCOUNTS` fallback would return all accounts to any org when the tenant service was unavailable. This bug is fixed in TalosAI; Vigil's control plane was designed with awareness of this class of issue.

## 6. Boundary B4: Proxy ↔ AI APIs

The proxy's `allow_hosts` is restricted to **API endpoints only** (`constants.AI_API_DOMAINS`). Browser-facing AI UI sites (`claude.ai`, `chatgpt.com`, `gemini.google.com`, `perplexity.ai` — listed in `constants.AI_BROWSER_DOMAINS`) are explicitly NOT proxied. Those surfaces are captured by the Chrome extension via DOM observation. Rationale and history are in `constants.py`; the architectural decision was ratified in PR #51 (2026-05-26) after the new-laptop install verification surfaced cert-error UX hits on the browser path.

> **v0.2.1 capture-coverage note (macOS Electron apps).** Boundary B4 (proxy-traffic capture surface) is **not violated** by the macOS desktop AI app capture gaps; the bypass occurs at the OS routing layer **before traffic reaches the boundary**. The bypass means Vigil doesn't see certain flows, not that it sees them and fails to enforce the boundary. Trust-boundary properties (X.509 NameConstraints, no-modification, sensitive-data masking, 30-day auto-purge) remain intact for every flow the proxy does intercept.
>
> Mechanism: on macOS the system HTTPSProxy is configured at a single IPv4 host via `networksetup -setsecurewebproxy`. Electron-based AI apps (Claude Desktop, ChatGPT Desktop) split networking across child processes — the network-service helper honors that proxy for routine traffic, but the main process may maintain persistent IPv6 channels to AI APIs that bypass the IPv4 system proxy entirely. PAC (proxy auto-config) was empirically tested in the v0.2.1 sprint: validated for native CFNetwork apps (Swift `URLSession` test routed an IPv6-resolvable host through the IPv4 proxy successfully), but for Electron main processes it routes a subset of traffic and cannot redirect already-established channels.
>
> The v0.3 Network Extension architecture addresses the routing-layer gap by capturing at the OS network stack level, where routing-layer bypasses are not possible. `ai-monitor --status` surfaces the live capture state per surface (PR #72's four-verdict matrix) so users see the honest verdict rather than a uniform "captured" label.

### 6.1 Spoofing

**T4.1: Proxy presents a malicious CA cert to the user.**

- *Vector:* Compromised installer ships a different CA certificate that has broad MITM capability.
- *Mitigation:* The custom CA is generated per-install by `security.py::generate_custom_ca` with X.509 NameConstraints limiting it to AI domains only. The setup wizard explains this in plain language before prompting for trust.
- *Residual risk:* A compromised installer could ship a backdoored `security.py`. Mitigated by Apache 2.0 licensing (anyone can audit), code signing (planned v0.3), and reproducible builds (planned v1.0).

**T4.1a: Proxy is enabled without the CA actually being trusted (partial trust state).**

- *Vector:* `security.py::trust_ca_cert` invokes `security add-trusted-cert` via osascript. osascript can return exit 0 even when the admin password dialog was cancelled, Touch ID timed out, or `add-trusted-cert` ran but the user has not actually applied admin trust settings. Pre-fix the wizard recorded `trust_ca = ok` based on osascript exit; the system proxy was then enabled and routed AI traffic through a CA that browsers/apps did not actually trust, producing cert errors with zero useful capture and exposing the user to a confused trust state.
- *Mitigation:* `security.py::verify_ca_trusted` is called immediately after `trust_ca_cert` and joins on the cert's SHA-1 fingerprint to confirm presence in both (a) `security find-certificate -Z -a /Library/Keychains/System.keychain` and (b) `security trust-settings-export` admin-domain output. The setup wizard gates Step 3 (system proxy) on this verification — refusing to enable the system proxy if trust did not actually apply. `--status` shows the two-line CA cert + CA trust state so a partial-trust drift is visible without re-running setup.
- *Residual risk:* Trust state can drift after install (admin trust settings cleared by another tool, FileVault rotation in macOS upgrade scenarios). `--status` surfaces the current state; the user must re-run `ai-monitor --setup` to recover. The trust-settings-export plist is written to a `tempfile.mkstemp`-allocated path; `security` rewrites it with its own umask, so the chmod 600 is reapplied before reading and the file is unlinked in `finally`.

**T4.1b: osascript silently fails to apply admin trust on macOS Sequoia (15) and later (Bug 2).**

- *Vector:* `osascript "do shell script ... with administrator privileges"` runs the inner `security add-trusted-cert -d -r trustRoot` as root, but the spawned subprocess lacks GUI session ownership in the WindowServer's sense. The `SecTrustSettingsSetTrustSettings` call inside `security` returns `errSecInteractionNotAllowed`; the `security` binary writes the error to stderr but exits 0. The cert is added to System.keychain, but admin trust is NOT applied. On Sequoia+ this is the common-path outcome, not an exception — confirmed by the new-laptop verification at `~/Documents/vigil-notes/v02-reproduction-new-laptop-2026-05-27.md`. The `authorizationdb write com.apple.trust-settings.admin allow` workaround is dead on Sequoia (SIP-protected; see GitHub Actions runner-images #11893).
- *Mitigation:* `security.py::trust_ca_cert_with_fallback` implements a two-attempt strategy. Attempt 1 keeps the osascript invocation (still works on Monterey/Ventura). Attempt 2 — invoked when `verify_ca_trusted` reports `in_keychain_but_not_trusted` after attempt 1 — prints the exact `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <cert>` command for the user's terminal and polls `verify_ca_trusted` every 2 seconds for up to 120 seconds. The user runs `sudo` in their own terminal under their own sudo policy (preserves Apple's "user explicitly authorized" guarantee — Vigil never executes `sudo` itself). The poll detects trust convergence within one tick and prints `✅ Certificate trusted. Continuing setup.` `stdin_fallback=sys.stdin.isatty()` so CI / daemon mode skips the fallback and returns False immediately rather than hanging on input. osascript stderr is captured and logged via `logger.warning`, so failure modes are visible in daemon logs.
- *Residual risk:* User can skip the fallback (Ctrl-C) or let it time out; in both cases the wizard records `trust_ca = manual_required` and Step 3 (system proxy) is gated off. The user runs `sudo` outside Vigil's control, so an attacker on the user's machine could in principle replace the cert file between when Vigil prints the command and when the user pastes it. This is the same trust model as every other macOS app that documents a manual `sudo security` step (mitmproxy, Charles, Proxyman before they shipped privileged helpers); the threat is bounded by the user already having local code execution on their own machine. v0.3 will ship a notarized SMJobBless / SMAppService privileged helper to eliminate the terminal sudo step entirely — see `~/Documents/vigil-notes/v03-privileged-helper-smjobbless.md`. Design rationale and the implementation plan: `docs/design/bug2-osascript-trust.md`.

### 6.2 Tampering

**T4.2: Proxy modifies AI API responses.**

- *Vector:* Proxy is in-band and could in principle modify responses.
- *Mitigation:* The mitmproxy addon (`watch.py`) does not modify any flows; it only observes and logs. The dual-write to CSV + DB pattern preserves the original on disk.
- *Residual risk:* Bug or malicious modification to `watch.py` could enable response tampering. Mitigated by code review and the architecture rubric flagging any new `flow.response.modify()` calls.

### 6.3 Information disclosure

**T4.3: Proxy logs leak AI API content.**

- *Vector:* Captured request/response bodies contain credentials, code, or sensitive content from the user's prompts.
- *Mitigation:* Same sensitive-data masking pipeline as Layer 1 JSONL events. The CSV dual-write goes to `~/claude_watch_output/sessions/` (chmod 700 directory).
- *Residual risk:* The user's own prompts and code are stored in plaintext (this is the product's value). Auto-purge after 30 days reduces but does not eliminate this exposure.

### 6.4 Elevation of privilege

**T4.4: Proxy is used to attack the user's banking, email, or other non-AI traffic.**

- *Vector:* Once the CA cert is trusted, any TLS site could be MITMed if mitmproxy chose to.
- *Mitigation:* This is the headline mitigation. X.509 NameConstraints in the CA cert are *cryptographically* enforced by the OS cert validator. The CA can only sign leaf certs for the configured AI domains. Even if the CA private key is stolen, it cannot be used to MITM banking.
- *Residual risk:* Bug in NameConstraints enforcement at the OS level (rare). Specifically tested on macOS 14+; older OS versions may have weaker enforcement.

## 7. Boundary B5: Browser Extension ↔ Daemon (v0.2.1+)

### 7.1 Spoofing

**T5.1: Malicious extension impersonates the legitimate browser extension.**

- *Vector:* A different extension with the same `manifest.json` name posts heartbeats and captured content to the daemon.
- *Mitigation:* The daemon authenticates the extension via the same bearer token used for dashboard access. The extension stores the token in `chrome.storage.local` which is origin-isolated.
- *Residual risk:* A malicious extension could read another extension's storage if the user installs both. Standard Chrome security model.

### 7.2 Tampering

**T5.2: Extension sends fabricated capture data to the daemon.**

- *Vector:* Compromised extension sends fake user prompts to the daemon to manipulate the dashboard.
- *Mitigation:* Extension data is treated as untrusted input. The `extension_heartbeats` and capture tables are visually distinguished in the dashboard from CLI-captured data.
- *Residual risk:* Compromised extension could inject false alerts or hide real ones. Mitigated by the heartbeat health indicator showing selector failures and user-match counts.

### 7.3 Information disclosure

**T5.3: Extension exfiltrates capture data to a third-party server.**

- *Vector:* Malicious modification to the extension's background script.
- *Mitigation:* The legitimate extension is published only via the Chrome Web Store with code review. Apache 2.0 licensed source on GitHub for verification.
- *Residual risk:* Compromised CWS account or malicious update. Standard extension threat model.

## 7.5. Boundary B7: Vigil Discovery ↔ Filesystem/Subprocess Input (added v0.2.2 — PARTIALLY mitigated)

Added 2026-06-05 with the v0.2.2 P1.2 PR. The discovery feature reads
attacker-controllable bytes from the local filesystem — MCP config files,
skill manifests, `package.json` files — and promotes them into
Vigil-trusted `Asset` records persisted to the `assets` table. The
crossing point: raw bytes read by a `DiscoverySource.discover()`
implementation become Vigil-controlled Python data structures.

**Status: PARTIALLY mitigated, NOT closed.** Display-time HTML
escaping (the Elevation row below) is deferred to Phase 7. Until that
lands, B7 remains in the partial-mitigation state.

**STRIDE for B7:**

- **Spoofing** — *Vector:* Attacker replaces a config file (e.g., a
  malicious skill swaps `claude_desktop_config.json` before a scan).
  *Mitigation:* `validate_path` rejects symlink escape + `..`
  traversal; B2 chmod-600 protects the resulting `assets` DB. Status:
  mitigated.

- **Tampering** — *Vector:* A malicious package ships `package.json`
  with path-traversal strings in `name` or `version`. *Mitigation:*
  `validate_path` rejects traversal; `safe_yaml_load` rejects unsafe
  constructors (`!!python/object/apply:`) AND billion-laughs alias
  bombs (anchor cap 10 / alias cap 15, data-derived). Status:
  mitigated.

- **Information disclosure** — *Vector:* Discovery captures token
  values into `Asset.current_state` and persists them via
  `json.dumps`. *Mitigation:* `redact_secrets_in_env` is heuristic
  (8 value patterns + 5 name-suffix patterns), env-scoped,
  source-invoked. **Residuals possible** when the token shape is
  novel or when the source author forgets to call the redactor.
  **chmod-600 on `monitor.db` is the at-rest backstop**, NOT
  redaction completeness. Status: **partially mitigated**.

- **DoS** — *Vector:* Crafted YAML with billion-laughs alias expansion
  detonates at `json.dumps` (per the 2026-06-05 empirical detonation
  profile: `safe_load` is bounded; `json.dumps` unfolds shared refs).
  *Mitigation:* `safe_yaml_load` rejects > 10 anchors or > 15 aliases
  BEFORE `yaml.safe_load` runs. `validate_path` enforces the 10 MiB
  file-size cap. `safe_subprocess` enforces wall-clock timeouts.
  Status: mitigated.

- **Elevation** — *Vector:* A crafted skill manifest injects HTML
  content that reaches the dashboard via `Asset.current_state` without
  escaping, causing XSS in the operator's browser. *Mitigation:*
  Spec §4.7.5 requires HTML-escaping at display time — **deferred to
  Phase 7 (UI shell)**. **Status: deferred. B7 is NOT closed.**

## 8. Boundary B6: Agent Identity (planned v0.3)

The boundary between "an AI agent claims to be Claude Code" and "the system confirms this is the legitimate Claude Code binary, signed by Anthropic, in its expected location."

v0.2 does not enforce this boundary. The existing process scanner detects AI agents by process name only, without verifying provenance. This is a known gap — addressed in v0.3.

v0.3 introduces agent provenance verification via code signature, expected install location, binary hash registry, and behavior policy. See [docs/design/agent-detection.md](../design/agent-detection.md) for the full design including STRIDE analysis for B6 and the policy model.

Threats deferred to v0.3:

- **T6.1:** Adversarial binary renamed to match a known agent.
- **T6.2:** Hidden agent installed in `/tmp`, `~/Library/Caches/`, or cron, calling AI APIs to exfiltrate data.
- **T6.3:** Compromised legitimate agent reading files beyond expected scope.
- **T6.4:** Compromised known-agent registry granting silent allowlist to malicious binaries.

Until v0.3 mitigations exist, v0.2's existing protections are limited to:

- Sensitive-data detection pipeline (catches credential exposure regardless of which agent caused it).
- Process inventory in the System tab (visibility-only, no policy).

## 9. Summary risk table

| Boundary | Highest residual risk | Mitigation maturity | Action item |
|----------|----------------------|---------------------|-------------|
| B1 User↔Dashboard | New endpoint missing auth | Strong (C1-FOLLOWUP verified) | Custom AST check planned |
| B2 Daemon↔DB | Plaintext bypass at insert | Strong (C3 fail-closed) | DB encryption-at-rest in v0.3 |
| B3 Daemon↔CP | Plaintext leak in sync | Strong (sync sanitizer + fail-closed) | New field type means update `_SANITIZE_TEXT_FIELDS` |
| B4 Proxy↔AI | NameConstraints bug at OS | Strong (cryptographic enforcement) | Periodic verification on new macOS versions |
| B5 Browser ext | Fabricated capture data | Moderate (visual distinction) | Heartbeat health enforcement |
| B6 Agent Identity | Adversarial binary impersonation | None in v0.2; v0.3 addresses | See design doc |

## 10. Open threat-model questions

- Should the daemon refuse to run if the user is root? (Currently allowed; should perhaps warn.)
- Should the dashboard be HTTPS-only on `localhost`? (Token over HTTP is acceptable on loopback, but some users will set `--bind 0.0.0.0` for remote access; that should force HTTPS.)
- Should the auto-purge be configurable down to 7 days? (Currently fixed at 30; some enterprise customers may want shorter.)
- Should the control plane sync default to OFF in OSS, requiring explicit opt-in? (Currently OFF by default; documented as opt-in only.)

## 11. Review history

- 2026-05-24: Initial draft for v0.2 launch.
- Future: Quarterly review or on any major architectural change.
