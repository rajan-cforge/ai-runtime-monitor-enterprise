# Design Doc — Agent Provenance and Behavior Classification

**Status:** v0.3 design candidate (post-v0.2 launch)
**Author:** Rajan Yadav, Founder & CEO, GoCloudForge, Inc.
**Last updated:** 2026-05-25
**Target version:** v0.3 (Q3 2026)
**Replaces:** None (new capability)
**Companion docs:** [PRD](../spec/PRD.md), [THREAT-MODEL](../spec/THREAT-MODEL.md), [ARCHITECTURE](../ARCHITECTURE.md)

## 1. Why this exists

Vigil v0.2 detects AI agent activity and surfaces sensitive-data exposure. It assumes the AI agents on the user's machine are legitimate (Claude Code, Cursor, Copilot, etc.) and watches what they do.

This assumption is increasingly unsafe.

Three threat patterns motivate this design:

**Pattern A — Planted helper scripts.** An attacker drops a script into `/tmp`, `~/Library/LaunchAgents/`, `~/.cache/`, or similar locations, gives it a benign name, and configures it to call AI APIs (Anthropic, OpenAI). The script exfiltrates data by encoding it in prompts and reading responses, or simply uses the AI APIs as a covert channel. To v0.2's monitoring, this looks like "an unknown process is talking to api.anthropic.com" — which the current system flags weakly because it doesn't have a strong concept of "expected" agents.

**Pattern B — Compromised legitimate agents.** A real AI agent (Claude Desktop, ChatGPT Desktop) is compromised via supply chain attack, malicious update, or attacker access to the user's account. The compromised agent reads files it shouldn't, accesses credentials it has no business touching, or extends its scope. v0.2 sees this as "Claude Desktop is doing things" — true but missing the point that it's doing things outside its normal pattern.

**Pattern C — Adversarial AI agents posing as legitimate.** An attacker installs a custom binary or extension that masquerades as a known AI agent (renames itself "claude" or "cursor"), runs from an unexpected location, and exploits the trust users have in AI agents. v0.2 might match it on process name and trust it without verifying provenance.

The April 2026 Vercel/Context.ai incident referenced in the PRD is a real example. The Context.ai Chrome extension had legitimate provenance but excessive permissions; the compromise chain abused that trust. Vigil v0.2 would have detected the credential exposure but not the structural risk of "this extension has Allow All permissions and shouldn't."

The threat is no longer just "AI agents leak data." It's "the AI agent itself is the threat vector."

## 2. What we're adding

Three capabilities, layered:

**Capability 1 — Agent provenance verification.** For every AI agent detected on the system, determine its identity beyond process name: code signature, file path, install method, expected vs actual location, expected vs actual binary hash. Classify as `verified` (known agent, expected location, valid signature), `unverified` (matches name pattern but lacks provenance signals), `suspicious` (mismatches expected location, unsigned binary, or runs from temp/cache directories), or `unknown` (no name match against the known-agent registry).

**Capability 2 — Behavior policy per agent identity.** Policies expressed as `<agent identity> + <action class> + <resource pattern> → <decision>`. Example: `claude-code (verified) reading ~/.env files in working directory → allow`. `unknown-agent reading ~/.env in user home → alert critical`. Policies have allowlist semantics by default (deny-unknown) with explicit override capability.

**Capability 3 — Hidden agent discovery.** Active scanning for AI agents that don't appear in standard process tables: scripts in `/tmp`, `~/Library/LaunchAgents/`, `~/.cache/`, cron entries, shell function definitions, npm/pip installed CLIs that call AI APIs. Plus detection of inbound network connections that look like AI agents reaching into the system from outside.

These three capabilities together turn "see what AI agents are doing" into "verify which agents are allowed and what each one may do."

## 3. Threat model expansion

The existing threat model documents five trust boundaries (B1-B5). This capability introduces a sixth.

**B6 — Agent identity boundary.** The boundary between "an AI agent claims to be Claude Code" and "the system confirms this is the legitimate Claude Code binary, signed by Anthropic, in its expected location."

STRIDE analysis for B6:

| Category | Threat | Mitigation |
|----------|--------|------------|
| Spoofing | Adversarial binary renamed to "claude" or "cursor" | Code signature verification; expected install location enforcement; binary hash registry |
| Tampering | Modified legitimate binary | Hash mismatch with expected version; signature break |
| Repudiation | User claims they didn't run a hidden agent | Agent discovery log captures launch context (parent process, user, timestamp) |
| Information disclosure | Adversarial agent reads sensitive files using AI-agent trust | Policy denies unknown agents; verified-agent policies are tightly scoped |
| Denial of service | Spammed agent processes overwhelm scanner | Rate-limited agent discovery; suspicious-pattern fast path |
| Elevation of privilege | Hidden agent installs persistence (LaunchAgent, cron) | Persistence-location scanning surfaces this explicitly |

The mitigations require new code (signature checker, hash registry, persistence scanner) and new data (agent registry, policy store). This is non-trivial; section 7 discusses scope.

## 4. Detection signal taxonomy

To classify an agent, we need observable signals. Six categories:

**Process signals (already partially collected in v0.2):**
- Process name and command line
- Parent process chain
- User context (uid, euid)
- Start time and source (terminal, launchd, cron, shell script, parent)
- Process binary path
- Working directory

**Filesystem signals:**
- Binary signature (codesign on macOS; signing cert chain)
- Binary hash (SHA-256 of the executable)
- Binary location (system path, user home, /tmp, hidden directory)
- Install method (Homebrew, npm global, pip, manual)
- File ACLs and ownership
- Embedded metadata (Info.plist on macOS, ELF notes on Linux)

**Network signals (already partially collected in v0.2):**
- Outbound connections to AI API hosts
- Connection patterns (continuous stream vs. periodic burst vs. one-shot)
- DNS lookups (which AI services queried)
- TLS SNI fields (which hostnames requested)
- Inbound connections claiming to be AI agents

**Behavior signals:**
- Files read and write patterns
- Sensitive file access (.env, .ssh, credentials)
- Subprocess spawning patterns
- API call rates and shapes (matches normal Claude Code patterns vs. abnormal)

**Provenance signals:**
- Match against known-good binary registry (we maintain this; see section 6)
- Match against known-bad binary registry (OSV, ThreatFox, our own corpus)
- Account/user that installed the binary
- Time of install vs. time of first observation

**Persistence signals:**
- Whether the agent is configured to auto-start (LaunchAgent, cron, shell rc, login items)
- Whether it has a launcher in non-standard locations
- Whether it persists across reboots

A classification engine takes signals across all six categories and produces a verdict. The verdict isn't a single boolean — it's a structured object: `{identity: 'claude-code', verification: 'verified', location_risk: 'low', persistence: 'standard', behavior_anomaly: null, signature_status: 'valid'}`. Policies act on the structured verdict, not raw signals.

## 5. Policy model

Policies are how the user (and eventually the organization) expresses "this agent may do this; that agent may not do that."

### 5.1 Policy structure

Each policy is a tuple:

```
identity: <agent name or pattern>
verification: <required verification level>
action: <file_read | file_write | network_connect | subprocess_spawn | sensitive_access>
resource: <path pattern, host pattern, or category>
context: <optional: working directory, time window, parent process>
decision: <allow | alert | deny>
priority: <integer, higher wins on conflict>
```

Example policies:

```yaml
- identity: claude-code
  verification: verified
  action: file_read
  resource: "**/.env"
  context: { working_dir_under: "{project_root}" }
  decision: allow
  priority: 100

- identity: "*"
  verification: any
  action: file_read
  resource: "**/.ssh/**"
  decision: alert
  priority: 90

- identity: "*"
  verification: unverified
  action: network_connect
  resource: "api.anthropic.com | api.openai.com | *"
  decision: alert
  priority: 80

- identity: "*"
  verification: any
  action: subprocess_spawn
  resource: "curl | wget | nc"
  context: { parent_in: ["/tmp/**", "~/Library/Caches/**"] }
  decision: deny
  priority: 110
```

Allow rules are explicit. Anything not matched by an allow rule is alerted by default (allowlist semantics). Deny rules are stronger than alert; they're for known-bad patterns where action should be taken without user intervention.

### 5.2 Default policy bundle

v0.3 ships with a default policy bundle that captures sensible defaults:

- Verified AI agents (Claude Code, Cursor, Copilot, Aider, etc.) may read/write files within their detected working directory
- Verified AI agents may connect to their corresponding AI API hosts
- Any agent reading `.env`, `.ssh/`, `~/Library/Keychains/`, `~/.aws/credentials`, `~/.gnupg/`, `~/.config/git/` is alerted
- Any unverified agent connecting to AI API hosts is alerted
- Any agent originating from `/tmp/`, `~/Library/Caches/`, or similar transient directories is alerted at critical severity
- Any agent installing persistence (LaunchAgent, cron) requires explicit approval

These defaults are conservative but not noisy. A developer running Claude Code on a real project should see zero alerts under defaults. An attacker dropping a `/tmp/helper.py` that calls Anthropic API should see immediate critical alerts.

### 5.3 Policy management UX

The user needs a way to:

1. See current effective policies
2. Add an exception ("this script in /tmp is mine; allow it")
3. Tighten a policy ("alert on Claude Code reading ~/.aws/, not just allow")
4. Roll back a policy change
5. Import a policy bundle from a known source (security team, community policies)

Three design options for the UX:

**Option A: Dashboard tab.** A new "Policies" tab in the dashboard alongside Alerts, Live Feed, etc. Pros: discoverable, integrated. Cons: dashboard is already nine tabs; adding a tenth strains the navigation.

**Option B: Dedicated app or menu bar.** A separate UI specifically for policy management. Could be a small macOS app or a menu bar item that opens to policy UI. Pros: gives policy management its own affordance. Cons: more infrastructure.

**Option C: YAML files + dashboard view.** Power users edit YAML files in `~/.config/ai-runtime-monitor/policies/`. Dashboard provides a read-only view of effective policies with diff history. Pros: simple, scriptable, gitable. Cons: less accessible for non-power-users.

**Recommended:** Option C with a path to Option A. Ship v0.3 with YAML-based policies and a read-only dashboard view. Add a Policies tab in v0.4 with WYSIWYG editing.

Rationale: policy editing is high-stakes (wrong policies can break the user's workflow or hide attacks). Power users want gitable, scriptable, code-review-able policies. Casual users will use defaults and rarely touch policies. The interactive UI is a v0.4 polish item, not a v0.3 blocker.

### 5.4 The "extension" question

You mentioned a browser extension for managing the allowlist. My judgment: not the right form factor for this.

Browser extensions are great for browser-scoped policies (cookies, scripts, content). Vigil's policy model is OS-scoped (file access, processes, network from any source). A browser extension can't enforce or even observe most of what we need to control.

If we want a "quick approve" UX for alerts, that belongs as a desktop notification with action buttons (macOS's notification center supports "Allow / Deny" buttons), not a browser extension. v0.4 territory.

The existing browser extension (v0.2.1) stays scoped to its current job: capturing content from claude.ai, chatgpt.com, gemini.google.com. Don't expand it into policy management.

## 6. Known-agent registry

The provenance system needs ground truth: what are the legitimate AI agents, where do they live, who signs them?

Registry structure:

```yaml
agents:
  claude-code:
    display_name: "Claude Code"
    publisher: "Anthropic, PBC"
    expected_install_paths:
      - "/usr/local/bin/claude"
      - "{HOME}/.local/bin/claude"
      - "/opt/homebrew/bin/claude"
    expected_signature_team_id: "K3DG87S4FN"  # Anthropic's macOS team ID
    binary_hash_pattern: "matches @anthropic-ai/claude-code-cli releases"
    expected_network_hosts:
      - "api.anthropic.com"
      - "console.anthropic.com"
    install_methods:
      - "npm install -g @anthropic-ai/claude-code-cli"
      - "brew install claude"
    documentation_url: "https://claude.com/code"
  
  cursor:
    display_name: "Cursor"
    publisher: "Anysphere, Inc."
    expected_install_paths:
      - "/Applications/Cursor.app"
    expected_signature_team_id: "ZE9F7Q8K2L"  # placeholder, look up real
    expected_network_hosts:
      - "api.cursor.sh"
      - "api2.cursor.sh"
    # ...
```

Maintenance:

- v0.3 ships with the registry baked into the source tree
- Updates come via the auto-update mechanism (config refresh from GoCloudForge servers, opt-in)
- Community contributions accepted via GitHub PR to the registry file
- Verification of registry entries is critical — we don't want adversaries adding fake "verified" entries

The registry is the single most attack-worthy artifact in this design. Compromise of the registry = silent allowlisting of arbitrary binaries. Defensive measures:

- Registry file signed by a key controlled by GoCloudForge
- Daemon verifies the signature before trusting the registry
- Registry updates require user confirmation in v0.3 (auto-update opt-in in v0.4)

## 7. Implementation scope

This is the part that determines whether it's a 2-week or 2-month feature.

### 7.1 Minimum viable v0.3 (4-6 weeks)

- Agent inventory: list every AI agent process with its provenance signals (location, signature status, hash)
- Hidden-agent scanner: walk `/tmp/`, `~/Library/LaunchAgents/`, cron, shell rc files for AI-API-calling scripts
- Known-agent registry: hardcoded for the top 10 AI agents (Claude Code, Cursor, Copilot, Aider, Continue, Codex CLI, Gemini CLI, OpenClaw, Windsurf, plus a generic catch)
- Basic policy engine: identity + action + resource → decision, allowlist semantics
- Default policy bundle covering the most important cases (sensitive file access, unverified network, /tmp scripts)
- Dashboard read-only "Agents" tab: shows the inventory with verification badges
- Dashboard read-only "Policies" view: shows effective policies, no editing yet

Out of v0.3:

- Interactive policy editor in dashboard (v0.4)
- Desktop notifications with action buttons (v0.4)
- Auto-update of the agent registry (v0.4)
- Fleet-scoped policies (v1.0 Enterprise)
- ML-based behavior anomaly detection (v1.0+)
- Signing certs for the registry itself (v1.0)

### 7.2 What changes in existing modules

`monitor.py` — adds the agent provenance scanner alongside the existing ProcessScanner. Probably creates a new `AgentProvenanceScanner` class that runs on the same scheduling pattern.

`constants.py` — adds `KNOWN_AGENTS` registry data structure.

`db.py` — new tables: `agent_inventory`, `agent_policies`, `agent_alerts` (alerts specifically tied to policy violations, distinct from sensitive-data alerts).

`security.py` — possibly adds signature verification helpers if we go beyond shelling out to `codesign`.

New module `policy_engine.py` — the policy evaluator. Pure functions, no I/O. Easy to test.

New module `agent_provenance.py` — the provenance signal collector. Has I/O (codesign, file hash, etc.).

`dashboard.html` — new tab, new view logic.

`docs/spec/functional/policy_engine.md` and `agent_provenance.md` — new functional specs.

### 7.3 Risks

**Risk 1: Provenance signals are platform-specific.** macOS codesign is well-understood; Linux package provenance is messier; Windows is its own thing. v0.3 may be macOS-only for this capability, with Linux/Windows in v0.4.

**Risk 2: False positives kill the feature.** If "Claude Code reading .env" alerts the user every time they do legitimate development, the alerts become noise and the user disables them. Default policies must be conservative *and* permissive of normal workflows.

**Risk 3: Performance.** Agent provenance signals are expensive to collect (codesign is slow, hashing is slow). Caching is critical. Scanning every process on every cycle is non-starter; scanning new processes once at first sighting is the right pattern.

**Risk 4: Policy expressiveness ceiling.** YAML policies can capture simple rules but get awkward for nuanced ones ("Claude Code reading .env is okay only on weekdays during work hours"). v0.3 commits to allowlist semantics with simple patterns; richer expressiveness is v0.4+.

**Risk 5: Registry compromise.** Already discussed. Defensive measures required from day one.

### 7.4 Open questions

These are deferred to v0.3 sprint kickoff, not decided in this design doc:

- **Do we ship Linux support in v0.3 or v0.4?** Depends on customer pull. Many enterprise developers use Linux. Skipping it limits the addressable market.
- **Should hidden-agent scanning be opt-in or default-on?** It scans paths some users consider private. Default-on is more secure; opt-in is more respectful. Probably opt-in with prominent prompt during the wizard.
- **What's the threshold for "suspicious location"?** /tmp is obvious. ~/.cache/ contains both legitimate (npm cache) and suspicious patterns. Need an empirical signal-vs-noise analysis.
- **How do we handle in-development AI agents?** A developer building their own AI agent will get flagged as "unverified" forever. There needs to be a "trust this binary for development" affordance.
- **Cross-product policy interaction with EDR.** If the customer has CrowdStrike, does Vigil's policy engine coordinate or compete? Probably coordinate — Vigil's alerts feed CrowdStrike's investigation tools. Detailed integration is v1.0 Enterprise work.
- **Privacy implications.** The hidden-agent scanner reads files in user directories. We need clear documentation about what we scan and why, possibly an "audit mode" that shows the user exactly what the scanner is reading.

## 8. UX direction

This section is intentionally light because UX is best designed iteratively against real user feedback. But initial directions:

### 8.1 Agents tab

A new tab in the dashboard listing all detected AI agents. Columns:

- Identity (name + display badge)
- Verification status (verified / unverified / suspicious / unknown — color-coded)
- Location (path, with risk highlight for `/tmp/`, etc.)
- First seen (timestamp)
- Last activity (timestamp)
- Behavior summary (recent files read, recent connections, recent subprocess calls)
- Policy match summary (how many alerts has it triggered)

Clicking an agent opens a detail panel with full provenance signals and behavior history.

### 8.2 Policy view

A read-only view (in v0.3) showing:

- Active policies in priority order
- Match counts (how many times each policy has fired)
- Suggested policy changes based on observed behavior ("you've allowed Claude Code 47 times; want to make this default for similar agents?")

### 8.3 Alert evolution

The existing Alerts tab gets a new alert category: "Policy violation." These are alerts where an agent's behavior violated a policy. They sit alongside the existing "Sensitive data exposure" alerts.

A user clicking on a policy violation alert sees:
- The agent that triggered it
- The action that triggered it
- The resource involved
- The policy that fired (with link to view the policy)
- Suggested response (deny in future, allow this once, allow always for this resource)

### 8.4 First-run UX

When v0.3 launches, existing users get a one-time prompt: "Vigil v0.3 introduces agent provenance verification. Review your AI agents [show count] to see which are verified and which need attention." The user can defer or step through.

For new users, the wizard adds a step explaining what agent provenance is and asking whether to enable the hidden-agent scanner.

## 9. Strategic narrative

This feature is the bridge between Vigil's "detect" stage (v0.2) and its "prevent" stage (v1.5). The pitch deck's three-stage roadmap — detect, prevent, reduce blast radius — gets its first concrete prevention capability here.

Before v0.3: Vigil sees AI agent activity.
After v0.3: Vigil sees AI agents themselves, verifies their identity, and applies policies to what they do.

This is the answer to "what does Vigil do that CrowdStrike AIDR doesn't?" CrowdStrike does behavioral anomaly detection on processes. It doesn't know which AI agent is which, doesn't have an allowlist concept, can't distinguish "Claude Code reading .env in a project directory" from "unknown agent reading .env in user home." Vigil v0.3 does.

For investor and design-partner conversations, this design doc is the artifact that says "we've thought about this and have a real plan." The PRD roadmap entry (added in a separate small PR) is the public commitment. The v0.3 implementation is the proof.

## 10. Roadmap commitment

This design lands as a v0.3 capability:

- **Phase 0 (now, May 2026):** This design doc lands as `docs/design/agent-detection.md`. PRD updated with a single sentence in section 6 (v0.3 roadmap). Threat model updated to add B6 boundary placeholder noting v0.3 mitigation.
- **Phase 1 (v0.2 launch, May 2026):** No code work on this feature. Launch happens.
- **Phase 2 (post-launch, June 2026):** Design doc reviewed with first design partners. Gather initial feedback. Refine the registry, the default policies, the UX direction.
- **Phase 3 (v0.3 sprint, July-August 2026):** Implementation per Section 7.1 scope. Targeted v0.3 release: late Q3 2026.

This pacing means the feature is shipped right rather than rushed. v0.2 launches on its v0.2 promises; v0.3 delivers a category-creating capability with proper design backing it.

## 11. Authority

This design doc is a candidate for v0.3 work. It is not a binding commitment to specific implementation choices. The v0.3 sprint kickoff will:

- Validate this design against actual code-reviewer + architect + performance agent rubrics
- Surface any constraints the design didn't anticipate
- Refine the policy model based on real registry data
- Confirm the UX direction with design partners

Per the source-honesty contract: this is a "derived" design — emerged from a feature direction discussion, not from a pre-existing requirement. It is being surfaced for explicit ratification before v0.3 implementation begins.

## 12. Action items

- [ ] Land this design doc as `docs/design/agent-detection.md` (small PR; criticality C0)
- [ ] Update PRD section 6 v0.3 roadmap with one-sentence entry (small PR; criticality C0)
- [ ] Update THREAT-MODEL.md to add B6 boundary as v0.3 mitigation placeholder (small PR; criticality C0)
- [ ] Share design doc with 3-5 prospective design partners post-launch
- [ ] Schedule v0.3 sprint kickoff for early June 2026
- [ ] Build initial known-agent registry data (~10 agents) as v0.3 prep work
