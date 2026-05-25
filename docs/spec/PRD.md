# Product Requirements Document — AI Runtime Monitor (Vigil)

**Document version:** 1.0
**Last updated:** 2026-05-24
**Owner:** Rajan Yadav, Founder & CEO, GoCloudForge, Inc.
**Status:** v0.2 launch candidate
**Audience:** Investors, enterprise customers, internal team

---

## 1. Product vision

AI coding agents (Claude Code, Cursor, Copilot, ChatGPT Desktop) now write a measurable fraction of code that ships to production. They install dependencies, access credentials, modify files, and call external APIs. No existing security product watches what they do on the developer's machine.

AI Runtime Monitor (product name: Vigil) is endpoint security for the AI developer. It captures every action AI agents take on a developer's machine, detects supply-chain and credential-exposure risks in real time, and surfaces them through a local-first dashboard. The platform extends to fleet-scale monitoring through a control plane, enabling security teams to govern AI agent usage across their developer population.

The long-term vision spans three stages: **detect** (visibility into AI agent actions, shipping in v1.0), **prevent** (block excessive OAuth scopes, malicious packages, unauthorized exfiltration), and **reduce blast radius** (least-privilege execution, session isolation, credential vaulting).

## 2. Problem statement

### 2.1 The Vercel/Context.ai incident (April 19, 2026)

A real-world incident illustrates the threat surface:

1. A Context.ai employee downloaded Roblox exploits to their personal machine. Lumma Stealer infected the machine and exfiltrated Google Workspace credentials.
2. A Vercel employee installed the Context.ai Chrome extension and granted "Allow All" Google Workspace permissions to the AI tool.
3. The attacker used the stolen OAuth token to access the Vercel employee's Google account, then pivoted into Vercel internal systems via the OAuth trust chain.
4. Vercel environment variables and customer credentials were exfiltrated and sold on BreachForums for $2M.

No security tool in the chain saw the attack. The OAuth grant was visible in Google's audit log but no endpoint product surfaced it as risky. The Chrome extension's permissions were not flagged by any antivirus or EDR. The exfiltration happened through normal API channels that supply-chain scanners don't watch.

### 2.2 The structural gap

Three categories of security products serve developers today, and none of them watch AI agent runtime behavior on the endpoint:

- **EDR / antivirus** (CrowdStrike, SentinelOne, Microsoft Defender) watches for malware. AI agents are not malware — they are sanctioned tools doing sanctioned work that occasionally produces risky outcomes.
- **Supply chain security** (Snyk, Socket.dev, Checkmarx) scans repository dependencies. AI agents install packages at runtime that never enter the repository.
- **Developer observability** (LangSmith, Langfuse, Braintrust) monitors LangChain applications the developer writes. It doesn't monitor the AI agents the developer uses.

The gap is the AI agent itself — the entity that installs the dependency, writes the code, accesses the credential, and calls the external API. No product addresses this category.

### 2.3 Market validation

- 85% of developers use AI agents daily (Stack Overflow Developer Survey 2025).
- 88% of organizations reported AI agent security incidents (IBM Cost of Data Breach Report 2025).
- Only 14% of organizations deploy AI agents with full security approval.
- 0% of organizations have endpoint visibility into AI agent actions today.
- Average cost of a shadow AI breach: $4.63M (IBM 2025).
- $18B in cybersecurity VC funding in 2025 (+26% YoY); only $414M went to AI security across 13 companies — massively underfunded relative to the threat.

## 3. Target users

### 3.1 Primary persona: Senior developer at a 100–10,000 person company

- Uses Claude Code, Cursor, or similar AI agents 4+ hours per day.
- Has shipped at least one critical bug introduced by an AI agent.
- Recognizes the security risk but lacks the time or tooling to monitor what their AI agents do overnight or in background sessions.
- Wants visibility without enterprise-software friction. Will install a free local tool to see what's happening on their own machine.
- Decision authority: $0 to $50/month for personal tools without procurement approval.

### 3.2 Secondary persona: Engineering team lead

- Has 5–50 developers under them.
- Concerned about credential exposure, malicious packages, and unauthorized data access via AI agents.
- Has heard about the Vercel/Context.ai incident and similar.
- Will champion adoption of a tool that gives their team visibility, then escalate to security/CISO for fleet-scale governance.
- Decision authority: $500–$5,000/month for team tools.

### 3.3 Tertiary persona: CISO / security leader

- 100–10,000 person engineering organization.
- Mandate to manage AI agent risk but lacks a product category to buy.
- Familiar with EDR, CSPM, CASB, SIEM. Sees AI agent monitoring as the obvious next category.
- Procurement authority: $50K–$500K annually for enterprise tools.
- Decision timeline: 3–6 months including security review, legal, procurement.

## 4. Core capabilities (v0.2)

### 4.1 Three-layer monitoring

The product captures AI agent activity through three independent layers, each functional standalone and complementary in combination:

- **Layer 1: JSONL session tailing** — Reads structured event logs that Claude Code writes to `~/.claude/projects/`. Captures every tool call, file access, command execution, prompt, and response. Zero configuration required. Works for Claude Code and OpenClaw out of the box.
- **Layer 2: System monitoring** — Polls process tables, network connections, file system events, and Chrome history via psutil and watchdog. Detects AI processes, connections to AI API hosts, file modifications by AI agents, and browser usage of AI services (ChatGPT, Gemini, Claude Web, Copilot, Perplexity, DeepSeek).
- **Layer 3: HTTPS proxy interception (optional)** — mitmproxy-based addon that intercepts AI API traffic when agents are configured with `HTTPS_PROXY`. Captures full request and response payloads, exact token counts, system prompts, message previews, tool call arguments, and latency. Selectively MITMs only AI domains via X.509 NameConstraints (banking, email, and unrelated traffic is never intercepted).

### 4.2 Sensitive data detection (DLP)

- Detects AWS keys, GitHub tokens, Anthropic API keys, OpenAI keys, Slack tokens, private keys, JWTs, credit cards, SSNs, and 15+ other sensitive patterns in AI session data.
- Validators (Luhn checksum, Shannon entropy, JWT decode, SSN rules) reduce false positives. Only matches with confidence "high" or "medium" surface as alerts.
- Severity-ranked alerts (Critical, High, Medium, Low) with drill-down to the exact turn where exposure occurred.
- Auto-purge of plaintext fragments after 30 days; metadata is retained indefinitely.
- Masking on display (first 4 + asterisks + last 4) and stable hashing for deduplication without storing plaintext.

### 4.3 Supply chain intelligence

- 19 package managers supported (pip, npm, cargo, gem, go, brew, apt, and others).
- pip-audit and OSV.dev integration for CVE detection on installed dependencies.
- ThreatFox and URLhaus integration for IP and URL threat intelligence (15K+ malicious indicators).
- Registry metadata for PyPI and npm (publication recency, maintainer changes, popularity signals).
- Typosquat detection via Levenshtein distance against popular package names.
- Pre-install detection: catches packages requested by AI agents before they execute the install.

### 4.4 Cost and usage tracking

- Token counting and cost estimation for Claude, GPT-4, Gemini, and other models.
- Burn rate forecasting with subscription plan detection.
- Per-session, per-project, per-model breakdowns.
- Daily and weekly trend visualization.

### 4.5 Dashboard

Local-first dashboard on `localhost:9081` with nine tabs:

- **Session Explorer** — Full conversation timeline replay with Deep Dive cockpit (turn rail, API inspector, context gauge).
- **Live Feed** — Real-time stream of all agent events.
- **Supply Chain** — Package inventory, CVE list, malicious package alerts, threat intel state.
- **Alerts** — Sensitive data alerts with pattern filtering and session-level triage.
- **API Traffic** — Request body inspection, token counts, cost per call, latency.
- **Activity Timeline** — Unified chronological feed across all AI sources.
- **Analytics** — Token usage charts, cost trends, tool frequency, model distribution, burn rate.
- **System** — Process table, network connections, file activity.
- **Insights** — Project intelligence (which projects use which models, which sessions hit credentials, which agents call which APIs).

### 4.6 Fleet dashboard (v0.2 — limited; v1.0 — full)

- Control plane aggregates data from every endpoint installed in the org.
- RBAC with five roles (owner, admin, operator, member, viewer).
- Org-scoped data isolation.
- SSO via SAML and OIDC.
- SIEM integration via webhook export.

## 5. Non-goals

The product explicitly does NOT do the following:

- **Replace EDR or antivirus.** Vigil watches AI agent behavior, not arbitrary malware. Customers still need EDR for general endpoint protection.
- **Replace SAST/DAST tools.** Vigil is runtime, not static. Code quality scanning belongs to other products.
- **Replace LLM observability for owned applications.** If a developer writes a LangChain app, they should use LangSmith or Langfuse to monitor it. Vigil monitors the AI agent the developer uses, not the AI app the developer builds.
- **Monitor inside agent containers or sandboxes.** v0.2 monitors the developer's primary machine. Container-scoped agents are a v0.3+ feature.
- **Enforce policies in v0.2.** Detection only. AI-agent allowlist enforcement ships in v0.3 — the first concrete prevention capability — per [docs/design/agent-detection.md](../design/agent-detection.md). Broader prevention features (blocking OAuth scopes, blocking malicious packages) ship in v1.5.
- **Monitor mobile devices.** v0.2 is macOS and Linux. Windows is v0.3. iOS/Android are not in the roadmap.
- **Monitor agents inside CI/CD pipelines.** That's a server-side problem; Vigil is endpoint-side.

## 6. Roadmap

### v0.2 — Detect (launching Day 7 of current sprint, May 2026)

- All three monitoring layers active.
- Sensitive data detection with 12 validators.
- Supply chain intelligence with OSV + ThreatFox + URLhaus.
- Local dashboard with 9 tabs.
- Browser extension scanner (deferred to v0.2.1, 5–7 days post-launch).
- macOS support; Linux best-effort.
- Open source under Apache 2.0.

### v0.2.1 — Browser Extension (post-launch, Days 12–14)

- Chrome extension content capture for claude.ai, chatgpt.com, gemini.google.com.
- Heartbeat-based health reporting.
- Integration with the daemon's alert pipeline.

### v0.3 — Hardening and Distribution (Q3 2026)

- Signed and notarized macOS .dmg installer.
- Homebrew formula.
- Windows support (process and network monitoring; proxy via WinDivert).
- Encrypted database at rest (SQLCipher).
- Container-scoped agent monitoring.

Plus: **agent provenance and behavior classification** — detect AI agents on the system (including hidden/renamed processes, /tmp scripts, scheduled tasks), verify their identity via code signature and known-binary registry, and apply behavior policies (e.g., file-read scope per agent identity). See [docs/design/agent-detection.md](../design/agent-detection.md). This is the first concrete capability in the "prevent" stage of the detect→prevent→reduce-blast-radius roadmap.

### v1.0 — Fleet Dashboard (Q4 2026)

- Production control plane with multi-tenant data isolation.
- RBAC + SSO (SAML, OIDC).
- SIEM integration (Splunk, Datadog, Sumo, generic webhook).
- Compliance reporting (SOC 2, ISO 27001 alignment).
- Pro and Enterprise pricing tiers active.

### v1.5 — Prevent (Q1 2027)

- Block excessive OAuth scopes at the OS level.
- Pre-install package blocking with override.
- Credential boundary rules (which agents can access which credentials) — richer, multi-condition policies extending the basic agent allowlist semantics shipped in v0.3.

(AI-agent allowlist enforcement — the foundation of the "prevent" stage — ships earlier, in v0.3. See [docs/design/agent-detection.md](../design/agent-detection.md).)

### v2.0 — Reduce Blast Radius (Q2–Q3 2027)

- Least-privilege execution for AI agents.
- Session isolation via container or process sandbox.
- Credential vaulting (zero-trust access to secrets).
- Kill switch / circuit breaker for runaway agents.

## 7. Success metrics

### 7.1 Adoption metrics (v0.2 launch + first 90 days)

- 10,000+ free-tier installs.
- 100+ active fleet endpoints (across paying and trial customers).
- 5,000+ GitHub stars.
- Show HN front page placement.
- Product Hunt top 5 for the day.

### 7.2 Engagement metrics (90-day post-install)

- Daily active dashboard sessions per install: ≥ 0.6 (most users open the dashboard several times per week).
- Alerts surfaced per install per week: 3–10 (high enough to feel valuable, not so high it becomes noise).
- 30-day retention: ≥ 60% of installs still running at day 30.

### 7.3 Revenue metrics (first 12 months post-launch)

- 50+ Pro subscribers ($29/month).
- 10+ Enterprise design partners (paid contracts, NDA-protected).
- $250K ARR by month 12.

### 7.4 Security efficacy metrics

- True positive rate per alert category: ≥ 85% across credential detection.
- False positive rate: ≤ 10% on stable categories (Anthropic key, AWS key, GitHub PAT).
- Median time from credential creation event to alert: < 30 seconds.

## 8. Pricing

### 8.1 Free (OSS) — $0

- Single machine.
- JSONL session tailing.
- Process and network monitoring.
- Browser extension (when available).
- Local dashboard.
- All threat intelligence feeds.
- Apache 2.0 license; community support.

### 8.2 Pro — $29/month per user

- Everything in Free.
- SSL inspection proxy (full API capture).
- Custom CA generation and trust.
- LaunchAgent service for auto-start.
- Encrypted database (SQLCipher).
- Email support (response within 48h).
- 30-day data retention default; configurable.

### 8.3 Enterprise — Contact sales

- Everything in Pro.
- Fleet dashboard (control plane).
- RBAC with five roles.
- SSO (SAML, OIDC).
- SIEM integration.
- Prevention policies (when available; v1.5+).
- SOC 2 reports.
- Custom data retention.
- Slack-based support channel; 4-hour response.
- Annual or multi-year contracts.

## 9. Competitive positioning

| Category | Examples | What they cover | What they miss |
|----------|---------|-----------------|----------------|
| Enterprise EDR | CrowdStrike AIDR, Microsoft Agent 365 | Malware, behavioral anomalies | AI agent semantic actions; sells top-down at $50K+ |
| Developer observability | LangSmith, Langfuse, Braintrust | Developer's own LLM apps | AI agents the developer uses (Claude Code, Cursor) |
| Supply chain security | Socket.dev, Snyk, Checkmarx | Repository dependencies | Runtime installs by AI agents |
| Vigil | — | All of the above at the developer endpoint | (Vigil is what's missing) |

Differentiation:

- Bottom-up adoption (developer installs free tier; team escalates to CISO) versus top-down enterprise sales.
- Endpoint-resident; works for individual developers and small teams without IT involvement.
- Cross-tool: monitors Claude Code, Cursor, Copilot, ChatGPT Desktop, Aider, and 11+ others — no other product covers more than two.
- Open source core builds community and credibility; commercial tiers (Pro, Enterprise) provide revenue.

## 10. Open questions

These are intentionally unresolved as of v0.2 launch and tracked for post-launch decision:

- Pricing for academic and individual open-source contributors. Free tier likely covers them, but enterprise contributors at large companies need clarification.
- Windows support priority. Customer pull will determine whether v0.3 includes Windows or pushes it to v0.4.
- Cloud-hosted control plane vs. self-hosted only. Initial Enterprise tier is self-hosted (customer runs the control plane). A cloud-hosted SaaS version may follow.
- Prevention policy scope and risk. Blocking OAuth scopes and packages is high-value but has user-experience risk if false positives interrupt work. Will be tested with design partners before general availability.
- Mobile coverage. iOS/Android are not in the roadmap, but developer use of mobile AI tools (ChatGPT mobile app) may force a future decision.

## 11. References

- [ARCHITECTURE.md](../../ARCHITECTURE.md) — Technical architecture and component design.
- [openapi.yaml](./openapi.yaml) — machine-readable OpenAPI 3.0 spec for the local daemon HTTP API.
- [API-CONTRACTS.md](./API-CONTRACTS.md) — narrative companion: trust model, auth, pagination, versioning.
- [THREAT-MODEL.md](./THREAT-MODEL.md) — STRIDE threat model for v0.2.
- [SECURITY-MANIFEST.md](./SECURITY-MANIFEST.md) — Mapping of implemented controls to OWASP ASVS and NIST SSDF.
- [SSDLC_ENFORCEMENT.md](../SSDLC_ENFORCEMENT.md) — Engineering process and enforcement controls.
- AI Runtime Monitor pitch deck (April 2026 v2) — Strategic context, market analysis, fundraising materials.
