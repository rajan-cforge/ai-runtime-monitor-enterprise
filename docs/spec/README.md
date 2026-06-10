# Vigil specification index

This directory holds the formal specifications for AI Runtime Monitor (Vigil). These documents are the source of truth for what the product does, how it's architected, what threats it addresses, and how its design intent is enforced.

## Document map

| Document | Purpose | Audience | Status |
|----------|---------|----------|--------|
| [PRD.md](./PRD.md) | Product requirements — what Vigil is, who it's for, what's in v0.2 | Investors, customers, internal team | Landed (PR #34) |
| [openapi.yaml](./openapi.yaml) | Machine-readable API spec for all 22+ endpoints | API consumers, client generators, contract testers | Landed (PR #36) |
| [API-CONTRACTS.md](./API-CONTRACTS.md) | Human-readable narrative for openapi.yaml | Developers building integrations, customers | Landed (PR #36) |
| [THREAT-MODEL.md](./THREAT-MODEL.md) | STRIDE threat model across 6 trust boundaries (B6 planned v0.3) | Security reviewers, enterprise procurement | Landed (PR #37); B6 added PR #44 |
| [SECURITY-MANIFEST.md](./SECURITY-MANIFEST.md) | Controls mapped to OWASP ASVS, NIST SSDF, OWASP Top 10 | Security reviewers, compliance auditors | Landed (PR #37) |
| [DATA-CLASSIFICATION.md](./DATA-CLASSIFICATION.md) | Data sensitivity tiers, retention policies, third-party transmission | Enterprise procurement, compliance auditors | Landed (PR #37) |
| [functional/](./functional/) | Per-module functional specs (monitor, sync, security, watch, wizard, status, db, config, scanners) | Engineers maintaining the codebase | Landed (PR #38) |
| [dependency-rationale.md](./dependency-rationale.md) | Justification for each runtime dependency; required by spec-requirements CI rule on `pyproject.toml` changes | Engineers proposing new dependencies, reviewers | Landed (PR #40) |

Plus the technical architecture reference (lives at `docs/ARCHITECTURE.md`, consolidated in PR #35):

| Document | Purpose |
|----------|---------|
| [../ARCHITECTURE.md](../ARCHITECTURE.md) | Technical architecture, trust boundaries, data flows, module dependency graph, deployment model, extensibility points |

## Source-honesty rules

These specs follow the source-honesty contract from the SSDLC framework:

- When a requirement is referenced but not yet authored, it is logged as **"not yet authored"** in the relevant doc, never invented
- When an architectural decision emerges from implementation that wasn't in a prior spec, it is marked **"derived"** and surfaced for explicit ratification before merge
- When code diverges from a spec, the resolution is either spec revision (explicit PR) or code revert — never silent divergence

## Maintenance triggers

These specs must be reviewed and possibly updated when any of the following occur:

| Trigger | Documents affected |
|---------|--------------------|
| New AI capability added (detection rule, scanner type) | PRD, functional spec for the relevant module |
| API endpoint added, removed, or signature changed | openapi.yaml, API-CONTRACTS.md |
| New trust boundary introduced (e.g., cloud control plane) | THREAT-MODEL.md, SECURITY-MANIFEST.md |
| New security control implemented or required | SECURITY-MANIFEST.md |
| Major version bump (v0.2 → v0.3, v1.0, etc.) | All docs (full review) |
| Customer or auditor question reveals a gap | Whichever doc the question hit |

The maintenance trigger list is the input to the CI enforcement rules in `.github/spec-requirements.yaml` (active in CI as of PR #40 — the spec-requirements job in `.github/workflows/ci.yml` is a required status check on `main`).

## Document lifecycle

### Created in this drop (2026-05-24)

All six primary docs were authored in a single session to fill the spec gap that existed at v0.2 launch. The pitch deck, README, ARCHITECTURE.md, and code itself provided the source material. Each doc was reviewed against the actual code to ensure accuracy.

### Pre-launch updates

Updates between now and v0.2 launch (Day 7) are limited to corrections and clarifications. No new sections.

### Post-launch

After v0.2 launch:
- Quarterly reviews of all docs
- Per-change updates triggered by the CI spec-requirements rules
- Major revision at each major version bump (v0.3, v1.0)

## Relationship to other docs

The spec directory is one of several documentation layers in the project. The complete map:

```
docs/
├── spec/                          # This directory — formal specs
│   ├── PRD.md
│   ├── openapi.yaml
│   ├── API-CONTRACTS.md
│   ├── THREAT-MODEL.md
│   ├── SECURITY-MANIFEST.md
│   ├── DATA-CLASSIFICATION.md
│   ├── dependency-rationale.md
│   ├── functional/
│   └── README.md (this file)
├── design/                        # Design candidates awaiting ratification
│   └── agent-detection.md         # v0.3 capability design
├── SSDLC_ENFORCEMENT.md           # Engineering process and controls catalog
├── BRANCHING.md                   # Git workflow and merge strategy
├── CLAUDE-WATCH.md                # claude-watch user/operator guide
├── SSL_INSPECTION.md              # HTTPS proxy + CA setup
├── SUPPLY_CHAIN_DESIGN.md         # Supply-chain attack surface design
└── ARCHITECTURE.md                # Technical architecture (separate from spec/)
```

Project-level docs (BRANCHING, SSDLC_ENFORCEMENT, etc.) describe **how** we work. Spec docs (this directory) describe **what** the product is.

The product-level README.md at the repo root is the entry point for new users. It links to the spec docs for those who want more depth.

## Standards bundle

This project aligns to the following external standards:

- **OWASP ASVS Level 2** — primary application security standard
- **NIST SP 800-218 SSDF** — secure software development framework
- **OWASP Top 10 2021** — common application security risks
- **AWS Well-Architected Security Pillar** — for control plane infrastructure (post v1.0)

Mappings to specific controls are in [SECURITY-MANIFEST.md](./SECURITY-MANIFEST.md). Gaps are documented honestly with target versions.

## How to use these docs

### For investors
Start with [PRD.md](./PRD.md). It covers product vision, market, competitive positioning, and roadmap. The [SECURITY-MANIFEST.md](./SECURITY-MANIFEST.md) provides evidence of engineering rigor.

### For enterprise procurement
Read [THREAT-MODEL.md](./THREAT-MODEL.md) and [SECURITY-MANIFEST.md](./SECURITY-MANIFEST.md). These document the security posture in detail with explicit residual risks.

### For API consumers
Use [openapi.yaml](./openapi.yaml) directly with your client generator of choice. Read [API-CONTRACTS.md](./API-CONTRACTS.md) for design rationale.

### For contributors
Read the relevant [functional/](./functional/) spec before modifying a module. Read [PRD.md](./PRD.md) Section 5 (non-goals) before proposing new features. Read [SSDLC_ENFORCEMENT.md](../SSDLC_ENFORCEMENT.md) for the engineering process.

### For Claude Code (AI-assisted development)
The architect-reviewer agent applies the rubrics from `.claude/rubrics/` against every PR. Those rubrics reference these spec docs. The spec-requirements.yaml CI gate (live as of PR #40) enforces that changes touching specific code paths come with corresponding spec updates.

## Contact

For questions about any of these specs:

- Security questions: security@gocloudforge.com
- Product questions: rajan@gocloudforge.com
- Engineering questions: open a GitHub issue
