# Security Policy — Vigil

Vigil is an endpoint security product. We take security reports seriously and aim to respond quickly.

## Reporting Vulnerabilities

**Please do not open a public GitHub issue for security vulnerabilities.**

Email: **security@gocloudforge.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)
- Whether you'd like credit in the disclosure

PGP encryption is available on request — reply to our initial acknowledgement and we'll exchange keys before you send the full report.

### Response Process

| Stage | Target SLA |
|-------|------------|
| Acknowledgement of report | 48 hours |
| Initial assessment + severity rating | 7 days |
| Fix + private disclosure to reporter | 30 days (severity-dependent) |
| Public advisory + CVE (if applicable) | 90 days from initial report |

If a critical issue requires an out-of-cycle release, we'll coordinate the disclosure window with you before publishing.

## Supported Versions

| Version | Supported            |
|---------|----------------------|
| 0.2.x   | Yes — active branch  |
| 0.1.x   | No — please upgrade  |

Security fixes only land on the active branch. v0.1.x users should upgrade to v0.2.x; the upgrade is a `pip install -U ai-runtime-monitor` away.

## Scope

Vigil monitors AI agent activity on the local machine. The following components are in-scope for security reports:

- **Dashboard HTTP server** — binds to `127.0.0.1:9081` by default. Bearer-token authenticated.
- **mitmproxy interception** — uses a locally-generated CA with `NameConstraints` (permitted to AI API hostnames only).
- **SQLite event store** — `~/claude_watch_output/vigil.db`, mode `0600`.
- **Browser extension** — content script reading AI chat page DOM, isolated world, localhost-only outbound.
- **JSONL session transcripts** — read from `~/.claude/` and equivalent OpenCLAW paths.
- **CLI entry points** — `ai-monitor`, `claude-watch`.

Detailed threat model and trust boundaries: see [docs/spec/THREAT-MODEL.md](docs/spec/THREAT-MODEL.md).

Data classification (sensitivity tiers, storage, retention): see [docs/spec/DATA-CLASSIFICATION.md](docs/spec/DATA-CLASSIFICATION.md).

## Out of Scope

- Findings that require local user access to a machine where Vigil is already running (Vigil's threat model assumes the operating user is trusted).
- Vulnerabilities in upstream dependencies that are unreachable from any Vigil code path (please report those to the upstream project).
- Self-XSS or social-engineering attacks against the operator.

## Best Practices

- Run Vigil under your own user account — never as root.
- Keep `~/claude_watch_output/` permissions restricted (`chmod 700`). Vigil enforces this automatically via `security.enforce_permissions`.
- Review DLP alerts regularly — Vigil flags but does not block.
- Do not commit the SQLite database to version control.
- Rotate the dashboard bearer token if you suspect it has been exposed (`ai-monitor --rotate-token`).
- Trust the Vigil CA only on machines where you actively use the proxy — `claude-watch --uninstall-ca` removes it cleanly.

## Security Testing

Run security scans locally:

```bash
make security    # Bandit static analysis + ruff S* rules
pip-audit        # Dependency CVE check
make trivy       # Container scan (if using the Docker image)
```

Continuous scans run on every PR via:
- CodeQL (`.github/workflows/codeql.yml`)
- Bandit (`.github/workflows/security.yml`)
- pip-audit + SBOM (`.github/workflows/supply-chain.yml`)
- TruffleHog secret-history scan
- detect-secrets pre-commit hook

## Bug Bounty

Vigil does not yet operate a formal bug bounty program. We acknowledge security researchers in release notes when they choose to be named. As we approach a 1.0 release we'll publish a bounty schedule.

---

Copyright 2026 GoCloudForge, Inc.
