# Security Policy

## Reporting Vulnerabilities

**Please do not open a public issue for security vulnerabilities.**

Email: **rajan.conch@gmail.com**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if available)

You should receive a response within 48 hours. We will work with you to understand and address the issue before any public disclosure.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Scope

This project monitors AI agent activity on your local machine. Security concerns include:

- **Data egress**: Sensitive data detected in AI sessions is stored locally in SQLite. Ensure the database file (`~/claude_watch_output/`) has appropriate file permissions.
- **Dashboard access**: The HTTP dashboard binds to `localhost:9081` by default. Do not expose it to untrusted networks.
- **mitmproxy mode**: The `claude-watch` proxy intercepts HTTPS traffic. The generated CA certificate should be treated as sensitive.

## Threat Model

### Attack Surface

| Component | Risk | Mitigation |
|-----------|------|------------|
| Dashboard HTTP server | Network exposure if bind changed from localhost | Default bind to 127.0.0.1; warn on non-localhost bind |
| SQLite database | Contains sensitive session data (prompts, tool outputs, detected secrets) | File permissions 0600; stored in ~/claude_watch_output/ |
| mitmproxy CA (proxy mode) | MITM on all HTTPS if CA key compromised | CA cert restricted permissions; document handling |
| JSONL transcripts | Full conversation history including any secrets typed or generated | Inherit OS file permissions from ~/.claude/ and ~/.openclaw/ |
| Browser extension | Content script reads AI chat page DOM | Isolated world; localhost-only network; no page modification |
| Chrome History copy | Temporary copy of browser history during scan | Copied to temp file, deleted immediately after read |

### Data Classification

| Data Type | Sensitivity | Storage | Retention |
|-----------|-------------|---------|-----------|
| Session transcripts | HIGH | events table | Indefinite (user manages) |
| Detected secrets | CRITICAL | events.data_json (masked in UI) | Indefinite |
| API traffic (proxy) | HIGH | api_calls table + CSV | Indefinite |
| Browser visits | MEDIUM | browser_sessions table | Indefinite |
| Process list | LOW | processes table | Overwritten each scan |
| Network connections | LOW | connections table | Overwritten each scan |

### Security Testing

Run security scans locally:
```bash
make security    # Bandit static analysis
pip-audit        # Dependency vulnerability check
```

Weekly automated scans run via GitHub Actions (.github/workflows/security.yml).

## Best Practices

- Run the monitor under your own user account, not as root
- Keep `~/claude_watch_output/` permissions restricted (`chmod 700`)
- Review alerts regularly for actual credential exposures
- Do not commit the SQLite database to version control
