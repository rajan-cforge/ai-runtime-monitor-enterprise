# Security Manifest — AI Runtime Monitor (Vigil) v0.2

**Last updated:** 2026-05-24
**Standards mapped:** OWASP ASVS Level 2, NIST SP 800-218 SSDF, OWASP Top 10 2021
**Status:** v0.2 launch candidate

This document maps Vigil's implemented security controls to industry-standard frameworks. Each control includes the standard reference, where the control lives in code, and the verification path.

## 1. Scope and methodology

This manifest covers:

- Application security controls (authentication, authorization, input validation, output encoding, cryptography, error handling, data protection)
- Secure development lifecycle controls (the SSDLC enforcement framework documented in `docs/SSDLC_ENFORCEMENT.md`)
- Software supply chain controls (dependency management, vulnerability scanning, SBOM generation)

Out of scope:

- Infrastructure controls (no infrastructure for v0.2; daemon runs on user's own machine)
- Compliance reports (SOC 2 Type II, ISO 27001 audits planned for v1.0 Enterprise tier)
- Penetration test evidence (planned post-launch via design partners)

Coverage levels:

- **IMPLEMENTED** — control is active in v0.2 with verified evidence
- **PARTIAL** — control is partially implemented; gaps documented
- **PLANNED** — control is on the roadmap with target version
- **N/A** — control does not apply to v0.2 (e.g., infrastructure controls for a non-hosted product)

## 2. OWASP ASVS Level 2 mapping

### V1: Architecture, Design, and Threat Modeling

| Control | Status | Evidence |
|---------|--------|----------|
| V1.1.1 Secure SDLC documented | IMPLEMENTED | `docs/SSDLC_ENFORCEMENT.md` documents the 8-layer enforcement model |
| V1.1.2 Threat modeling performed | IMPLEMENTED | `docs/spec/THREAT-MODEL.md` documents STRIDE analysis across 5 trust boundaries |
| V1.1.3 User stories with security ACs | PARTIAL | PRD includes security capabilities; not all user stories have per-AC security criteria |
| V1.1.4 Trust boundaries identified | IMPLEMENTED | Threat model identifies B1-B5 boundaries with mitigations |
| V1.1.5 Threat model includes data classification | PARTIAL | Threat model references plaintext sensitive data; formal data classification doc is planned for v1.0 |
| V1.1.6 Centralized security controls | IMPLEMENTED | `security.py` centralizes CA generation, token handling, masking, hashing, permission enforcement |
| V1.1.7 Secure-by-default architecture | IMPLEMENTED | Bind address defaults to 127.0.0.1; proxy is opt-in; control plane sync is opt-in |

### V2: Authentication

| Control | Status | Evidence |
|---------|--------|----------|
| V2.1.1 Authentication required | IMPLEMENTED | All `/api/*` endpoints require bearer token via `DashboardHandler` |
| V2.1.5 Constant-time credential comparison | IMPLEMENTED | `security.py::verify_token` uses `hmac.compare_digest` |
| V2.1.7 Compromised password protection | N/A | No passwords in v0.2; token-based auth only |
| V2.4.1 Modern password hashing | IMPLEMENTED | Control plane endpoint key stored as bcrypt hash (`endpoints.api_key_hash`) |
| V2.7.6 Authentication state never logged | IMPLEMENTED | Token values never appear in log output (verified by `sync.py::_sanitize_string` warning format) |

### V3: Session Management

| Control | Status | Evidence |
|---------|--------|----------|
| V3.2.1 Session tokens generated server-side | IMPLEMENTED | `security.py::ensure_dashboard_token` uses `secrets.token_urlsafe(32)` |
| V3.2.2 Session tokens use 64+ bits of entropy | IMPLEMENTED | 32 bytes = 256 bits of entropy |
| V3.7.1 Session lifetime limits | PARTIAL | No session expiry in v0.2 (token persists indefinitely); rotation via `ai-monitor --setup` |
| V3.7.2 Session invalidation on logout | N/A | No logout flow in v0.2 (single-user product) |

### V4: Access Control

| Control | Status | Evidence |
|---------|--------|----------|
| V4.1.1 Principle of least privilege | IMPLEMENTED | CA certificate restricted to AI domains via X.509 NameConstraints |
| V4.1.2 No client-side enforcement | IMPLEMENTED | All authorization happens server-side in `DashboardHandler` |
| V4.1.3 Centralized access control | IMPLEMENTED | Single `DashboardHandler` with consistent auth check |
| V4.1.5 Access denied by default | IMPLEMENTED | Token check rejects unauthenticated requests with 401 |
| V4.2.1 Anti-CSRF | PARTIAL | Localhost-only binding mitigates CSRF; bearer token in custom header further reduces risk; no CSRF token in v0.2 |

### V5: Validation, Sanitization, and Encoding

| Control | Status | Evidence |
|---------|--------|----------|
| V5.1.1 Input validation enforced | IMPLEMENTED | Query parameters validated for type and range in `DashboardHandler` |
| V5.1.2 No unsafe deserialization | IMPLEMENTED | All deserialization via `json.loads` with try/except; no `pickle` or `yaml.unsafe_load` |
| V5.2.1 Sanitization before output | IMPLEMENTED | Four context-aware HTML escape helpers (escHtml, escAttr, escJs, escUrl) per Phase 3A C2 fix |
| V5.2.2 Sanitize unstructured data | IMPLEMENTED | `sync.py::_sanitize_payload` walks payloads scanning for sensitive patterns |
| V5.3.1 Output encoding context-aware | IMPLEMENTED | Same as V5.2.1; helpers are context-specific |
| V5.3.4 SQL injection prevention | IMPLEMENTED | All SQL uses parameterized queries; no string interpolation with user input |
| V5.3.6 LDAP injection prevention | N/A | No LDAP in v0.2 |
| V5.5.1 Deserialization input validation | IMPLEMENTED | JSON deserialization wrapped in try/except returning defaults |

### V6: Stored Cryptography

| Control | Status | Evidence |
|---------|--------|----------|
| V6.1.1 Secure key generation | IMPLEMENTED | RSA 2048-bit keys via `cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key` |
| V6.1.2 Avoid weak cryptography | IMPLEMENTED | SHA-256 for hashing; no MD5 or SHA-1 in code paths |
| V6.2.1 Key storage protected | IMPLEMENTED | CA private key chmod 600; mitmproxy confdir chmod 700 |
| V6.2.5 No hardcoded keys | IMPLEMENTED | All keys are generated at runtime |
| V6.3.1 Random number generation uses CSPRNG | IMPLEMENTED | `secrets.token_urlsafe` (cryptographic) and `os.urandom` for purge |
| V6.4.1 Encryption at rest | PARTIAL | SQLite + chmod 600 in v0.2; SQLCipher AES-256 planned v0.3 |
| V6.4.2 Encryption in transit | IMPLEMENTED | HTTPS for sync to control plane; local API on loopback (HTTPS planned for remote bind) |

### V7: Error Handling and Logging

| Control | Status | Evidence |
|---------|--------|----------|
| V7.1.1 Errors don't leak sensitive info | IMPLEMENTED | Exception handlers return generic error messages; sensitive data is masked before any log output |
| V7.1.2 Log injection prevention | IMPLEMENTED | Log messages use parameterized formatting (`logger.warning("sanitize failed: %s", type)`) |
| V7.3.1 Logs include security-relevant events | PARTIAL | Authentication failures, sanitization failures, file permission fixes all logged; full audit trail planned v1.0 |
| V7.3.3 Log integrity protection | PARTIAL | Logs are append-only files with chmod 600; tamper-evident logging via signing planned v1.0 |

### V8: Data Protection

| Control | Status | Evidence |
|---------|--------|----------|
| V8.1.1 Sensitive data classification | PARTIAL | Plaintext snippets, masked values, and metadata distinguished in code; formal classification doc planned v1.0 |
| V8.1.6 Data minimization | IMPLEMENTED | Auto-purge strips plaintext from rows older than 30 days |
| V8.2.1 Client-side caching limits | IMPLEMENTED | Dashboard uses localStorage only for the bearer token; no sensitive content cached client-side |
| V8.2.2 Browser memory cleared | PARTIAL | Browser holds dashboard data while tab is open; cleared on tab close |
| V8.3.4 Sensitive data masked on display | IMPLEMENTED | `security.py::mask_value` returns first 4 + asterisks + last 4 chars |
| V8.3.5 Sensitive data not logged | IMPLEMENTED | Logging of sensitive paths uses type names (not values); sanitization failures log type only |

### V9: Communication

| Control | Status | Evidence |
|---------|--------|----------|
| V9.1.1 TLS 1.2+ enforced | IMPLEMENTED | Sync to control plane uses HTTPS; requests library defaults to TLS 1.2+ |
| V9.1.2 Strong cipher suites | IMPLEMENTED | requests library uses system TLS config |
| V9.1.3 Certificate validation | IMPLEMENTED | requests.post verifies certs by default; never `verify=False` |
| V9.2.4 Certificate pinning | PARTIAL | Standard CA bundle in v0.2; certificate pinning planned for v1.0 Enterprise |

### V10: Malicious Code

| Control | Status | Evidence |
|---------|--------|----------|
| V10.1.1 Anti-malware in dependencies | IMPLEMENTED | pip-audit + OSV.dev scan dependencies; SBOM generated via CycloneDX |
| V10.2.1 No backdoors | IMPLEMENTED | Apache 2.0 license enables public source review |
| V10.3.2 Update integrity verified | PARTIAL | pip uses TLS to PyPI; package signature verification planned for v0.3 release |

### V11: Business Logic

| Control | Status | Evidence |
|---------|--------|----------|
| V11.1.5 Rate limiting | PARTIAL | Sync agent has exponential backoff; dashboard rate limiting planned v1.0 |
| V11.1.6 Idempotency for sensitive ops | IMPLEMENTED | DB inserts use `INSERT OR IGNORE`; sync uses watermark-based delta sync |

### V12: Files and Resources

| Control | Status | Evidence |
|---------|--------|----------|
| V12.1.1 File upload validation | N/A | No file uploads in v0.2 |
| V12.3.1 File access restrictions | IMPLEMENTED | All DB and config files chmod 600/700 enforced on startup |
| V12.3.6 Path traversal prevention | IMPLEMENTED | All file operations use `Path` objects with validated paths; no string concatenation for paths |

### V13: API and Web Service

| Control | Status | Evidence |
|---------|--------|----------|
| V13.1.1 API authentication enforced | IMPLEMENTED | Bearer token on every endpoint |
| V13.1.5 Content-type validation | IMPLEMENTED | API expects JSON; rejects other content types |
| V13.2.1 RESTful API conventions | IMPLEMENTED | HTTP methods, status codes, JSON responses |
| V13.2.5 JSON serialization safe | IMPLEMENTED | Standard `json.dumps`; no custom encoders that could leak |
| V13.3.1 GraphQL injection prevention | N/A | No GraphQL in v0.2 |
| V13.4.1 WebSocket origin validation | N/A | No WebSockets in v0.2 |

### V14: Configuration

| Control | Status | Evidence |
|---------|--------|----------|
| V14.1.1 No default credentials | IMPLEMENTED | All tokens generated at first run; no defaults |
| V14.1.2 Build process secure | IMPLEMENTED | Build via standard Python tooling; reproducible builds planned v1.0 |
| V14.1.4 Production hardening | PARTIAL | Localhost default, file perms enforcement; full hardening guide planned post-launch |
| V14.2.1 Dependency scanning | IMPLEMENTED | pip-audit in CI workflow on every PR |
| V14.2.2 Patch management | IMPLEMENTED | Dependabot security updates enabled |
| V14.4.1 Security headers (HTTPS) | N/A | HTTP-only on localhost in v0.2 |
| V14.5.1 HTTP method restrictions | IMPLEMENTED | DashboardHandler dispatches only on GET (and POST for control plane ingest) |

## 3. NIST SP 800-218 SSDF mapping

### PO: Prepare the Organization

| Practice | Status | Evidence |
|----------|--------|----------|
| PO.1: Define security requirements | IMPLEMENTED | Threat model, security manifest, SSDLC enforcement docs |
| PO.2: Implement roles and responsibilities | PARTIAL | Solo founder for now; security responsibility documented as sole maintainer |
| PO.3: Implement supporting toolchains | IMPLEMENTED | CI workflows for lint, security, supply chain; pre-commit hooks; grader + architect + performance review agents |
| PO.4: Define and use criteria for software security checks | IMPLEMENTED | Rubrics in `.claude/rubrics/`; required CI status checks in branch protection |
| PO.5: Implement and maintain secure environments | PARTIAL | Developer machine + GitHub Actions runners; cloud control plane environment planned v1.0 |

### PS: Protect the Software

| Practice | Status | Evidence |
|----------|--------|----------|
| PS.1: Protect all forms of code | IMPLEMENTED | Branch protection on main; required reviews; signed release tags (planned v0.3) |
| PS.2: Provide a mechanism for verifying software integrity | PARTIAL | Apache 2.0 source on GitHub; signed binaries planned v0.3 |
| PS.3: Archive and protect software | IMPLEMENTED | Git history; immutable release tags; full audit trail via PR history |

### PW: Produce Well-Secured Software

| Practice | Status | Evidence |
|----------|--------|----------|
| PW.1: Design software to meet security requirements | IMPLEMENTED | Threat model drives security design; PRD includes security capabilities |
| PW.2: Review software design | IMPLEMENTED | Architect-reviewer agent on every PR |
| PW.3: Verify third-party software complies | IMPLEMENTED | pip-audit + license scanning + SBOM generation |
| PW.4: Reuse well-secured software | IMPLEMENTED | Standard library cryptography (hashlib, hmac, secrets); cryptography library for X.509 |
| PW.5: Create source code following secure coding practices | IMPLEMENTED | ruff lint with security rules; bandit SAST; pre-commit hooks; CLAUDE.md mandatory patterns |
| PW.6: Configure compilation and build processes | IMPLEMENTED | Standard Python build; reproducible builds planned |
| PW.7: Review and analyze human-readable code | IMPLEMENTED | Grader + architect + performance multi-agent review pipeline |
| PW.8: Test executable code | IMPLEMENTED | 1398+ tests passing; coverage ratchet; size ratchet; functional coverage warn |
| PW.9: Configure software to have secure settings by default | IMPLEMENTED | Localhost bind; opt-in proxy; opt-in control plane sync; chmod 600/700 enforced |

### RV: Respond to Vulnerabilities

| Practice | Status | Evidence |
|----------|--------|----------|
| RV.1: Identify and confirm vulnerabilities on an ongoing basis | IMPLEMENTED | Weekly CodeQL scans; per-PR pip-audit; trufflehog for secrets in history |
| RV.2: Assess, prioritize, and remediate | IMPLEMENTED | SECURITY.md vulnerability reporting process; incident response captured in docs/incidents/ (local, not in repo per source-honesty contract) |
| RV.3: Analyze vulnerabilities to identify root causes | PARTIAL | Phase 3A C1-C4 fixes documented with rationale; broader root-cause analysis discipline planned |

## 4. OWASP Top 10 2021 mapping

| Risk | Status | Notes |
|------|--------|-------|
| A01: Broken Access Control | MITIGATED | Bearer token auth, centralized in DashboardHandler; tested via C1-FOLLOWUP curl verification |
| A02: Cryptographic Failures | MITIGATED | TLS for sync; chmod 600 for at-rest; constant-time comparison; SHA-256; X.509 NameConstraints |
| A03: Injection | MITIGATED | Parameterized SQL; context-aware HTML escaping (C2 fix); subprocess argv lists (C4 fix) |
| A04: Insecure Design | MITIGATED | Threat model documented; secure-by-default config; fail-closed sanitizer |
| A05: Security Misconfiguration | MITIGATED | Localhost default; file permission enforcement on startup; no defaults that bypass auth |
| A06: Vulnerable and Outdated Components | MITIGATED | pip-audit in CI; Dependabot; SBOM generation |
| A07: Identification and Authentication Failures | MITIGATED | Token-based with constant-time comparison; bcrypt for control plane keys |
| A08: Software and Data Integrity Failures | PARTIAL | Branch protection prevents tampering; signed builds planned v0.3 |
| A09: Security Logging and Monitoring Failures | PARTIAL | Authentication failures and sanitization failures logged; full audit trail planned v1.0 |
| A10: Server-Side Request Forgery | MITIGATED | No user-controlled URL fetching in v0.2 |

## 5. Reference: where to find each control in code

| Control | Location |
|---------|----------|
| Token generation | `security.py::ensure_dashboard_token` |
| Token verification | `security.py::verify_token` |
| File permission enforcement | `security.py::enforce_permissions` |
| CA generation with NameConstraints | `security.py::generate_custom_ca` |
| Sensitive data masking | `security.py::mask_value` |
| Stable hashing for dedup | `security.py::hash_value` |
| Auto-purge of plaintext | `security.py::purge_old_sensitive_data` |
| HTML output encoding (4 helpers) | `dashboard.html` (escHtml, escAttr, escJs, escUrl) |
| SQL parameterized queries | `db.py`, `monitor.py`, `sync.py` (every `execute` call) |
| Subprocess argv list (no shell=True) | `security.py::trust_ca_cert`, throughout `watch.py` |
| Sanitization fail-closed | `sync.py::_sanitize_string`, `_sanitize_payload` |
| bcrypt for endpoint keys | Control plane server (separate repo) |
| pip-audit CI gate | `.github/workflows/ci-security.yml` |
| Bandit CI gate | `.github/workflows/ci.yml` (bandit job) |
| SBOM generation | `.github/workflows/ci-supply-chain.yml` |
| License gate (GPL block) | `.github/workflows/ci-supply-chain.yml` |
| Branch protection | GitHub Rulesets (id 16801272) |
| Secret scanning push protection | GitHub repo settings (Security) |
| CodeQL | GitHub repo settings (Security) |

## 6. Gap analysis (v0.2 vs full ASVS Level 2)

The following ASVS Level 2 controls are not yet IMPLEMENTED. Each has a target version:

- V3.7.1 Session lifetime limits — **v1.0** (tokens currently persist until manual rotation)
- V4.2.1 Anti-CSRF token — **v1.0** (localhost-only mitigates; full token planned)
- V6.4.1 Encryption at rest — **v0.3** (SQLCipher integration)
- V7.3.1 Full audit trail — **v1.0** (control plane logging)
- V7.3.3 Tamper-evident logs — **v1.0** (signed log entries)
- V9.2.4 Certificate pinning — **v1.0 Enterprise**
- V11.1.5 API rate limiting — **v1.0**

The product is currently positioned at OWASP ASVS Level 1+ with several Level 2 controls. v1.0 brings it to Level 2 compliant. Level 3 (highest tier; for high-assurance environments) is a v2.0+ goal aligned with compliance certifications (SOC 2 Type II, ISO 27001).

## 7. Verification

For investors, customers, or auditors who want to verify these claims:

- The Apache 2.0 source code is on [github.com/rajan-cforge/ai-runtime-monitor-enterprise](https://github.com/rajan-cforge/ai-runtime-monitor-enterprise)
- The CI workflows are in `.github/workflows/`
- The grader, architect, and performance reviewer agents are in `.claude/agents/`
- The rubrics they apply are in `.claude/rubrics/`
- Every PR shows the multi-agent verdict in comments
- Branch protection rulesets are in repo Settings → Rules
- This document and the threat model live in `docs/spec/`

For deeper verification, contact security@gocloudforge.com.
