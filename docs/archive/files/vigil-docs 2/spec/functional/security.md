# Functional Spec — security.py

**Module:** `src/claude_monitoring/security.py`
**Status:** v0.2 launch candidate
**Audit history:** C1 (constant-time comparison), origin of NameConstraints CA pattern

## 1. Purpose

`security.py` is the centralized location for all security primitives in the project. The module exists because security concerns were originally scattered across `monitor.py`, `watch.py`, and ad-hoc helper functions. Centralization makes the security surface auditable in one place and ensures consistency.

The module owns five concerns:

1. **Custom CA generation** with X.509 NameConstraints (only signs leaf certs for AI domains)
2. **File permission enforcement** (chmod 600/700 on sensitive paths)
3. **Dashboard token generation and validation**
4. **Sensitive-data masking and stable hashing**
5. **Auto-purge of old sensitive data plaintext**

Every function in this module fails closed: any error returns a safe default rather than crashing the CLI. The only exception is `generate_custom_ca`, which raises if the `cryptography` library is not installed (it is a required dependency, so this should not happen in normal use).

## 2. Public contract

### 2.1 Path helpers

```python
def get_cert_dir() -> Path: ...
def get_ca_cert_path() -> Path: ...
def get_ca_key_path() -> Path: ...
def get_mitmproxy_confdir() -> Path: ...
def get_token_path() -> Path: ...
def get_setup_marker_path() -> Path: ...
```

All return `Path` objects computed from `config.get_output_dir()`. Idempotent; no side effects.

### 2.2 CA generation

```python
def generate_custom_ca(
    cert_path: Path | None = None,
    key_path: Path | None = None,
    domains: list[str] | None = None,
    hostname: str | None = None,
) -> tuple[Path, Path]:
    """Generate a branded CA cert unique to this install.
    
    The cert is constrained by X.509 NameConstraints so it can ONLY sign
    leaf certs for the configured AI domains. Even if the CA key is
    compromised, it cannot be used to MITM banking or email — the
    constraint is enforced by the OS cert validator.
    """

def get_ca_info(cert_path: Path | None = None) -> dict | None:
    """Return a summary of the installed CA, or None if not present."""

def trust_ca_cert(cert_path: Path | None = None) -> bool:
    """Prompt for admin password and add the CA to the system keychain."""

def untrust_ca_cert(cert_path: Path | None = None) -> bool:
    """Remove the CA from the system keychain. For uninstall."""
```

### 2.3 Permission enforcement

```python
def enforce_permissions() -> list[str]:
    """Tighten permissions on sensitive paths. Returns list of paths fixed."""
```

Walks a fixed list of sensitive files (chmod 600) and directories (chmod 700) and applies the expected permissions. Idempotent.

### 2.4 Token management

```python
def ensure_dashboard_token() -> str:
    """Return the dashboard auth token, creating it if missing."""

def verify_token(presented: str, expected: str | None = None) -> bool:
    """Constant-time token comparison."""
```

### 2.5 Sensitive data masking

```python
def mask_value(value: str | None) -> str:
    """Mask a credential for display: first 4 + asterisks + last 4."""

def hash_value(value: str | None) -> str:
    """Stable 16-char hash of a credential for dedup without storing plaintext."""
```

### 2.6 Auto-purge

```python
def purge_old_sensitive_data(db, retention_days: int = 30) -> int:
    """Strip snippet and matched_value from sensitive alerts older than N days.
    
    Returns the number of rows scrubbed. Metadata (pattern, severity,
    timestamp) is retained indefinitely.
    """
```

## 3. Inputs

- **Configuration:** paths and ports from `config.py`
- **System state:** existing files in `~/claude_watch_output/` (idempotent over existing state)
- **External entropy:** `secrets.token_urlsafe` for token generation; `rsa.generate_private_key` for CA key

## 4. Outputs

- **Files written:** CA cert (chmod 644), CA private key (chmod 600), dashboard token (chmod 600), mitmproxy confdir contents
- **macOS keychain entry:** the CA cert added to the system keychain via `security add-trusted-cert` (via osascript admin dialog)
- **Database updates:** UPDATEs to sensitive event rows during auto-purge (removes plaintext, retains metadata)

## 5. Side effects

- **File system mutation** — within `~/claude_watch_output/` only
- **Permission changes** — `chmod` calls on the listed sensitive paths
- **macOS admin dialog** — `trust_ca_cert` triggers a native admin password prompt via osascript
- **No network I/O**
- **No process creation** (other than the osascript helper for trust)

## 6. Failure modes

| Mode | Visible symptom | Recovery |
|------|-----------------|----------|
| `cryptography` library missing | `generate_custom_ca` raises ImportError | Install via `pip install cryptography` (it's a required dep, so this is unusual) |
| CA cert dir not writable | `generate_custom_ca` raises PermissionError | Fix directory permissions; rerun |
| osascript user-cancels | `trust_ca_cert` returns False | User can retry; manual trust via `security add-trusted-cert` documented in wizard |
| Keychain doesn't have System.keychain | `trust_ca_cert` returns False | macOS edge case; usually means a corrupted keychain |
| Token file readable by others | `enforce_permissions` fixes it; logs that it was wrong | Auto-recovered |
| Auto-purge DB locked | Returns 0; logs warning | Retries on next scheduled run |
| Auto-purge query fails | Returns 0; logs warning | Manual investigation needed if persistent |

## 7. The NameConstraints story

The X.509 NameConstraints extension is the headline security feature of `security.py`. Without it, trusting any CA cert would create a wildcard MITM capability on the user's machine. With it, even if the CA private key is stolen, the OS cert validator refuses to honor any leaf cert outside the constrained domain list.

The constraint is set in `generate_custom_ca`:

```python
.add_extension(
    x509.NameConstraints(
        permitted_subtrees=[x509.DNSName(d) for d in domains],
        excluded_subtrees=None,
    ),
    critical=True,
)
```

The domain list comes from `constants.AI_PROXY_DOMAINS`:
- `api.anthropic.com`
- `api.openai.com`
- `generativelanguage.googleapis.com`
- `api.mistral.ai`
- and ~10 other AI service hostnames

If an attacker steals the CA key and tries to sign a cert for `mybank.com`, the OS validator rejects the cert because `mybank.com` is not in `permitted_subtrees`. This is *cryptographically enforced*, not just policy.

Testing the constraint: any macOS user can verify this by trying to use the Vigil CA to inspect `mybank.com` via mitmproxy. The TLS handshake fails with a constraint violation error.

This pattern is the technical bedrock of the product's trust story. The setup wizard's Step 2 explanation ("banking, email, Netflix are NEVER inspected") is true *because of* NameConstraints, not because the proxy code chooses to skip them.

## 8. Hot-path notes

Functions in this module are mostly cold-path (run at setup, on startup, periodically). The exception is `verify_token`, which runs on every `/api/*` request.

Patterns to preserve for `verify_token`:
- Always uses `hmac.compare_digest` (constant time)
- Reads `expected` from file only if not passed; cached reads are fine but the file is small so re-reading is also acceptable
- Returns False on any exception (never throws)

`mask_value` and `hash_value` are also reasonably hot when alerts are being processed in bulk. They are pure functions with no I/O.

`enforce_permissions` is called on every daemon startup. It walks ~10 paths and chmods them if needed. Cost is negligible.

`purge_old_sensitive_data` runs daily on a schedule. The cost is bounded by the size of the `events` table; on heavy users this could be 100K+ rows, but the SQLite UPDATE with index-backed WHERE is sub-second.

## 9. Audit history

| Audit | Issue | Resolution |
|-------|-------|-----------|
| C1 (Phase 3A) | `verify_token` used `==` comparison (potentially timing-leakable) | Switched to `hmac.compare_digest`; PR #13 |
| Origin | The need for NameConstraints was identified during initial security architecture review | Pattern established before C1; never had a vulnerable version |

The module's security posture has been reviewed multiple times in the project history (Audit 2026-05-21, Phase 3A C1-C4) and the patterns established have not regressed.

## 10. Extension points

- **Add a new sensitive path to enforce:** append to `_PROTECTED_FILES_600` or `_PROTECTED_DIRS_700`
- **Add a new masking rule:** modify `mask_value` (currently the same masking rule for all credentials; could become per-type)
- **Add a new CA domain:** modify `constants.AI_PROXY_DOMAINS` (no code change in `security.py` needed)
- **Add a new auto-purge target:** add a new function similar to `purge_old_sensitive_data` for different data types

## 11. Testing

- **Unit tests:** `tests/test_security.py` covers token generation, verification (including timing-safety expectation), permission enforcement, masking, hashing, NameConstraints in generated CA
- **Integration tests:** wizard flow exercises CA generation + trust + verification end-to-end
- **Adversarial tests:** explicitly test that `verify_token` rejects empty, None, mismatched, and timing-suspicious inputs

## 12. Dependencies

- Standard library: `hashlib`, `hmac`, `os`, `secrets`, `socket`, `subprocess`, `datetime`, `pathlib`
- Project modules: `config`, `constants`
- Third-party: `cryptography` (required for CA generation; used heavily)

## 13. Future direction

- **HSM/keychain integration (v1.0 Enterprise):** store the CA private key in the macOS Secure Enclave instead of on disk
- **Per-domain certificate rotation (v0.3):** auto-rotate the CA on a schedule with revocation
- **Certificate transparency logging (v1.0):** publish issued leaf certs to CT logs for additional audit trail
- **Centralized secrets management (v1.0):** integrate with HashiCorp Vault for enterprise deployments
- **HKDF-based token derivation (v1.0):** derive multiple tokens (dashboard, extension, control plane) from a master key with HKDF
