# Functional Spec — wizard.py

**Module:** `src/claude_monitoring/wizard.py`
**Status:** v0.2 launch candidate

## 1. Purpose

`wizard.py` implements two user-facing flows:

1. **First-run setup wizard** (Section 8 in the code) — runs automatically the first time `ai-monitor --start` is invoked on a fresh install. Walks the user through CA generation, trust, system proxy enablement, and initialization. Each step is opt-in with a clear explanation of what it does and what data stays local.

2. **Secure uninstall** (Section 9) — disables the system proxy, removes the CA from the keychain, overwrites the database with random bytes, and deletes the data directory. Triggered by `ai-monitor --purge`.

Both flows are user-facing and high-stakes — they affect system-level configuration. The wizard's interactive prompts and explanations are part of the product's user trust story (the same trust story that NameConstraints and selective MITM technically implement).

## 2. Public contract

### 2.1 Setup wizard

```python
def is_first_run() -> bool:
    """Check if the wizard has been run before."""

def run_setup_wizard(force: bool = False) -> bool:
    """Run the four-step wizard. Returns True on success.
    
    Steps that fail set 'ok=False' in the marker JSON so a future
    --status can show what's incomplete. The wizard never aborts
    halfway — it completes every step it can and reports the result.
    """
```

### 2.2 Secure uninstall

```python
def run_purge(confirm_token: str | None = None) -> bool:
    """Disable proxy, remove cert, overwrite DB, delete data dir.
    
    Requires the user to type 'DELETE' to confirm. ``confirm_token``
    lets tests bypass the interactive prompt.
    """
```

## 3. The four wizard steps

Each step is independently retryable and reports its outcome in the marker JSON.

### Step 1: Generate the CA

Calls `security.generate_custom_ca()`. Creates a per-install RSA-2048 CA certificate with:
- Common name including the machine hostname
- X.509 NameConstraints limiting it to AI domains only
- 1-year validity
- Private key with chmod 600

The cert is written to `~/claude_watch_output/certs/ai-monitor-ca.pem`. The mitmproxy-compatible layout (cert+key combined) is also written to `~/claude_watch_output/certs/mitmproxy/`.

### Step 2: Trust the CA

Calls `security.trust_ca_cert()`, which uses macOS's osascript to display a native admin password dialog (Touch ID supported). The CA is added to `/Library/Keychains/System.keychain` with `add-trusted-cert -d -r trustRoot`.

If the user declines (chooses N) or cancels the admin dialog, the wizard records the skip and continues. The product still works (CLI tools can use `HTTPS_PROXY` directly), but desktop apps and browser TLS will fail with cert errors.

The wizard's explanation of this step is verbose and intentional — it tells the user exactly what the trust grant enables and what it does not enable. The user-facing copy is:

> What this does:
> - Allows inspection of AI API traffic (Anthropic, OpenAI, etc.)
> - Banking, email, Netflix, etc. are NEVER inspected
> - Same approach used by Zscaler and enterprise security tools
> - Certificate is restricted to AI domains only (X.509 NameConstraints)

This text is part of the product's trust model. The technical mechanism (NameConstraints) is real; the explanation makes that mechanism legible to a non-security-expert developer.

### Step 3: Enable system proxy

Calls `_enable_system_proxy()`, which runs `networksetup -setsecurewebproxy Wi-Fi 127.0.0.1 9080` to route the user's Wi-Fi traffic through mitmproxy.

This step defaults to NO (not Y) because it has machine-wide side effects:
- Other VPN/proxy tools may conflict
- Some apps cache the proxy setting and don't pick up changes immediately
- Browser apps will fail TLS if the CA isn't trusted

Users can enable it later with `ai-monitor --enable-system-proxy`. CLI tools can also use `HTTPS_PROXY` directly without enabling the system proxy.

### Step 4: Initialize

Initializes the database, generates the dashboard token, and enforces file permissions on the output directory. Calls:
- `db.init_db()` — creates the 7 tables and 13 indexes
- `security.ensure_dashboard_token()` — generates a 32-byte URL-safe token
- `security.enforce_permissions()` — applies chmod 600/700 to sensitive paths

The token is printed to the user with a clickable URL: `http://localhost:9081?token=<token>`. The user typically bookmarks this URL.

## 4. Inputs

- **stdin (interactive):** Y/n prompts at each step
- **Configuration:** paths from `config.py`
- **System state:** existing files, current keychain state, current system proxy state

For non-interactive runs (CI, automated install), the wizard uses defaults:
- Step 1: always generates the CA (default Y)
- Step 2: trusts the CA (default Y)
- Step 3: does NOT enable system proxy (default N)
- Step 4: always initializes (no prompt)

The non-interactive defaults make the wizard safe to run from CI without surprises.

## 5. Outputs

- **stdout:** colored progress output (using ANSI escape codes)
- **Files written:** CA cert, CA key, mitmproxy confdir contents, dashboard token, setup marker
- **macOS keychain entry:** the CA cert
- **Network state:** system proxy enabled (if user opted in)
- **Database initialized:** all tables created

## 6. The setup marker

`~/claude_watch_output/.setup_complete` is a JSON file written at the end of the wizard:

```json
{
  "version": "1.0.0",
  "setup_date": "2026-05-24T15:30:00Z",
  "hostname": "rajan-macbook",
  "cert_trusted": true,
  "proxy_enabled": false,
  "steps": {
    "generate_ca": "ok",
    "trust_ca": "ok",
    "system_proxy": "skipped",
    "initialize": "ok"
  },
  "dashboard_token": "<token>"
}
```

The marker is chmod 600 because it contains the dashboard token. Future runs check this marker to skip the wizard. `ai-monitor --setup` forces a rerun regardless of the marker's state.

## 7. The purge flow

The purge flow is the inverse of setup:

1. Disable system proxy (if enabled)
2. Remove the CA from the keychain (via osascript admin dialog)
3. Overwrite the database with random bytes (best effort; encrypted DBs don't strictly need this)
4. Delete the entire `~/claude_watch_output/` directory

Each step is independent: if one fails, the others still proceed. The function returns True only if all destructive steps succeeded.

The confirmation prompt is intentionally strict: the user must type the literal string "DELETE" (case-sensitive). This is to prevent accidental purges in interactive sessions and to give automation a clear opt-in signal (`confirm_token="DELETE"`).

## 8. Failure modes

| Mode | Visible symptom | Recovery |
|------|-----------------|----------|
| `cryptography` library missing | Step 1 fails | Install dependency; rerun wizard |
| osascript user-cancels | Step 2 fails or step is skipped | User can retry by running `ai-monitor --setup` or trust manually |
| `networksetup` not available | Step 3 fails (Linux, etc.) | Use HTTPS_PROXY directly |
| Database initialization fails | Step 4 fails | Manual investigation; usually disk space or permissions |
| Non-interactive on a tty | Returns default for each prompt | Safe; uses documented defaults |

## 9. Side effects

- **File system:** writes to `~/claude_watch_output/`
- **macOS keychain:** add (setup) or remove (purge) the CA
- **System proxy:** enable (if user opts in) or disable (purge)
- **Process spawning:** `osascript` for keychain operations, `networksetup` for proxy state

## 10. Testing

- **Unit tests:** `tests/test_wizard.py` covers `is_first_run`, `_prompt` (with mocked stdin), each step's flow, and the marker writing
- **Non-interactive mode:** explicit tests verify default behaviors when `stdin.isatty()` is False
- **Purge tests:** verify that `confirm_token="DELETE"` proceeds and any other value cancels
- **Idempotency:** running the wizard twice does not re-create files that exist

## 11. UX design rationale

The wizard's user-facing copy is deliberate. Three principles:

1. **Explain before asking.** Every Y/n prompt is preceded by a multi-line explanation of what the action does and what it does not do. The user should never see a prompt and wonder "what does this mean for me?"

2. **Default to safe, not to convenient.** Step 3 (system proxy) defaults to N because it has machine-wide side effects. The user can enable it later in seconds; reversing an accidental enable is harder.

3. **Honest about limits.** The wizard tells the user that skipping step 2 limits proxy capture to CLI tools. It tells them that skipping step 3 means desktop apps won't be captured. There's no marketing-speak; the user gets the technical facts.

## 12. Dependencies

- Standard library: `json`, `os`, `socket`, `subprocess`, `sys`, `datetime`
- Project modules: `config`, `security`, `status`, `db`

## 13. Future direction

- **GUI wizard (v0.3):** native macOS GUI wrapper for users who don't want a CLI experience
- **One-line install (v0.3):** `curl ... | sh` style installer that runs the wizard non-interactively
- **Web-based onboarding (v1.0 Enterprise):** for fleet installs, the wizard pulls config from the control plane
- **Linux support (v0.3):** equivalent setup flow using Linux trust store (update-ca-certificates)
- **Windows support (v0.4):** Windows certificate store integration
