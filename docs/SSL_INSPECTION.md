# SSL Inspection — How It Works

This document explains how AI Runtime Monitor intercepts HTTPS traffic
from AI coding agents and why it works despite modern TLS protections.
Written for a non-security audience.

---

## The problem in plain English

Every AI coding tool on your machine talks to its backend over HTTPS.
HTTPS encrypts the traffic so nobody between the app and the server can
read it. That's normally a good thing — but if you're trying to monitor
what your AI agents are doing, it's a problem. You can see *that* Claude
Code talked to api.anthropic.com, but not *what* it said.

SSL inspection means we sit in the middle of that encrypted connection,
decrypt it, read it, and re-encrypt it before forwarding. This is the
same technique that enterprise security tools like CrowdStrike, Zscaler,
and Netskope use on corporate networks.

## Why someone might say "this shouldn't work"

Modern HTTPS has multiple layers of protection against exactly this:

1. **Certificate validation** — the app checks that the server's
   certificate was signed by a trusted Certificate Authority (CA). Our
   fake certificate isn't signed by a real CA, so the app should reject
   it.

2. **HSTS / certificate pinning** — some sites (like claude.ai) tell
   browsers "only trust certificates from specific CAs." Even if you add
   a new CA, the browser should ignore it for pinned sites.

3. **Bundled CA stores** — Node.js (which Claude Code runs on) ships its
   own list of trusted CAs and ignores the operating system's trust
   store. So even adding our CA to macOS Keychain shouldn't help.

All three of these are real protections. Here's how we work around each
one — legitimately, using the same mechanisms that every enterprise proxy
uses.

## How we make it work

### Step 1: Generate a custom Certificate Authority

On first install, we generate a per-machine CA certificate using the
`cryptography` Python library (`security.py`). This is a root CA with a
private key that can sign leaf certificates for specific domains.

The CA has two critical properties:

- **Unique per machine** — the Common Name includes your hostname
  (e.g., "AI Runtime Monitor - Mac-45"), so each install can be
  identified and revoked independently.

- **Name Constraints extension** — this is the key security feature.
  The CA certificate contains an X.509 extension that says "this CA
  is ONLY allowed to sign certificates for these 19 AI domains."
  Even if the private key were stolen, it could not be used to forge
  certificates for your bank, email, or any non-AI site. This is
  enforced by the operating system's certificate validator, not by
  our code.

Constrained domains (the full list):
```
api.anthropic.com       api.openai.com          api.cursor.sh
api.groq.com            api.together.xyz        api.fireworks.ai
api.mistral.ai          api.cohere.ai           api.deepseek.com
api.perplexity.ai       api.githubcopilot.com
copilot-proxy.githubusercontent.com
generativelanguage.googleapis.com
api-inference.huggingface.co
claude.ai               chatgpt.com             chat.openai.com
gemini.google.com       perplexity.ai
```

### Step 2: Trust the CA in macOS Keychain

The setup wizard prompts you to add the CA to the macOS System Keychain
as a trusted root. This requires admin credentials (supports Touch ID).
The actual command:

```
security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain \
  ~/claude_watch_output/certs/ai-monitor-ca.pem
```

Once trusted, any app that validates certificates against the macOS
Keychain will accept leaf certificates signed by our CA — but **only**
for the 19 domains listed in the Name Constraints.

### Step 3: Run mitmproxy as a local proxy

We run `mitmdump` (the headless version of mitmproxy) on port 9080. It
listens for HTTPS connections and only intercepts traffic to AI domains:

```
mitmdump --listen-port 9080 \
         --allow-hosts ^(api\.anthropic\.com|claude\.ai|chatgpt\.com|...): \
         --set confdir=~/claude_watch_output/certs/mitmproxy \
         --set upstream_cert=false \
         --ssl-insecure
```

**`--allow-hosts`** is the filter. Only matching domains get their TLS
terminated. All other traffic (banking, email, Netflix) passes through
as an opaque tunnel — mitmproxy never sees the plaintext.

### Step 4: Route AI app traffic through the proxy

Two mechanisms:

- **CLI tools** (Claude Code, aider, etc.): Set the `HTTPS_PROXY`
  environment variable before launching the tool.
- **Desktop Electron apps** (Claude Desktop, ChatGPT, Cursor): Enable
  the macOS system proxy via `networksetup`, which routes all HTTPS
  traffic on the Wi-Fi interface through port 9080.

---

## Solving each "this shouldn't work" objection

### Objection 1: Certificate validation should reject the fake cert

**Answer:** We generate a real CA and add it to the OS trust store.
When mitmproxy intercepts `api.anthropic.com`, it creates a leaf
certificate on the fly, signed by our CA. The client validates the
leaf cert, walks the chain up to our CA, finds it in the Keychain,
and accepts it.

This is the standard mechanism for every enterprise SSL inspection
tool. It's not a hack — it's the intended behavior of X.509 trust
chains.

### Objection 2: HSTS / certificate pinning should block this

**Answer:** Chrome (and Chromium-based browsers/Electron apps) has a
deliberate exception: **locally-installed root CAs are exempt from
HSTS pin enforcement.** This is documented in the Chromium source
(`transport_security_state.h`). The rationale: enterprises need to
inspect TLS for security tools like ours, and HSTS pins shouldn't
block legitimately-administered machines.

This means even though `claude.ai` uses HSTS pinning, Chrome will
accept our forged certificate because the signing CA was installed
locally (not shipped with the OS). This is the same exemption that
makes Zscaler, Netskope, and every corporate HTTPS proxy work.

**Important caveat:** This only works if the CA is in the **System
Keychain** (machine-wide trust), not just the user's login keychain.

### Objection 3: Node.js ignores the OS trust store

**Answer:** Correct — Node.js ships a bundled Mozilla CA list and
doesn't read the macOS Keychain. That's why Claude Code (which is
a Node.js app) needs an extra environment variable:

```bash
export NODE_EXTRA_CA_CERTS=~/claude_watch_output/certs/mitmproxy/mitmproxy-ca-cert.pem
```

This tells Node to trust our CA **in addition to** its bundled CAs.
Without it, Claude Code rejects the proxy's certificate with
`UNABLE_TO_GET_ISSUER_CERT_LOCALLY`.

Similarly, Python tools that use the `certifi` library (which also
bundles its own CA list) need:

```bash
export SSL_CERT_FILE=~/claude_watch_output/certs/mitmproxy/mitmproxy-ca-cert.pem
export REQUESTS_CA_BUNDLE=~/claude_watch_output/certs/mitmproxy/mitmproxy-ca-cert.pem
```

We generate a `proxy_env.sh` helper script that sets all of these.

### Objection 4: The NameConstraints wildcard problem

There was one real bug we had to fix. When mitmproxy intercepts
`chatgpt.com`, by default it copies the real server's certificate
Subject Alternative Names (SANs) into the forged leaf certificate.
The real `chatgpt.com` cert has SANs like `*.chatgpt.com`,
`cdn.oaistatic.com`, and other CDN domains.

Our CA's Name Constraints only permit `chatgpt.com`, not
`cdn.oaistatic.com`. So the forged leaf cert contained a SAN that
violated its own issuer's constraints. macOS rejected it with
`ERR_CERT_AUTHORITY_INVALID`.

**Fix:** `--set upstream_cert=false` tells mitmproxy to generate leaf
certs with **only** the SNI hostname (just `chatgpt.com`), not the
upstream cert's full SAN list.

### Objection 5: Stale certs after CA regeneration

If the CA was regenerated (new hostname, new key) but mitmproxy's
config directory still had cached leaf certs signed by the old CA, the
client would see a leaf cert signed by a CA that wasn't in the Keychain.

**Fix:** On every mitmdump launch, we rebuild the config directory from
the canonical cert+key files and delete all cached leaf certs. This
forces mitmproxy to regenerate fresh leaf certs on the next connection.

---

## What we can and cannot intercept — the honest truth

Verified against the production database (8,000+ captured calls):

### Full content capture (prompts, responses, tokens, tool calls)

| App | How traffic reaches us | What we capture | Status |
|-----|----------------------|-----------------|--------|
| **Claude Code** | `HTTPS_PROXY` env var → proxy | Full JSON request/response bodies | Works IF proxy env vars are set. JSONL file parsing is the primary channel and works without the proxy. |
| **OpenClaw** | `HTTPS_PROXY` env var → proxy | Full JSON bodies | Works. Also has JSONL as primary channel. |

### Metadata-only capture (host, path, status, sizes, latency)

| App | How traffic reaches us | What we capture | Why no content |
|-----|----------------------|-----------------|----------------|
| **Claude Desktop** | macOS system proxy → mitmproxy | HTTP envelope only | Routes 100% of conversation traffic through `claude.ai` web backend, which uses SSE streaming. We flag these as `_is_browser_metadata` and skip body parsing because SSE is not reliably parseable from the proxy. |
| **ChatGPT Desktop** | macOS system proxy → mitmproxy | HTTP envelope only | Same — routes through `chatgpt.com` web backend with SSE. |
| **Chrome claude.ai** | macOS system proxy → mitmproxy | HTTP envelope only | Same SSE limitation. The Chrome extension captures actual conversation content via DOM scraping. |
| **Chrome chatgpt.com** | macOS system proxy → mitmproxy | HTTP envelope only | Same. Extension captures content. |
| **Chrome gemini.google.com** | macOS system proxy → mitmproxy | HTTP envelope only | Uses protobuf, not JSON. Extension captures content. |

### Not captured

| App | Why | Workaround |
|-----|-----|------------|
| **Cursor** | Cursor's Electron stack bypasses the macOS system proxy for its AI traffic. Zero rows in the database. `api.cursor.sh` is in our allowlist but Cursor now uses `api2.cursor.sh` and other endpoints, and ignores the system proxy entirely. | Configure Cursor manually: Settings > Network > HTTP Proxy > `http://127.0.0.1:9080`. Shell `HTTPS_PROXY` env var does NOT work for Electron apps. |
| **Claude Code without proxy env** | Claude Code works fine without the proxy — JSONL file parsing captures everything. The proxy adds network-level detail but isn't required. | The JSONL channel is the primary monitoring path for Claude Code and requires zero configuration. |

### Where the data comes from (by the numbers)

From the production database:

```
chatgpt_web    (chatgpt.com)        3,403 calls  metadata only   via system proxy
claude_web     (claude.ai)          3,001 calls  metadata only   via system proxy
anthropic_api  (api.anthropic.com)    679 calls  mixed*          via system proxy
gemini_web     (gemini.google.com)    636 calls  metadata only   via system proxy
openai_api     (api.openai.com)         4 calls  full content    via system proxy
cursor                                  0 calls  (nothing)       bypasses proxy
```

*The 679 `anthropic_api` rows are NOT from Claude Code. 526 are
non-conversation endpoints (OAuth, update checks, MCP registry). 153
are token-count rows from OpenClaw's JSONL files, mislabeled as
`source='proxy'` because the database column defaults to 'proxy'.

---

## The two-channel model

The key insight: **the proxy is not the only monitoring channel.** For
Claude Code and OpenClaw, the primary channel is JSONL file parsing —
the agents write structured logs to disk, and the monitor reads them.
This captures everything: prompts, responses, thinking, tool calls,
token usage, costs.

The proxy adds:
- **Network-level visibility** that JSONL doesn't have (HTTP status
  codes, response sizes, latency, endpoint paths)
- **Desktop app monitoring** (Claude Desktop, ChatGPT Desktop) that
  don't write JSONL files — process detection + proxy metadata is all
  we get
- **Browser AI session correlation** — matching proxy metadata with
  Chrome extension DOM captures for a complete picture

For a SOC analyst, the monitoring coverage looks like:

```
                    JSONL    Proxy    Extension   Process
                   (content) (network) (DOM)      (detect)
Claude Code          ***       **        -           *
OpenClaw             ***       **        -           *
Claude Desktop        -        **        -          **
ChatGPT Desktop       -        **        -          **
Cursor                -         -        -          **
Chrome claude.ai      -        **       ***          -
Chrome chatgpt.com    -        **       ***          -
Chrome gemini.com     -        **       ***          -
Ollama                -         -        -          **

*** = full content   ** = metadata/detection   * = basic   - = none
```

---

## Security properties of the inspection

1. **Name Constraints (X.509)** — the CA can only sign certs for 19 AI
   domains. Enforced by the OS, not by our code. A leaked key cannot
   forge certs for non-AI sites.

2. **System proxy auto-disabled on crash** — if the monitor dies, the
   watchdog disables the macOS system proxy. Your network never silently
   routes through an orphaned proxy.

3. **File permissions** — CA private key is `chmod 600`. Certificate
   directory is `chmod 700`. Dashboard token is `chmod 600`. Verified on
   every startup.

4. **Per-machine CA** — each install gets a unique CA with the hostname
   in the Common Name. CAs can be individually revoked without affecting
   other machines.

5. **Selective interception** — non-AI traffic is never decrypted. The
   `--allow-hosts` regex on mitmproxy ensures only the 19 listed domains
   are intercepted. Everything else tunnels through untouched.
