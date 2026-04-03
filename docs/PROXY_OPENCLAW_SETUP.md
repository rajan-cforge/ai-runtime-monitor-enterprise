# OpenClaw API Traffic Capture

Three options for capturing OpenClaw's API calls in AI Runtime Monitor.

## Option C: JSONL Extraction (Default, No Setup Required)

AI Runtime Monitor automatically extracts API call metadata from OpenClaw's JSONL session transcripts. Each assistant message in the JSONL contains usage, model, provider, and cost data which is inserted into the `api_calls` table.

**What you get:** Model, token counts (input/output/cache), cost per call, response ID, stop reason.

**What you don't get:** Raw request/response bodies, streaming chunks, latency timing, system prompt content.

**This is enabled by default** when OpenClaw JSONL monitoring is active.

## Option A: LaunchAgent Proxy Injection (Full Capture)

For full request/response body capture, route OpenClaw's traffic through the mitmproxy.

### Setup

1. Start the monitor with proxy: `ai-monitor --start --with-proxy`

2. Edit the OpenClaw LaunchAgent plist:
```bash
# Open in editor
nano ~/Library/LaunchAgents/ai.openclaw.gateway.plist
```

3. Add these to the `EnvironmentVariables` dict:
```xml
<key>HTTPS_PROXY</key>
<string>http://127.0.0.1:9080</string>
<key>HTTP_PROXY</key>
<string>http://127.0.0.1:9080</string>
<key>NODE_EXTRA_CA_CERTS</key>
<string>/Users/YOUR_USERNAME/.mitmproxy/mitmproxy-ca-cert.pem</string>
```

4. Reload the LaunchAgent:
```bash
launchctl unload ~/Library/LaunchAgents/ai.openclaw.gateway.plist
launchctl load ~/Library/LaunchAgents/ai.openclaw.gateway.plist
```

### Why This Is Needed

The OpenClaw gateway runs as a macOS LaunchAgent daemon started by `launchd`. It does not inherit shell environment variables like `HTTPS_PROXY`. Setting `export HTTPS_PROXY=...` in your terminal only affects processes started from that shell.

### Trade-offs

- **Pro:** Full request/response capture including streaming, system prompts, and tool call details
- **Con:** Requires modifying the plist and reloading the daemon
- **Con:** If the proxy isn't running, OpenClaw API calls will fail (Node.js will try to route through a non-existent proxy)
- **Con:** Requires trusting the mitmproxy CA certificate

## Option B: OpenClaw Native Proxy Support (Future)

OpenClaw's underlying Anthropic Node SDK reads `ANTHROPIC_BASE_URL` but does not natively support `HTTPS_PROXY`. This would require OpenClaw to add proxy configuration at the application level (e.g., in `openclaw.json`).

**Status:** Not yet available. Track OpenClaw upstream for proxy support.
