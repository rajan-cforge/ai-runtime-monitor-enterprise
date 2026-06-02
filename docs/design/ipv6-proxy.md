# IPv6 dual-stack proxy listener

**Status:** Implemented in v0.2.1.
**Issue:** https://github.com/rajan-cforge/ai-runtime-monitor-enterprise/issues/70
**Criticality:** C3 — touches the proxy capture path; behaviour change
visible in production data.

## Problem

Claude Desktop was bypassing the HTTPS proxy intermittently even when
`ai-monitor --enable-system-proxy` had set the macOS system proxy.
2026-06-01 verification:

```
sudo lsof -nP -p 76774  # Claude Desktop main PID
# 1 ESTABLISHED to 127.0.0.1:9080 (via proxy)
# 2 ESTABLISHED to [2607:6bc0::10]:443 (IPv6 direct, bypass)
```

Mixed Happy Eyeballs behaviour — IPv4 connections went through the
proxy, IPv6 connections did not.

## Initial hypothesis (wrong)

We initially thought macOS `networksetup -setsecurewebproxy` only
configures the IPv4 proxy, leaving IPv6 traffic unrouted. The proposed
fix was a "dual-stack networksetup invocation."

## Architectural review finding (correct)

`networksetup -setsecurewebproxy` is **stack-agnostic**. The OS routes
both IPv4 and IPv6 destinations through whatever proxy host you set.
Claude Desktop's IPv6 connections WERE being routed to
`127.0.0.1:9080` correctly at the OS layer.

The actual cause: **mitmproxy was only listening on `0.0.0.0:9080`
(IPv4)**. When IPv6 connections arrived from Claude Desktop, mitmproxy
refused them, and macOS fell back to direct connection.

## Fix

One-line change in `watch.py:run_start()` — add `--listen-host ::` to
the mitmdump cmdline:

```python
cmd = [
    "mitmdump",
    "--listen-host", "::",
    "--listen-port", str(proxy_port),
    ...
]
```

## Why `--listen-host ::` works on macOS (and the gotcha on Linux)

On macOS (Darwin / BSD), the default for the `IPV6_V6ONLY` socket
option is **0** — meaning a single socket bound to `::` accepts both
IPv4-mapped addresses (`::ffff:127.0.0.1`) and native IPv6 connections.
mitmproxy 10.x relies on this default and binds a single dual-stack
socket. No second listener needed.

On **Linux**, the default for `IPV6_V6ONLY` is **1** — `--listen-host
::` would give IPv6-only and IPv4 traffic would fail. A Linux port
would require either:

- Explicitly setting `IPV6_V6ONLY=0` (requires either patching mitmproxy
  or running with `sysctl net.ipv6.bindv6only=0`), or
- Running two mitmproxy instances (one bound IPv4, one IPv6) and
  forwarding both to the same addon.

Out of scope for v0.2.1; documented here for any future Linux port.

### Re-verify on mitmproxy version bumps

`pyproject.toml` pins `mitmproxy>=10.0` with no upper bound. mitmproxy
10.x binds `::` via Python's `socket.socket(AF_INET6)` without
explicitly setting `IPV6_V6ONLY`, relying on the OS default. **If a
future mitmproxy release adds an explicit `setsockopt(IPPROTO_IPV6,
IPV6_V6ONLY, 1)` for cross-platform portability** (which is plausible
on Linux-focused refactors), this fix would silently regress to
IPv6-only on macOS — Claude Desktop's IPv4 traffic would suddenly
bypass.

Mitigation: on any mitmproxy major-version bump, re-run the
verification curl (streaming Anthropic call from a terminal with
`HTTPS_PROXY=http://127.0.0.1:9080`) AND confirm with `lsof -nP -i
:9080 -sTCP:LISTEN` that mitmproxy is bound to both `*:9080` (IPv4)
and `[::]:9080` (IPv6). The integration test in
`tests/test_watch_cli.py::TestMitmdumpDualStackListener` only pins
the cmdline; it does not exercise the actual socket bind. A
defence-in-depth follow-up would be a smoke test that opens a TCP
connection to `[::1]:9080` from the test runner and asserts it
accepts — out of scope here.

## Alternatives considered

1. **Add a second `networksetup` call for IPv6.** Rejected — there is
   no IPv6-specific `-setsecurewebproxy` flag; the existing call is
   stack-agnostic, so a second call is meaningless and would be
   misleading.

2. **Add a second mitmproxy process bound to IPv4.** Rejected — on
   macOS, the single `::` listener already accepts IPv4; a second
   process would double the resource footprint without capturing
   anything new.

3. **Switch to mitmproxy's `--mode transparent` or `--mode socks`.**
   Rejected — transparent mode requires pf rules and is brittle;
   socks mode requires every app to opt in. The regular HTTPS proxy
   mode is the documented integration path.

## Verification

The cmdline change is pinned by three new tests in
`tests/test_watch_cli.py::TestMitmdumpDualStackListener`:

1. `test_cmdline_includes_listen_host_for_dual_stack` — asserts
   `--listen-host ::` appears in the argv passed to `os.execvp`.
2. `test_cmdline_still_includes_listen_port` — regression test that
   the new flag doesn't shadow `--listen-port`.
3. `test_listen_host_precedes_listen_port` — pins the canonical
   ordering for cmdline readability.

End-to-end verification post-merge: send a message in Claude Desktop,
confirm the connection appears in lsof as `127.0.0.1:9080` ESTABLISHED
(no IPv6 direct connections), and the DB receives `/v1/messages` rows
with populated tokens.

## Backward compatibility

Existing daemons running before this fix will not pick up the IPv6
listener until they're restarted. Users on an in-place upgrade need
to run `ai-monitor --stop && ai-monitor --start --with-proxy` after
`pip install -e .`. The `is_mitmproxy_process` check in
`lifecycle.py:191` will adopt a running daemon as-is; the IPv6
listener is absent until that daemon dies and `ProxyManager.restart()`
spawns the new cmdline. Documented in the v0.2.1 CHANGELOG entry and
the final-verification checklist.

## Out of scope for this PR

- **State file for proxy restore.** When `--disable-system-proxy`
  runs, restore the user's pre-Vigil proxy configuration. UX
  improvement, not capture-completeness. Deferred to v0.2.2 (or
  later — value depends on whether users actually have prior proxy
  configs).

- **`--status` IPv4/IPv6 row split.** Cosmetic display change. Both
  rows would come from the same single networksetup call (per the
  architect's Q1 — the setting is stack-agnostic). Pure UX.
  Deferred.

- **`_identify_port_holder` updating for `::` bind.** Only called by
  the dashboard `bind_with_retry`, which still binds IPv4 (`127.0.0.1`)
  per `get_bind_address()`. Not affected by this PR.
