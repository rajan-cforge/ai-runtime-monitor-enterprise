# Lifecycle reliability — stale PID, port collisions, stuck system proxy

**Status:** Implementation
**Criticality:** C3 — touches the monitor shutdown path (hot) and the
dashboard bind path (load-bearing for `--status`). No new trust boundary,
no secrets, no crypto.

## Motivation

Analysis of `~/claude_watch_output/logs/monitor.log` (4,027 lines, Apr 13 →
May 28) shows three recurring failure modes that the existing
`detect_stale_state()` reaper catches *after the fact* but never prevents:

| Pattern                          | Occurrences | Symptom                                         |
| -------------------------------- | ----------- | ----------------------------------------------- |
| `crash: stale_monitor_pid`       | ~40         | PID file outlives the monitor process           |
| `crash: stuck_system_proxy`      | ~20         | macOS Wi-Fi HTTPS proxy left ON after shutdown  |
| `OSError [Errno 48] (port 9081)` | ~10         | Restart races prior instance for dashboard port |

The pattern reappeared today on the new laptop: `ai-monitor --status`
reports `Monitor: ❌ Stopped` and `LaunchAgent: ⚠ Loaded but not running`
while `pgrep` finds both `ai-monitor` and `mitmdump` processes still
running — exactly the "stale monitor + orphan mitmdump" state.

## Root causes

### 1. `stale_monitor_pid` — shutdown ordering

`start_monitoring`'s `signal_handler` (monitor.py:4996) removes the PID
file at line 5017 — **after** `pm.stop(disable_proxy=True)` at 5004,
which can block up to ~10s (5s mitmdump SIGTERM wait + 5s
`networksetup` timeout). When launchd's `KillTimeout` fires before
`remove_pid_file` runs, the file is leaked. `detect_stale_state` then
fires on the next `--start` and logs the crash.

The `atexit` handler at 4769 does remove the PID file first, but
`atexit` does not run on SIGKILL, OOM, or `os._exit()`.

### 2. `OSError [Errno 48]` — bind race during restart

`ReusableHTTPServer` sets `allow_reuse_address = True` (SO_REUSEADDR).
On macOS this covers sockets in `TIME_WAIT` but **not** sockets still
in `LISTEN` from a process that has not fully exited. The bind at
monitor.py:4924 has no retry — a single `OSError` aborts startup, and
launchd's `KeepAlive` restarts within `ThrottleInterval=10s`, hitting
the same race repeatedly (the log shows 4 attempts in 36 seconds on
5/25 17:43–17:44).

### 3. `stuck_system_proxy` — same root cause as #1

System proxy disable lives inside `pm.stop(disable_proxy=True)`. When
the slow shutdown is interrupted, the proxy stays ON. The next
`--start`'s `detect_stale_state` catches it, but the user's network has
already been routing through a dead proxy for the gap window (median:
hours).

## Proposed approach

Three surgical changes, all additive at the API layer.

### A. `lifecycle.cleanup_for_shutdown(pid_file)` — atomic, side-effect-only

Removes the PID file and disables the system proxy in two cheap,
unconditional calls. Designed to be the **first** statement in every
shutdown path (signal handler and `atexit`), so even when later cleanup
is interrupted by SIGKILL the user's machine is returned to a sane
state.

Both inner calls are idempotent and swallow their own errors — the
caller is on its way out anyway.

### B. `lifecycle.bind_with_retry(factory, port, ...)` — bounded backoff

Wraps the `ReusableHTTPServer` construction in a retry loop with a
backoff schedule of `(0.5, 1.0, 2.0, 4.0)` seconds across 5 attempts
(~7.5s total). On each `EADDRINUSE`, logs a diagnostic identifying the
LISTEN holder via `lsof` so operators can correlate. Re-raises any
non-EADDRINUSE error immediately. Re-raises EADDRINUSE on the final
attempt with full context.

Calibrated against the observed restart cadence: launchd's
`ThrottleInterval=10s` means a fresh attempt starts ~10s after the
previous instance was signalled. Even a SIGKILL'd Python process
typically releases its dashboard socket within 1–3s after the kernel
reclaims the FD; 7.5s of retry coverage is well above that.

### C. `start_monitoring` — reorder signal handler

`signal_handler` calls `cleanup_for_shutdown` as its first action,
**before** `pm.stop`. The atexit handler does the same. `pm.stop` is
still called for the mitmdump SIGTERM and `_PROXY_MANAGER` housekeeping,
but with `disable_proxy=False` since the proxy is already off.

## Alternatives considered

- **`os.register_at_fork` / `os._exit` trick.** Rejected — fragile,
  relies on interpreter internals, and doesn't help with SIGKILL.
- **Move the PID file into the watchdog thread's heartbeat.** Rejected
  — adds complexity; the file IS the cross-process handshake with
  `--status`, so consolidating it with heartbeat would shift the
  failure mode rather than fix it.
- **Auto-kill the port holder during bind retry.** Rejected — too
  destructive for a generic helper. `detect_stale_state` already
  handles process-level cleanup with the PID-file context that
  identifies whether the holder is "us". The bind helper logs but
  never kills.
- **Switch SO_REUSEADDR to SO_REUSEPORT.** Rejected — SO_REUSEPORT
  allows simultaneous listeners, which would let two monitor instances
  silently coexist on port 9081 each catching half the traffic. The
  resulting split-brain dashboard state would be worse than the
  current restart failure.

## Threat surface

- No new trust boundary. The dashboard bind address and port are
  unchanged; the auth token check on each `DashboardHandler` route is
  unchanged.
- No new subprocess invocations except a single `lsof` query during
  bind retries — read-only, bounded timeout (2s), best-effort failure.
- `cleanup_for_shutdown` calls `networksetup -setsecurewebproxystate
  Wi-Fi off` via the existing `disable_system_proxy()` (argv list,
  never `shell=True`). This is the same call that was previously made
  via `pm.stop`; only the ordering changes.

## Verification plan

Unit tests in `tests/test_lifecycle.py`:

1. **`test_removes_pid_file_and_disables_proxy`** + **`test_removes_pid_before_disabling_proxy`** —
   the first asserts both side effects happened; the second pins the
   ordering (PID removal before proxy disable) using a shared `ordering`
   list with side-effect-instrumented mocks. Without the ordering test a
   refactor that swapped the two `suppress` blocks would still pass.
2. **`test_cleanup_for_shutdown_swallows_pid_errors`** — patches
   `remove_pid_file` to raise; asserts `disable_system_proxy` still
   runs and the helper does not raise.
3. **`test_cleanup_for_shutdown_swallows_proxy_errors`** — patches
   `disable_system_proxy` to raise; asserts the PID file is still
   removed and the helper does not raise.
4. **`test_bind_with_retry_returns_on_first_success`** — factory
   returns sentinel immediately; asserts no sleep was called.
5. **`test_bind_with_retry_retries_on_eaddrinuse`** — factory raises
   `OSError(EADDRINUSE)` twice then returns; asserts 2 backoff sleeps
   and final return.
6. **`test_bind_with_retry_raises_after_max_attempts`** — factory
   always raises EADDRINUSE; asserts the original OSError is re-raised
   with full traceback after the configured attempts.
7. **`test_bind_with_retry_does_not_retry_on_other_errors`** — factory
   raises `OSError(EACCES)`; asserts immediate re-raise with no
   sleep.
8. **`test_bind_with_retry_logs_holder`** — patches `_identify_port_holder`
   to return a known string; asserts the warning log line includes it.

Manual smoke test (documented in PR body): start monitor, send SIGTERM,
verify PID file is removed within 100ms and `networksetup
-getsecurewebproxy Wi-Fi` reports `Enabled: No`. Then restart immediately
and verify no `OSError [Errno 48]` in the log.

## Out of scope

- Privileged helper / SMAppService — tracked separately under v0.3.
- Replacing launchd KeepAlive with a custom supervisor.
- Moving the bind retry loop into `ReusableHTTPServer` itself — the
  retry is a property of the *startup orchestrator*, not the server.
