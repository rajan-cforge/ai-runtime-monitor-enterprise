# Bug 2 — osascript CA trust application fix

**Status:** Implementation (this PR fixes Bug 2 per the corrected plan in `~/Documents/vigil-notes/v02-one-click-install-corrected-plan-2026-05-27.md`).

**Criticality:** C3 — touches the CA trust boundary; modifies macOS root trust list flow.

## Motivation

`ai-monitor --setup`'s Step 2 (Trust the CA) silently fails on macOS Sequoia (15) and the new-laptop's macOS 26.5. The wizard reports "Certificate trust step appeared to succeed, but verification failed" — the osascript path completes (Touch ID prompts, exit 0), the cert ends up in `/Library/Keychains/System.keychain`, but the admin trust setting is **not** applied. Users see "in_keychain_but_not_trusted" and are told to run `sudo security add-trusted-cert ...` manually.

This is the headline UX failure of the launch-readiness sprint. On any modern macOS, the wizard's "happy path" is broken for most users.

## Root cause

`security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain <cert>` performs two privileged operations:

1. **Add the cert to the System keychain.** Requires root.
2. **Modify the admin trust-settings domain** via `SecTrustSettingsSetTrustSettings(cert, kSecTrustSettingsDomainAdmin, ...)`. Requires root AND a GUI session context that can satisfy a user-interaction authorization check.

The `osascript "do shell script ... with administrator privileges"` mechanism grants root via the deprecated `AuthorizationExecuteWithPrivileges` codepath. The spawned subprocess has uid 0 (enough for operation 1), but no GUI session ownership in the WindowServer's sense (insufficient for operation 2). The Security framework returns `errSecInteractionNotAllowed` for operation 2; the `security` binary surfaces a stderr message but exits 0 anyway. osascript exits 0 (the script ran). The Python `subprocess.run` sees `returncode == 0` and returns success. `verify_ca_trusted` correctly catches the actual state.

Apple DTS has confirmed this behavior: *"add-trusted-cert is triggering user interaction and then the user interaction is failing because of the way you're running the security tool."* (Sources cited at end of doc.)

The `authorizationdb write com.apple.trust-settings.admin allow` workaround that worked through Sonoma is **dead on Sequoia**: Apple SIP-protected that right; the write fails with `(-60005)`.

The only fully-automated path that converges on Sequoia+ is an SMJobBless / SMAppService privileged helper (notarized native binary + XPC). That's v0.3 scope (see `~/Documents/vigil-notes/v03-privileged-helper-smjobbless.md`).

## Proposed approach — two-attempt strategy with poll-based convergence

**Two attempts, in order:**

1. **osascript** (kept for the macOS versions where Touch ID still works — Monterey/Ventura sometimes converge here). Capture stderr; route to `logger.warning` so the failure mode is logged but doesn't clutter the wizard's stdout.

2. **Verify** via existing `verify_ca_trusted(cert_path)`. If `(True, "trusted")`, done.

3. **Terminal sudo fallback.** Print the exact `sudo security add-trusted-cert -d -r trustRoot -k System.keychain <cert path>` command — referencing the cert path that `ensure_ca_cert` returned (Bug 8 invariant — must not be a freshly-regenerated path). Then **poll** `verify_ca_trusted` every 2 seconds for up to 2 minutes. Accept Enter as an early manual check. Break the moment verify returns `(True, "trusted")`.

The poll-based convergence is critical: today's failure mode is "user ran sudo but wizard still says failed" because the wizard verified once and gave up. Polling means the wizard actively re-checks; it cannot miss a successful trust application.

### Why poll instead of just `input()`

A single `input("Press Enter when done")` + re-verify has one failure mode: if the user runs sudo, types Enter, but trust still hasn't propagated through the Security framework cache, the second verify fails and the wizard says "Step failed." Polling tolerates that latency — verify will succeed within the next 2-second tick.

### Common-path messaging on Sequoia+

The architect's review and the user's feedback both flag that **the fallback is the common path on Sequoia+, not an exception.** Frame Step 2 accordingly:

```
[2/5] Trust the monitoring certificate

  macOS requires trust changes to be authorized from your
  terminal. Run this one command:

    sudo security add-trusted-cert -d -r trustRoot \
      -k /Library/Keychains/System.keychain \
      /Users/.../claude_watch_output/ca-cert.pem

  Waiting for trust... (press Enter to check now, Ctrl-C to skip)
```

No red ❌. No "step failed." This is the expected flow on modern macOS. Only show an error if the fallback times out or the user skips.

### Coordination with Bug 8

The fallback's printed cert path MUST be the cert that `ensure_ca_cert` returned. If we accidentally regenerate or use a different path, we recreate Bug 8 from a different code site. Tests assert no regeneration occurs during the fallback flow.

## Alternatives considered

1. **Drop osascript entirely; go straight to sudo prompt.** Simpler, but loses Touch ID convenience on the macOS versions where it works. Rejected.
2. **`authorizationdb` workaround.** Dead on Sequoia (SIP-protected). Rejected.
3. **Privileged helper (SMJobBless / SMAppService).** The correct long-term answer; ships in v0.3. Out of scope for v0.2.
4. **Shipping a separately-installed `vigil-helper` script.** Adds a second binary that needs its own install path; not significantly less friction than the sudo command. Rejected.
5. **Pure Python via pyobjc + SecTrustSettingsSetTrustSettings.** The pyobjc bridge can call into the Security framework, but the same GUI-session-ownership constraint applies; the Python process doesn't have a session either. Rejected.

## Threat surface

The trust step modifies the macOS root trust list. Threats considered:

- **The `input("Press Enter")` gate**: reads from stdin. Discards the value. Used only as a wakeup signal. No injection vector.
- **The printed sudo command**: constructed with `shlex.quote(str(cert_path))`. `cert_path` is config-derived (not user input). Even if the path contained shell metacharacters, the quoting is correct. The command is **not executed by Vigil** — the user runs it in their own terminal under their own sudo policy. This preserves Apple's "user explicitly authorized" guarantee.
- **The poll loop**: bounded at 120 seconds with a 2-second tick. Cannot consume excessive resources or run forever.
- **The osascript stderr**: routed to `logger.warning`, not stdout. Visible in daemon logs (sensitive to log handlers; if the user has stdout logging enabled, it ends up there too). Contains macOS error strings — no user data. No injection threat.

The threat surface is unchanged from the existing `trust_ca_cert` — Vigil never executes `sudo security` itself; it asks the user to. This PR makes that ask more reliable, not more permissive.

## Verification plan

### Unit tests (added in this PR)

`tests/test_security_hardening.py::TestTrustCaCertWithFallback`:

1. `test_returns_true_when_osascript_succeeds_and_trust_verified` — osascript returns `(True, "")`, `verify_ca_trusted` returns `(True, "trusted")` → result True, no polling, no input prompt.
2. `test_returns_false_when_osascript_fails_and_stdin_fallback_disabled` — osascript returns `(False, "<error>")`, `stdin_fallback=False` → result False, no polling, no input prompt.
3. `test_polls_verify_until_success_after_sudo_fallback` — osascript returns `(True, "<errSecInteractionNotAllowed>")`, first verify `(False, ...)`, second verify `(True, "trusted")` → result True, poll loop executed exactly twice.
4. `test_poll_times_out_after_120_seconds` — both verifies return `(False, ...)`; mock `time.monotonic` to advance past the 120s budget → result False, exit code 2 from caller.
5. `test_enter_keypress_triggers_immediate_recheck` — first verify False, simulate Enter press during sleep, second verify True → result True, did not wait the full 2s tick.
6. `test_keyboard_interrupt_during_poll_returns_false` — first verify False, simulate Ctrl-C during sleep → result False (skipped).
7. `test_fallback_prints_cert_path_from_ensure_ca_cert` — pre-place a cert via `ensure_ca_cert`, run fallback path, capture stdout, assert the printed sudo command references THAT cert's path. No regeneration.
8. `test_osascript_stderr_is_logged_when_present` — osascript returns `(True, "SecTrustSettingsSetTrustSettings: ...")`, capture logging → warning emitted with the stderr text.
9. `test_does_not_regenerate_cert_during_fallback` — Bug 8 coordination test. Snapshot cert SHA before fallback, drive fallback to completion via mocks, snapshot SHA after — must be identical.

### Manual verification (new laptop, post-merge)

```bash
# Clean slate
sudo security delete-certificate -c "AI Runtime Monitor" /Library/Keychains/System.keychain 2>/dev/null
rm -f ~/claude_watch_output/ca-cert.pem ~/claude_watch_output/ca-key.pem

# Single-command happy path on modern macOS (Sequoia+, macOS 26.5)
ai-monitor --setup
# → Step 2 prints "Waiting for trust..." with the exact sudo command
# → User pastes + runs the sudo command in the SAME terminal
# → Wizard polls and detects trust within 2-4 seconds
# → Step 2 prints "✅ Certificate trusted. Continuing setup."
# → Steps 3-5 proceed
# → Exit code 0

# Subsequent run is a no-op (Bug 8 invariant)
ai-monitor --setup
# → Step 1: "Reusing existing certificate"
# → Step 2: "Certificate already trusted (verified in admin trust settings)"
```

### Non-tty (CI) path

```bash
ai-monitor --setup < /dev/null
# → Step 2 osascript fails (no GUI on CI runners anyway)
# → stdin_fallback=False; wizard prints the manual command, exits non-zero
# → No hang on input()
```

## Implementation map

| File | Change |
|------|--------|
| `src/claude_monitoring/security.py` | Extract `_run_osascript_trust(cert_path) → (bool, str)` private helper. Add `import logging; logger = logging.getLogger(__name__)`. Add `trust_ca_cert_with_fallback(cert_path, *, stdin_fallback=True, poll_seconds=2, max_wait_seconds=120) → bool`. Update `trust_ca_cert` to call the new helper and log stderr; bool return preserved for backwards-compat. |
| `src/claude_monitoring/wizard.py` | Import `trust_ca_cert_with_fallback`. Step 2 replaces `osascript_ok = trust_ca_cert(); verified, code = verify_ca_trusted(...)` with `verified = trust_ca_cert_with_fallback(cert_path, stdin_fallback=sys.stdin.isatty())`. Remove the now-redundant manual-command printout (lives inside the helper now). Refresh messaging to the "common path" framing. |
| `tests/test_security_hardening.py` | New `TestTrustCaCertWithFallback` with 9 test cases. |
| `tests/test_cleanup_wizard_purge.py` | Update existing wizard-trust tests to monkeypatch `trust_ca_cert_with_fallback` instead of `trust_ca_cert`. |
| `docs/spec/functional/security.md` | Add §2.2.b on the two-attempt strategy and §6.b on the osascript GUI-session-ownership failure mode. |
| `docs/spec/functional/wizard.md` | Update §8 (failure modes) to reflect the new common-path framing on Sequoia+. |

## References

- [SecTrustSettingsSetTrustSettings requires authentication — Apple Developer Forums](https://developer.apple.com/forums/thread/692105)
- [security add-trusted-cert password-twice — Apple Developer Forums](https://developer.apple.com/forums/thread/671582)
- [macOS 15 Sequoia breaks `authorizationdb write` — GitHub Actions runner-images #11893](https://github.com/actions/runner-images/issues/11893)
- [Trusting Certificates in System Keychain without Prompting — Twocanoes Software](https://twocanoes.com/trusting-certificates-in-system-keychain-without-prompting/)
- v0.3 follow-up: [v03-privileged-helper-smjobbless.md](file:///Users/rajanyadav/Documents/vigil-notes/v03-privileged-helper-smjobbless.md)
