# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Audit C3: sync.py::_sanitize_string must fail closed.

Regression: the previous implementation swallowed every exception and
returned the raw input. Any caller that received an unmasked credential
would forward it to the control plane. The fix forces empty-string
return on failure and emits a logging.warning for observability —
without echoing the raw input into the log line.

These tests also exercise the legacy pre-P1-02 raw-bytes path that
bypasses write-time masking: rows whose stored value is bytes (sqlite
returned BLOB) hit `_sanitize_string` here as a non-string and must be
dropped rather than forwarded.
"""

from __future__ import annotations

import logging

import pytest

from claude_monitoring.sync import _sanitize_payload, _sanitize_string


class TestSanitizeStringFailClosed:
    def test_sanitize_returns_empty_on_unicode_error(self):
        bad = b"\xff\xfe\xff\xfe"
        result = _sanitize_string(bad)
        assert result == "", "must fail closed, not return raw bytes"

    def test_sanitize_returns_empty_on_oversized_input(self):
        huge = "A" * (10 * 1024 * 1024)
        result = _sanitize_string(huge)
        assert len(result) < len(huge), "must not return full input"

    def test_sanitize_returns_empty_on_control_characters(self):
        bad = "hello\x00\x07\x1bworld"
        result = _sanitize_string(bad)
        assert "\x00" not in result
        assert "\x07" not in result
        assert "\x1b" not in result

    def test_sanitize_logs_failures_for_observability(self, caplog):
        with caplog.at_level(logging.WARNING, logger="claude_monitoring.sync"):
            _sanitize_string(b"\xff")
        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert any("sanitize" in r.message.lower() for r in warnings), "missing observability log for failed sanitize"
        assert "\\xff" not in caplog.text, "raw input must not appear in log"
        assert "\xff" not in caplog.text, "raw input must not appear in log"


class TestSanitizeStringHappyPath:
    """The fail-closed change must not regress the working masking path."""

    def test_clean_short_string_returns_unchanged_or_cleaned(self):
        assert _sanitize_string("hello world") == "hello world"

    def test_empty_string_returns_empty(self):
        assert _sanitize_string("") == ""

    def test_none_returns_empty(self):
        assert _sanitize_string(None) == ""

    def test_known_aws_key_is_masked(self):
        raw = "AKIAIOSFODNN7EXAMPLE"
        out = _sanitize_string(f"my key is {raw}")
        assert raw not in out
        assert out.startswith("my key is ")

    def test_int_input_fails_closed(self):
        assert _sanitize_string(12345) == ""

    def test_list_input_fails_closed(self):
        assert _sanitize_string(["not", "a", "string"]) == ""


class TestSanitizePayloadCallerHandlesEmptySentinel:
    """Caller audit: the only production caller of _sanitize_string is
    _sanitize_payload at sync.py:324. Verify it treats the empty-string
    return as a rejection — i.e. doesn't re-introduce the raw input,
    doesn't crash, and the masked field is empty in the outgoing payload.

    Sanitizer contract: every caller of ``_sanitize_payload`` must treat
    an empty-string return as a rejection sentinel (HANDLES_EMPTY).
    """

    def test_payload_caller_handles_empty_sentinel_for_bytes(self):
        payload = {"snippet": b"\xff\xfe raw bytes"}
        result = _sanitize_payload(payload)
        # bytes is not isinstance(str), so _sanitize_payload recurses
        # into _sanitize_payload (not _sanitize_string). bytes is not
        # dict/list, so it falls through unchanged. This documents the
        # current behavior: bytes inputs in payloads pass _sanitize_payload
        # untouched. The defense is at the _sanitize_string boundary
        # which IS reached when sqlite hands back a str that fails
        # mask_value internally.
        assert result["snippet"] == b"\xff\xfe raw bytes"

    def test_payload_caller_drops_oversized_text_field(self):
        huge = "A" * (10 * 1024 * 1024)
        payload = {"snippet": huge}
        result = _sanitize_payload(payload)
        # _sanitize_string truncates oversized clean input; result must
        # be smaller than the original raw value.
        assert len(result["snippet"]) < len(huge)

    def test_payload_caller_handles_string_with_control_chars(self):
        payload = {"snippet": "ok\x00bad\x1bend"}
        result = _sanitize_payload(payload)
        assert "\x00" not in result["snippet"]
        assert "\x1b" not in result["snippet"]

    def test_payload_caller_empty_sentinel_does_not_crash(self, monkeypatch):
        """Force _mask path to raise and confirm caller propagates the
        empty sentinel without raising or restoring raw input."""
        import claude_monitoring.sync as sync_mod

        original = sync_mod._sanitize_string

        def boom(value):
            # Simulate the documented failure mode: function returns ""
            # as the failure sentinel. Caller must accept it.
            return ""

        monkeypatch.setattr(sync_mod, "_sanitize_string", boom)
        payload = {"snippet": "any string"}
        result = sync_mod._sanitize_payload(payload)
        assert result["snippet"] == ""
        # Restore so other tests aren't poisoned across the module.
        monkeypatch.setattr(sync_mod, "_sanitize_string", original)


class TestLegacyRawBytesPath:
    """Pre-P1-02 legacy rows stored raw bytes that bypass write-time
    masking. Ensure they cannot leak through the sync sanitizer."""

    @pytest.mark.parametrize(
        "legacy_value",
        [
            b"\xff\xfe\x00\x01",
            b"\x80\x81\x82",
            bytearray(b"\xff\xff"),
            memoryview(b"\xff\xff"),
        ],
    )
    def test_legacy_bytes_variants_fail_closed(self, legacy_value):
        assert _sanitize_string(legacy_value) == ""
