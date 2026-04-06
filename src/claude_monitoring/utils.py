# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Shared utility functions for AI Runtime Monitor.

Used by both monitor.py and watch.py.
"""

import re
from datetime import datetime, timezone

from claude_monitoring.constants import (
    AI_PROCESS_EXACT,
    AI_PROCESS_PATTERNS,
    KNOWN_EXAMPLE_SECRETS,
    SENSITIVE_PATTERNS,
)


def scan_sensitive(text, names_only=False, validate=True):
    """Scan text for sensitive data patterns.

    Args:
        text: Text to scan. Truncated to 50K chars for performance.
        names_only: If True, return list of pattern name strings (watch.py compat).
                    If False, return list of dicts with name/severity/category.
        validate: If True (default), run validators to reduce false positives.
                  Only matches with confidence "high" or "medium" are returned.

    Returns:
        List of matches (dicts or strings depending on names_only).
    """
    if not text:
        return []
    scan_text = text[:50000] if len(text) > 50000 else text

    if validate:
        from claude_monitoring.validators import VALIDATORS
    else:
        VALIDATORS = None

    found = []
    for name, info in SENSITIVE_PATTERNS.items():
        pattern = info["pattern"]
        try:
            match = re.search(pattern, scan_text)
            if not match:
                continue

            # Run validator if available and validation is enabled
            if VALIDATORS and name in VALIDATORS:
                validator = VALIDATORS[name]
                match_text = match.group(0)
                result = validator(match_text, scan_text)
                if not result.get("valid", False):
                    continue
                if result.get("confidence") not in ("high", "medium"):
                    continue

            if names_only:
                found.append(name)
            else:
                entry = {
                    "name": name,
                    "severity": info["severity"],
                    "category": info["category"],
                    "matched_value": match.group(0),
                    "match_start": match.start(),
                }
                if VALIDATORS and name in VALIDATORS:
                    entry["validated"] = True
                found.append(entry)
        except re.error:
            continue
    return found


def _is_known_example(pattern_name, text):
    """Check if a sensitive pattern match is a known example/test value.

    Args:
        pattern_name: The pattern name (e.g. "aws_key").
        text: The text that was scanned.

    Returns:
        True if the match is a known example that should be skipped.
    """
    examples = KNOWN_EXAMPLE_SECRETS.get(pattern_name, set())
    if not examples:
        return False
    for example in examples:
        if example in text:
            return True
    return False


def extract_file_paths(text):
    """Extract file paths mentioned in text.

    Returns:
        Deduplicated list of file paths found.
    """
    paths = re.findall(r'(?:^|[\s\'"])(/(?:[\w\-./]+))', text)
    return list(set(p for p in paths if len(p) > 3 and "." in p.split("/")[-1]))


def extract_urls(text):
    """Extract HTTP/HTTPS URLs from text.

    Returns:
        List of URL strings found.
    """
    return re.findall(r'https?://[^\s\'"<>]+', text)


def now_iso():
    """Current UTC timestamp in ISO format."""
    return datetime.now(timezone.utc).isoformat()


def is_ai_process(name, cmdline, exe_path=""):
    """Check if a process is an AI process using two-tier matching.

    Tier 1: Exact process name match (fast).
    Tier 2: Substring pattern match with exclusion list.
    Skips macOS system services.

    Returns:
        True if the process is identified as an AI process.
    """
    if name in AI_PROCESS_EXACT:
        return True
    # Skip macOS system services
    if exe_path and (exe_path.startswith("/System/Library/") or exe_path.startswith("/usr/libexec/")):
        return False
    name_lower = (name or "").lower()
    cmdline_lower = (cmdline or "").lower()
    for pattern, config in AI_PROCESS_PATTERNS.items():
        if pattern in name_lower or pattern in cmdline_lower:
            if any(excl in name for excl in config.get("exclude", [])):
                continue
            return True
    return False
