# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Validators for sensitive data pattern matches.

Each pattern type gets a validator that goes beyond regex to reduce false positives.
Validators return: {"valid": bool, "confidence": "high"|"medium"|"low",
                     "details": str, "live": bool|None}

Liveness checks (network calls to verify if a secret is active) are optional
and gated by a flag — never run automatically.
"""

import base64
import json
import math
import re
from urllib.parse import urlparse

# ─────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────


def shannon_entropy(text):
    """Calculate Shannon entropy of a string (bits per character)."""
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _luhn_checksum(number_str):
    """Validate a number string using the Luhn algorithm. Returns True if valid."""
    digits = [int(d) for d in number_str]
    odd_digits = digits[-1::-2]
    even_digits = digits[-2::-2]
    total = sum(odd_digits)
    for d in even_digits:
        d *= 2
        if d > 9:
            d -= 9
        total += d
    return total % 10 == 0


_RESULT_SKIP = {"valid": False, "confidence": "low", "details": "", "live": None}

# JSON metadata keys whose numeric values should not be treated as credit cards / phones
_JSON_ID_KEYS = frozenset(
    {
        "request_id",
        "session_id",
        "sender_id",
        "message_id",
        "chat_id",
        "user_id",
        "update_id",
        "updateId",
        "responseId",
        "msg_id",
        "cache_read_tokens",
        "cache_write_tokens",
        "input_tokens",
        "output_tokens",
        "cache_read_input_tokens",
        "cache_creation_input_tokens",
        "totalTokens",
        "timestamp",
    }
)

_PLACEHOLDER_PASSWORDS = frozenset(
    {
        "changeme",
        "password",
        "xxx",
        "***",
        "your_password_here",
        "redacted",
        "todo",
        "placeholder",
        "example",
        "secret",
        "test",
        "dummy",
        "sample",
        "none",
        "null",
        "undefined",
    }
)

_TEST_SSNS = frozenset({"078-05-1120", "219-09-9999"})

_EXAMPLE_CONTEXT_WORDS = frozenset(
    {
        "regex",
        "pattern",
        "example",
        "test",
        "sample",
        "mock",
        "fixture",
        "placeholder",
        "demo",
        "dummy",
        "fake",
    }
)


def _near_json_key(text, match_text, radius=50):
    """Check if match_text appears near a JSON-like key that suggests it's an ID, not PII."""
    pos = text.find(match_text)
    if pos < 0:
        return False
    window = text[max(0, pos - radius) : pos + len(match_text) + radius].lower()
    for key in _JSON_ID_KEYS:
        if key.lower() in window:
            return True
    return False


def _in_example_context(text, radius=100):
    """Check if text appears to be in a documentation/test/example context."""
    text_lower = text.lower()
    return any(word in text_lower for word in _EXAMPLE_CONTEXT_WORDS)


# ─────────────────────────────────────────────────────────────
# Validators
# ─────────────────────────────────────────────────────────────


def validate_credit_card(match_text, surrounding_text=""):
    """Validate a credit card number match."""
    digits = re.sub(r"[^0-9]", "", match_text)

    if not (13 <= len(digits) <= 19):
        return {**_RESULT_SKIP, "details": f"wrong digit count: {len(digits)}"}

    # All same digit = not a real card
    if len(set(digits)) == 1:
        return {**_RESULT_SKIP, "details": "all same digit"}

    # Check if near a JSON ID key
    ctx = surrounding_text or match_text
    if _near_json_key(ctx, match_text):
        return {**_RESULT_SKIP, "details": "appears in JSON metadata context"}

    if not _luhn_checksum(digits):
        return {**_RESULT_SKIP, "details": "failed Luhn checksum"}

    return {"valid": True, "confidence": "high", "details": "Luhn valid", "live": None}


def validate_phone_number(match_text, surrounding_text=""):
    """Validate a phone number match, filtering Telegram/messaging metadata IDs."""
    ctx = surrounding_text or match_text

    # Check if near messaging metadata keys
    id_keywords = ("sender_id", "message_id", "chat_id", "user_id", "telegram", "updateId", "update_id")
    digits = re.sub(r"[^0-9]", "", match_text)
    pos = ctx.find(match_text)
    if pos >= 0:
        window = ctx[max(0, pos - 50) : pos + len(match_text) + 50].lower()
        for kw in id_keywords:
            if kw.lower() in window:
                return {**_RESULT_SKIP, "details": f"near '{kw}' — likely a messaging ID"}

    # Check if the number follows a key containing "id"
    pre = ctx[max(0, pos - 30) : pos].lower() if pos >= 0 else ""
    if re.search(r'"[^"]*id[^"]*"\s*[:=]\s*"?\s*$', pre):
        return {**_RESULT_SKIP, "details": "follows an ID key in JSON"}

    # Check for real phone format indicators
    has_format = bool(re.search(r"(\+1[- ]?)?\(?\d{3}\)?[- .]\d{3}[- .]\d{4}", match_text))

    if has_format:
        return {"valid": True, "confidence": "high", "details": "formatted phone number", "live": None}

    # Raw 10-digit number without formatting — lower confidence
    if len(digits) == 10:
        return {"valid": True, "confidence": "medium", "details": "unformatted 10-digit number", "live": None}

    return {"valid": True, "confidence": "medium", "details": "numeric match", "live": None}


def validate_ssn(match_text, surrounding_text=""):
    """Validate a Social Security Number match."""
    m = re.match(r"(\d{3})-(\d{2})-(\d{4})", match_text.strip())
    if not m:
        return {**_RESULT_SKIP, "details": "not in xxx-xx-xxxx format"}

    area, group, serial = m.group(1), m.group(2), m.group(3)

    if area == "000" or area == "666" or (900 <= int(area) <= 999):
        return {**_RESULT_SKIP, "details": f"invalid area number: {area}"}
    if group == "00":
        return {**_RESULT_SKIP, "details": "invalid group number: 00"}
    if serial == "0000":
        return {**_RESULT_SKIP, "details": "invalid serial: 0000"}

    full = f"{area}-{group}-{serial}"
    if full in _TEST_SSNS:
        return {**_RESULT_SKIP, "details": f"known test SSN: {full}"}

    ctx = surrounding_text or match_text
    if _in_example_context(ctx):
        return {**_RESULT_SKIP, "details": "appears in example/test context"}

    return {"valid": True, "confidence": "high", "details": "valid SSN format", "live": None}


def validate_aws_key(match_text, surrounding_text=""):
    """Validate an AWS access key."""
    key = match_text.strip()

    if len(key) != 20:
        return {**_RESULT_SKIP, "details": f"wrong length: {len(key)} (expected 20)"}

    prefix = key[:4]
    if prefix not in ("AKIA", "ASIA", "AROA", "AIDA"):
        return {**_RESULT_SKIP, "details": f"invalid prefix: {prefix}"}

    # Check rest is uppercase alphanumeric
    rest = key[4:]
    if not re.match(r"^[A-Z0-9]+$", rest):
        return {**_RESULT_SKIP, "details": "non-uppercase-alphanumeric chars after prefix"}

    return {"valid": True, "confidence": "high", "details": f"valid AWS key format ({prefix})", "live": None}


def validate_github_token(match_text, surrounding_text=""):
    """Validate a GitHub token."""
    token = match_text.strip()
    prefixes = {"ghp_": 40, "gho_": 40, "ghu_": 40, "ghs_": 40, "ghr_": 40}

    matched_prefix = None
    for prefix, _expected_len in prefixes.items():
        if token.startswith(prefix):
            matched_prefix = prefix
            break

    if not matched_prefix:
        return {**_RESULT_SKIP, "details": "no valid GitHub token prefix"}

    body = token[4:]
    if not re.match(r"^[A-Za-z0-9_]+$", body):
        return {**_RESULT_SKIP, "details": "invalid characters in token body"}

    if len(body) < 36:
        return {**_RESULT_SKIP, "details": f"token body too short: {len(body)}"}

    ctx = surrounding_text or match_text
    if _in_example_context(ctx):
        return {"valid": True, "confidence": "medium", "details": "valid format but in example context", "live": None}

    return {"valid": True, "confidence": "high", "details": f"valid GitHub token ({matched_prefix[:-1]})", "live": None}


def validate_anthropic_key(match_text, surrounding_text=""):
    """Validate an Anthropic API key."""
    key = match_text.strip()
    if not key.startswith("sk-ant-"):
        return {**_RESULT_SKIP, "details": "missing sk-ant- prefix"}

    if len(key) < 40:
        return {**_RESULT_SKIP, "details": f"too short: {len(key)} (expected 40+)"}

    body = key[7:]
    if not re.match(r"^[A-Za-z0-9\-_]+$", body):
        return {**_RESULT_SKIP, "details": "invalid characters in key body"}

    return {"valid": True, "confidence": "high", "details": "valid Anthropic key format", "live": None}


def validate_openai_key(match_text, surrounding_text=""):
    """Validate an OpenAI API key."""
    key = match_text.strip()
    if not key.startswith("sk-"):
        return {**_RESULT_SKIP, "details": "missing sk- prefix"}

    # Not an Anthropic key
    if key.startswith("sk-ant-"):
        return {**_RESULT_SKIP, "details": "this is an Anthropic key, not OpenAI"}

    if len(key) < 32:
        return {**_RESULT_SKIP, "details": f"too short: {len(key)} (expected 32+)"}

    return {"valid": True, "confidence": "high", "details": "valid OpenAI key format", "live": None}


def validate_slack_webhook(match_text, surrounding_text=""):
    """Validate a Slack webhook URL."""
    url = match_text.strip()
    m = re.match(r"https://hooks\.slack\.com/services/(T[A-Z0-9]+)/(B[A-Z0-9]+)/([A-Za-z0-9]+)", url)
    if not m:
        return {**_RESULT_SKIP, "details": "invalid Slack webhook format"}

    return {"valid": True, "confidence": "high", "details": "valid Slack webhook URL", "live": None}


def validate_jwt(match_text, surrounding_text=""):
    """Validate a JWT token by decoding header and payload."""
    token = match_text.strip()
    parts = token.split(".")
    if len(parts) != 3:
        return {**_RESULT_SKIP, "details": f"expected 3 segments, got {len(parts)}"}

    # Decode header
    try:
        header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
        header_json = base64.urlsafe_b64decode(header_b64)
        header = json.loads(header_json)
        if "alg" not in header:
            return {**_RESULT_SKIP, "details": "header missing 'alg' field"}
    except Exception:
        return {**_RESULT_SKIP, "details": "header is not valid base64url JSON"}

    # Decode payload
    try:
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        payload_json = base64.urlsafe_b64decode(payload_b64)
        payload = json.loads(payload_json)
    except Exception:
        return {**_RESULT_SKIP, "details": "payload is not valid base64url JSON"}

    # Check expiration
    import time

    exp = payload.get("exp")
    if exp is not None and isinstance(exp, (int, float)):
        if exp < time.time():
            return {"valid": True, "confidence": "medium", "details": "valid JWT but expired", "live": None}

    return {"valid": True, "confidence": "high", "details": "valid JWT with decodable header/payload", "live": None}


def validate_private_key(match_text, surrounding_text=""):
    """Validate a private key block."""
    if "BEGIN" not in match_text:
        return {**_RESULT_SKIP, "details": "missing BEGIN marker"}

    ctx = surrounding_text or match_text
    if _in_example_context(ctx):
        return {"valid": True, "confidence": "medium", "details": "private key in example/test context", "live": None}

    return {"valid": True, "confidence": "high", "details": "private key header detected", "live": None}


def validate_password(match_text, surrounding_text=""):
    """Validate a password-in-code match."""
    # Extract the password value from patterns like: password = "value" or password: "value"
    m = re.search(r"""(?i)(?:password|passwd|pwd)\s*[:=]\s*['"]([^'"]+)['"]""", match_text)
    if not m:
        return {**_RESULT_SKIP, "details": "could not extract password value"}

    value = m.group(1)

    if len(value) < 6:
        return {**_RESULT_SKIP, "details": f"too short: {len(value)} chars"}

    if value.lower() in _PLACEHOLDER_PASSWORDS:
        return {**_RESULT_SKIP, "details": f"placeholder password: {value}"}

    # Check if line is a comment
    ctx = surrounding_text or match_text
    line = ctx.strip()
    if line.startswith("#") or line.startswith("//"):
        return {**_RESULT_SKIP, "details": "in a comment"}

    entropy = shannon_entropy(value)
    if entropy < 2.0:
        return {**_RESULT_SKIP, "details": f"low entropy: {entropy:.2f}"}
    elif entropy < 3.0:
        return {"valid": True, "confidence": "medium", "details": f"moderate entropy: {entropy:.2f}", "live": None}
    else:
        return {"valid": True, "confidence": "high", "details": f"high entropy: {entropy:.2f}", "live": None}


def validate_db_connection(match_text, surrounding_text=""):
    """Validate a database connection string."""
    try:
        parsed = urlparse(match_text)
    except Exception:
        return {**_RESULT_SKIP, "details": "not a valid URI"}

    password = parsed.password
    if not password:
        return {**_RESULT_SKIP, "details": "no password in connection string"}

    if password.lower() in _PLACEHOLDER_PASSWORDS:
        return {**_RESULT_SKIP, "details": f"placeholder password: {password}"}

    entropy = shannon_entropy(password)
    if entropy < 2.0:
        return {**_RESULT_SKIP, "details": f"password has low entropy: {entropy:.2f}"}
    elif entropy < 3.0:
        return {"valid": True, "confidence": "medium", "details": f"password entropy: {entropy:.2f}", "live": None}
    else:
        return {"valid": True, "confidence": "high", "details": f"password entropy: {entropy:.2f}", "live": None}


def validate_bearer_token(match_text, surrounding_text=""):
    """Validate a Bearer token match."""
    # Extract the actual token value
    m = re.search(r"Bearer\s+([A-Za-z0-9_\-\.]+)", match_text, re.IGNORECASE)
    if not m:
        return {**_RESULT_SKIP, "details": "could not extract bearer token"}

    token = m.group(1)
    if len(token) < 20:
        return {**_RESULT_SKIP, "details": f"token too short: {len(token)}"}

    ctx = surrounding_text or match_text
    if _in_example_context(ctx):
        return {"valid": True, "confidence": "medium", "details": "bearer token in example context", "live": None}

    return {"valid": True, "confidence": "high", "details": f"bearer token ({len(token)} chars)", "live": None}


def validate_generic_api_key(match_text, surrounding_text=""):
    """Validate a generic api_key match."""
    m = re.search(r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{20,})", match_text)
    if not m:
        return {**_RESULT_SKIP, "details": "could not extract key value"}

    value = m.group(1)
    ctx = surrounding_text or match_text
    if _in_example_context(ctx):
        return {"valid": True, "confidence": "medium", "details": "API key in example context", "live": None}

    entropy = shannon_entropy(value)
    if entropy < 3.0:
        return {**_RESULT_SKIP, "details": f"low entropy key: {entropy:.2f}"}

    return {"valid": True, "confidence": "high", "details": f"API key, entropy: {entropy:.2f}", "live": None}


def validate_base64_secret(match_text, surrounding_text=""):
    """Validate a base64-encoded secret match."""
    m = re.search(r"(?i)(?:secret|token|key|auth)\s*[:=]\s*['\"]?([A-Za-z0-9+/]{40,}={0,2})", match_text)
    if not m:
        return {**_RESULT_SKIP, "details": "could not extract base64 value"}

    value = m.group(1)
    entropy = shannon_entropy(value)

    ctx = surrounding_text or match_text
    if _in_example_context(ctx):
        return {"valid": True, "confidence": "medium", "details": "base64 secret in example context", "live": None}

    if entropy < 3.5:
        return {**_RESULT_SKIP, "details": f"low entropy base64: {entropy:.2f}"}

    return {"valid": True, "confidence": "high", "details": f"base64 secret, entropy: {entropy:.2f}", "live": None}


# Patterns that don't need deep validation — just pass through
def _passthrough_validator(match_text, surrounding_text=""):
    """Default validator for patterns that rely on regex alone (env_file, internal_url, etc.)."""
    return {"valid": True, "confidence": "medium", "details": "regex match", "live": None}


# ─────────────────────────────────────────────────────────────
# Registry: pattern name → validator function
# ─────────────────────────────────────────────────────────────

VALIDATORS = {
    "credit_card": validate_credit_card,
    "phone_number": validate_phone_number,
    "ssn": validate_ssn,
    "aws_key": validate_aws_key,
    "aws_secret": _passthrough_validator,
    "github_token": validate_github_token,
    "anthropic_key": validate_anthropic_key,
    "openai_key": validate_openai_key,
    "slack_webhook": validate_slack_webhook,
    "discord_webhook": _passthrough_validator,
    "stripe_key": _passthrough_validator,
    "jwt_token": validate_jwt,
    "private_key": validate_private_key,
    "password_in_code": validate_password,
    "bearer_token": validate_bearer_token,
    "api_key_generic": validate_generic_api_key,
    "db_connection": validate_db_connection,
    "base64_secret": validate_base64_secret,
    "email_bulk": _passthrough_validator,
    "env_file": _passthrough_validator,
    "internal_url": _passthrough_validator,
    "ip_address_private": _passthrough_validator,
}


# ─────────────────────────────────────────────────────────────
# Liveness Checks (optional, network-calling)
# ─────────────────────────────────────────────────────────────


def liveness_check_github_token(token):
    """Check if a GitHub token is live by calling the GitHub API."""
    try:
        import requests

        resp = requests.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {token}", "User-Agent": "clawguard-liveness"},
            timeout=5,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "live": True,
                "details": f"LIVE — user: {data.get('login', '?')}, scopes: {resp.headers.get('X-OAuth-Scopes', 'unknown')}",
            }
        elif resp.status_code == 401:
            return {"live": False, "details": "expired or revoked"}
        else:
            return {"live": None, "details": f"unexpected status: {resp.status_code}"}
    except Exception as e:
        return {"live": None, "details": f"network error: {e}"}


def liveness_check_anthropic_key(key):
    """Check if an Anthropic API key is live."""
    try:
        import requests

        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-haiku-4-5-20251001",
                "max_tokens": 1,
                "messages": [{"role": "user", "content": "hi"}],
            },
            timeout=5,
        )
        if resp.status_code == 200:
            return {"live": True, "details": "LIVE — key accepted by Anthropic API"}
        elif resp.status_code in (401, 403):
            return {"live": False, "details": "invalid or revoked key"}
        else:
            return {"live": None, "details": f"unexpected status: {resp.status_code}"}
    except Exception as e:
        return {"live": None, "details": f"network error: {e}"}


def liveness_check_openai_key(key):
    """Check if an OpenAI API key is live."""
    try:
        import requests

        resp = requests.get(
            "https://api.openai.com/v1/models",
            headers={"Authorization": f"Bearer {key}"},
            timeout=5,
        )
        if resp.status_code == 200:
            return {"live": True, "details": "LIVE — key accepted by OpenAI API"}
        elif resp.status_code == 401:
            return {"live": False, "details": "invalid or revoked key"}
        else:
            return {"live": None, "details": f"unexpected status: {resp.status_code}"}
    except Exception as e:
        return {"live": None, "details": f"network error: {e}"}


def liveness_check_slack_webhook(url):
    """Check if a Slack webhook is live."""
    try:
        import requests

        resp = requests.post(url, json={"text": ""}, timeout=5)
        if resp.status_code == 200:
            return {"live": True, "details": "LIVE — webhook responded 200"}
        elif resp.status_code == 404:
            return {"live": False, "details": "webhook not found (deleted)"}
        else:
            return {"live": None, "details": f"status: {resp.status_code}"}
    except Exception as e:
        return {"live": None, "details": f"network error: {e}"}


LIVENESS_CHECKS = {
    "github_token": liveness_check_github_token,
    "anthropic_key": liveness_check_anthropic_key,
    "openai_key": liveness_check_openai_key,
    "slack_webhook": liveness_check_slack_webhook,
}
