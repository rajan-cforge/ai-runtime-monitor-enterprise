"""Tests for validators.py liveness checks and additional edge cases.

Covers:
  - liveness_check_github_token: mocked requests for live/expired/error
  - liveness_check_anthropic_key: mocked requests for live/invalid/error
  - liveness_check_openai_key: mocked requests for live/invalid/error
  - liveness_check_slack_webhook: mocked requests for live/deleted/error
  - Additional validator edge cases for coverage gaps
"""

import sys
from unittest.mock import MagicMock, patch

import pytest

from claude_monitoring.validators import (
    LIVENESS_CHECKS,
    _in_example_context,
    _near_json_key,
    liveness_check_anthropic_key,
    liveness_check_github_token,
    liveness_check_openai_key,
    liveness_check_slack_webhook,
    validate_anthropic_key,
    validate_base64_secret,
    validate_bearer_token,
    validate_generic_api_key,
    validate_github_token,
    validate_jwt,
    validate_openai_key,
    validate_phone_number,
    validate_ssn,
)


@pytest.fixture()
def mock_requests():
    """Provide a mock requests module that the liveness functions will import."""
    mock_mod = MagicMock()
    with patch.dict(sys.modules, {"requests": mock_mod}):
        yield mock_mod


# ─────────────────────────────────────────────────────────────
# Helper function tests
# ─────────────────────────────────────────────────────────────


class TestNearJsonKey:
    def test_match_found(self):
        text = '{"input_tokens": 12345}'
        assert _near_json_key(text, "12345") is True

    def test_match_not_found(self):
        text = "just some random text with 12345"
        assert _near_json_key(text, "12345") is False

    def test_match_text_not_in_text(self):
        assert _near_json_key("hello world", "missing") is False


class TestInExampleContext:
    def test_example_context_detected(self):
        assert _in_example_context("this is an example for testing") is True

    def test_no_example_context(self):
        assert _in_example_context("production api key stored here") is False

    def test_regex_context(self):
        assert _in_example_context("the regex pattern matches") is True


# ─────────────────────────────────────────────────────────────
# Additional validator edge cases
# ─────────────────────────────────────────────────────────────


class TestValidatePhoneNumberEdgeCases:
    def test_id_key_in_pre_context(self):
        ctx = '"some_id": "5551234567"'
        result = validate_phone_number("5551234567", ctx)
        assert result["valid"] is False
        assert "ID key" in result["details"]

    def test_non_10_digit_medium_confidence(self):
        result = validate_phone_number("12345678901")
        assert result["valid"] is True
        assert result["confidence"] == "medium"


class TestValidateSSNEdgeCases:
    def test_not_in_format(self):
        result = validate_ssn("12345 6789")
        assert result["valid"] is False
        assert "format" in result["details"]


class TestValidateGitHubTokenEdgeCases:
    def test_invalid_characters_in_body(self):
        token = "ghp_ABCD!@#$%^&*()_+=EFGHIJKLMNOPQRSTUVWX"
        result = validate_github_token(token)
        assert result["valid"] is False
        assert "invalid characters" in result["details"]


class TestValidateAnthropicKeyEdgeCases:
    def test_invalid_characters_in_body(self):
        key = "sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$abcdefghijklm"
        result = validate_anthropic_key(key)
        assert result["valid"] is False
        assert "invalid characters" in result["details"]

    def test_missing_prefix(self):
        result = validate_anthropic_key("not-an-anthropic-key-at-all-really")
        assert result["valid"] is False
        assert "prefix" in result["details"]


class TestValidateOpenAIKeyEdgeCases:
    def test_missing_prefix(self):
        result = validate_openai_key("not-an-openai-key-at-all-really-long")
        assert result["valid"] is False
        assert "prefix" in result["details"]


class TestValidateJWTEdgeCases:
    def test_bad_payload_json(self):
        import base64

        header = base64.urlsafe_b64encode(b'{"alg":"HS256"}').rstrip(b"=").decode()
        # Invalid JSON payload
        payload = base64.urlsafe_b64encode(b"not json").rstrip(b"=").decode()
        token = f"{header}.{payload}.sig"
        result = validate_jwt(token)
        assert result["valid"] is False
        assert "payload" in result["details"]

    def test_header_missing_alg(self):
        import base64

        header = base64.urlsafe_b64encode(b'{"typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(b'{"sub":"1"}').rstrip(b"=").decode()
        token = f"{header}.{payload}.sig"
        result = validate_jwt(token)
        assert result["valid"] is False
        assert "alg" in result["details"]


class TestValidateBearerTokenEdgeCases:
    def test_short_token_rejected(self):
        result = validate_bearer_token("Bearer abc")
        assert result["valid"] is False
        assert "short" in result["details"]

    def test_example_context_medium(self):
        result = validate_bearer_token(
            "Bearer ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop",
            "example token for testing",
        )
        assert result["valid"] is True
        assert result["confidence"] == "medium"


class TestValidateGenericApiKeyEdgeCases:
    def test_no_match(self):
        result = validate_generic_api_key("no key here")
        assert result["valid"] is False

    def test_low_entropy_key(self):
        result = validate_generic_api_key("api_key=aaaaaaaaaaaaaaaaaaaa")
        assert result["valid"] is False
        assert "entropy" in result["details"]


class TestValidateBase64SecretEdgeCases:
    def test_no_match(self):
        result = validate_base64_secret("no secret here")
        assert result["valid"] is False

    def test_low_entropy_base64(self):
        low_entropy = "A" * 50
        result = validate_base64_secret(f"secret={low_entropy}")
        assert result["valid"] is False
        assert "entropy" in result["details"]


# ─────────────────────────────────────────────────────────────
# Liveness checks
# ─────────────────────────────────────────────────────────────


class TestLivenessCheckGitHubToken:
    def test_live_token(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"login": "testuser"}
        resp.headers = {"X-OAuth-Scopes": "repo, user"}
        mock_requests.get.return_value = resp

        result = liveness_check_github_token("ghp_testtoken123")
        assert result["live"] is True
        assert "testuser" in result["details"]
        assert "repo" in result["details"]

    def test_expired_token(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 401
        mock_requests.get.return_value = resp

        result = liveness_check_github_token("ghp_expired123")
        assert result["live"] is False
        assert "expired" in result["details"]

    def test_unexpected_status(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 403
        mock_requests.get.return_value = resp

        result = liveness_check_github_token("ghp_forbidden123")
        assert result["live"] is None
        assert "403" in result["details"]

    def test_network_error(self, mock_requests):
        mock_requests.get.side_effect = Exception("connection refused")

        result = liveness_check_github_token("ghp_error123")
        assert result["live"] is None
        assert "network error" in result["details"]


class TestLivenessCheckAnthropicKey:
    def test_live_key(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 200
        mock_requests.post.return_value = resp

        result = liveness_check_anthropic_key("sk-ant-test123")
        assert result["live"] is True
        assert "LIVE" in result["details"]

    def test_invalid_key(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 401
        mock_requests.post.return_value = resp

        result = liveness_check_anthropic_key("sk-ant-invalid")
        assert result["live"] is False
        assert "invalid" in result["details"]

    def test_forbidden_key(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 403
        mock_requests.post.return_value = resp

        result = liveness_check_anthropic_key("sk-ant-forbidden")
        assert result["live"] is False

    def test_unexpected_status(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 500
        mock_requests.post.return_value = resp

        result = liveness_check_anthropic_key("sk-ant-server-error")
        assert result["live"] is None
        assert "500" in result["details"]

    def test_network_error(self, mock_requests):
        mock_requests.post.side_effect = Exception("timeout")

        result = liveness_check_anthropic_key("sk-ant-timeout")
        assert result["live"] is None
        assert "network error" in result["details"]


class TestLivenessCheckOpenAIKey:
    def test_live_key(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 200
        mock_requests.get.return_value = resp

        result = liveness_check_openai_key("sk-test123")
        assert result["live"] is True
        assert "LIVE" in result["details"]

    def test_invalid_key(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 401
        mock_requests.get.return_value = resp

        result = liveness_check_openai_key("sk-invalid")
        assert result["live"] is False
        assert "invalid" in result["details"]

    def test_unexpected_status(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 429
        mock_requests.get.return_value = resp

        result = liveness_check_openai_key("sk-ratelimited")
        assert result["live"] is None
        assert "429" in result["details"]

    def test_network_error(self, mock_requests):
        mock_requests.get.side_effect = Exception("dns failure")

        result = liveness_check_openai_key("sk-dns-fail")
        assert result["live"] is None
        assert "network error" in result["details"]


class TestLivenessCheckSlackWebhook:
    def test_live_webhook(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 200
        mock_requests.post.return_value = resp

        result = liveness_check_slack_webhook("https://hooks.slack.com/services/T00/B00/xxx")
        assert result["live"] is True
        assert "LIVE" in result["details"]

    def test_deleted_webhook(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 404
        mock_requests.post.return_value = resp

        result = liveness_check_slack_webhook("https://hooks.slack.com/services/T00/B00/xxx")
        assert result["live"] is False
        assert "deleted" in result["details"]

    def test_unexpected_status(self, mock_requests):
        resp = MagicMock()
        resp.status_code = 500
        mock_requests.post.return_value = resp

        result = liveness_check_slack_webhook("https://hooks.slack.com/services/T00/B00/xxx")
        assert result["live"] is None
        assert "500" in result["details"]

    def test_network_error(self, mock_requests):
        mock_requests.post.side_effect = Exception("connection reset")

        result = liveness_check_slack_webhook("https://hooks.slack.com/services/T00/B00/xxx")
        assert result["live"] is None
        assert "network error" in result["details"]


class TestValidatePasswordEdgeCases:
    def test_no_match_pattern(self):
        from claude_monitoring.validators import validate_password

        result = validate_password("no password here at all")
        assert result["valid"] is False
        assert "could not extract" in result["details"]

    def test_js_comment_rejected(self):
        from claude_monitoring.validators import validate_password

        result = validate_password('// password = "secret123!"', '// password = "secret123!"')
        assert result["valid"] is False
        assert "comment" in result["details"]


class TestValidateDBConnectionEdgeCases:
    def test_high_entropy_password(self):
        from claude_monitoring.validators import validate_db_connection

        result = validate_db_connection("postgres://user:xK9mP2qR7nZ@host/db")
        assert result["valid"] is True
        assert result["confidence"] == "high"

    def test_medium_entropy_password(self):
        from claude_monitoring.validators import validate_db_connection

        result = validate_db_connection("postgres://user:hello12@host/db")
        assert result["valid"] is True
        assert result["confidence"] == "medium"


class TestValidateBearerTokenMoreCases:
    def test_no_bearer_match(self):
        from claude_monitoring.validators import validate_bearer_token

        result = validate_bearer_token("Authorization: Basic abc123")
        assert result["valid"] is False

    def test_valid_long_bearer_token(self):
        from claude_monitoring.validators import validate_bearer_token

        token = "Bearer " + "A" * 30 + "bCdEfG1234567890"
        result = validate_bearer_token(token)
        assert result["valid"] is True
        assert result["confidence"] == "high"


class TestValidateGenericApiKeyMoreCases:
    def test_example_context(self):
        from claude_monitoring.validators import validate_generic_api_key

        result = validate_generic_api_key(
            "api_key=xK9mP2qR7nZaB3cD4eF5gH6",
            "example API key for testing",
        )
        assert result["valid"] is True
        assert result["confidence"] == "medium"

    def test_high_entropy_key(self):
        from claude_monitoring.validators import validate_generic_api_key

        result = validate_generic_api_key("api_key=xK9mP2qR7nZaB3cD4eF5gH6")
        assert result["valid"] is True
        assert result["confidence"] == "high"


class TestValidateBase64SecretMoreCases:
    def test_example_context(self):
        from claude_monitoring.validators import validate_base64_secret

        val = "A" * 20 + "bCdEfGhIjKlMnOpQrStUvWx"
        result = validate_base64_secret(
            f"secret={val}",
            "example secret for demo purposes",
        )
        assert result["valid"] is True
        assert result["confidence"] == "medium"

    def test_high_entropy_secret(self):
        from claude_monitoring.validators import validate_base64_secret

        # Must be 40+ chars of base64 charset [A-Za-z0-9+/]
        val = "xK9mP2qR7nZaB3cD4eF5gH6iJ8kL0mN1oP2qR3sT"
        result = validate_base64_secret(f"secret={val}")
        assert result["valid"] is True
        assert result["confidence"] == "high"


class TestLivenessRegistry:
    def test_registry_has_expected_keys(self):
        assert "github_token" in LIVENESS_CHECKS
        assert "anthropic_key" in LIVENESS_CHECKS
        assert "openai_key" in LIVENESS_CHECKS
        assert "slack_webhook" in LIVENESS_CHECKS

    def test_registry_values_are_callable(self):
        for fn in LIVENESS_CHECKS.values():
            assert callable(fn)
