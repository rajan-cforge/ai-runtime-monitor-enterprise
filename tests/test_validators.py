"""Tests for validators.py — sensitive data validation beyond regex."""

from claude_monitoring.validators import (
    _luhn_checksum,
    shannon_entropy,
    validate_anthropic_key,
    validate_aws_key,
    validate_credit_card,
    validate_db_connection,
    validate_github_token,
    validate_jwt,
    validate_openai_key,
    validate_password,
    validate_phone_number,
    validate_private_key,
    validate_slack_webhook,
    validate_ssn,
)


class TestLuhnChecksum:
    def test_valid_visa(self):
        assert _luhn_checksum("4111111111111111") is True

    def test_valid_mastercard(self):
        assert _luhn_checksum("5500000000000004") is True

    def test_valid_amex(self):
        assert _luhn_checksum("340000000000009") is True

    def test_invalid_number(self):
        assert _luhn_checksum("4111111111111112") is False

    def test_single_digit(self):
        assert _luhn_checksum("0") is True

    def test_all_zeros(self):
        assert _luhn_checksum("0000000000000000") is True


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_high_entropy(self):
        # Random-looking string should have high entropy
        e = shannon_entropy("aB3$xZ9!mK2@pL7&")
        assert e > 3.0

    def test_low_entropy(self):
        e = shannon_entropy("aaaaab")
        assert e < 1.5

    def test_medium_entropy(self):
        e = shannon_entropy("password123")
        assert 2.0 < e < 4.0


class TestValidateCreditCard:
    def test_valid_visa_passes(self):
        result = validate_credit_card("4111111111111111")
        assert result["valid"] is True
        assert result["confidence"] == "high"

    def test_valid_mastercard_passes(self):
        result = validate_credit_card("5500000000000004")
        assert result["valid"] is True

    def test_invalid_luhn_fails(self):
        result = validate_credit_card("4111111111111112")
        assert result["valid"] is False
        assert "Luhn" in result["details"]

    def test_too_few_digits_fails(self):
        result = validate_credit_card("411111")
        assert result["valid"] is False

    def test_all_same_digit_fails(self):
        result = validate_credit_card("1111111111111111")
        # Luhn passes for all-1s actually... but we check same-digit first
        # All same digit = not real card
        result = validate_credit_card("4444444444444444")
        assert result["valid"] is False
        assert "same digit" in result["details"]

    def test_json_metadata_context_suppressed(self):
        ctx = '{"input_tokens": 4512345678901234, "responseId": "msg_012345"}'
        result = validate_credit_card("4512345678901234", ctx)
        assert result["valid"] is False
        assert "metadata" in result["details"]

    def test_card_with_spaces(self):
        result = validate_credit_card("4111 1111 1111 1111")
        assert result["valid"] is True

    def test_card_with_dashes(self):
        result = validate_credit_card("4111-1111-1111-1111")
        assert result["valid"] is True


class TestValidatePhoneNumber:
    def test_formatted_us_phone(self):
        result = validate_phone_number("(555) 123-4567")
        assert result["valid"] is True
        assert result["confidence"] == "high"

    def test_plus_one_format(self):
        result = validate_phone_number("+1-555-123-4567")
        assert result["valid"] is True

    def test_telegram_sender_id_suppressed(self):
        ctx = '{"sender_id": "7465847486", "sender": "Aj K"}'
        result = validate_phone_number("7465847486", ctx)
        assert result["valid"] is False
        assert "sender_id" in result["details"]

    def test_message_id_suppressed(self):
        ctx = '{"message_id": "1234567890"}'
        result = validate_phone_number("1234567890", ctx)
        assert result["valid"] is False

    def test_telegram_metadata_context(self):
        ctx = 'telegram bot update: {"chat_id": 5551234567}'
        result = validate_phone_number("5551234567", ctx)
        assert result["valid"] is False

    def test_update_id_suppressed(self):
        ctx = '{"updateId": "9876543210"}'
        result = validate_phone_number("9876543210", ctx)
        assert result["valid"] is False

    def test_plain_10_digit_medium_confidence(self):
        result = validate_phone_number("5551234567", "Call me at 5551234567 please")
        assert result["valid"] is True
        assert result["confidence"] == "medium"


class TestValidateSSN:
    def test_valid_ssn(self):
        result = validate_ssn("123-45-6789")
        assert result["valid"] is True
        assert result["confidence"] == "high"

    def test_area_000_invalid(self):
        result = validate_ssn("000-45-6789")
        assert result["valid"] is False
        assert "000" in result["details"]

    def test_area_666_invalid(self):
        result = validate_ssn("666-45-6789")
        assert result["valid"] is False
        assert "666" in result["details"]

    def test_area_900_invalid(self):
        result = validate_ssn("900-45-6789")
        assert result["valid"] is False

    def test_area_999_invalid(self):
        result = validate_ssn("999-45-6789")
        assert result["valid"] is False

    def test_group_00_invalid(self):
        result = validate_ssn("123-00-6789")
        assert result["valid"] is False
        assert "00" in result["details"]

    def test_serial_0000_invalid(self):
        result = validate_ssn("123-45-0000")
        assert result["valid"] is False
        assert "0000" in result["details"]

    def test_known_test_ssn(self):
        result = validate_ssn("078-05-1120")
        assert result["valid"] is False
        assert "test SSN" in result["details"]

    def test_known_test_ssn_2(self):
        result = validate_ssn("219-09-9999")
        assert result["valid"] is False

    def test_example_context_suppressed(self):
        result = validate_ssn("123-45-6789", "This is a test example: 123-45-6789")
        assert result["valid"] is False
        assert "example" in result["details"]

    def test_valid_area_899(self):
        # 899 is valid (< 900)
        result = validate_ssn("899-45-6789")
        assert result["valid"] is True


class TestValidateAWSKey:
    def test_valid_akia_key(self):
        result = validate_aws_key("AKIAI44QH8DHBR3XYZAB")
        assert result["valid"] is True
        assert "AKIA" in result["details"]

    def test_valid_asia_key(self):
        result = validate_aws_key("ASIAI44QH8DHBR3XYZAB")
        assert result["valid"] is True

    def test_invalid_prefix(self):
        result = validate_aws_key("XXXX1234567890123456")
        assert result["valid"] is False

    def test_wrong_length(self):
        result = validate_aws_key("AKIA12345")
        assert result["valid"] is False
        assert "length" in result["details"]

    def test_lowercase_after_prefix_fails(self):
        result = validate_aws_key("AKIAabcdefghijklmnop")
        assert result["valid"] is False


class TestValidateGitHubToken:
    def test_valid_ghp_token(self):
        token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"
        result = validate_github_token(token)
        assert result["valid"] is True
        assert result["confidence"] == "high"

    def test_valid_gho_token(self):
        token = "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"
        result = validate_github_token(token)
        assert result["valid"] is True

    def test_wrong_prefix(self):
        result = validate_github_token("ghx_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
        assert result["valid"] is False

    def test_too_short(self):
        result = validate_github_token("ghp_short")
        assert result["valid"] is False
        assert "short" in result["details"]

    def test_example_context_medium(self):
        token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"
        result = validate_github_token(token, "This is a test example token")
        assert result["valid"] is True
        assert result["confidence"] == "medium"


class TestValidateAnthropicKey:
    def test_valid_key(self):
        key = "sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"
        result = validate_anthropic_key(key)
        assert result["valid"] is True
        assert result["confidence"] == "high"

    def test_wrong_prefix(self):
        result = validate_anthropic_key("sk-not-anthropic-key-at-all")
        assert result["valid"] is False

    def test_too_short(self):
        result = validate_anthropic_key("sk-ant-short")
        assert result["valid"] is False


class TestValidateOpenAIKey:
    def test_valid_key(self):
        key = "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
        result = validate_openai_key(key)
        assert result["valid"] is True

    def test_anthropic_key_rejected(self):
        key = "sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"
        result = validate_openai_key(key)
        assert result["valid"] is False
        assert "Anthropic" in result["details"]

    def test_too_short(self):
        result = validate_openai_key("sk-short")
        assert result["valid"] is False


class TestValidateJWT:
    def test_valid_jwt(self):
        # Real JWT structure: header.payload.signature
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = validate_jwt(token)
        assert result["valid"] is True
        assert result["confidence"] == "high"

    def test_expired_jwt(self):
        # JWT with exp=0 (expired in 1970)
        import base64
        import json as j

        header = base64.urlsafe_b64encode(j.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(j.dumps({"sub": "test", "exp": 0}).encode()).rstrip(b"=").decode()
        token = f"{header}.{payload}.fakesig"
        result = validate_jwt(token)
        assert result["valid"] is True
        assert result["confidence"] == "medium"
        assert "expired" in result["details"]

    def test_invalid_segments(self):
        result = validate_jwt("not.a.valid.jwt.at.all")
        assert result["valid"] is False

    def test_two_segments_only(self):
        result = validate_jwt("abc.def")
        assert result["valid"] is False

    def test_bad_header_json(self):
        result = validate_jwt("bm90anNvbg.eyJzdWIiOiIxIn0.sig")
        assert result["valid"] is False


class TestValidatePassword:
    def test_real_password_high_entropy(self):
        result = validate_password('password = "xK9$mP2!qR7&nZ"')
        assert result["valid"] is True
        assert result["confidence"] == "high"

    def test_placeholder_password_rejected(self):
        result = validate_password('password = "changeme"')
        assert result["valid"] is False
        assert "placeholder" in result["details"]

    def test_short_password_rejected(self):
        result = validate_password('password = "abc"')
        assert result["valid"] is False

    def test_low_entropy_rejected(self):
        result = validate_password('password = "aaaaaa"')
        assert result["valid"] is False
        assert "entropy" in result["details"]

    def test_comment_rejected(self):
        result = validate_password('# password = "secret123!"', '# password = "secret123!"')
        assert result["valid"] is False
        assert "comment" in result["details"]

    def test_redacted_rejected(self):
        result = validate_password('password = "REDACTED"')
        assert result["valid"] is False

    def test_medium_entropy(self):
        result = validate_password('password = "hello12"')
        assert result["valid"] is True
        assert result["confidence"] == "medium"


class TestValidateSlackWebhook:
    def test_valid_webhook(self):
        url = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
        result = validate_slack_webhook(url)
        assert result["valid"] is True

    def test_invalid_format(self):
        result = validate_slack_webhook("https://hooks.slack.com/invalid")
        assert result["valid"] is False


class TestValidatePrivateKey:
    def test_valid_rsa_key(self):
        result = validate_private_key("-----BEGIN RSA PRIVATE KEY-----")
        assert result["valid"] is True
        assert result["confidence"] == "high"

    def test_valid_generic_key(self):
        result = validate_private_key("-----BEGIN PRIVATE KEY-----")
        assert result["valid"] is True

    def test_example_context(self):
        result = validate_private_key("-----BEGIN PRIVATE KEY-----", "This is an example key for testing")
        assert result["valid"] is True
        assert result["confidence"] == "medium"

    def test_missing_begin(self):
        result = validate_private_key("not a key at all")
        assert result["valid"] is False


class TestValidateDBConnection:
    def test_valid_postgres_uri(self):
        result = validate_db_connection("postgres://user:xK9$mP2@host:5432/db")
        assert result["valid"] is True

    def test_no_password(self):
        result = validate_db_connection("postgres://user@host:5432/db")
        assert result["valid"] is False

    def test_placeholder_password(self):
        result = validate_db_connection("postgres://user:password@host:5432/db")
        assert result["valid"] is False
        assert "placeholder" in result["details"]

    def test_low_entropy_password(self):
        result = validate_db_connection("postgres://user:aaaaaa@host:5432/db")
        assert result["valid"] is False
        assert "entropy" in result["details"]


class TestKnownExampleFiltering:
    """Verify KNOWN_EXAMPLE_SECRETS still work through the validation pipeline."""

    def test_known_aws_example_still_filtered(self):
        from claude_monitoring.utils import _is_known_example

        assert _is_known_example("aws_key", "found AKIAIOSFODNN7EXAMPLE") is True

    def test_real_key_not_filtered(self):
        from claude_monitoring.utils import _is_known_example

        assert _is_known_example("aws_key", "key=AKIAI44QH8DHBR3XYZAB") is False


class TestScanSensitiveIntegration:
    """Test that scan_sensitive with validate=True reduces false positives."""

    def test_api_metadata_no_credit_card_alert(self):
        from claude_monitoring.utils import scan_sensitive

        text = '{"input_tokens": 4512345678901234, "output_tokens": 500}'
        results = scan_sensitive(text, validate=True)
        names = [r["name"] for r in results]
        assert "credit_card" not in names

    def test_telegram_sender_id_no_phone_alert(self):
        from claude_monitoring.utils import scan_sensitive

        text = '{"sender_id": "7465847486", "message_id": "4"}'
        results = scan_sensitive(text, validate=True)
        names = [r["name"] for r in results]
        assert "phone_number" not in names

    def test_real_credit_card_still_detected(self):
        from claude_monitoring.utils import scan_sensitive

        text = "My card is 4111111111111111"
        results = scan_sensitive(text, validate=True)
        names = [r["name"] for r in results]
        assert "credit_card" in names

    def test_real_aws_key_still_detected(self):
        from claude_monitoring.utils import scan_sensitive

        text = "key=AKIAI44QH8DHBR3XYZAB"
        results = scan_sensitive(text, validate=True)
        names = [r["name"] for r in results]
        assert "aws_key" in names

    def test_validated_field_present(self):
        from claude_monitoring.utils import scan_sensitive

        text = "key=AKIAI44QH8DHBR3XYZAB"
        results = scan_sensitive(text, validate=True)
        aws = [r for r in results if r["name"] == "aws_key"]
        assert aws[0].get("validated") is True

    def test_invalid_ssn_000_filtered(self):
        from claude_monitoring.utils import scan_sensitive

        text = "SSN: 000-45-6789"
        results = scan_sensitive(text, validate=True)
        names = [r["name"] for r in results]
        assert "ssn" not in names

    def test_placeholder_password_filtered(self):
        from claude_monitoring.utils import scan_sensitive

        text = 'password = "changeme"'
        results = scan_sensitive(text, validate=True)
        names = [r["name"] for r in results]
        assert "password_in_code" not in names

    def test_validate_false_preserves_old_behavior(self):
        from claude_monitoring.utils import scan_sensitive

        text = '{"sender_id": "7465847486"}'
        results = scan_sensitive(text, validate=False)
        names = [r["name"] for r in results]
        # Without validation, phone_number should still match
        assert "phone_number" in names
