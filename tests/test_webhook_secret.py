# tests/test_webhook_secret.py
from __future__ import annotations

import hashlib
import hmac
import base64

from providers.webhooks._utils import verify_webhook_secret, webhook_result_status
from providers.webhooks.jellyfintrakt import _verify_webhook_secret as jf_verify
from providers.webhooks.embytrakt import _verify_webhook_secret as emby_verify
from providers.webhooks import plextrakt


class TestSharedVerifyWebhookSecret:
    def test_empty_secret_rejected(self):
        """No secret configured => fail closed, not silently accepted."""
        assert verify_webhook_secret({}, "") is False

    def test_valid_secret(self):
        assert verify_webhook_secret({"X-CW-Webhook-Secret": "abc123"}, "abc123") is True

    def test_valid_secret_lowercase_header(self):
        assert verify_webhook_secret({"x-cw-webhook-secret": "abc123"}, "abc123") is True

    def test_invalid_secret(self):
        assert verify_webhook_secret({"X-CW-Webhook-Secret": "wrong"}, "abc123") is False

    def test_missing_header_with_secret_set(self):
        assert verify_webhook_secret({}, "abc123") is False


class TestJellyfinWebhookSecret:
    def test_empty_secret_rejected(self):
        assert jf_verify({}, "") is False

    def test_valid_secret(self):
        assert jf_verify({"X-CW-Webhook-Secret": "abc123"}, "abc123") is True

    def test_valid_secret_lowercase_header(self):
        assert jf_verify({"x-cw-webhook-secret": "abc123"}, "abc123") is True

    def test_invalid_secret(self):
        assert jf_verify({"X-CW-Webhook-Secret": "wrong"}, "abc123") is False

    def test_missing_header_with_secret_set(self):
        assert jf_verify({}, "abc123") is False


class TestEmbyWebhookSecret:
    def test_empty_secret_rejected(self):
        assert emby_verify({}, "") is False

    def test_valid_secret(self):
        assert emby_verify({"X-CW-Webhook-Secret": "abc123"}, "abc123") is True

    def test_valid_secret_lowercase_header(self):
        assert emby_verify({"x-cw-webhook-secret": "abc123"}, "abc123") is True

    def test_invalid_secret(self):
        assert emby_verify({"X-CW-Webhook-Secret": "wrong"}, "abc123") is False

    def test_missing_header_with_secret_set(self):
        assert emby_verify({}, "abc123") is False


class TestPlexVerifySignature:
    def setup_method(self):
        # Reset the module-level one-time-warning flag so each test observes
        # its own attempt cleanly.
        plextrakt._PLEX_SECRET_WARNED = False

    def test_empty_secret_rejected(self):
        assert plextrakt._verify_signature(b"{}", {"X-Plex-Signature": "whatever"}, "") is False

    def test_valid_signature(self):
        secret = "abc123"
        raw = b'{"event":"media.play"}'
        digest = hmac.new(secret.encode("utf-8"), raw, hashlib.sha1).digest()
        sig = base64.b64encode(digest).decode("ascii")
        assert plextrakt._verify_signature(raw, {"X-Plex-Signature": sig}, secret) is True

    def test_invalid_signature(self):
        raw = b'{"event":"media.play"}'
        assert plextrakt._verify_signature(raw, {"X-Plex-Signature": "bogus"}, "abc123") is False

    def test_missing_signature_header_with_secret_set(self):
        assert plextrakt._verify_signature(b"{}", {}, "abc123") is False

    def test_missing_raw_body_with_secret_set(self):
        assert plextrakt._verify_signature(None, {"X-Plex-Signature": "x"}, "abc123") is False


class TestWebhookResultStatus:
    def test_invalid_webhook_secret_is_401(self):
        assert webhook_result_status({"ok": False, "error": "invalid_webhook_secret"}) == 401

    def test_invalid_signature_is_401(self):
        assert webhook_result_status({"ok": False, "error": "invalid_signature"}) == 401

    def test_other_error_stays_200(self):
        assert webhook_result_status({"ok": False, "error": "unknown_event"}) == 200

    def test_no_error_is_200(self):
        assert webhook_result_status({"ok": True, "action": "start"}) == 200
