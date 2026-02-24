# tests/test_webhook_secret.py
from __future__ import annotations

from providers.webhooks.jellyfintrakt import _verify_webhook_secret as jf_verify
from providers.webhooks.embytrakt import _verify_webhook_secret as emby_verify


class TestJellyfinWebhookSecret:
    def test_empty_secret_bypasses(self):
        assert jf_verify({}, "") is True

    def test_valid_secret(self):
        assert jf_verify({"X-CW-Webhook-Secret": "abc123"}, "abc123") is True

    def test_valid_secret_lowercase_header(self):
        assert jf_verify({"x-cw-webhook-secret": "abc123"}, "abc123") is True

    def test_invalid_secret(self):
        assert jf_verify({"X-CW-Webhook-Secret": "wrong"}, "abc123") is False

    def test_missing_header_with_secret_set(self):
        assert jf_verify({}, "abc123") is False


class TestEmbyWebhookSecret:
    def test_empty_secret_bypasses(self):
        assert emby_verify({}, "") is True

    def test_valid_secret(self):
        assert emby_verify({"X-CW-Webhook-Secret": "abc123"}, "abc123") is True

    def test_valid_secret_lowercase_header(self):
        assert emby_verify({"x-cw-webhook-secret": "abc123"}, "abc123") is True

    def test_invalid_secret(self):
        assert emby_verify({"X-CW-Webhook-Secret": "wrong"}, "abc123") is False

    def test_missing_header_with_secret_set(self):
        assert emby_verify({}, "abc123") is False
