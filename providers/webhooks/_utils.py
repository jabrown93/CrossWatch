from __future__ import annotations

"""Shared utilities for CrossWatch webhook handlers."""

import hmac
from typing import Any, Mapping


def verify_webhook_secret(headers: Mapping[str, str], secret: str) -> bool:
    """Check X-CW-Webhook-Secret header against configured secret.

    Fails CLOSED: a webhook with no secret configured is rejected, not
    silently accepted. Configure emby.webhook_secret / jellyfin.webhook_secret
    to receive scrobble webhooks from these providers.
    """
    if not secret:
        return False
    header_val = headers.get("X-CW-Webhook-Secret") or headers.get("x-cw-webhook-secret") or ""
    if not header_val:
        return False
    return hmac.compare_digest(header_val, secret)


# Error codes returned by process_webhook() that indicate the request failed
# payload authentication (bad/missing secret or signature), as opposed to a
# processing error unrelated to auth (unknown event, parse failure, etc).
_AUTH_ERROR_CODES = frozenset({"invalid_webhook_secret", "invalid_signature"})


def webhook_result_status(res: Mapping[str, Any]) -> int:
    """Map a webhook-processing result dict to an HTTP status code.

    Auth-rejection reasons get 401 so a rejected webhook is visibly rejected
    at the transport level, not just internally flagged while still
    returning 200. Non-auth processing errors are left at 200 (existing
    behavior for e.g. unknown events / parse issues).
    """
    if res.get("error") in _AUTH_ERROR_CODES:
        return 401
    return 200
