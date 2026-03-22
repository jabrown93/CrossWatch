from __future__ import annotations

"""Shared utilities for CrossWatch webhook handlers."""

import hmac
from typing import Mapping


def verify_webhook_secret(headers: Mapping[str, str], secret: str) -> bool:
    """Check X-CW-Webhook-Secret header against configured secret."""
    if not secret:
        return True
    header_val = headers.get("X-CW-Webhook-Secret") or headers.get("x-cw-webhook-secret") or ""
    if not header_val:
        return False
    return hmac.compare_digest(header_val, secret)
