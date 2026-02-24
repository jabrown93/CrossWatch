# cw_platform/url_validation.py
# Server URL validation helpers.
# Copyright (c) 2025-2026 CrossWatch / Cenodude (https://github.com/cenodude/CrossWatch)
from __future__ import annotations

from urllib.parse import urlparse

# Cloud metadata endpoints that should never be contacted by a media-server URL.
_METADATA_HOSTS = frozenset({
    "169.254.169.254",
    "metadata.google.internal",
    "metadata.google.internal.",
})


def validate_server_url(url: str, field_name: str = "server_url") -> list[str]:
    """Return a list of warning strings for *url*.

    Does NOT reject private/RFC-1918 IPs — those are the normal case for
    local media servers.  Only flags clearly suspicious patterns.
    """
    warnings: list[str] = []
    raw = (url or "").strip()
    if not raw:
        return warnings

    parsed = urlparse(raw)

    if parsed.scheme not in ("http", "https"):
        warnings.append(f"{field_name}: scheme '{parsed.scheme}' is not http or https")

    if not parsed.hostname:
        warnings.append(f"{field_name}: no hostname found in URL")

    if parsed.hostname and parsed.hostname.lower().rstrip(".") in _METADATA_HOSTS:
        warnings.append(
            f"{field_name}: URL points to a cloud metadata endpoint ({parsed.hostname}) "
            "— this is almost certainly unintended"
        )

    if parsed.path and ".." in parsed.path:
        warnings.append(f"{field_name}: URL path contains '..' (path traversal)")

    return warnings
