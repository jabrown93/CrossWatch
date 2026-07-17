# cw_platform/url_validation.py
# Server URL validation helpers.
# Copyright (c) 2025-2026 CrossWatch / Cenodude (https://github.com/cenodude/CrossWatch)
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import unquote, urlparse

# Cloud metadata hostnames that should never be contacted by a media-server URL.
# Checked as a literal-hostname match; IP-literal and DNS-resolved cases are
# additionally covered by _is_dangerous_ip() below (link-local + explicit IPs).
_METADATA_HOSTS = frozenset({
    "169.254.169.254",
    "metadata.google.internal",
})

# Cloud metadata IPs that are not in the standard link-local range and so
# wouldn't be caught by ipaddress.is_link_local alone.
_METADATA_IPS = frozenset({
    "100.100.100.200",   # Alibaba Cloud
    "fd00:ec2::254",      # AWS IMDSv2 (IPv6)
})


def _is_dangerous_ip(host: str) -> bool:
    """True if *host* (a literal IP string) is a cloud-metadata or link-local address."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if str(ip) in _METADATA_IPS:
        return True
    # Covers 169.254.0.0/16 (incl. 169.254.169.254) and fe80::/10.
    return bool(ip.is_link_local)


def _resolves_to_dangerous_ip(hostname: str) -> bool:
    """Resolve *hostname* and check every returned address against the
    metadata/link-local blocklist. Resolution failures are treated as
    "not dangerous" (not a finding) — a transient DNS hiccup at config-save
    time shouldn't be conflated with an actual SSRF target, and other checks
    (scheme, traversal) still apply regardless.
    """
    try:
        infos = socket.getaddrinfo(hostname, None)
    except (socket.gaierror, UnicodeError, OSError):
        return False
    for info in infos:
        sockaddr = info[4]
        if not sockaddr:
            continue
        addr = sockaddr[0]
        if _is_dangerous_ip(addr):
            return True
    return False


def validate_server_url(url: str, field_name: str = "server_url") -> list[str]:
    """Return a list of warning strings for *url*.

    Does NOT reject private/RFC-1918 IPs — those are the normal case for
    local media servers.  Only flags clearly suspicious patterns: bad scheme,
    missing hostname, path traversal, and cloud-metadata/link-local targets
    (checked both as a literal IP/hostname and via DNS resolution, so a
    hostname that merely resolves to a metadata address is also caught).
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

    host = parsed.hostname or ""
    host_norm = host.lower().rstrip(".")
    if host_norm in _METADATA_HOSTS:
        warnings.append(
            f"{field_name}: URL points to a cloud metadata endpoint ({parsed.hostname}) "
            "— this is almost certainly unintended"
        )
    elif host and _is_dangerous_ip(host.strip("[]")):
        warnings.append(
            f"{field_name}: URL points to a link-local/cloud-metadata address ({parsed.hostname}) "
            "— this is almost certainly unintended"
        )
    elif host and _resolves_to_dangerous_ip(host):
        warnings.append(
            f"{field_name}: hostname ({parsed.hostname}) resolves to a link-local/cloud-metadata "
            "address — this is almost certainly unintended"
        )

    if parsed.path:
        if ".." in unquote(parsed.path):
            warnings.append(f"{field_name}: URL path contains '..' (path traversal)")

    return warnings


def assert_server_url_safe(url: str, field_name: str = "server_url") -> None:
    """Raise ValueError if *url* fails validate_server_url(). Use this at
    config-save time to actually reject a dangerous URL instead of merely
    warning about it.
    """
    warnings = validate_server_url(url, field_name)
    if warnings:
        raise ValueError("; ".join(warnings))
