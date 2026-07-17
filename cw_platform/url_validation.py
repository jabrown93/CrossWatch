# cw_platform/url_validation.py
# Server URL validation helpers.
# Copyright (c) 2025-2026 CrossWatch / Cenodude (https://github.com/cenodude/CrossWatch)
from __future__ import annotations

import ipaddress
import socket
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

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
    # Unwrap IPv4-mapped IPv6 literals (e.g. ::ffff:100.100.100.200) so they're
    # checked against the same blocklist/link-local rules as their IPv4 form.
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
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


def _redirect_stays_on_host(current: str, target: str) -> bool:
    """True if *target* is the same host as *current* and doesn't downgrade
    https to http.

    Callers attach credentials to every hop — Jellyfin/Emby send the user's
    password in the request body, Tautulli sends its apikey as a query param,
    and both send provider tokens as headers. requests' own redirect handling
    only strips the Authorization header, which covers none of those, so any
    hop off the user's configured host is refused rather than sanitised. Port
    changes are allowed (same machine); an https->http downgrade is not, since
    it would put those credentials on the wire in the clear.
    """
    cur = urlparse(current)
    nxt = urlparse(target)
    cur_host = (cur.hostname or "").lower().rstrip(".")
    nxt_host = (nxt.hostname or "").lower().rstrip(".")
    if not nxt_host or nxt_host != cur_host:
        return False
    return not (cur.scheme == "https" and nxt.scheme != "https")


def _rebuild_redirect(method: str, kwargs: dict[str, Any], status: int) -> tuple[str, dict[str, Any]]:
    """Apply requests' own method/body redirect semantics to a hop.

    guarded_request drives redirects by hand, so requests.Session's
    rebuild_method()/resolve_redirects() never run and their behaviour has to
    be reproduced here: 302/303 turn any non-HEAD request into a GET, 301
    turns a POST into a GET, and anything other than 307/308 drops the body.
    """
    if status in (301, 302, 303) and method != "HEAD":
        # 302/303 rewrite any method; 301 only rewrites POST (browser behaviour).
        if status != 301 or method == "POST":
            method = "GET"
    if status not in (307, 308):
        kwargs = {k: v for k, v in kwargs.items() if k not in ("json", "data", "files")}
        headers = kwargs.get("headers")
        if isinstance(headers, dict):
            dropped = ("content-length", "content-type", "transfer-encoding")
            kwargs["headers"] = {k: v for k, v in headers.items() if k.lower() not in dropped}
    return method, kwargs


def guarded_request(method: str, url: str, *, field_name: str = "server_url", max_redirects: int = 5, **kwargs: Any):
    """requests.request() wrapper that re-validates the target host on every
    redirect hop, not just the initial URL.

    A URL that passes assert_server_url_safe() once (e.g. at login/save time)
    can still be turned into an SSRF: requests follows redirects by default
    and never re-checks the new Location, so a server that looks safe at
    validation time can 302 the actual request to a metadata/link-local
    address. This disables automatic redirect-following and instead
    validates + follows each hop manually, raising ValueError (like
    assert_server_url_safe) if any hop is unsafe, leaves the configured host
    (see _redirect_stays_on_host), or the chain is too long.
    """
    import requests

    current_method = method
    current_url = url
    body_kwargs = dict(kwargs)
    body_kwargs.pop("allow_redirects", None)
    for _ in range(max_redirects + 1):
        assert_server_url_safe(current_url, field_name)
        resp = requests.request(current_method, current_url, allow_redirects=False, **body_kwargs)
        if not resp.is_redirect:
            return resp
        location = resp.headers.get("Location")
        if not location:
            return resp
        next_url = urljoin(current_url, location)
        if not _redirect_stays_on_host(current_url, next_url):
            raise ValueError(
                f"{field_name}: refusing to follow a redirect off the configured host "
                f"({urlparse(current_url).hostname} -> {urlparse(next_url).hostname or location}) "
                "— this request carries credentials"
            )
        current_method, body_kwargs = _rebuild_redirect(current_method, body_kwargs, resp.status_code)
        current_url = next_url
    raise ValueError(f"{field_name}: exceeded {max_redirects} redirects while validating target host")
