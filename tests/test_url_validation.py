# tests/test_url_validation.py
from __future__ import annotations

import socket

import pytest

from cw_platform.url_validation import assert_server_url_safe, validate_server_url


def test_valid_http_url():
    assert validate_server_url("http://192.168.1.100:32400", "plex.server_url") == []


def test_valid_https_url():
    assert validate_server_url("https://media.local:8096", "jf.server") == []


def test_empty_url_no_warnings():
    assert validate_server_url("", "plex.server_url") == []


def test_bad_scheme():
    warnings = validate_server_url("ftp://host:21/data", "test")
    assert any("scheme" in w for w in warnings)


def test_missing_hostname():
    warnings = validate_server_url("http://", "test")
    assert any("hostname" in w.lower() for w in warnings)


def test_cloud_metadata_ipv4():
    warnings = validate_server_url("http://169.254.169.254/latest/meta-data/", "test")
    assert any("metadata" in w.lower() for w in warnings)


def test_cloud_metadata_gce():
    warnings = validate_server_url("http://metadata.google.internal/computeMetadata/", "test")
    assert any("metadata" in w.lower() for w in warnings)


def test_path_traversal():
    warnings = validate_server_url("http://localhost:32400/../../etc/passwd", "test")
    assert any(".." in w for w in warnings)


def test_private_ip_allowed():
    """Private IPs are the normal case — no warnings expected."""
    assert validate_server_url("http://10.0.0.5:8096", "test") == []
    assert validate_server_url("http://172.16.0.1:32400", "test") == []


def test_link_local_range_ipv4():
    """The full 169.254.0.0/16 range is blocked, not just the single
    literal metadata IP."""
    warnings = validate_server_url("http://169.254.1.1:80/", "test")
    assert any("link-local" in w.lower() or "metadata" in w.lower() for w in warnings)


def test_link_local_ipv6():
    warnings = validate_server_url("http://[fe80::1]:80/", "test")
    assert any("link-local" in w.lower() or "metadata" in w.lower() for w in warnings)


def test_metadata_ip_alibaba():
    warnings = validate_server_url("http://100.100.100.200/latest/meta-data/", "test")
    assert any("metadata" in w.lower() for w in warnings)


def test_metadata_ip_aws_imdsv2_ipv6():
    warnings = validate_server_url("http://[fd00:ec2::254]/latest/meta-data/", "test")
    assert any("metadata" in w.lower() for w in warnings)


def test_ipv4_mapped_ipv6_metadata_ip_is_flagged():
    """An IPv4-mapped IPv6 literal wrapping a blocked metadata IP must not
    bypass the check just because it isn't itself in the link-local range."""
    warnings = validate_server_url("http://[::ffff:100.100.100.200]/", "test")
    assert any("metadata" in w.lower() or "link-local" in w.lower() for w in warnings)


def test_ipv4_mapped_ipv6_link_local_is_flagged():
    warnings = validate_server_url("http://[::ffff:169.254.169.254]/", "test")
    assert any("metadata" in w.lower() or "link-local" in w.lower() for w in warnings)


def test_hostname_resolving_to_metadata_ip_is_flagged(monkeypatch):
    """A hostname that isn't itself a metadata name/IP but resolves to one
    should still be caught (defeats a DNS-based bypass of the literal checks)."""

    def fake_getaddrinfo(host, port, *args, **kwargs):
        assert host == "evil.example.com"
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    warnings = validate_server_url("http://evil.example.com/", "test")
    assert any("resolves to" in w.lower() for w in warnings)


def test_hostname_resolving_to_safe_ip_is_not_flagged(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.50", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert validate_server_url("http://media.local/", "test") == []


def test_dns_resolution_failure_is_not_a_finding(monkeypatch):
    """Transient DNS failure at save time should not itself be flagged as
    an SSRF finding."""

    def fake_getaddrinfo(host, port, *args, **kwargs):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert validate_server_url("http://unresolvable.example.com/", "test") == []


def test_assert_server_url_safe_raises_on_finding():
    with pytest.raises(ValueError):
        assert_server_url_safe("http://169.254.169.254/latest/meta-data/", "test")


def test_assert_server_url_safe_passes_on_clean_url():
    assert_server_url_safe("http://192.168.1.100:32400", "test")  # no raise
    assert_server_url_safe("", "test")  # empty is not a finding
