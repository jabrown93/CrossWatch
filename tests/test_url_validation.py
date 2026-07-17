# tests/test_url_validation.py
from __future__ import annotations

import socket

import pytest
import responses

from cw_platform.url_validation import assert_server_url_safe, guarded_request, validate_server_url


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


class TestGuardedRequest:
    @responses.activate
    def test_no_redirect_passes_through(self):
        responses.add(responses.GET, "http://192.168.1.100:32400/Users", json={"ok": True}, status=200)
        r = guarded_request("GET", "http://192.168.1.100:32400/Users", field_name="test")
        assert r.status_code == 200
        assert r.json() == {"ok": True}

    @responses.activate
    def test_redirect_to_safe_host_is_followed(self):
        responses.add(
            responses.GET,
            "http://192.168.1.100:32400/Users",
            status=302,
            headers={"Location": "http://192.168.1.100:32400/Users/"},
        )
        responses.add(responses.GET, "http://192.168.1.100:32400/Users/", json={"ok": True}, status=200)
        r = guarded_request("GET", "http://192.168.1.100:32400/Users", field_name="test")
        assert r.status_code == 200
        assert r.json() == {"ok": True}

    @responses.activate
    def test_redirect_to_metadata_ip_is_blocked(self):
        """A server that passes the initial host check but 302s the actual
        request to a metadata address must not have that redirect followed."""
        responses.add(
            responses.GET,
            "http://media.example.com/Users",
            status=302,
            headers={"Location": "http://169.254.169.254/latest/meta-data/"},
        )
        with pytest.raises(ValueError):
            guarded_request("GET", "http://media.example.com/Users", field_name="test")

    @responses.activate
    def test_redirect_to_link_local_via_relative_location_is_blocked(self):
        responses.add(
            responses.GET,
            "http://media.example.com/Users",
            status=302,
            headers={"Location": "//169.254.169.254/latest/meta-data/"},
        )
        with pytest.raises(ValueError):
            guarded_request("GET", "http://media.example.com/Users", field_name="test")

    def test_unsafe_initial_url_is_blocked_before_any_request(self):
        with pytest.raises(ValueError):
            guarded_request("GET", "http://169.254.169.254/", field_name="test")

    @responses.activate
    def test_redirect_chain_too_long_is_blocked(self):
        for i in range(7):
            responses.add(
                responses.GET,
                f"http://192.168.1.100/{i}",
                status=302,
                headers={"Location": f"http://192.168.1.100/{i + 1}"},
            )
        with pytest.raises(ValueError):
            guarded_request("GET", "http://192.168.1.100/0", field_name="test", max_redirects=5)

    @responses.activate
    def test_cross_host_redirect_does_not_leak_credentials(self):
        """A malicious media server must not be able to redirect a login POST
        to a host of its choosing and collect the username/password."""
        responses.add(
            responses.POST,
            "http://media.example.com/Users/AuthenticateByName",
            status=307,
            headers={"Location": "http://attacker.example.net/collect"},
        )
        responses.add(responses.POST, "http://attacker.example.net/collect", json={}, status=200)
        with pytest.raises(ValueError, match="off the configured host"):
            guarded_request(
                "POST",
                "http://media.example.com/Users/AuthenticateByName",
                field_name="test",
                json={"Username": "u", "Pw": "hunter2"},
            )
        # The redirect target must never have been contacted at all.
        assert [c.request.url for c in responses.calls] == [
            "http://media.example.com/Users/AuthenticateByName"
        ]

    @responses.activate
    def test_cross_host_redirect_to_safe_public_host_is_still_rejected(self):
        """Rejection is about leaving the configured host, not about the target
        being an SSRF address — a perfectly routable third party still gets the
        credentials if we follow it."""
        responses.add(
            responses.GET,
            "http://media.example.com/api/v2",
            status=302,
            headers={"Location": "http://other.example.com/api/v2"},
        )
        with pytest.raises(ValueError, match="off the configured host"):
            guarded_request("GET", "http://media.example.com/api/v2", field_name="test", params={"apikey": "secret"})
        assert len(responses.calls) == 1

    @responses.activate
    def test_https_to_http_downgrade_on_same_host_is_rejected(self):
        responses.add(
            responses.GET,
            "https://media.example.com/Users",
            status=302,
            headers={"Location": "http://media.example.com/Users"},
        )
        with pytest.raises(ValueError, match="off the configured host"):
            guarded_request("GET", "https://media.example.com/Users", field_name="test")

    @responses.activate
    def test_http_to_https_upgrade_on_same_host_is_followed(self):
        """The common real-world case: the server redirects a plain-http probe
        to its TLS endpoint. Same host, strictly safer wire — must still work."""
        responses.add(
            responses.GET,
            "http://media.example.com/Users",
            status=301,
            headers={"Location": "https://media.example.com/Users"},
        )
        responses.add(responses.GET, "https://media.example.com/Users", json={"ok": True}, status=200)
        r = guarded_request("GET", "http://media.example.com/Users", field_name="test")
        assert r.status_code == 200
        assert r.json() == {"ok": True}

    @responses.activate
    def test_same_host_302_rewrites_post_to_get_and_drops_body(self):
        """requests turns a 302'd POST into a bodyless GET; guarded_request
        drives redirects by hand and has to reproduce that."""
        responses.add(
            responses.POST,
            "http://192.168.1.100:8096/Users/AuthenticateByName",
            status=302,
            headers={"Location": "http://192.168.1.100:8096/Users/Auth"},
        )
        responses.add(responses.GET, "http://192.168.1.100:8096/Users/Auth", json={"ok": True}, status=200)
        r = guarded_request(
            "POST",
            "http://192.168.1.100:8096/Users/AuthenticateByName",
            field_name="test",
            json={"Username": "u", "Pw": "hunter2"},
            headers={"Content-Type": "application/json"},
        )
        assert r.status_code == 200
        followed = responses.calls[1].request
        assert followed.method == "GET"
        assert not followed.body
        assert "Content-Type" not in followed.headers

    @responses.activate
    def test_same_host_307_preserves_method_and_body(self):
        responses.add(
            responses.POST,
            "http://192.168.1.100:8096/Users/AuthenticateByName",
            status=307,
            headers={"Location": "http://192.168.1.100:8096/Users/Auth"},
        )
        responses.add(responses.POST, "http://192.168.1.100:8096/Users/Auth", json={"ok": True}, status=200)
        r = guarded_request(
            "POST",
            "http://192.168.1.100:8096/Users/AuthenticateByName",
            field_name="test",
            json={"Username": "u", "Pw": "hunter2"},
        )
        assert r.status_code == 200
        followed = responses.calls[1].request
        assert followed.method == "POST"
        assert b"hunter2" in followed.body
