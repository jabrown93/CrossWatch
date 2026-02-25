# tests/test_url_validation.py
from __future__ import annotations

from cw_platform.url_validation import validate_server_url


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
