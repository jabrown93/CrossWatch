# tests/test_redact_config.py
from __future__ import annotations

import copy
from cw_platform.config_base import _SECRET_PATHS, _REDACT, redact_config


def _build_cfg_with_secrets() -> dict:
    """Build a minimal config dict with a truthy value at every _SECRET_PATHS location."""
    cfg: dict = {}
    for path in _SECRET_PATHS:
        node = cfg
        for key in path[:-1]:
            node = node.setdefault(key, {})
        node[path[-1]] = "secret_value"
    # Add a sessions array for app_auth
    cfg.setdefault("app_auth", {})["sessions"] = [
        {"token_hash": "tok1"},
        {"token_hash": "tok2"},
    ]
    return cfg


def test_all_secret_paths_redacted():
    cfg = _build_cfg_with_secrets()
    out = redact_config(cfg)
    for path in _SECRET_PATHS:
        node = out
        for key in path[:-1]:
            assert isinstance(node, dict)
            node = node[key]
        assert node[path[-1]] == _REDACT, f"Path {path} was not redacted"


def test_sessions_array_redacted():
    cfg = _build_cfg_with_secrets()
    out = redact_config(cfg)
    for s in out["app_auth"]["sessions"]:
        assert s["token_hash"] == _REDACT


def test_non_secrets_preserved():
    cfg = _build_cfg_with_secrets()
    cfg["plex"]["server_url"] = "http://localhost:32400"
    cfg["jellyfin"]["server"] = "http://jf:8096"
    out = redact_config(cfg)
    assert out["plex"]["server_url"] == "http://localhost:32400"
    assert out["jellyfin"]["server"] == "http://jf:8096"


def test_missing_fields_dont_crash():
    """redact_config should not crash on empty or partial configs."""
    assert redact_config({}) == {}
    assert redact_config({"plex": {}}) == {"plex": {}}
    assert redact_config({"app_auth": {"sessions": []}}) == {"app_auth": {"sessions": []}}


def test_empty_secret_not_redacted():
    """Empty-string secrets should stay empty, not get the redaction marker."""
    cfg = {"plex": {"account_token": ""}}
    out = redact_config(cfg)
    assert out["plex"]["account_token"] == ""


def test_original_not_mutated():
    cfg = _build_cfg_with_secrets()
    original = copy.deepcopy(cfg)
    redact_config(cfg)
    assert cfg == original
