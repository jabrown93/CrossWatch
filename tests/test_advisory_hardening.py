"""Regression checks for the four security advisories fixed on 2026-08-29.

Each test pins the *behaviour* the advisory was about, not the shape of the fix,
so a future refactor that reopens the hole fails here.
"""
from __future__ import annotations

import types
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi import HTTPException
from starlette.requests import Request


def _request(headers: dict[str, str] | None = None, *, client_ip: str = "127.0.0.1") -> Request:
    raw_headers = [(b"host", b"testserver")]
    for k, v in (headers or {}).items():
        raw_headers.append((str(k).lower().encode("latin-1"), str(v).encode("latin-1")))
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/api/watchlist",
            "raw_path": b"/api/watchlist",
            "query_string": b"",
            "headers": raw_headers,
            "client": (client_ip, 12345),
            "server": ("testserver", 80),
        }
    )


# --- GHSA-vrw5-p3r4-4927: static API key is unrestricted admin -----------------


def test_api_key_brute_force_is_rate_limited() -> None:
    """A wrong key must cost the caller the same lockout a wrong password does.

    Uses a dedicated client IP and restores the shared _LOGIN_FAILS bucket, so
    this cannot leak a lockout into the other auth tests.
    """
    from api import appAuthAPI as auth

    ip = "10.99.0.7"
    cfg = {"security": {"api_key": "k" * 40}}
    saved = dict(auth._LOGIN_FAILS)
    try:
        auth._LOGIN_FAILS.pop(ip, None)
        for _ in range(3):
            assert auth.api_key_authenticated(cfg, _request({"x-api-key": "wrong"}, client_ip=ip)) is False
        # Lockout is now active, so even the correct key is refused.
        assert auth.api_key_authenticated(cfg, _request({"x-api-key": "k" * 40}, client_ip=ip)) is False
    finally:
        auth._LOGIN_FAILS.clear()
        auth._LOGIN_FAILS.update(saved)


def test_api_key_absent_header_is_not_a_failed_attempt() -> None:
    """Not sending the header at all is a cookie-auth request, not a guess."""
    from api import appAuthAPI as auth

    ip = "10.99.0.8"
    cfg = {"security": {"api_key": "k" * 40}}
    saved = dict(auth._LOGIN_FAILS)
    try:
        auth._LOGIN_FAILS.pop(ip, None)
        for _ in range(10):
            assert auth.api_key_authenticated(cfg, _request(client_ip=ip)) is False
        assert ip not in auth._LOGIN_FAILS
        assert auth.api_key_authenticated(cfg, _request({"x-api-key": "k" * 40}, client_ip=ip)) is True
    finally:
        auth._LOGIN_FAILS.clear()
        auth._LOGIN_FAILS.update(saved)


def _stub_env(monkeypatch, cfg_api, load_cfg, save_cfg) -> None:
    monkeypatch.setattr(
        cfg_api,
        "_env",
        lambda: {
            "CW": None,
            "cfg_base": types.SimpleNamespace(),
            "load": load_cfg,
            "save": save_cfg,
            "prune": lambda *_: None,
            "ensure": lambda *_: None,
            "norm_pair": lambda *_: None,
            "probes_cache": None,
            "probes_status_cache": None,
            "scheduler": None,
        },
    )


def _stub_request() -> Any:
    """api_config_save only touches request.app; the checks under test run first."""
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))


def test_config_save_rejects_short_api_key(monkeypatch) -> None:
    from api import configAPI as cfg_api

    saved: dict = {}
    _stub_env(monkeypatch, cfg_api, lambda: {}, lambda cfg: saved.update(cfg))

    with pytest.raises(HTTPException) as exc:
        cfg_api.api_config_save(_stub_request(), {"security": {"api_key": "test"}})

    assert exc.value.status_code == 400
    assert "security.api_key" in str(exc.value.detail)
    assert not saved


def test_config_save_accepts_long_api_key(monkeypatch) -> None:
    from api import configAPI as cfg_api

    saved: dict = {}
    _stub_env(monkeypatch, cfg_api, lambda: {}, lambda cfg: saved.update(cfg))

    cfg_api.api_config_save(_stub_request(), {"security": {"api_key": "a" * 32}})
    assert saved["security"]["api_key"] == "a" * 32


def test_config_save_does_not_relitigate_an_existing_short_key(monkeypatch) -> None:
    """An already-set short key (or an env-locked one) must not wedge every
    unrelated config save — only a *changed* key is validated."""
    from api import configAPI as cfg_api

    current = {"security": {"api_key": "legacy-short"}}
    saved: dict = {}
    _stub_env(monkeypatch, cfg_api, lambda: dict(current), lambda cfg: saved.update(cfg))

    cfg_api.api_config_save(_stub_request(), {"runtime": {"debug": True}})
    assert saved["security"]["api_key"] == "legacy-short"


