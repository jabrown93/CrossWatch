from __future__ import annotations

import json

from starlette.requests import Request


def _auth_cfg() -> dict:
    from api import appAuthAPI as auth

    salt = b"0123456789abcdef"
    return {
        "security": {},
        "app_auth": {
            "enabled": True,
            "username": "admin",
            "reset_required": False,
            "remember_session_enabled": False,
            "remember_session_days": 30,
            "oidc": {
                "enabled": True,
                "issuer": "https://idp.test/application/o/crosswatch/",
                "client_id": "cw-client",
                "client_secret": "cw-secret",
                "public_base_url": "https://cw.test",
                "groups_claim": "groups",
                "allowed_groups": ["crosswatch"],
                "session_hours": 2,
            },
            "password": {
                "scheme": "pbkdf2_sha256",
                "iterations": 260_000,
                "salt": auth._b64e(salt),
                "hash": auth._b64e(auth._pbkdf2_hash("secrett1", salt, iterations=260_000)),
            },
            "session": {"token_hash": "", "expires_at": 0},
            "sessions": [],
            "last_login_at": 0,
        },
    }


def _request(path: str, *, query: str = "", headers: dict[str, str] | None = None) -> Request:
    raw_headers = [(b"host", b"testserver")]
    for k, v in (headers or {}).items():
        raw_headers.append((str(k).lower().encode("latin-1"), str(v).encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": query.encode("latin-1"),
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    return Request(scope)


def _all_set_cookie_headers(resp) -> str:
    return "\n".join(
        value.decode("latin-1")
        for key, value in getattr(resp, "raw_headers", [])
        if key.decode("latin-1").lower() == "set-cookie"
    )


def test_issue_session_honors_ttl_override() -> None:
    from api import appAuthAPI as auth

    cfg = _auth_cfg()
    req = _request("/api/app-auth/login")
    _token, exp = auth._issue_session(cfg, req, ttl_sec=7200)
    assert 0 < exp - auth._now() <= 7200


def test_oidc_login_redirects_to_idp_and_sets_flow_cookie(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)
    monkeypatch.setattr(
        oidc_api.authOIDC,
        "start_flow",
        lambda *_a, **_k: {"ok": True, "state": "st", "auth_url": "https://idp.test/authorize?x=1"},
    )

    resp = oidc_api.api_oidc_login(_request("/api/app-auth/oidc/login", query="next=/watchlist"))

    assert resp.status_code == 302
    assert resp.headers["location"] == "https://idp.test/authorize?x=1"
    assert f"{oidc_api.FLOW_COOKIE_NAME}=" in _all_set_cookie_headers(resp)


def test_oidc_login_falls_back_to_local_when_start_fails(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)

    def _boom(*_a, **_k):
        raise RuntimeError("idp down")

    monkeypatch.setattr(oidc_api.authOIDC, "start_flow", _boom)

    resp = oidc_api.api_oidc_login(_request("/api/app-auth/oidc/login"))
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login?local=1&oidc_error=start_failed"


def test_oidc_login_sanitizes_next(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)
    seen: dict = {}

    def _start(_cfg, *, next_path, flow_nonce_hash):
        seen["next"] = next_path
        return {"ok": True, "state": "st", "auth_url": "https://idp.test/authorize"}

    monkeypatch.setattr(oidc_api.authOIDC, "start_flow", _start)

    oidc_api.api_oidc_login(_request("/api/app-auth/oidc/login", query="next=https://evil.example"))
    assert seen["next"] == "/"
    oidc_api.api_oidc_login(_request("/api/app-auth/oidc/login", query="next=//evil.example"))
    assert seen["next"] == "/"


def test_oidc_callback_success_sets_session_cookie(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    saved: dict = {}
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)
    monkeypatch.setattr(oidc_api, "save_config", lambda c: saved.setdefault("cfg", c))
    monkeypatch.setattr(
        oidc_api.authOIDC,
        "complete_flow",
        lambda *_a, **_k: {
            "ok": True,
            "flow_nonce_hash": oidc_api.authOIDC._sha256_hex("flow-nonce"),
            "next": "/watchlist",
            "identity": {"sub": "user-1", "username": "jared", "email": "j@x.com", "groups": ["crosswatch"]},
        },
    )

    req = _request(
        "/api/app-auth/oidc/callback",
        query="code=abc&state=st",
        headers={"cookie": f"{oidc_api.FLOW_COOKIE_NAME}=flow-nonce"},
    )
    resp = oidc_api.api_oidc_callback(req)

    assert resp.status_code == 302
    assert resp.headers["location"] == "/watchlist"
    assert len(cfg["app_auth"]["sessions"]) == 1
    exp = int(cfg["app_auth"]["sessions"][0]["expires_at"])
    from api import appAuthAPI as auth

    assert 0 < exp - auth._now() <= 2 * 3600
    assert "cw_auth=" in _all_set_cookie_headers(resp)
    assert saved.get("cfg") is cfg


def test_oidc_callback_requires_matching_flow_cookie(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)
    monkeypatch.setattr(
        oidc_api.authOIDC,
        "complete_flow",
        lambda *_a, **_k: {
            "ok": True,
            "flow_nonce_hash": oidc_api.authOIDC._sha256_hex("expected"),
            "next": "/",
            "identity": {"sub": "user-1", "username": "jared", "email": "", "groups": []},
        },
    )

    resp = oidc_api.api_oidc_callback(_request("/api/app-auth/oidc/callback", query="code=abc&state=st"))
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login?local=1&oidc_error=failed"
    assert cfg["app_auth"]["sessions"] == []


def test_oidc_callback_denied_maps_to_denied_code(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)
    monkeypatch.setattr(
        oidc_api.authOIDC,
        "complete_flow",
        lambda *_a, **_k: {"ok": False, "error": "nope", "code": "denied"},
    )

    resp = oidc_api.api_oidc_callback(
        _request(
            "/api/app-auth/oidc/callback",
            query="code=abc&state=st",
            headers={"cookie": f"{oidc_api.FLOW_COOKIE_NAME}=n"},
        )
    )
    assert resp.headers["location"] == "/login?local=1&oidc_error=denied"


def test_oidc_callback_idp_error_redirects_local(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)

    resp = oidc_api.api_oidc_callback(_request("/api/app-auth/oidc/callback", query="error=access_denied"))
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login?local=1&oidc_error=denied"


def test_oidc_status_reports_availability(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)
    resp = oidc_api.api_oidc_status(_request("/api/app-auth/oidc/status"))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["login_available"] is True


def _login_route(monkeypatch, cfg):
    """Register routes on a throwaway FastAPI app and return the /login endpoint."""
    from fastapi import FastAPI

    from api import appAuthAPI as auth

    monkeypatch.setattr(auth, "load_config", lambda: cfg)
    monkeypatch.setattr(auth, "save_config", lambda *_a, **_k: None)
    app = FastAPI()
    auth.register_app_auth(app)
    for route in app.routes:
        if getattr(route, "path", "") == "/login" and "GET" in getattr(route, "methods", set()):
            return route.endpoint
    raise AssertionError("/login route not registered")


def test_login_auto_redirects_to_oidc(monkeypatch) -> None:
    from services import authOIDC

    cfg = _auth_cfg()
    monkeypatch.setattr(authOIDC, "issuer_reachable", lambda _cfg: True)
    endpoint = _login_route(monkeypatch, cfg)

    resp = endpoint(_request("/login", query="next=/watchlist"))
    assert resp.status_code == 302
    assert resp.headers["location"] == "/api/app-auth/oidc/login?next=%2Fwatchlist"


def test_login_local_escape_hatch_renders_form(monkeypatch) -> None:
    from services import authOIDC

    cfg = _auth_cfg()
    monkeypatch.setattr(authOIDC, "issuer_reachable", lambda _cfg: True)
    endpoint = _login_route(monkeypatch, cfg)

    resp = endpoint(_request("/login", query="local=1"))
    assert resp.status_code == 200
    body = resp.body.decode("utf-8")
    assert 'id="p"' in body
    assert "/api/app-auth/oidc/login" in body


def test_login_falls_back_to_form_when_issuer_down(monkeypatch) -> None:
    from services import authOIDC

    cfg = _auth_cfg()
    monkeypatch.setattr(authOIDC, "issuer_reachable", lambda _cfg: False)
    endpoint = _login_route(monkeypatch, cfg)

    resp = endpoint(_request("/login"))
    assert resp.status_code == 200
    assert 'id="p"' in resp.body.decode("utf-8")


def test_login_shows_mapped_error_not_raw_query(monkeypatch) -> None:
    from services import authOIDC

    cfg = _auth_cfg()
    monkeypatch.setattr(authOIDC, "issuer_reachable", lambda _cfg: True)
    endpoint = _login_route(monkeypatch, cfg)

    resp = endpoint(_request("/login", query="oidc_error=%3Cscript%3E"))
    assert resp.status_code == 200
    body = resp.body.decode("utf-8")
    assert "<script>alert" not in body
    assert "Single sign-on failed" in body
    assert 'class="cw-msg show"' in body


def test_login_no_redirect_when_oidc_disabled(monkeypatch) -> None:
    cfg = _auth_cfg()
    cfg["app_auth"]["oidc"]["enabled"] = False
    endpoint = _login_route(monkeypatch, cfg)

    resp = endpoint(_request("/login"))
    assert resp.status_code == 200
    body = resp.body.decode("utf-8")
    assert "/api/app-auth/oidc/login" not in body


def test_login_sanitizes_malicious_next_paths(monkeypatch) -> None:
    from services import authOIDC

    cfg = _auth_cfg()
    monkeypatch.setattr(authOIDC, "issuer_reachable", lambda _cfg: True)
    endpoint = _login_route(monkeypatch, cfg)

    # Protocol-relative URL should be sanitized to "/"
    resp = endpoint(_request("/login", query="next=//evil.example"))
    assert resp.status_code == 302
    assert resp.headers["location"] == "/api/app-auth/oidc/login?next=%2F"

    # Absolute URL should be sanitized to "/"
    resp = endpoint(_request("/login", query="next=https://evil.example"))
    assert resp.status_code == 302
    assert resp.headers["location"] == "/api/app-auth/oidc/login?next=%2F"


def _logout_route(monkeypatch, cfg):
    """Register routes on a throwaway FastAPI app and return the /logout endpoint."""
    from fastapi import FastAPI

    from api import appAuthAPI as auth

    monkeypatch.setattr(auth, "load_config", lambda: cfg)
    monkeypatch.setattr(auth, "save_config", lambda *_a, **_k: None)
    app = FastAPI()
    auth.register_app_auth(app)
    for route in app.routes:
        if getattr(route, "path", "") == "/logout" and "GET" in getattr(route, "methods", set()):
            return route.endpoint
    raise AssertionError("/logout route not registered")


def test_logout_with_oidc_redirects_to_local_login(monkeypatch) -> None:
    from api import appAuthAPI as auth

    cfg = _auth_cfg()
    endpoint = _logout_route(monkeypatch, cfg)

    # Seed a session in config so auth_required still returns True after logout
    cfg["app_auth"]["sessions"].append({
        "token_hash": "test-hash",
        "expires_at": auth._now() + 3600,
    })

    token = "test-token"
    resp = endpoint(_request("/logout", headers={"cookie": f"{auth.COOKIE_NAME}={token}"}))

    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == "/login?local=1"


def test_login_guards_oidc_redirect_during_reset(monkeypatch) -> None:
    from services import authOIDC

    cfg = _auth_cfg()
    cfg["app_auth"]["reset_required"] = True
    monkeypatch.setattr(authOIDC, "issuer_reachable", lambda _cfg: True)
    endpoint = _login_route(monkeypatch, cfg)

    resp = endpoint(_request("/login"))
    assert resp.status_code == 200
    body = resp.body.decode("utf-8")
    assert 'id="p"' in body
