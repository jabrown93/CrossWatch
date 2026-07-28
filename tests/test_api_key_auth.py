from __future__ import annotations

from starlette.requests import Request


def _request(headers: dict[str, str] | None = None) -> Request:
    raw_headers = [(b"host", b"testserver")]
    for k, v in (headers or {}).items():
        raw_headers.append((str(k).lower().encode("latin-1"), str(v).encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/api/watchlist",
        "raw_path": b"/api/watchlist",
        "query_string": b"",
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    return Request(scope)


def test_api_key_matches() -> None:
    from api import appAuthAPI as auth

    cfg = {"security": {"api_key": "machine-key-123"}}
    assert auth.api_key_authenticated(cfg, _request({"x-api-key": "machine-key-123"})) is True


def test_api_key_rejects_wrong_or_missing() -> None:
    from api import appAuthAPI as auth

    cfg = {"security": {"api_key": "machine-key-123"}}
    assert auth.api_key_authenticated(cfg, _request({"x-api-key": "nope"})) is False
    assert auth.api_key_authenticated(cfg, _request()) is False


def test_api_key_disabled_when_unset() -> None:
    from api import appAuthAPI as auth

    for cfg in ({}, {"security": {}}, {"security": {"api_key": ""}}, {"security": {"api_key": "   "}}):
        assert auth.api_key_authenticated(cfg, _request({"x-api-key": ""})) is False
        assert auth.api_key_authenticated(cfg, _request({"x-api-key": "anything"})) is False


def test_middleware_accepts_api_key(monkeypatch) -> None:
    """Behavioral test: middleware gate accepts valid X-API-Key and rejects invalid/missing.
    Auth must be enabled with credentials + security.api_key configured."""
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    from api import appAuthAPI as auth
    import crosswatch as cw_module

    # Config: auth enabled + credentials + api_key set
    cfg = {
        "security": {"api_key": "test-key-123"},
        "app_auth": {
            "enabled": True,
            "username": "admin",
            "reset_required": False,
            "password": {
                "scheme": "pbkdf2_sha256",
                "iterations": 260_000,
                "salt": auth._b64e(b"0123456789abcdef"),
                "hash": auth._b64e(auth._pbkdf2_hash("secret", b"0123456789abcdef", iterations=260_000)),
            },
            "sessions": [],
        },
    }

    # Monkeypatch load_config to return our test config
    monkeypatch.setattr(cw_module, "load_config", lambda: cfg)

    # Build a minimal app with the auth gate middleware and a protected route
    app = FastAPI()

    @app.middleware("http")
    async def app_auth_gate(request: Request, call_next):
        from urllib.parse import quote

        try:
            cfg = cw_module.load_config()
        except Exception:
            return JSONResponse({"ok": False, "error": "Service unavailable"}, status_code=503)

        path = request.url.path or "/"

        # Simplified gate: only check auth for /api/test
        if not path.startswith("/api/"):
            return await call_next(request)

        if not cw_module.app_auth_required(cfg):
            return await call_next(request)

        # Check session cookie first
        token = request.cookies.get(cw_module.APP_AUTH_COOKIE)
        if cw_module.app_is_authenticated(cfg, token):
            return await call_next(request)

        # Check API key as fallback
        if cw_module.app_api_key_authenticated(cfg, request):
            return await call_next(request)

        # Both auth methods failed
        return JSONResponse({"ok": False, "error": "Unauthorized"}, status_code=401)

    @app.get("/api/test")
    def protected_route():
        return {"ok": True}

    client = TestClient(app)

    # Test 1: no cookie + no API key → 401
    resp = client.get("/api/test")
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"

    # Test 2: no cookie + correct API key → NOT 401
    resp = client.get("/api/test", headers={"X-API-Key": "test-key-123"})
    assert resp.status_code != 401, f"Expected non-401, got {resp.status_code}: {resp.text}"
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"

    # Test 3: no cookie + wrong API key → 401
    resp = client.get("/api/test", headers={"X-API-Key": "wrong-key"})
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"
