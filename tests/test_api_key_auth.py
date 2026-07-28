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
    """Behavioral test: real app_auth_gate middleware accepts valid X-API-Key and rejects invalid/missing.
    Auth must be enabled with credentials + security.api_key configured."""
    from starlette.testclient import TestClient

    from api import appAuthAPI as auth
    import crosswatch

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

    # Monkeypatch the real load_config that app_auth_gate middleware calls
    monkeypatch.setattr(crosswatch, "load_config", lambda: cfg)

    # Use the real app and its real middleware
    client = TestClient(crosswatch.app, raise_server_exceptions=False)

    # Test 1: no cookie + no API key → 401 (gate blocks)
    resp = client.get("/api/watchlist")
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"

    # Test 2: no cookie + correct API key → NOT 401 (gate passes)
    resp = client.get("/api/watchlist", headers={"X-API-Key": "test-key-123"})
    assert resp.status_code != 401, f"Expected non-401, got {resp.status_code}: {resp.text}"

    # Test 3: no cookie + wrong API key → 401 (gate blocks)
    resp = client.get("/api/watchlist", headers={"X-API-Key": "wrong-key"})
    assert resp.status_code == 401, f"Expected 401, got {resp.status_code}: {resp.text}"
