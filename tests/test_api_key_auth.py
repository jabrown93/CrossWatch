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


def test_middleware_accepts_api_key() -> None:
    # Guard the wiring, not just the helper: the gate must consult the API key
    # after the cookie check fails.
    import inspect

    import crosswatch

    src = inspect.getsource(crosswatch.app_auth_gate)
    assert "app_api_key_authenticated" in src
