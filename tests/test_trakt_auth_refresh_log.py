from __future__ import annotations

from typing import Any

import pytest

from providers.auth import _auth_TRAKT as trakt


class _Resp:
    def __init__(self, status: int, body: Any, text: str = "") -> None:
        self.status_code = status
        self._body = body
        self.text = text

    def json(self) -> Any:
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def _cfg() -> dict[str, Any]:
    return {
        "trakt": {
            "client_id": "cid",
            "client_secret": "csecret",
            "access_token": "old-access",
            "refresh_token": "old-refresh",
            "expires_at": 1,
        }
    }


@pytest.fixture
def logged(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    lines: list[str] = []
    monkeypatch.setattr(trakt, "_real_log", lambda msg, **_: lines.append(msg))
    monkeypatch.setattr(trakt, "_save_config", lambda cfg: None)
    return lines


def _refresh(monkeypatch: pytest.MonkeyPatch, resp: _Resp) -> dict[str, Any]:
    monkeypatch.setattr(trakt.requests, "post", lambda *a, **k: resp)
    return trakt.PROVIDER.refresh(_cfg())


def test_refresh_failure_logs_status_and_known_oauth_error(monkeypatch: pytest.MonkeyPatch, logged: list[str]) -> None:
    res = _refresh(monkeypatch, _Resp(400, {"error": "invalid_grant", "error_description": "session not found"}))

    assert res["status"] == "refresh_failed:400"
    assert "TRAKT: token refresh failed 400: invalid_grant (session not found)" in logged


def test_refresh_failure_drops_unknown_error_text(monkeypatch: pytest.MonkeyPatch, logged: list[str]) -> None:
    body = {"error": "refresh_token=old-refresh", "error_description": "client_secret csecret"}
    _refresh(monkeypatch, _Resp(401, body))

    failed = [m for m in logged if m.startswith("TRAKT: token refresh failed")]
    assert failed == ["TRAKT: token refresh failed 401: unknown"]


def test_refresh_failure_without_json_logs_status_only(monkeypatch: pytest.MonkeyPatch, logged: list[str]) -> None:
    _refresh(monkeypatch, _Resp(503, ValueError("no json"), text="<html>old-refresh</html>"))

    failed = [m for m in logged if m.startswith("TRAKT: token refresh failed")]
    assert failed == ["TRAKT: token refresh failed 503: unknown"]
    assert not any("old-refresh" in m or "csecret" in m for m in logged)
