# tests/test_tracearr_redirect_guard.py
# Fork: the Tracearr sync client must not follow redirects or call unsafe hosts.
from __future__ import annotations

from typing import Any

import pytest

from providers.sync import _mod_TRACEARR as mod


class _Resp:
    def __init__(self, status: int, location: str | None = None):
        self.status_code = status
        self.headers = {"Location": location} if location else {}
        self.is_redirect = 300 <= status < 400 and bool(location)
        self.text = "{}"
        self.content = b"{}"

    def json(self) -> Any:
        return {}


class _Session:
    def __init__(self, resp: _Resp):
        self.resp = resp
        self.calls: list[dict[str, Any]] = []
        self.headers: dict[str, str] = {}

    def request(self, method: str, url: str, **kw: Any) -> _Resp:
        self.calls.append({"method": method, "url": url, **kw})
        return self.resp


def _client(server_url: str, resp: _Resp) -> tuple[mod.TRACEARRClient, _Session]:
    c = mod.TRACEARRClient(mod.TRACEARRConfig(server_url=server_url, api_key="k", max_retries=1), {})
    s = _Session(resp)
    c.session = s
    return c, s


def test_redirect_is_refused_not_followed() -> None:
    c, s = _client("http://tracearr.local:3000", _Resp(302, "http://169.254.169.254/latest/meta-data"))
    with pytest.raises(RuntimeError, match="redirect refused"):
        c.get("/history")
    assert s.calls and s.calls[0]["allow_redirects"] is False


def test_metadata_host_is_rejected_before_any_request() -> None:
    c, s = _client("http://169.254.169.254", _Resp(200))
    with pytest.raises(ValueError):
        c.get("/history")
    assert s.calls == []
