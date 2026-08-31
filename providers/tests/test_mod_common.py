from __future__ import annotations

from typing import cast

import requests


def _response(status: int) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    return response


class _SequenceSession:
    def __init__(self, *results):
        self.results = list(results)
        self.calls = 0

    def request(self, method, url, **kwargs):
        result = self.results[self.calls]
        self.calls += 1
        if isinstance(result, Exception):
            raise result
        return result


def test_parse_rate_limit_common_headers():
    import sync._mod_common as m

    headers = {
        "X-RateLimit-Limit": "100",
        "X-RateLimit-Remaining": "42",
        "X-RateLimit-Reset": "1700000000",
    }
    out = m.parse_rate_limit(headers)
    assert out == {"limit": 100, "remaining": 42, "reset": 1700000000}


def test_parse_rate_limit_missing_headers():
    import sync._mod_common as m

    out = m.parse_rate_limit({})
    assert out == {"limit": None, "remaining": None, "reset": None}


def test_request_with_retries_retries_read_exception(monkeypatch):
    import sync._mod_common as m

    session = _SequenceSession(requests.Timeout("temporary"), _response(200))
    monkeypatch.setattr(m.time, "sleep", lambda _: None)

    response = m.request_with_retries(cast(requests.Session, session), "GET", "https://example.test/items", max_retries=2)

    assert response.status_code == 200
    assert session.calls == 2


def test_request_with_retries_does_not_retry_write_5xx(monkeypatch):
    import sync._mod_common as m

    session = _SequenceSession(_response(503), _response(200))
    monkeypatch.setattr(m.time, "sleep", lambda _: None)

    response = m.request_with_retries(cast(requests.Session, session), "POST", "https://example.test/items", max_retries=2)

    assert response.status_code == 503
    assert session.calls == 1


def test_request_with_retries_allows_explicit_idempotent_post_retry(monkeypatch):
    import sync._mod_common as m

    session = _SequenceSession(_response(503), _response(200))
    monkeypatch.setattr(m.time, "sleep", lambda _: None)

    response = m.request_with_retries(
        cast(requests.Session, session),
        "POST",
        "https://example.test/query",
        max_retries=2,
        idempotent=True,
    )

    assert response.status_code == 200
    assert session.calls == 2
