from __future__ import annotations

from types import SimpleNamespace
from typing import cast

import pytest
import requests


class _CommitThenTimeoutSession:
    def __init__(self) -> None:
        self.calls = 0

    def request(self, method, url, **kwargs):
        self.calls += 1
        raise requests.Timeout("response lost after commit")


def test_trakt_history_add_does_not_retry_commit_then_timeout() -> None:
    import sync.trakt._history as history

    session = _CommitThenTimeoutSession()
    adapter = SimpleNamespace(
        client=SimpleNamespace(session=cast(requests.Session, session)),
        cfg=SimpleNamespace(
            client_id="client",
            access_token="token",
            timeout=0.01,
            max_retries=2,
            history_write_timeout=0.01,
        ),
    )

    with pytest.raises(requests.RequestException):
        history.add(
            adapter,
            [{"type": "movie", "ids": {"trakt": 1}, "watched_at": "2026-01-01T00:00:00Z"}],
        )

    assert session.calls == 1
