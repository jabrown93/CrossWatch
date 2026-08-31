from __future__ import annotations

import asyncio
import importlib
import threading
from typing import Any

import pytest

from api import scrobbleAPI


class _Request:
    headers = {"content-type": "application/json"}

    async def body(self) -> bytes:
        return b"{}"


@pytest.mark.parametrize(
    ("handler_name", "processor_module", "processor_name", "emits_follow_on"),
    [
        ("webhook_jellyfintrakt", "providers.webhooks.jellyfin", "process_webhook", True),
        ("webhook_embytrakt", "providers.webhooks.emby", "process_webhook", True),
        ("webhook_trakt", "providers.webhooks.plex", "process_webhook", True),
        ("webhook_plexwatcher", "providers.scrobble.plex.watch", "process_rating_webhook", False),
    ],
)
def test_webhook_blocking_work_runs_off_event_loop_thread(
    monkeypatch: pytest.MonkeyPatch,
    handler_name: str,
    processor_module: str,
    processor_name: str,
    emits_follow_on: bool,
) -> None:
    processor_threads: list[int] = []
    emitter_threads: list[int] = []
    processor_started = threading.Event()
    processor_release = threading.Event()

    def processor(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        processor_threads.append(threading.get_ident())
        processor_started.set()
        assert processor_release.wait(timeout=1)
        return {"ignored": True}

    def emitter(*_args: Any, **_kwargs: Any) -> None:
        emitter_threads.append(threading.get_ident())

    module = importlib.import_module(processor_module)
    monkeypatch.setattr(module, processor_name, processor)
    monkeypatch.setattr("crosswatch._UIHostLogger", lambda *_args, **_kwargs: lambda *_a, **_k: None)
    monkeypatch.setattr(scrobbleAPI, "_resolve_media_webhook_request", lambda *_args: ({}, "default", None))
    monkeypatch.setattr(scrobbleAPI, "_resolve_plexwatcher_target", lambda *_args: ("legacy", {}, None))
    monkeypatch.setattr(scrobbleAPI, "_debug_on", lambda: False)
    monkeypatch.setattr(scrobbleAPI, "_emit_scheduler_webhook_event", emitter)
    monkeypatch.setattr(scrobbleAPI, "_emit_activity_webhook_event", emitter)

    async def invoke() -> int:
        event_loop_thread = threading.get_ident()
        handler_task = asyncio.create_task(getattr(scrobbleAPI, handler_name)(_Request()))
        for _ in range(1_000):
            if processor_started.is_set():
                break
            await asyncio.sleep(0.001)
        assert processor_started.is_set()
        processor_release.set()
        response = await handler_task
        assert response.status_code == 200
        return event_loop_thread

    event_loop_thread = asyncio.run(invoke())

    assert processor_threads and processor_threads[0] != event_loop_thread
    if emits_follow_on:
        assert len(emitter_threads) == 2
        assert all(thread_id != event_loop_thread for thread_id in emitter_threads)
