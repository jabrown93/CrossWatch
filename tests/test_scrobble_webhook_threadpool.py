from __future__ import annotations

import asyncio
import importlib
import threading
from typing import Any, cast

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


def test_same_provider_webhooks_are_serialized(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    calls_lock = threading.Lock()
    first_started = threading.Event()
    second_started = threading.Event()
    first_release = threading.Event()

    def processor(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        nonlocal calls
        with calls_lock:
            calls += 1
            call_number = calls
        if call_number == 1:
            first_started.set()
            assert first_release.wait(timeout=2)
        else:
            second_started.set()
        return {"ignored": True}

    module = importlib.import_module("providers.webhooks.jellyfin")
    monkeypatch.setattr(module, "process_webhook", processor)
    monkeypatch.setattr("crosswatch._UIHostLogger", lambda *_args, **_kwargs: lambda *_a, **_k: None)
    monkeypatch.setattr(scrobbleAPI, "_resolve_media_webhook_request", lambda *_args: ({}, "default", None))
    monkeypatch.setattr(scrobbleAPI, "_debug_on", lambda: False)
    monkeypatch.setattr(scrobbleAPI, "_emit_scheduler_webhook_event", lambda *_args: None)
    monkeypatch.setattr(scrobbleAPI, "_emit_activity_webhook_event", lambda *_args: None)
    monkeypatch.setattr(
        scrobbleAPI,
        "_WEBHOOK_PROCESS_LOCKS",
        {"jellyfin": asyncio.Lock(), "emby": asyncio.Lock(), "plex": asyncio.Lock()},
        raising=False,
    )
    webhook = cast(Any, scrobbleAPI.webhook_jellyfintrakt)

    async def invoke() -> bool:
        first = asyncio.create_task(webhook(_Request()))
        for _ in range(1_000):
            if first_started.is_set():
                break
            await asyncio.sleep(0.001)
        assert first_started.is_set()

        second = asyncio.create_task(webhook(_Request()))
        for _ in range(100):
            if second_started.is_set():
                break
            await asyncio.sleep(0.001)
        overlapped = second_started.is_set()
        first_release.set()
        responses = await asyncio.gather(first, second)
        assert all(response.status_code == 200 for response in responses)
        return overlapped

    assert asyncio.run(invoke()) is False


def test_scheduler_webhook_events_are_serialized(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = 0
    calls_lock = threading.Lock()
    first_started = threading.Event()
    second_started = threading.Event()
    first_release = threading.Event()

    def processor(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        return {"ok": True, "action": "/scrobble/start", "status": 200}

    def scheduler_emitter(*_args: Any, **_kwargs: Any) -> None:
        nonlocal calls
        with calls_lock:
            calls += 1
            call_number = calls
        if call_number == 1:
            first_started.set()
            assert first_release.wait(timeout=2)
        else:
            second_started.set()

    module = importlib.import_module("providers.webhooks.jellyfin")
    monkeypatch.setattr(module, "process_webhook", processor)
    monkeypatch.setattr("crosswatch._UIHostLogger", lambda *_args, **_kwargs: lambda *_a, **_k: None)
    monkeypatch.setattr(scrobbleAPI, "_resolve_media_webhook_request", lambda *_args: ({}, "default", None))
    monkeypatch.setattr(scrobbleAPI, "_debug_on", lambda: False)
    monkeypatch.setattr(scrobbleAPI, "_emit_scheduler_webhook_event", scheduler_emitter)
    monkeypatch.setattr(scrobbleAPI, "_emit_activity_webhook_event", lambda *_args: None)
    monkeypatch.setattr(
        scrobbleAPI,
        "_WEBHOOK_PROCESS_LOCKS",
        {"jellyfin": asyncio.Lock(), "emby": asyncio.Lock(), "plex": asyncio.Lock()},
        raising=False,
    )
    monkeypatch.setattr(scrobbleAPI, "_SCHEDULER_EVENT_LOCK", asyncio.Lock(), raising=False)
    webhook = cast(Any, scrobbleAPI.webhook_jellyfintrakt)

    async def invoke() -> bool:
        first = asyncio.create_task(webhook(_Request()))
        for _ in range(1_000):
            if first_started.is_set():
                break
            await asyncio.sleep(0.001)
        assert first_started.is_set()

        second = asyncio.create_task(webhook(_Request()))
        for _ in range(100):
            if second_started.is_set():
                break
            await asyncio.sleep(0.001)
        overlapped = second_started.is_set()
        first_release.set()
        responses = await asyncio.gather(first, second)
        assert all(response.status_code == 200 for response in responses)
        return overlapped

    assert asyncio.run(invoke()) is False
