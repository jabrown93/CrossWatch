# tests/test_applier_ops.py
# Regression coverage for cw_platform/orchestrator/_applier.py's apply_add/apply_update/apply_remove,
# which were unified onto a shared _apply_op in refactor commit 62ebac4. Pins the emitted event
# names, payload keys (added/updated/removed), and spotlight action tagging that must stay
# identical per-verb after the parameterization.
from __future__ import annotations

from typing import Any

import pytest

from cw_platform.orchestrator import _applier


class FakeDstOps:
    def __init__(self, response: dict[str, Any] | None = None) -> None:
        self.add_calls: list[list[dict[str, Any]]] = []
        self.remove_calls: list[list[dict[str, Any]]] = []
        self._response = response

    def add(self, cfg, items, *, feature, dry_run=False):
        batch = [dict(x) for x in items]
        self.add_calls.append(batch)
        return self._response or {"ok": True, "count": len(batch)}

    def remove(self, cfg, items, *, feature, dry_run=False):
        batch = [dict(x) for x in items]
        self.remove_calls.append(batch)
        return self._response or {"ok": True, "count": len(batch)}


class Recorder:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def __call__(self, name: str, **fields: Any) -> None:
        self.events.append((name, fields))

    def named(self, name: str) -> list[dict[str, Any]]:
        return [f for n, f in self.events if n == name]


def _dbg(*_a: Any, **_k: Any) -> None:
    pass


ITEMS = [
    {"type": "movie", "title": "A", "year": 2000, "ids": {"imdb": "tt01"}},
    {"type": "movie", "title": "B", "year": 2001, "ids": {"imdb": "tt02"}},
]


@pytest.mark.parametrize(
    "op_name, payload_key, verb",
    [
        ("apply_add", "added", "add"),
        ("apply_update", "updated", "update"),
        ("apply_remove", "removed", "remove"),
    ],
)
def test_apply_op_emits_start_and_done_with_verb_specific_payload_key(op_name, payload_key, verb):
    ops = FakeDstOps()
    emit = Recorder()
    fn = getattr(_applier, op_name)

    res = fn(
        dst_ops=ops,
        cfg={},
        dst_name="DST",
        feature="watchlist",
        items=ITEMS,
        dry_run=False,
        emit=emit,
        dbg=_dbg,
        chunk_size=0,
        chunk_pause_ms=0,
    )

    assert res["confirmed"] == 2
    assert res["count"] == 2

    starts = emit.named(f"apply:{verb}:start")
    assert starts == [{"dst": "DST", "feature": "watchlist", "count": 2}]

    dones = emit.named(f"apply:{verb}:done")
    assert len(dones) == 1
    done = dones[0]
    assert done["dst"] == "DST"
    assert done["feature"] == "watchlist"
    assert done["count"] == 2
    assert done[payload_key] == 2
    # Only the verb-matching payload key is present, not the other two.
    other_keys = {"added", "updated", "removed"} - {payload_key}
    assert not other_keys & done.keys()


def test_apply_add_calls_dst_ops_add_not_remove():
    ops = FakeDstOps()
    emit = Recorder()
    _applier.apply_add(
        dst_ops=ops, cfg={}, dst_name="DST", feature="watchlist", items=ITEMS,
        dry_run=False, emit=emit, dbg=_dbg, chunk_size=0, chunk_pause_ms=0,
    )
    assert len(ops.add_calls) == 1
    assert ops.remove_calls == []


def test_apply_update_also_calls_dst_ops_add():
    # apply_update intentionally routes through dst_ops.add (updates are upserts), not a
    # separate update method - pin this since it's easy to "fix" during a refactor.
    ops = FakeDstOps()
    emit = Recorder()
    _applier.apply_update(
        dst_ops=ops, cfg={}, dst_name="DST", feature="watchlist", items=ITEMS,
        dry_run=False, emit=emit, dbg=_dbg, chunk_size=0, chunk_pause_ms=0,
    )
    assert len(ops.add_calls) == 1
    assert ops.remove_calls == []


def test_apply_remove_calls_dst_ops_remove_not_add():
    ops = FakeDstOps()
    emit = Recorder()
    _applier.apply_remove(
        dst_ops=ops, cfg={}, dst_name="DST", feature="watchlist", items=ITEMS,
        dry_run=False, emit=emit, dbg=_dbg, chunk_size=0, chunk_pause_ms=0,
    )
    assert len(ops.remove_calls) == 1
    assert ops.add_calls == []


@pytest.mark.parametrize(
    "op_name, verb",
    [("apply_add", "add"), ("apply_update", "update"), ("apply_remove", "remove")],
)
def test_apply_op_emits_ui_spotlight_with_matching_action(op_name, verb):
    ops = FakeDstOps({"ok": True, "confirmed_keys": ["imdb:tt01", "imdb:tt02"]})
    emit = Recorder()
    fn = getattr(_applier, op_name)
    fn(
        dst_ops=ops, cfg={}, dst_name="DST", feature="watchlist", items=ITEMS,
        dry_run=False, emit=emit, dbg=_dbg, chunk_size=0, chunk_pause_ms=0,
    )
    spotlights = emit.named("ui:spotlight")
    assert len(spotlights) == 1
    assert spotlights[0]["action"] == verb
    assert spotlights[0]["feature"] == "watchlist"
    assert spotlights[0]["count"] == 2


def test_apply_add_empty_items_short_circuits_with_zero_counts():
    ops = FakeDstOps()
    emit = Recorder()
    res = _applier.apply_add(
        dst_ops=ops, cfg={}, dst_name="DST", feature="watchlist", items=[],
        dry_run=False, emit=emit, dbg=_dbg, chunk_size=0, chunk_pause_ms=0,
    )
    assert res["confirmed"] == 0
    assert res["attempted"] == 0
    assert ops.add_calls == []
    done = emit.named("apply:add:done")[0]
    assert done["added"] == 0


def test_apply_add_chunks_items_per_chunk_size():
    ops = FakeDstOps()
    emit = Recorder()
    items = [{"ids": {"imdb": f"tt{i:02d}"}} for i in range(5)]
    res = _applier.apply_add(
        dst_ops=ops, cfg={}, dst_name="DST", feature="watchlist", items=items,
        dry_run=False, emit=emit, dbg=_dbg, chunk_size=2, chunk_pause_ms=0,
    )
    assert res["confirmed"] == 5
    # 5 items at chunk_size=2 -> 3 calls (2, 2, 1)
    assert [len(c) for c in ops.add_calls] == [2, 2, 1]


def test_apply_add_dry_run_forwarded_to_dst_ops():
    seen_dry_run: list[bool] = []

    class RecordingOps(FakeDstOps):
        def add(self, cfg, items, *, feature, dry_run=False):
            seen_dry_run.append(dry_run)
            return super().add(cfg, items, feature=feature, dry_run=dry_run)

    ops = RecordingOps()
    emit = Recorder()
    _applier.apply_add(
        dst_ops=ops, cfg={}, dst_name="DST", feature="watchlist", items=ITEMS,
        dry_run=True, emit=emit, dbg=_dbg, chunk_size=0, chunk_pause_ms=0,
    )
    assert seen_dry_run == [True]
