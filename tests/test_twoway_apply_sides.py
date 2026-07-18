# tests/test_twoway_apply_sides.py
# Characterization coverage for the apply-remove/apply-update/apply-add phases inside
# cw_platform/orchestrator/_pairs_twoway.py's _two_way_sync, written before collapsing
# the per-side (A/B) duplicated blocks into shared same-file helpers. A `sed`-normalized
# diff confirmed the A and B blocks are pure mechanical mirrors (only names differ:
# a/b, aops/bops, A_eff/B_eff, resA_*/resB_*, etc.) - these tests pin the actual
# behavior of both sides, including paths that had zero prior direct coverage:
# apply-update (never exercised before), provider-down handling for update/add, and
# the have_exact_keys / ambiguous_partial / verify_after_write branches of apply-add.
from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from cw_platform.id_map import canonical_key
from cw_platform.orchestrator import _pairs_twoway as twoway
from cw_platform.orchestrator import _unresolved


@pytest.fixture(autouse=True)
def _isolate_unresolved_state(monkeypatch, tmp_path):
    # record_unresolved/load_unresolved_keys persist to a hardcoded STATE_DIR
    # (see _unresolved.py), not the per-test CONFIG_BASE. Without this, tests
    # that don't mock record_unresolved (e.g. the verify_after_write case)
    # write real state that leaks into later tests reading the same path -
    # same isolation pattern as tests/test_history_specials.py.
    monkeypatch.setattr(_unresolved, "STATE_DIR", tmp_path)


class _StateStore:
    def __init__(self, state: dict[str, Any] | None = None) -> None:
        self.state: dict[str, Any] = state or {}
        self.tomb: dict[str, Any] = {}

    def load_state(self) -> dict[str, Any]:
        return self.state

    def save_state(self, value: dict[str, Any]) -> None:
        self.state = value

    def load_tomb(self) -> dict[str, Any]:
        return self.tomb

    def save_tomb(self, value: dict[str, Any]) -> None:
        self.tomb = value


class _Ops:
    """Configurable fake provider ops. Each of add/update/remove can be overridden
    with a callable(items) -> response_dict; defaults to a plain confirmed-all response."""

    def __init__(self, add_fn=None, update_fn=None, remove_fn=None, caps: dict[str, Any] | None = None) -> None:
        self.added: list[dict[str, Any]] = []
        self.updated: list[dict[str, Any]] = []
        self.removed: list[dict[str, Any]] = []
        self._add_fn = add_fn
        self._update_fn = update_fn
        self._remove_fn = remove_fn
        self._caps = caps or {"history": {"observed_deletes": False}, "ratings": {"observed_deletes": False}}

    def add(self, _cfg, items, *, feature, dry_run=False):
        self.added.extend(dict(item) for item in items)
        if self._add_fn:
            return self._add_fn(items)
        return {
            "ok": True,
            "count": len(items),
            "confirmed_keys": [canonical_key(item) for item in items],
        }

    def update(self, _cfg, items, *, feature, dry_run=False):
        self.updated.extend(dict(item) for item in items)
        if self._update_fn:
            return self._update_fn(items)
        return {
            "ok": True,
            "count": len(items),
            "confirmed_keys": [canonical_key(item) for item in items],
        }

    def remove(self, _cfg, items, *, feature, dry_run=False):
        self.removed.extend(dict(item) for item in items)
        if self._remove_fn:
            return self._remove_fn(items)
        return {"ok": True, "count": len(items), "confirmed_keys": [canonical_key(item) for item in items]}

    def capabilities(self):
        return self._caps


def _install_common_monkeypatches(monkeypatch, *, allow_adds: bool, allow_removals: bool) -> None:
    monkeypatch.setattr(twoway, "_supports_feature", lambda _ops, _feature: True)
    monkeypatch.setattr(twoway, "_health_feature_ok", lambda _health, _feature: True)
    monkeypatch.setattr(twoway, "_resolve_flags", lambda _fcfg, _sync: {"allow_adds": allow_adds, "allow_removals": allow_removals})
    monkeypatch.setattr(twoway, "_anime_pair_feature_options", lambda *_args, **_kwargs: {"use_anime_mapping": False})
    monkeypatch.setattr(twoway, "_anime_config_with_pair_feature_options", lambda cfg, _opts: cfg)
    monkeypatch.setattr(twoway, "_index_semantics", lambda *_args, **_kwargs: "full")
    monkeypatch.setattr(twoway, "prev_checkpoint", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(twoway, "module_checkpoint", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(twoway, "keys_for_feature", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(twoway, "_manual_policy", lambda *_args, **_kwargs: ([], set()))
    monkeypatch.setattr(twoway, "_provider_ignore_dropped_enabled", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(twoway, "apply_blocklist", lambda _state, items, **_kwargs: list(items))
    monkeypatch.setattr(twoway, "_maybe_block_massdelete", lambda items, **_kwargs: list(items))
    monkeypatch.setattr(twoway, "effective_chunk_size", lambda *_args, **_kwargs: 100)
    monkeypatch.setattr(twoway, "load_blackbox_keys", lambda *_args, **_kwargs: set())
    monkeypatch.setattr(twoway, "record_attempts", lambda *_args, **_kwargs: {"ok": True, "count": 0})
    monkeypatch.setattr(twoway, "record_success", lambda *_args, **_kwargs: {"ok": True, "count": 0})


def _run_two_way(
    monkeypatch,
    *,
    feature: str,
    a_snap: dict[str, dict[str, Any]],
    b_snap: dict[str, dict[str, Any]],
    a_name: str = "PLEX",
    b_name: str = "SIMKL",
    prev_state: dict[str, Any] | None = None,
    allow_adds: bool = True,
    allow_removals: bool = True,
    a_ops: _Ops | None = None,
    b_ops: _Ops | None = None,
    health_status: dict[str, str] | None = None,
    fcfg: dict[str, Any] | None = None,
    verify_after_write: bool = False,
):
    _install_common_monkeypatches(monkeypatch, allow_adds=allow_adds, allow_removals=allow_removals)
    status_by_provider = health_status or {}
    monkeypatch.setattr(
        twoway, "_health_status", lambda h: status_by_provider.get((h or {}).get("_name", ""), "up")
    )
    aops = a_ops or _Ops()
    bops = b_ops or _Ops()
    monkeypatch.setattr(twoway, "build_snapshots_for_feature", lambda **_kwargs: {a_name: a_snap, b_name: b_snap})
    ctx = SimpleNamespace(
        config={
            "sync": {
                "include_observed_deletes": False,
                "blackbox": {"enabled": False},
                "verify_after_write": verify_after_write,
            },
            "runtime": {},
        },
        providers={a_name: aops, b_name: bops},
        emit=lambda *_args, **_kwargs: None,
        emit_info=lambda *_args, **_kwargs: None,
        dbg=lambda *_args, **_kwargs: None,
        dry_run=False,
        snap_cache={},
        snap_ttl_sec=0,
        state_store=_StateStore(prev_state),
        stats_manual_blocked=0,
        apply_chunk_pause_ms=0,
    )
    health_map = {a_name: {"_name": a_name}, b_name: {"_name": b_name}}
    result = twoway._two_way_sync(ctx, a_name, b_name, feature=feature, fcfg=(fcfg or {}), health_map=health_map)
    return result, aops, bops, ctx


ITEM_700 = {"type": "movie", "title": "Movie700", "year": 2020, "ids": {"tmdb": "700"}, "watched_at": "2024-01-01T00:00:00Z"}
ITEM_800 = {"type": "movie", "title": "Movie800", "year": 2020, "ids": {"tmdb": "800"}, "watched_at": "2024-01-01T00:00:00Z"}


def _prev_state_with(a_name: str, b_name: str, a_items: dict[str, Any], b_items: dict[str, Any]) -> dict[str, Any]:
    return {
        "providers": {
            a_name: {"history": {"baseline": {"items": a_items}}},
            b_name: {"history": {"baseline": {"items": b_items}}},
        }
    }


# --- apply-remove: both sides -------------------------------------------------------


def test_apply_remove_both_sides_pops_effective_index_and_marks_tombstones(monkeypatch):
    # 800 was known to SIMKL before, now gone from SIMKL but still on PLEX -> remove from PLEX (A).
    # 700 was known to PLEX before, now gone from PLEX but still on SIMKL -> remove from SIMKL (B).
    prev_state = _prev_state_with("PLEX", "SIMKL", {"tmdb:700": ITEM_700}, {"tmdb:800": ITEM_800})
    result, aops, bops, ctx = _run_two_way(
        monkeypatch,
        feature="history",
        a_snap={"tmdb:800": ITEM_800},
        b_snap={"tmdb:700": ITEM_700},
        prev_state=prev_state,
        allow_adds=True,
        allow_removals=True,
    )

    assert result["rem_from_A"] == 1
    assert result["rem_from_B"] == 1
    assert aops.removed and canonical_key(aops.removed[0]) == "tmdb:800"
    assert bops.removed and canonical_key(bops.removed[0]) == "tmdb:700"
    assert aops.added == [] and bops.added == []

    tomb_keys = ctx.state_store.tomb.get("keys", {})
    assert any("tmdb:800" in k for k in tomb_keys)
    assert any("tmdb:700" in k for k in tomb_keys)


def test_apply_remove_provider_down_skips_and_records_unresolved(monkeypatch):
    prev_state = _prev_state_with("PLEX", "SIMKL", {}, {"tmdb:800": ITEM_800})
    recorded: list[tuple[str, str, list, str]] = []
    monkeypatch.setattr(
        twoway, "record_unresolved",
        lambda provider, feature, items, hint=None: recorded.append((provider, feature, list(items), hint)),
    )
    result, aops, bops, ctx = _run_two_way(
        monkeypatch,
        feature="history",
        a_snap={"tmdb:800": ITEM_800},
        b_snap={},
        prev_state=prev_state,
        allow_adds=True,
        allow_removals=True,
        health_status={"PLEX": "down"},
    )

    assert result["rem_from_A"] == 0
    assert aops.removed == []
    assert any(r[0] == "PLEX" and r[3] == "provider_down:remove" for r in recorded)


# --- apply-update: both sides (ratings, previously zero direct coverage) -----------


def test_apply_update_both_sides_when_ratings_differ(monkeypatch):
    # tmdb:500: PLEX rating newer/higher -> wins -> propagates to SIMKL as an update
    #   (SIMKL already has this key, so it's reclassified from add to update).
    # tmdb:600: SIMKL rating newer -> wins -> propagates to PLEX as an update.
    a_snap = {
        "tmdb:500": {"type": "movie", "title": "X", "year": 2020, "ids": {"tmdb": "500"},
                     "rating": 8, "rated_at": "2024-01-02T00:00:00Z"},
        "tmdb:600": {"type": "movie", "title": "Y", "year": 2021, "ids": {"tmdb": "600"},
                     "rating": 3, "rated_at": "2024-01-01T00:00:00Z"},
    }
    b_snap = {
        "tmdb:500": {"type": "movie", "title": "X", "year": 2020, "ids": {"tmdb": "500"},
                     "rating": 5, "rated_at": "2024-01-01T00:00:00Z"},
        "tmdb:600": {"type": "movie", "title": "Y", "year": 2021, "ids": {"tmdb": "600"},
                     "rating": 9, "rated_at": "2024-01-02T00:00:00Z"},
    }
    result, aops, bops, ctx = _run_two_way(
        monkeypatch, feature="ratings", a_snap=a_snap, b_snap=b_snap,
        allow_adds=True, allow_removals=False,
    )

    assert result["upd_to_A"] == 1
    assert result["upd_to_B"] == 1
    # apply_update routes through dst_ops.add, not a separate update method (see
    # cw_platform/orchestrator/_applier.py - updates are upserts); confirmed by
    # tests/test_applier_ops.py::test_apply_update_also_calls_dst_ops_add. So the
    # update payloads land in .added, not .updated, on this fake.
    assert bops.updated == [] and aops.updated == []
    assert bops.added and canonical_key(bops.added[0]) == "tmdb:500" and bops.added[0]["rating"] == 8
    assert aops.added and canonical_key(aops.added[0]) == "tmdb:600" and aops.added[0]["rating"] == 9


def test_apply_update_provider_down_skips_and_records_unresolved(monkeypatch):
    a_snap = {
        "tmdb:500": {"type": "movie", "title": "X", "year": 2020, "ids": {"tmdb": "500"},
                     "rating": 8, "rated_at": "2024-01-02T00:00:00Z"},
    }
    b_snap = {
        "tmdb:500": {"type": "movie", "title": "X", "year": 2020, "ids": {"tmdb": "500"},
                     "rating": 5, "rated_at": "2024-01-01T00:00:00Z"},
    }
    recorded: list[tuple[str, str, list, str]] = []
    monkeypatch.setattr(
        twoway, "record_unresolved",
        lambda provider, feature, items, hint=None: recorded.append((provider, feature, list(items), hint)),
    )
    result, aops, bops, ctx = _run_two_way(
        monkeypatch, feature="ratings", a_snap=a_snap, b_snap=b_snap,
        allow_adds=True, allow_removals=False, health_status={"SIMKL": "down"},
    )

    assert result["upd_to_B"] == 0
    assert bops.updated == []
    assert any(r[0] == "SIMKL" and r[3] == "provider_down:update" for r in recorded)
    assert result["unresolved_to_B"] == 1


# --- apply-add: have_exact_keys / ambiguous_partial / verify_after_write -----------


NEW_ITEM = {"type": "movie", "title": "Fresh", "year": 2022, "ids": {"tmdb": "900"}, "watched_at": "2024-01-01T00:00:00Z"}


def test_apply_add_with_confirmed_keys_uses_provider_reported_keys(monkeypatch):
    result, aops, bops, ctx = _run_two_way(
        monkeypatch, feature="history", a_snap={"tmdb:900": NEW_ITEM}, b_snap={},
        allow_adds=True, allow_removals=False,
    )
    assert result["adds_to_B"] == 1
    assert bops.added and canonical_key(bops.added[0]) == "tmdb:900"


def test_apply_add_without_confirmed_keys_falls_back_to_count_based_reconciliation(monkeypatch):
    b_ops = _Ops(add_fn=lambda items: {"ok": True, "count": len(items)})  # no confirmed_keys
    result, aops, bops, ctx = _run_two_way(
        monkeypatch, feature="history", a_snap={"tmdb:900": NEW_ITEM}, b_snap={},
        allow_adds=True, allow_removals=False, b_ops=b_ops,
    )
    assert result["adds_to_B"] == 1
    assert bops.added and canonical_key(bops.added[0]) == "tmdb:900"


def test_apply_add_ambiguous_partial_when_provider_reports_skipped_without_exact_keys(monkeypatch):
    # Two items attempted, provider reports only 1 confirmed plus skipped=True, but
    # WITHOUT confirmed_keys telling us which one succeeded. With 2 candidates and a
    # provider-confirmed count of 1, we can't tell which item actually landed, so the
    # ambiguous_partial guard conservatively reports 0 effective adds rather than
    # guessing (see _pairs_twoway.py's `ambiguous_partial_B` computation).
    other_item = {"type": "movie", "title": "Fresh2", "year": 2022, "ids": {"tmdb": "901"}, "watched_at": "2024-01-01T00:00:00Z"}
    b_ops = _Ops(add_fn=lambda items: {"ok": True, "count": 1, "skipped": True})
    result, aops, bops, ctx = _run_two_way(
        monkeypatch, feature="history",
        a_snap={"tmdb:900": NEW_ITEM, "tmdb:901": other_item}, b_snap={},
        allow_adds=True, allow_removals=False, b_ops=b_ops,
    )
    assert result["adds_to_B"] == 0
    assert result["resB_add"]["skipped"] == 1


def test_apply_add_verify_after_write_filters_keys_still_unresolved(monkeypatch):
    # Provider confirms the add server-side (confirmed_keys present -> have_exact_keys),
    # but a post-write re-check of unresolved-keys shows it's still unresolved, so
    # verify_after_write must exclude it from the effective/success count even though
    # the item was genuinely sent to the provider.
    monkeypatch.setattr(twoway, "_apply_verify_after_write_supported", lambda _ops: True)
    calls = {"n": 0}

    def _load_unresolved(provider, feature, cross_features=False):
        # 1st call = unresolved_before (empty); 2nd call = unresolved_after (empty);
        # 3rd call = the verify-after-write re-check, which reports it unresolved.
        calls["n"] += 1
        return {"tmdb:900"} if calls["n"] >= 3 else set()

    monkeypatch.setattr(twoway, "load_unresolved_keys", _load_unresolved)
    b_ops = _Ops()
    result, aops, bops, ctx = _run_two_way(
        monkeypatch, feature="history", a_snap={"tmdb:900": NEW_ITEM}, b_snap={},
        allow_adds=True, allow_removals=False, b_ops=b_ops, verify_after_write=True,
    )

    assert result["adds_to_B"] == 0
    assert bops.added and canonical_key(bops.added[0]) == "tmdb:900"


def test_apply_add_provider_down_skips_and_records_unresolved(monkeypatch):
    recorded: list[tuple[str, str, list, str]] = []
    monkeypatch.setattr(
        twoway, "record_unresolved",
        lambda provider, feature, items, hint=None: recorded.append((provider, feature, list(items), hint)),
    )
    result, aops, bops, ctx = _run_two_way(
        monkeypatch, feature="history", a_snap={"tmdb:900": NEW_ITEM}, b_snap={},
        allow_adds=True, allow_removals=False, health_status={"SIMKL": "down"},
    )
    assert result["adds_to_B"] == 0
    assert bops.added == []
    assert any(r[0] == "SIMKL" and r[3] == "provider_down:add" for r in recorded)
    assert result["unresolved_to_B"] == 1
