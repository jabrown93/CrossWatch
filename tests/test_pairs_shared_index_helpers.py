# tests/test_pairs_shared_index_helpers.py
# Regression coverage for the index-manipulation helpers that live in
# cw_platform/orchestrator/_pairs_oneway.py and are now imported (not redefined) by
# _pairs_twoway.py per refactor commit 62ebac4. These are the exact functions twoway's
# _two_way_sync depends on via import - pinning them directly protects against a
# future refactor accidentally changing oneway's copy out from under twoway.
from __future__ import annotations

from cw_platform.orchestrator._pairs_oneway import (
    _PROVIDER_KEY_MAP,
    _effective_library_whitelist,
    _enrich_index_payload,
    _filter_index_by_libraries,
    _rekey_index_to_match_other_keys,
)
from cw_platform.orchestrator._pairs_twoway import (
    _PROVIDER_KEY_MAP as twoway_key_map,
    _effective_library_whitelist as twoway_whitelist,
    _enrich_index_payload as twoway_enrich,
    _filter_index_by_libraries as twoway_filter,
    _rekey_index_to_match_other_keys as twoway_rekey,
)


def test_twoway_imports_the_same_objects_as_oneway_not_copies():
    # Guards the specific refactor invariant: twoway must import oneway's helpers,
    # not redefine its own. If a future change reintroduces a local copy in twoway,
    # these identity checks catch it even though both would behave the same.
    assert twoway_key_map is _PROVIDER_KEY_MAP
    assert twoway_whitelist is _effective_library_whitelist
    assert twoway_enrich is _enrich_index_payload
    assert twoway_filter is _filter_index_by_libraries
    assert twoway_rekey is _rekey_index_to_match_other_keys


def _typed_tokens(it):
    ids = it.get("ids") or {}
    return {f"{k}:{v}" for k, v in ids.items() if v}


def _merge_payload(existing, new):
    out = dict(existing)
    out.update({k: v for k, v in new.items() if v not in (None, "")})
    return out


def test_rekey_index_to_match_other_keys_noop_when_already_aligned():
    idx = {"tmdb:1": {"ids": {"tmdb": "1"}}}
    other = {"tmdb:1": {"ids": {"tmdb": "1"}}}
    out = _rekey_index_to_match_other_keys(idx, other, typed_tokens=_typed_tokens, merge_payload=_merge_payload)
    assert out == {"tmdb:1": {"ids": {"tmdb": "1"}}}


def test_rekey_index_to_match_other_keys_remaps_by_shared_tmdb_id():
    # idx is keyed by imdb, but the other side has the same title keyed by tmdb.
    # A shared tmdb id in idx's payload should let it rekey onto other's key.
    idx = {"imdb:tt01": {"ids": {"imdb": "tt01", "tmdb": "99"}}}
    other = {"tmdb:99": {"ids": {"tmdb": "99"}}}
    out = _rekey_index_to_match_other_keys(idx, other, typed_tokens=_typed_tokens, merge_payload=_merge_payload)
    assert set(out.keys()) == {"tmdb:99"}


def test_rekey_index_to_match_other_keys_no_match_keeps_original_key():
    idx = {"imdb:tt01": {"ids": {"imdb": "tt01"}}}
    other = {"tmdb:99": {"ids": {"tmdb": "99"}}}
    out = _rekey_index_to_match_other_keys(idx, other, typed_tokens=_typed_tokens, merge_payload=_merge_payload)
    assert out == idx


def test_rekey_index_to_match_other_keys_empty_inputs():
    assert _rekey_index_to_match_other_keys({}, {"a": {}}, typed_tokens=_typed_tokens, merge_payload=_merge_payload) == {}
    idx = {"a": {"ids": {}}}
    assert _rekey_index_to_match_other_keys(idx, {}, typed_tokens=_typed_tokens, merge_payload=_merge_payload) == idx


def test_enrich_index_payload_merges_ids_and_keeps_prev_as_base():
    cur = {"k1": {"ids": {"tmdb": "1"}, "title": "New Title"}}
    prev = {"k1": {"ids": {"imdb": "tt01"}, "title": "Old Title", "extra": "keep"}}
    out = _enrich_index_payload(cur, prev, "watchlist")
    assert out["k1"]["ids"] == {"tmdb": "1", "imdb": "tt01"}
    assert out["k1"]["title"] == "New Title"
    assert out["k1"]["extra"] == "keep"


def test_enrich_index_payload_history_picks_newest_watched_at():
    cur = {"k1": {"watched_at": "2026-06-01T00:00:00Z"}}
    prev = {"k1": {"watched_at": "2026-01-01T00:00:00Z"}}
    out = _enrich_index_payload(cur, prev, "history")
    assert out["k1"]["watched_at"] == "2026-06-01T00:00:00Z"


def test_enrich_index_payload_ratings_picks_newest_rated_at():
    cur = {"k1": {"rated_at": "2026-01-01T00:00:00Z"}}
    prev = {"k1": {"rated_at": "2026-06-01T00:00:00Z"}}
    out = _enrich_index_payload(cur, prev, "ratings")
    assert out["k1"]["rated_at"] == "2026-06-01T00:00:00Z"


def test_enrich_index_payload_empty_cur_or_prev_returns_cur_copy():
    cur = {"k1": {"title": "X"}}
    assert _enrich_index_payload(cur, {}, "watchlist") == cur
    assert _enrich_index_payload({}, cur, "watchlist") == {}


def test_effective_library_whitelist_reads_per_provider_feature_config():
    cfg = {"emby": {"history": {"libraries": ["Movies", "TV"]}}}
    out = _effective_library_whitelist(cfg, "EMBY", "history", {})
    assert out == ["Movies", "TV"]


def test_effective_library_whitelist_pair_level_override_wins():
    cfg = {"emby": {"history": {"libraries": ["Movies"]}}}
    fcfg = {"libraries": {"EMBY": ["Kids"]}}
    out = _effective_library_whitelist(cfg, "EMBY", "history", fcfg)
    assert out == ["Kids"]


def test_effective_library_whitelist_not_applicable_outside_history_ratings():
    cfg = {"emby": {"watchlist": {"libraries": ["Movies"]}}}
    assert _effective_library_whitelist(cfg, "EMBY", "watchlist", {}) == []


def test_effective_library_whitelist_unknown_provider_returns_empty():
    assert _effective_library_whitelist({}, "UNKNOWNPROVIDER", "history", {}) == []


def test_filter_index_by_libraries_no_libs_returns_full_copy():
    idx = {"a": {"library_id": "1"}}
    assert _filter_index_by_libraries(idx, []) == idx


def test_filter_index_by_libraries_keeps_only_allowed_libraries():
    idx = {
        "a": {"library_id": "1"},
        "b": {"library_id": "2"},
    }
    out = _filter_index_by_libraries(idx, ["1"])
    assert out == {"a": {"library_id": "1"}}


def test_filter_index_by_libraries_unknown_library_dropped_by_default():
    idx = {"a": {}}
    assert _filter_index_by_libraries(idx, ["1"]) == {}


def test_filter_index_by_libraries_allow_unknown_keeps_items_without_library_id():
    idx = {"a": {}}
    assert _filter_index_by_libraries(idx, ["1"], allow_unknown=True) == {"a": {}}
