# tests/test_shared_helpers_regression.py
# Pins the byte-identical helper functions that refactor commit 62ebac4 hoisted out of
# per-provider/per-endpoint files into providers/sync/_mod_common.py,
# providers/scrobble/_sink_common.py, providers/webhooks/_utils.py, and
# cw_platform/config_base.py. These previously had no direct unit coverage - only
# exercised indirectly through whichever provider module happened to define them.
from __future__ import annotations

import json
import time
from typing import Any

import pytest
import responses

from cw_platform.config_base import _tmdb_api_key
from providers.scrobble import _sink_common
from providers.sync import _mod_common
from providers.webhooks import _utils as webhook_utils


# --- providers/sync/_mod_common.py -----------------------------------------------

def test_confirmed_keys_excludes_unresolved_and_dedupes():
    items = [{"ids": {"imdb": "tt01"}}, {"ids": {"imdb": "tt02"}}, {"ids": {"imdb": "tt02"}}]
    unresolved = [{"key": "imdb:tt02"}]
    key_of = lambda it: it["ids"]["imdb"] and f"imdb:{it['ids']['imdb']}"

    out = _mod_common._confirmed_keys(key_of, items, unresolved)

    assert out == ["imdb:tt01"]


def test_confirmed_keys_unresolved_as_bare_item_mapping():
    items = [{"ids": {"imdb": "tt01"}}, {"ids": {"imdb": "tt02"}}]
    key_of = lambda it: f"imdb:{it['ids']['imdb']}"
    unresolved = [{"item": {"ids": {"imdb": "tt02"}}}]

    assert _mod_common._confirmed_keys(key_of, items, unresolved) == ["imdb:tt01"]


def test_confirmed_keys_empty_unresolved():
    items = [{"ids": {"imdb": "tt01"}}]
    key_of = lambda it: f"imdb:{it['ids']['imdb']}"
    assert _mod_common._confirmed_keys(key_of, items, None) == ["imdb:tt01"]


def test_pair_scope_reads_first_matching_env_var(monkeypatch):
    monkeypatch.delenv("CW_PAIR_KEY", raising=False)
    monkeypatch.delenv("CW_PAIR_SCOPE", raising=False)
    monkeypatch.setenv("CW_SYNC_PAIR", "p1")
    monkeypatch.setenv("CW_PAIR", "p2")
    assert _mod_common._pair_scope() == "p1"


def test_pair_scope_none_when_unset(monkeypatch):
    for k in ("CW_PAIR_KEY", "CW_PAIR_SCOPE", "CW_SYNC_PAIR", "CW_PAIR"):
        monkeypatch.delenv(k, raising=False)
    assert _mod_common._pair_scope() is None


@pytest.mark.parametrize("val,expected", [("1", True), ("true", True), ("YES", True), ("on", True),
                                          ("0", False), ("", False), ("nope", False)])
def test_is_capture_mode(monkeypatch, val, expected):
    monkeypatch.setenv("CW_CAPTURE_MODE", val)
    assert _mod_common._is_capture_mode() is expected


def test_safe_scope_replaces_invalid_chars_and_collapses_underscores():
    assert _mod_common._safe_scope("Pair One / Two!!") == "Pair_One_Two"


def test_safe_scope_empty_falls_back_to_default():
    assert _mod_common._safe_scope("") == "default"
    assert _mod_common._safe_scope("///") == "default"


def test_safe_scope_truncates_to_96_chars():
    assert len(_mod_common._safe_scope("x" * 200)) == 96


def test_chunk_items_splits_into_expected_sizes():
    chunks = list(_mod_common._chunk_items([1, 2, 3, 4, 5], 2))
    assert chunks == [[1, 2], [3, 4], [5]]


def test_chunk_items_zero_or_negative_n_treated_as_one():
    assert list(_mod_common._chunk_items([1, 2], 0)) == [[1], [2]]
    assert list(_mod_common._chunk_items([1, 2], -5)) == [[1], [2]]


def test_pick_instance_id_prefers_explicit_env_vars(monkeypatch):
    for k in ("CW_SNAPSHOT_INSTANCE", "CW_INSTANCE_ID", "CW_PROFILE", "CW_PROVIDER_INSTANCE",
              "CW_INSTANCE", "CW_PAIR_SRC", "CW_PAIR_DST", "CW_PAIR_INSTANCE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("CW_INSTANCE_ID", "P01")
    assert _mod_common._pick_instance_id("EMBY") == "P01"


def test_pick_instance_id_uses_pair_src_dst_role(monkeypatch):
    for k in ("CW_SNAPSHOT_INSTANCE", "CW_INSTANCE_ID", "CW_PROFILE", "CW_PROVIDER_INSTANCE", "CW_INSTANCE"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("CW_PAIR_SRC", "emby")
    monkeypatch.setenv("CW_PAIR_SRC_INSTANCE", "P02")
    monkeypatch.delenv("CW_PAIR_DST", raising=False)
    monkeypatch.delenv("CW_PAIR_INSTANCE", raising=False)
    assert _mod_common._pick_instance_id("EMBY") == "P02"


def test_pick_instance_id_defaults_when_nothing_set(monkeypatch):
    for k in ("CW_SNAPSHOT_INSTANCE", "CW_INSTANCE_ID", "CW_PROFILE", "CW_PROVIDER_INSTANCE", "CW_INSTANCE",
              "CW_PAIR_SRC", "CW_PAIR_DST", "CW_PAIR_INSTANCE"):
        monkeypatch.delenv(k, raising=False)
    assert _mod_common._pick_instance_id("EMBY") == "default"


def test_merge_instance_block_default_strips_instances_key():
    raw = {"server": "x", "instances": {"p01": {"server": "y"}}}
    out = _mod_common._merge_instance_block(raw, "default")
    assert out == {"server": "x"}


def test_merge_instance_block_overlays_named_instance():
    raw = {"server": "x", "token": "t0", "instances": {"p01": {"server": "y"}}}
    out = _mod_common._merge_instance_block(raw, "p01")
    assert out == {"server": "y", "token": "t0"}


def test_merge_instance_block_missing_instance_falls_back_to_base():
    raw = {"server": "x", "instances": {"other": {"server": "y"}}}
    out = _mod_common._merge_instance_block(raw, "p01")
    assert out == {"server": "x"}


def test_iso_ok_valid_and_invalid():
    assert _mod_common._iso_ok("2026-01-01T00:00:00Z") is True
    assert _mod_common._iso_ok("not-a-date") is False
    assert _mod_common._iso_ok(None) is False
    assert _mod_common._iso_ok("") is False


def test_iso_z_normalizes_to_utc_z_suffix():
    assert _mod_common._iso_z("2026-01-01T00:00:00+00:00") == "2026-01-01T00:00:00Z"


def test_iso_z_naive_datetime_assumed_utc():
    assert _mod_common._iso_z("2026-01-01T00:00:00") == "2026-01-01T00:00:00Z"


def test_iso_z_raises_on_invalid():
    with pytest.raises(ValueError):
        _mod_common._iso_z("garbage")


def test_max_iso_picks_the_later_timestamp():
    a = "2026-01-01T00:00:00Z"
    b = "2026-06-01T00:00:00Z"
    assert _mod_common._max_iso(a, b) == b
    assert _mod_common._max_iso(b, a) == b


def test_max_iso_one_invalid_returns_the_valid_one():
    assert _mod_common._max_iso("garbage", "2026-01-01T00:00:00Z") == "2026-01-01T00:00:00Z"
    assert _mod_common._max_iso("2026-01-01T00:00:00Z", "garbage") == "2026-01-01T00:00:00Z"


def test_max_iso_both_invalid_returns_none():
    assert _mod_common._max_iso("garbage", "also-garbage") is None


# --- providers/scrobble/_sink_common.py ------------------------------------------

def test_merged_provider_block_no_instance_strips_instances_key():
    cfg = {"trakt": {"client_id": "x", "instances": {"p01": {"client_id": "y"}}}}
    out = _sink_common._merged_provider_block(cfg, "trakt")
    assert out == {"client_id": "x"}


def test_merged_provider_block_with_instance_overlay():
    cfg = {"trakt": {"client_id": "x", "token": "t0", "instances": {"p01": {"client_id": "y"}}}}
    out = _sink_common._merged_provider_block(cfg, "trakt", "p01")
    assert out == {"client_id": "y", "token": "t0"}


@pytest.mark.parametrize("raw,expected", [("movie", "movie"), ("movies", "movie"),
                                           ("Shows", "show"), ("episode", "episode")])
def test_norm_type(raw, expected):
    assert _sink_common._norm_type(raw) == expected


def test_norm_type_series_singular_is_not_remapped_to_show():
    # The "s"-strip runs before the "series"->"show" check, so a bare "series" input
    # (already singular after stripping trailing "s") never matches that branch - it
    # falls through as "serie". Only a plural "seriess"-shaped input would hit "show".
    # Pinning the existing behavior, not the apparently-intended one.
    assert _sink_common._norm_type("series") == "serie"


def test_cfg_delete_enabled_off_route_mode_blocks_regardless_of_delete_plex():
    cfg = {"scrobble": {"delete_plex": True, "delete_plex_types": ["movie"],
                         "watch": {"route_options": {"auto_remove_watchlist": "off"}}}}
    assert _sink_common._cfg_delete_enabled(cfg, "movie") is False


def test_cfg_delete_enabled_on_route_mode_bypasses_delete_plex_flag():
    cfg = {"scrobble": {"delete_plex": False, "delete_plex_types": ["movie"],
                         "watch": {"route_options": {"auto_remove_watchlist": "on"}}}}
    assert _sink_common._cfg_delete_enabled(cfg, "movie") is True


def test_cfg_delete_enabled_type_not_in_allowed_list():
    cfg = {"scrobble": {"delete_plex": True, "delete_plex_types": ["show"]}}
    assert _sink_common._cfg_delete_enabled(cfg, "movie") is False


def test_extract_skeleton_from_body_strips_volatile_fields():
    body = {"progress": 50, "app_version": "1.0", "app_date": "x", "action": "start"}
    assert _sink_common._extract_skeleton_from_body(body) == {"action": "start"}


@pytest.mark.parametrize("val,expected", [(50, 50), (-5, 0), (150, 100), ("70", 70), ("bad", 0)])
def test_clamp(val, expected):
    assert _sink_common._clamp(val) == expected


def test_app_meta_includes_build_date_when_present():
    cfg = {"runtime": {"version": "1.2.3", "build_date": "2026-01-01"}}
    assert _sink_common._app_meta(cfg) == {"app_version": "1.2.3", "app_date": "2026-01-01"}


def test_app_meta_omits_build_date_when_absent():
    cfg = {"runtime": {"version": "1.2.3"}}
    assert _sink_common._app_meta(cfg) == {"app_version": "1.2.3"}


def test_ar_seen_first_call_false_second_call_true(tmp_path, monkeypatch):
    monkeypatch.setattr(_sink_common, "_ar_state_file", lambda: tmp_path / "auto_remove_seen.json")
    assert _sink_common._ar_seen("k1") is False
    assert _sink_common._ar_seen("k1") is True


def test_ar_seen_expires_after_ttl(tmp_path, monkeypatch):
    state_file = tmp_path / "auto_remove_seen.json"
    monkeypatch.setattr(_sink_common, "_ar_state_file", lambda: state_file)
    assert _sink_common._ar_seen("k1") is False
    # Simulate the entry having aged past the TTL.
    data = json.loads(state_file.read_text())
    data["k1"] = time.time() - (_sink_common._AR_TTL + 5)
    state_file.write_text(json.dumps(data))
    assert _sink_common._ar_seen("k1") is False


# --- providers/webhooks/_utils.py ------------------------------------------------

def test_verify_webhook_secret_empty_secret_bypasses():
    assert webhook_utils.verify_webhook_secret({}, "") is True


def test_verify_webhook_secret_valid_and_invalid():
    assert webhook_utils.verify_webhook_secret({"X-CW-Webhook-Secret": "s"}, "s") is True
    assert webhook_utils.verify_webhook_secret({"X-CW-Webhook-Secret": "wrong"}, "s") is False


def test_tokens_prefers_auth_trakt_over_top_level_trakt():
    cfg = {
        "trakt": {"client_id": "cid", "client_secret": "secret", "access_token": "top-level-tok"},
        "auth": {"trakt": {"access_token": "auth-tok", "refresh_token": "rtok"}},
    }
    out = webhook_utils._tokens(cfg)
    assert out == {"client_id": "cid", "client_secret": "secret",
                    "access_token": "auth-tok", "refresh_token": "rtok"}


def test_headers_includes_bearer_only_when_access_token_present():
    cfg = {"trakt": {"client_id": "cid"}}
    h = webhook_utils._headers(cfg)
    assert h["trakt-api-key"] == "cid"
    assert "Authorization" not in h

    cfg2 = {"trakt": {"client_id": "cid", "access_token": "tok"}}
    h2 = webhook_utils._headers(cfg2)
    assert h2["Authorization"] == "Bearer tok"


def test_cache_get_put_roundtrip():
    cache: dict[Any, Any] = {}
    webhook_utils._cache_put(cache, ("a", 1), "value")
    assert webhook_utils._cache_get(cache, ("a", 1)) == "value"
    assert webhook_utils._cache_get(cache, ("missing",)) is None


def test_cache_put_clears_when_oversized():
    cache: dict[Any, Any] = {("k", i): i for i in range(2049)}
    webhook_utils._cache_put(cache, ("new",), "v")
    # Cache was cleared for being over the 2048 threshold, then the new entry added.
    assert cache == {("new",): "v"}


def test_best_id_key_order_same_for_movie_and_show():
    assert webhook_utils._best_id_key_order("movie") == ("tmdb", "imdb", "tvdb")
    assert webhook_utils._best_id_key_order("show") == ("tmdb", "imdb", "tvdb")


@responses.activate
def test_del_trakt_success_no_refresh():
    responses.add(responses.DELETE, "https://api.trakt.tv/checkin", status=204)
    cfg = {"trakt": {"client_id": "cid", "access_token": "tok"}}
    r = webhook_utils._del_trakt("/checkin", cfg)
    assert r.status_code == 204
    assert len(responses.calls) == 1


@responses.activate
def test_del_trakt_401_triggers_refresh_and_retries(monkeypatch):
    responses.add(responses.DELETE, "https://api.trakt.tv/checkin", status=401)
    responses.add(responses.DELETE, "https://api.trakt.tv/checkin", status=204)

    refreshed = []

    class FakeTraktAuth:
        @staticmethod
        def refresh(cfg):
            refreshed.append(True)
            cfg["trakt"]["access_token"] = "new-tok"

    import providers.auth._auth_TRAKT as auth_mod
    monkeypatch.setattr(auth_mod, "PROVIDER", FakeTraktAuth)
    monkeypatch.setattr(webhook_utils, "_save_config", lambda cfg: None)

    cfg = {"trakt": {"client_id": "cid", "access_token": "old-tok"}}
    r = webhook_utils._del_trakt("/checkin", cfg)

    assert refreshed == [True]
    assert r.status_code == 204
    assert len(responses.calls) == 2


def test_call_remove_across_skips_when_delete_plex_disabled(monkeypatch):
    monkeypatch.setattr(webhook_utils, "_load_config", lambda: {"scrobble": {"delete_plex": False}})
    called = []
    monkeypatch.setattr(webhook_utils, "_rm_across", lambda ids, mt: called.append((ids, mt)))
    webhook_utils._call_remove_across({"imdb": "tt01"}, "movie")
    assert called == []


def test_call_remove_across_calls_rm_across_when_type_allowed(monkeypatch):
    monkeypatch.setattr(
        webhook_utils, "_load_config",
        lambda: {"scrobble": {"delete_plex": True, "delete_plex_types": ["movies"]}},
    )
    called = []
    monkeypatch.setattr(webhook_utils, "_rm_across", lambda ids, mt: called.append((ids, mt)))
    webhook_utils._call_remove_across({"imdb": "tt01"}, "movie")
    assert called == [({"imdb": "tt01"}, "movie")]


def test_call_remove_across_empty_ids_is_noop(monkeypatch):
    called = []
    monkeypatch.setattr(webhook_utils, "_rm_across", lambda ids, mt: called.append((ids, mt)))
    webhook_utils._call_remove_across({}, "movie")
    assert called == []


# --- cw_platform/config_base._tmdb_api_key ---------------------------------------

def test_tmdb_api_key_reads_top_level_tmdb_block():
    assert _tmdb_api_key({"tmdb": {"api_key": "k1"}}) == "k1"


def test_tmdb_api_key_falls_back_to_tmdb_sync_block():
    assert _tmdb_api_key({"tmdb_sync": {"api_key": "k2"}}) == "k2"


def test_tmdb_api_key_prefers_tmdb_over_tmdb_sync():
    assert _tmdb_api_key({"tmdb": {"api_key": "k1"}, "tmdb_sync": {"api_key": "k2"}}) == "k1"


def test_tmdb_api_key_falls_back_to_per_instance_key():
    cfg = {"tmdb": {"instances": {"p01": {"api_key": "k3"}}}}
    assert _tmdb_api_key(cfg) == "k3"


def test_tmdb_api_key_missing_returns_empty_string():
    assert _tmdb_api_key({}) == ""
