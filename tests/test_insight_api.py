# tests/test_insight_api.py
# Characterization coverage for the routes originally in api/insightAPI.py (1914 lines,
# the single biggest file in the repo), now split into insight_stats.py/
# insight_snapshot.py/insight_analytics.py. insightAPI.py had zero prior test coverage.
# These tests pin the actual output of all 4 routes. Routes are invoked directly via the
# FastAPI route table (matching the existing tests/test_wall_api.py convention),
# bypassing Query() validation the way that convention already does.
from __future__ import annotations

import json
import threading
from typing import Any

from fastapi import FastAPI

from api import insightAPI, insight_analytics, insight_snapshot, insight_stats


class FakeStats:
    def __init__(self, data: dict[str, Any]) -> None:
        self.data = data
        self.lock = threading.Lock()

    def overview(self, state: Any) -> dict[str, Any]:
        return {}


class FakeFiles:
    def __init__(self, state: dict[str, Any]) -> None:
        self._state = state

    def load_state(self) -> dict[str, Any]:
        return self._state


class FakeOrchestrator:
    def __init__(self, state: dict[str, Any]) -> None:
        self.files = FakeFiles(state)


class FakeTime:
    @staticmethod
    def time() -> float:
        return 100000.0


def _endpoint(app: FastAPI, path: str):
    return next(r.endpoint for r in app.routes if getattr(r, "path", "") == path)


def _install_env(monkeypatch, cw, cfg: dict[str, Any] | None = None, save_config=None) -> None:
    env = (cw, lambda: (cfg if cfg is not None else {}), save_config or (lambda _c: None), lambda *a, **k: None)
    for mod in (insight_stats, insight_snapshot, insight_analytics):
        monkeypatch.setattr(mod, "_env", lambda env=env: env)


# --- /api/stats/raw ---------------------------------------------------------------


def test_stats_raw_returns_stats_data_under_lock(monkeypatch):
    app = FastAPI()
    insightAPI.register_insights(app)

    class CW:
        STATS = FakeStats({"foo": "bar"})

    _install_env(monkeypatch, CW)
    resp = _endpoint(app, "/api/stats/raw")()
    assert json.loads(resp.body) == {"foo": "bar"}


def test_stats_raw_returns_empty_dict_when_stats_missing(monkeypatch):
    app = FastAPI()
    insightAPI.register_insights(app)

    class CW:
        pass

    _install_env(monkeypatch, CW)
    resp = _endpoint(app, "/api/stats/raw")()
    assert json.loads(resp.body) == {}


# --- /api/stats --------------------------------------------------------------------


def test_stats_overview_merges_now_count_when_missing(monkeypatch):
    app = FastAPI()
    insightAPI.register_insights(app)

    class StatsClass:
        @staticmethod
        def _build_union_map(state, feature):
            return {"a": 1, "b": 2}

    class CW:
        STATS = FakeStats({})
        Stats = StatsClass

        @staticmethod
        def _load_state():
            return {"providers": {}}

    _install_env(monkeypatch, CW)
    out = _endpoint(app, "/api/stats")()
    assert out == {"ok": True, "now": 2}


def test_stats_overview_keeps_its_own_now_when_present(monkeypatch):
    app = FastAPI()
    insightAPI.register_insights(app)

    class StatsWithNow(FakeStats):
        def overview(self, state):
            return {"now": 7}

    class CW:
        STATS = StatsWithNow({})

        @staticmethod
        def _load_state():
            return {"providers": {}}

    _install_env(monkeypatch, CW)
    out = _endpoint(app, "/api/stats")()
    assert out == {"ok": True, "now": 7}


# --- /api/crosswatch/select-snapshot -------------------------------------------------


def test_select_snapshot_success_writes_restore_key(monkeypatch):
    app = FastAPI()
    insightAPI.register_insights(app)
    saved: dict[str, Any] = {}

    class CW:
        pass

    _install_env(monkeypatch, CW, cfg={"crosswatch": {}}, save_config=saved.update)
    out = _endpoint(app, "/api/crosswatch/select-snapshot")(feature="history", snapshot="2026-01-01.json")
    assert out == {"ok": True, "feature": "history", "snapshot": "2026-01-01.json"}
    assert saved["crosswatch"]["restore_history"] == "2026-01-01.json"


def test_select_snapshot_save_failure_returns_ok_false(monkeypatch):
    app = FastAPI()
    insightAPI.register_insights(app)

    def _boom(cfg):
        raise RuntimeError("disk full")

    class CW:
        pass

    _install_env(monkeypatch, CW, save_config=_boom)
    out = _endpoint(app, "/api/crosswatch/select-snapshot")(feature="watchlist", snapshot="x")
    assert out == {"ok": False, "error": "save_config_failed"}


# --- /api/insights -------------------------------------------------------------------


def test_insights_with_no_stats_or_state_returns_safe_defaults(monkeypatch):
    app = FastAPI()
    insightAPI.register_insights(app)
    monkeypatch.setattr(insight_analytics, "time", FakeTime)

    class CW:
        STATS = None
        REPORT_DIR = None
        CACHE_DIR = None
        Stats = None

        @staticmethod
        def _load_wall_snapshot():
            return []

        @staticmethod
        def _get_orchestrator():
            return None

        @staticmethod
        def _append_log(*a, **k):
            pass

        @staticmethod
        def _load_state():
            return {}

    _install_env(monkeypatch, CW)
    resp = _endpoint(app, "/api/insights")(limit_samples=60, history=3, runtime=0)
    payload = json.loads(resp.body)

    assert payload["now"] == 0
    assert payload["week"] == 0
    assert payload["month"] == 0
    assert payload["added"] == 0
    assert payload["removed"] == 0
    assert payload["series"] == []
    assert payload["history"] == []
    assert payload["events"] == []
    assert payload["http"] == {}
    assert payload["generated_at"] is None
    assert payload["watchtime"] == {
        "movies": 0, "shows": 0, "minutes": 0, "hours": 0.0, "days": 0.0, "method": "estimate",
    }
    assert payload["providers_active"] == {k: False for k in payload["providers_active"]}
    for feat, counts in payload["providers_by_feature"].items():
        assert set(counts.values()) == {0}
    for feat, data in payload["features"].items():
        assert data["now"] == 0 and data["added"] == 0 and data["removed"] == 0 and data["updated"] == 0
    assert payload["features"]["history"]["breakdown"] == {
        "anime": 0, "episodes": 0, "movies": 0, "shows": 0,
    }
    # Backfilled 12-point hourly grid since fewer than 2 real samples exist.
    assert len(payload["series_by_feature"]["history"]) == 12
    assert payload["series_by_feature"]["watchlist"] == []
    assert payload["crosswatch_snapshots"]["history"] == {
        "selected": "latest", "actual": None, "human": None, "ts": None, "has_snapshots": False,
    }


def test_insights_with_history_event_and_state_computes_breakdown_and_lanes(monkeypatch):
    app = FastAPI()
    insightAPI.register_insights(app)
    monkeypatch.setattr(insight_analytics, "time", FakeTime)

    state = {
        "providers": {
            "plex": {
                "history": {
                    "baseline": {
                        "items": {
                            "tmdb:100#s1e1": {
                                "type": "episode",
                                "series_title": "Show A",
                                "season": 1,
                                "episode": 1,
                                "watched_at": "2026-01-01T00:00:00Z",
                                "ids": {"tmdb": "100"},
                            },
                            "tmdb:200": {
                                "type": "movie",
                                "title": "Movie B",
                                "year": 2020,
                                "watched_at": "2026-01-02T00:00:00Z",
                                "ids": {"tmdb": "200"},
                            },
                        }
                    }
                }
            }
        }
    }
    stats_data = {
        "samples": [{"ts": 1000, "count": 5}, {"ts": 2000, "count": 6}],
        "events": [
            {
                "key": "tmdb:100#s1e1",
                "type": "episode",
                "action": "history_add",
                "feature": "history",
                "ts": 1700000000,
                "season": 1,
                "episode": 1,
                "title": "",
                "series_title": "Show A",
            },
        ],
        "http": {"foo": "bar"},
        "generated_at": "2026-01-01T00:00:00Z",
    }
    wall = [
        {"type": "movie", "ids": {"tmdb": "200"}},
        {"type": "show", "ids": {"tmdb": "300"}},
    ]

    class CW:
        STATS = FakeStats(stats_data)
        REPORT_DIR = None
        CACHE_DIR = None
        Stats = FakeStats

        @staticmethod
        def _load_wall_snapshot():
            return wall

        @staticmethod
        def _get_orchestrator():
            return FakeOrchestrator(state)

        @staticmethod
        def _append_log(*a, **k):
            pass

        @staticmethod
        def _load_state():
            return state

    _install_env(monkeypatch, CW, cfg={"tmdb": {}, "crosswatch": {}})
    resp = _endpoint(app, "/api/insights")(limit_samples=60, history=3, runtime=0)
    payload = json.loads(resp.body)

    assert payload["generated_at"] == "2026-01-01T00:00:00Z"
    assert payload["http"] == {"foo": "bar"}
    assert payload["series"] == [{"ts": 1000, "count": 5}, {"ts": 2000, "count": 6}]
    assert payload["history"] == []
    assert payload["now"] == 0 and payload["week"] == 5 and payload["month"] == 5

    assert payload["events"] == [
        {
            "key": "tmdb:100#s1e1",
            "type": "episode",
            "action": "history_add",
            "feature": "history",
            "ts": 1700000000,
            "season": 1,
            "episode": 1,
            "title": "",
            "series_title": "Show A",
            "display_title": "Show A - S01E01",
        }
    ]

    # One TMDB-tagged movie and one show in the wall snapshot, no TMDB lookups
    # performed (runtime=0), so both fall back to the fixed estimate minutes.
    assert payload["watchtime"] == {
        "movies": 1, "shows": 1, "minutes": 160, "hours": 2.7, "days": 0.1, "method": "estimate",
    }

    history_feat = payload["features"]["history"]
    assert history_feat["breakdown"] == {"anime": 0, "episodes": 1, "movies": 1, "shows": 1}
    assert history_feat["now"] == 2 and history_feat["week"] == 2 and history_feat["month"] == 2
    assert history_feat["providers"]["plex"] == 2
    assert history_feat["providers_mse"]["plex"] == {"anime": 0, "episodes": 1, "movies": 1, "shows": 1}
    assert history_feat["providers_instances"]["plex"] == {"default": 2}
    assert history_feat["providers_instances_mse"]["plex"] == {
        "default": {"anime": 0, "episodes": 1, "movies": 1, "shows": 1}
    }

    for feat_name, feat_data in payload["features"].items():
        if feat_name == "history":
            continue
        assert feat_data["breakdown"] if "breakdown" in feat_data else True
        assert set(feat_data["providers"].values()) == {0}

    watchlist_feat = payload["features"]["watchlist"]
    assert watchlist_feat["now"] == 0 and watchlist_feat["week"] == 5 and watchlist_feat["month"] == 5
    assert watchlist_feat["series"] == [{"ts": 1000, "count": 5}, {"ts": 2000, "count": 6}]

    assert payload["providers_active"] == {k: False for k in payload["providers_active"]}
    assert payload["instances_by_provider"] == {k: ["default"] for k in payload["instances_by_provider"]}
