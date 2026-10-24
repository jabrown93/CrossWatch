# tests/test_insight_api.py
# Characterization coverage for api/insightAPI.py, which ships with none of its own.
# These tests pin the actual output of all 4 routes. Routes are invoked directly via the
# FastAPI route table (matching the existing tests/test_wall_api.py convention),
# bypassing Query() validation the way that convention already does.
from __future__ import annotations

import json
import threading
from typing import Any

from fastapi import FastAPI

from api import insightAPI


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


def _stub_request():
    """api_insights only touches request.cookies for profile scoping."""
    from types import SimpleNamespace

    return SimpleNamespace(cookies={}, headers={}, query_params={})


def _install_env(monkeypatch, cw, cfg: dict[str, Any] | None = None, save_config=None) -> None:
    env = (cw, lambda: (cfg if cfg is not None else {}), save_config or (lambda _c: None), lambda *a, **k: None)
    monkeypatch.setattr(insightAPI, "_env", lambda env=env: env)


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
    out = _endpoint(app, "/api/crosswatch/select-snapshot")(feature="history", snapshot="2026-01-01.json", provider_instance="default")
    assert {k: out.get(k) for k in ("ok", "feature", "snapshot")} == {"ok": True, "feature": "history", "snapshot": "2026-01-01.json"}
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


def test_insights_with_no_stats_or_state_returns_safe_defaults(monkeypatch, tmp_path):
    # Insights read sync runs from the local DB; keep other tests' runs out.
    monkeypatch.setenv("CROSSWATCH_DB", str(tmp_path / "crosswatch.sqlite3"))
    from cw_platform.local_db.db import close_conn

    close_conn()
    app = FastAPI()
    insightAPI.register_insights(app)
    monkeypatch.setattr(insightAPI, "time", FakeTime)

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
    resp = _endpoint(app, "/api/insights")(_stub_request(), limit_samples=60, history=3, runtime=0, include_events=1, user_profile="")
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
        "anime": 0, "episodes": 0, "movies": 0, "shows": 0, "seasons": 0,
    }
    # Backfilled 12-point hourly grid since fewer than 2 real samples exist.
    assert len(payload["series_by_feature"]["history"]) == 12
    assert payload["series_by_feature"]["watchlist"] == []
    snap = payload["crosswatch_snapshots"]["history"]
    assert {k: snap.get(k) for k in ("selected", "actual", "human", "ts", "has_snapshots")} == {
        "selected": "latest", "actual": None, "human": None, "ts": None, "has_snapshots": False,
    }
