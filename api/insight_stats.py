# /api/insight_stats.py
# CrossWatch - lightweight stats snapshot routes, split out of insightAPI.py.
from __future__ import annotations

import json
from contextlib import nullcontext
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse

from ._insight_env import _env


def register_insight_stats(app: FastAPI) -> None:
    @app.get("/api/stats/raw", tags=["insight"])
    def api_stats_raw() -> JSONResponse:
        CW, _, _, _ = _env()
        STATS = getattr(CW, "STATS", None)
        if STATS is None:
            return JSONResponse({})
        lock = getattr(STATS, "lock", None) or nullcontext()
        try:
            with lock:
                return JSONResponse(json.loads(json.dumps(STATS.data)))
        except Exception:
            return JSONResponse({})

    @app.get("/api/stats", tags=["insight"])
    def api_stats() -> dict[str, Any]:
        CW, _, _, _ = _env()
        STATS = getattr(CW, "STATS", None)
        _load_state = getattr(CW, "_load_state", lambda: None)
        StatsClass = getattr(CW, "Stats", None)

        try:
            state = _load_state()
        except Exception:
            state = None

        base: dict[str, Any] = {}
        try:
            if STATS and hasattr(STATS, "overview"):
                base = STATS.overview(state) or {}
        except Exception:
            base = {}

        try:
            if (not base.get("now")) and state and StatsClass and hasattr(StatsClass, "_build_union_map"):
                base["now"] = len(StatsClass._build_union_map(state, "watchlist"))
        except Exception:
            pass

        return {"ok": True, **base}
