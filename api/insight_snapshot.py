# /api/insight_snapshot.py
# CrossWatch - crosswatch snapshot-selection route, split out of insightAPI.py.
from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Query

from ._insight_env import _env


def register_insight_snapshot(app: FastAPI) -> None:
    @app.post("/api/crosswatch/select-snapshot", tags=["insight"])
    def api_select_snapshot(
        feature: str = Query(..., pattern="^(watchlist|history|ratings|progress)$"),
        snapshot: str = Query(...),
    ) -> dict[str, Any]:
        _, load_config, save_config, _ = _env()
        try:
            cfg = load_config() or {}
        except Exception:
            cfg = {}
        cw = (cfg.get("crosswatch") or cfg.get("CrossWatch") or {}) or {}
        key = f"restore_{feature}"
        cw[key] = snapshot
        cfg["crosswatch"] = cw

        try:
            save_config(cfg)
        except Exception:
            return {"ok": False, "error": "save_config_failed"}

        return {"ok": True, "feature": feature, "snapshot": snapshot}
