# /api/insightAPI.py
# CrossWatch - Insights API for multiple services
# Copyright (c) 2025-2026 CrossWatch / Cenodude (https://github.com/cenodude/CrossWatch)
#
# Route bodies live in insight_stats.py (/api/stats, /api/stats/raw),
# insight_snapshot.py (/api/crosswatch/select-snapshot), and insight_analytics.py
# (/api/insights, the bulk of the original file). This module only wires them together
# so `register_insights` keeps its existing import path (see api/__init__.py).
from __future__ import annotations

from fastapi import FastAPI

from .insight_analytics import register_insight_analytics
from .insight_snapshot import register_insight_snapshot
from .insight_stats import register_insight_stats


def register_insights(app: FastAPI) -> None:
    register_insight_stats(app)
    register_insight_snapshot(app)
    register_insight_analytics(app)
