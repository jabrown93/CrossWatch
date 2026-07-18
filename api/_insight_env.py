# /api/_insight_env.py
# CrossWatch - shared runtime lookup for the insight API routes, split out of
# insightAPI.py so insight_stats.py/insight_snapshot.py/insight_analytics.py can all
# import it without a circular dependency on insightAPI.py itself.
from __future__ import annotations

from typing import Any, Callable


def _env() -> tuple[
    Any | None,
    Callable[[], dict[str, Any]],
    Callable[[dict[str, Any]], None],
    Callable[..., Any],
]:
    try:
        import crosswatch as CW
        from cw_platform.config_base import load_config as _load_cfg, save_config as _save_cfg
        from .metaAPI import get_runtime as _get_runtime
        return CW, _load_cfg, _save_cfg, _get_runtime
    except Exception:
        return None, (lambda: {}), (lambda _cfg: None), (lambda *a, **k: None)
