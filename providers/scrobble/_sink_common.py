# providers/scrobble/_sink_common.py
# CrossWatch - shared helpers for scrobble sinks (Trakt, SIMKL, MDBList)
# Copyright (c) 2025-2026 CrossWatch / Cenodude (https://github.com/cenodude/CrossWatch)
from __future__ import annotations

from collections.abc import Mapping
import json
import time
from pathlib import Path
from typing import Any

from cw_platform.config_base import load_config
from cw_platform.provider_instances import normalize_instance_id

# Shared by _app_meta / _ar_seen below; individual sinks keep their own
# copies of these constants for use in code paths that were not moved here.
APP_AGENT = "CrossWatch/Watcher/1.0"
_AR_TTL = 60


def _cfg() -> dict[str, Any]:
    try:
        return load_config()
    except Exception:
        return {}


def _is_debug() -> bool:
    try:
        return bool((_cfg().get("runtime") or {}).get("debug"))
    except Exception:
        return False


def _merged_provider_block(cfg: Mapping[str, Any], key: str, instance_id: Any = None) -> dict[str, Any]:
    base = cfg.get(key) if isinstance(cfg, Mapping) else None
    blk = dict(base or {}) if isinstance(base, Mapping) else {}
    inst = normalize_instance_id(instance_id)
    if inst != "default":
        insts = blk.get("instances")
        if isinstance(insts, Mapping) and isinstance(insts.get(inst), Mapping):
            overlay = dict(insts.get(inst) or {})
            blk.pop("instances", None)
            out = dict(blk)
            out.update(overlay)
            return out
    blk.pop("instances", None)
    return blk


def _norm_type(t: str) -> str:
    s = (t or "").strip().lower()
    if s.endswith("s"):
        s = s[:-1]
    if s == "series":
        s = "show"
    return s


def _cfg_delete_enabled(cfg: dict[str, Any], media_type: str) -> bool:
    s = cfg.get("scrobble") or {}
    watch = s.get("watch") or {}
    route_opts_raw = watch.get("route_options")
    route_opts: dict[str, Any] = route_opts_raw if isinstance(route_opts_raw, dict) else {}
    route_mode = str(route_opts.get("auto_remove_watchlist") or "inherit").strip().lower()
    if route_mode == "off":
        return False
    if not s.get("delete_plex"):
        if route_mode != "on":
            return False
    types = s.get("delete_plex_types") or []
    mt = _norm_type(media_type)
    if isinstance(types, str):
        return _norm_type(types) == mt
    try:
        allowed = {_norm_type(x) for x in types if str(x).strip()}
    except Exception:
        return False
    return mt in allowed


def _extract_skeleton_from_body(b: dict[str, Any]) -> dict[str, Any]:
    out = dict(b)
    out.pop("progress", None)
    out.pop("app_version", None)
    out.pop("app_date", None)
    return out


def _clamp(p: Any) -> int:
    try:
        v = int(float(p))
    except Exception:
        v = 0
    return max(0, min(100, v))


def _app_meta(cfg: dict[str, Any]) -> dict[str, str]:
    rt = cfg.get("runtime") or {}
    av = str(rt.get("version") or APP_AGENT)
    ad = (rt.get("build_date") or "").strip()
    return {"app_version": av, **({"app_date": ad} if ad else {})}


def _ar_state_file() -> Path:
    base = Path("/config/.cw_state") if Path("/config/config.json").exists() else Path(".cw_state")
    try:
        base.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return base / "auto_remove_seen.json"


def _ar_seen(key: str) -> bool:
    p = _ar_state_file()
    try:
        data = json.loads(p.read_text(encoding="utf-8")) or {}
    except Exception:
        data = {}
    now = time.time()
    try:
        data = {k: v for k, v in data.items() if (now - float(v)) < _AR_TTL}
    except Exception:
        data = {}
    if key in data:
        try:
            p.write_text(json.dumps(data), encoding="utf-8")
        except Exception:
            pass
        return True
    data[key] = now
    try:
        p.write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass
    return False
