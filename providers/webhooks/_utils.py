from __future__ import annotations

"""Shared utilities for CrossWatch webhook handlers."""

import hmac
from typing import Any, Mapping

import requests

from cw_platform.config_base import load_config, save_config
from providers.scrobble._auto_remove_watchlist import remove_across_providers_by_ids as _rm_across

try:
    from api.watchlistAPI import remove_across_providers_by_ids as _rm_across_api
except Exception:
    _rm_across_api = None

_TRAKT_API = "https://api.trakt.tv"


def verify_webhook_secret(headers: Mapping[str, str], secret: str) -> bool:
    """Check X-CW-Webhook-Secret header against configured secret."""
    if not secret:
        return True
    header_val = headers.get("X-CW-Webhook-Secret") or headers.get("x-cw-webhook-secret") or ""
    if not header_val:
        return False
    return hmac.compare_digest(header_val, secret)


def _load_config() -> dict[str, Any]:
    try:
        return load_config()
    except Exception:
        return {}


def _save_config(cfg: dict[str, Any]) -> None:
    try:
        save_config(cfg)
    except Exception:
        pass


def _is_debug() -> bool:
    try:
        rt = (_load_config().get("runtime") or {})
        return bool(rt.get("debug") or rt.get("debug_mods"))
    except Exception:
        return False


def _tokens(cfg: dict[str, Any]) -> dict[str, str]:
    tr = cfg.get("trakt") or {}
    au = ((cfg.get("auth") or {}).get("trakt") or {})
    return {
        "client_id": (tr.get("client_id") or "").strip(),
        "client_secret": (tr.get("client_secret") or "").strip(),
        "access_token": (au.get("access_token") or tr.get("access_token") or "").strip(),
        "refresh_token": (au.get("refresh_token") or tr.get("refresh_token") or "").strip(),
    }


def _app_meta(cfg: dict[str, Any]) -> dict[str, str]:
    rt = (cfg.get("runtime") or {})
    av = str(rt.get("version") or "CrossWatch/Scrobble")
    ad = (rt.get("build_date") or "").strip()
    meta: dict[str, str] = {"app_version": av}
    if ad:
        meta["app_date"] = ad
    return meta


def _headers(cfg: dict[str, Any]) -> dict[str, str]:
    t = _tokens(cfg)
    h = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "trakt-api-version": "2",
        "trakt-api-key": t["client_id"],
        "User-Agent": "CrossWatch/Scrobble",
    }
    if t["access_token"]:
        h["Authorization"] = f"Bearer {t['access_token']}"
    return h


def _del_trakt(path: str, cfg: dict[str, Any]) -> requests.Response:
    url = f"{_TRAKT_API}{path}"
    r = requests.delete(url, headers=_headers(cfg), timeout=12)
    if r.status_code == 401:
        try:
            from providers.auth._auth_TRAKT import PROVIDER as TRAKT_AUTH

            TRAKT_AUTH.refresh(cfg)
            _save_config(cfg)
        except Exception:
            return r
        try:
            r = requests.delete(url, headers=_headers(cfg), timeout=12)
        except Exception:
            pass
    return r


def _cache_get(cache: dict[tuple[Any, ...], Any], key: tuple[Any, ...]) -> Any | None:
    """Look up `key` in a per-module Trakt ID cache dict passed in by the caller."""
    try:
        return cache.get(key)
    except Exception:
        return None


def _cache_put(cache: dict[tuple[Any, ...], Any], key: tuple[Any, ...], value: Any) -> None:
    """Store `key`/`value` in a per-module Trakt ID cache dict passed in by the caller."""
    try:
        if len(cache) > 2048:
            cache.clear()
        cache[key] = value
    except Exception:
        pass


def _best_id_key_order(media_type: str) -> tuple[str, ...]:
    return ("tmdb", "imdb", "tvdb") if media_type == "movie" else ("tmdb", "imdb", "tvdb")


def _call_remove_across(ids: dict[str, Any], media_type: str) -> None:
    if not isinstance(ids, dict) or not ids:
        return
    try:
        cfg = _load_config()
        s = (cfg.get("scrobble") or {})
        if not s.get("delete_plex"):
            return
        tps = s.get("delete_plex_types") or []
        mt = (media_type or "").strip().lower()
        allow = False
        if isinstance(tps, list):
            allow = (mt in tps) or ((mt.rstrip("s") + "s") in tps)
        elif isinstance(tps, str):
            allow = mt in tps
        if not allow:
            return
    except Exception:
        pass
    try:
        if callable(_rm_across):
            _rm_across(ids, media_type)
            return
    except Exception:
        pass
    try:
        if callable(_rm_across_api):
            _rm_across_api(ids, media_type)  # type: ignore[arg-type]
            return
    except Exception:
        pass
