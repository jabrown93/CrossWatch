# cw_platform/config_env.py
# Environment-variable overrides for config paths.
# Deliberately free of config_base imports: config_base imports this module.
from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Any

GENERIC_PREFIX = "CW_CFG__"

# Short names for the settings a container deployment most often injects.
# Anything not listed here is still reachable through GENERIC_PREFIX.
ALIASES: dict[str, tuple[str, ...]] = {
    "CW_OIDC_ENABLED": ("app_auth", "oidc", "enabled"),
    "CW_OIDC_ISSUER": ("app_auth", "oidc", "issuer"),
    "CW_OIDC_CLIENT_ID": ("app_auth", "oidc", "client_id"),
    "CW_OIDC_CLIENT_SECRET": ("app_auth", "oidc", "client_secret"),
    "CW_OIDC_SCOPES": ("app_auth", "oidc", "scopes"),
    "CW_OIDC_GROUPS_CLAIM": ("app_auth", "oidc", "groups_claim"),
    "CW_OIDC_ALLOWED_GROUPS": ("app_auth", "oidc", "allowed_groups"),
    "CW_API_KEY": ("security", "api_key"),
}

_PATH_TO_ALIAS: dict[tuple[str, ...], str] = {path: name for name, path in ALIASES.items()}


def _log(msg: str, *, level: str = "INFO") -> None:
    try:
        from _logging import log as _real_log

        _real_log(msg, level=level, module="CONFIG")
    except Exception:
        print(f"[CONFIG] {level}: {msg}")


def _parse_value(raw: str) -> Any:
    """JSON first so bools, numbers, and lists survive; bare strings fall through.

    Most values (URLs, client ids, claim names) are not valid JSON, so the
    fallback is the common case rather than an error path.
    """
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return raw


def _generic_path(name: str) -> tuple[str, ...] | None:
    rest = name[len(GENERIC_PREFIX):]
    parts = tuple(p.lower() for p in rest.split("__") if p)
    return parts or None


def env_overrides(environ: Mapping[str, str] | None = None) -> dict[tuple[str, ...], Any]:
    """Config paths the environment owns, mapped to their parsed values.

    An empty variable is an override to the empty value, not an absence -- unset
    the variable to hand the field back to config.json.
    """
    src = os.environ if environ is None else environ
    out: dict[tuple[str, ...], Any] = {}
    generic_names: dict[tuple[str, ...], str] = {}

    for name, raw in src.items():
        if not name.startswith(GENERIC_PREFIX):
            continue
        path = _generic_path(name)
        if path is None:
            continue
        out[path] = _parse_value(raw)
        generic_names[path] = name

    for name, path in ALIASES.items():
        raw = src.get(name)
        if raw is None:
            continue
        if path in generic_names:
            _log(
                f"{name} and {generic_names[path]} both set {'.'.join(path)}; using {name}",
                level="WARNING",
            )
        out[path] = _parse_value(raw)

    return out


def env_locked_paths(environ: Mapping[str, str] | None = None) -> list[str]:
    """Dotted paths the environment owns, for the UI lock and the API response."""
    return sorted(".".join(path) for path in env_overrides(environ))


def env_var_for_path(path: tuple[str, ...] | str) -> str:
    """The variable name that owns a path, for user-facing messages."""
    parts = tuple(path.split(".")) if isinstance(path, str) else tuple(path)
    alias = _PATH_TO_ALIAS.get(parts)
    return alias if alias else GENERIC_PREFIX + "__".join(parts)


def _set_path(cfg: dict[str, Any], path: tuple[str, ...], value: Any) -> bool:
    cur: Any = cfg
    for part in path[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    if not isinstance(cur, dict):
        return False
    cur[path[-1]] = value
    return True


def apply_env_overrides(
    cfg: dict[str, Any],
    environ: Mapping[str, str] | None = None,
) -> list[tuple[str, ...]]:
    """Write env-owned values into cfg in place; returns the paths applied.

    Called before the normalizers so env values get the same clamping and
    coercion as file values.
    """
    applied: list[tuple[str, ...]] = []
    for path, value in env_overrides(environ).items():
        if _set_path(cfg, path, value):
            applied.append(path)
    return applied
