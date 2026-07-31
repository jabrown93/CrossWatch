from __future__ import annotations

import json
import types
from pathlib import Path
from types import SimpleNamespace

import pytest


def _stub_env(monkeypatch, cfg_api, load_cfg, save_cfg) -> None:
    from cw_platform import config_base

    monkeypatch.setattr(
        cfg_api,
        "_env",
        lambda: {
            "CW": None,
            "cfg_base": config_base,
            "load": load_cfg,
            "save": save_cfg,
            "prune": lambda *_: None,
            "ensure": lambda *_: None,
            "norm_pair": lambda *_: None,
            "probes_cache": None,
            "probes_status_cache": None,
            "scheduler": None,
        },
    )


def _stub_request():
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))


def test_get_config_reports_env_locked_paths(
    config_base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from api import configAPI as cfg_api
    from cw_platform.config_base import load_config, save_config

    monkeypatch.setenv("CW_OIDC_ISSUER", "https://from-env.example.com/")
    monkeypatch.setenv("CW_API_KEY", "machine-key")
    _stub_env(monkeypatch, cfg_api, load_config, save_config)

    body = json.loads(cfg_api.api_config().body)
    assert body["_env_locked"] == ["app_auth.oidc.issuer", "security.api_key"]


def test_get_config_omits_marker_content_when_no_env(
    config_base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from api import configAPI as cfg_api
    from cw_platform.config_base import load_config, save_config

    _stub_env(monkeypatch, cfg_api, load_config, save_config)
    assert json.loads(cfg_api.api_config().body)["_env_locked"] == []


def test_save_reports_and_discards_locked_change(
    config_base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from api import configAPI as cfg_api
    from cw_platform.config_base import load_config, save_config

    monkeypatch.setenv("CW_OIDC_ISSUER", "https://from-env.example.com/")
    _stub_env(monkeypatch, cfg_api, load_config, save_config)

    result = cfg_api.api_config_save(
        _stub_request(), {"app_auth": {"oidc": {"issuer": "https://from-ui.example.com/"}}}
    )
    assert result["env_locked_ignored"] == ["app_auth.oidc.issuer"]
    assert load_config()["app_auth"]["oidc"]["issuer"] == "https://from-env.example.com/"
    stored = json.loads((config_base / "config.json").read_text(encoding="utf-8"))
    assert "issuer" not in stored.get("app_auth", {}).get("oidc", {})


def test_save_keeps_unlocked_fields_from_same_payload(
    config_base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from api import configAPI as cfg_api
    from cw_platform.config_base import load_config, save_config

    monkeypatch.setenv("CW_OIDC_ISSUER", "https://from-env.example.com/")
    _stub_env(monkeypatch, cfg_api, load_config, save_config)

    result = cfg_api.api_config_save(
        _stub_request(),
        {
            "app_auth": {
                "oidc": {"issuer": "https://from-ui.example.com/", "client_id": "cw-ui"}
            }
        },
    )
    assert result["env_locked_ignored"] == ["app_auth.oidc.issuer"]
    assert load_config()["app_auth"]["oidc"]["client_id"] == "cw-ui"


def test_save_without_locked_change_reports_nothing(
    config_base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from api import configAPI as cfg_api
    from cw_platform.config_base import load_config, save_config

    monkeypatch.setenv("CW_OIDC_ISSUER", "https://from-env.example.com/")
    _stub_env(monkeypatch, cfg_api, load_config, save_config)

    result = cfg_api.api_config_save(_stub_request(), {"app_auth": {"oidc": {"client_id": "cw-ui"}}})
    assert "env_locked_ignored" not in result


def test_echoing_the_get_response_back_is_not_an_edit(
    config_base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A masked secret round-tripped by the UI must not read as a change."""
    from api import configAPI as cfg_api
    from cw_platform.config_base import load_config, save_config

    monkeypatch.setenv("CW_OIDC_CLIENT_SECRET", "env-secret")
    _stub_env(monkeypatch, cfg_api, load_config, save_config)

    body = json.loads(cfg_api.api_config().body)
    result = cfg_api.api_config_save(_stub_request(), body)
    assert "env_locked_ignored" not in result
