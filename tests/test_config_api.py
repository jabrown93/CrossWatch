from __future__ import annotations

import types

import pytest
from fastapi import HTTPException


def _stub_env(monkeypatch, cfg_api, load_cfg, save_cfg) -> None:
    monkeypatch.setattr(
        cfg_api,
        "_env",
        lambda: {
            "CW": None,
            "cfg_base": types.SimpleNamespace(),
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


def test_config_save_rejects_metadata_server_url(monkeypatch) -> None:
    from api import configAPI as cfg_api

    saved: dict = {}
    _stub_env(monkeypatch, cfg_api, lambda: {}, lambda cfg: saved.update(cfg))

    payload = {"plex": {"server_url": "http://169.254.169.254/latest/meta-data/"}}

    with pytest.raises(HTTPException) as exc_info:
        cfg_api.api_config_save(payload)

    assert exc_info.value.status_code == 400
    assert "plex.server_url" in str(exc_info.value.detail)
    assert not saved  # save() must never be reached for a rejected config


def test_config_save_rejects_metadata_server_url_in_instance(monkeypatch) -> None:
    from api import configAPI as cfg_api

    saved: dict = {}
    _stub_env(monkeypatch, cfg_api, lambda: {}, lambda cfg: saved.update(cfg))

    payload = {
        "jellyfin": {
            "server": "http://media.local:8096",
            "instances": {"evil": {"server": "http://169.254.169.254"}},
        }
    }

    with pytest.raises(HTTPException) as exc_info:
        cfg_api.api_config_save(payload)

    assert exc_info.value.status_code == 400
    assert "jellyfin.instances.evil.server" in str(exc_info.value.detail)
    assert not saved


def test_config_save_allows_lan_server_url(monkeypatch) -> None:
    from api import configAPI as cfg_api

    saved: dict = {}
    _stub_env(monkeypatch, cfg_api, lambda: {}, lambda cfg: saved.update(cfg))

    payload = {"plex": {"server_url": "http://192.168.1.50:32400"}}

    # Should not raise for a normal LAN server URL.
    cfg_api.api_config_save(payload)


def test_config_migrate_clears_pending_upgrade_marker(monkeypatch) -> None:
    from api import configAPI as cfg_api

    saved: dict = {}

    def load_cfg() -> dict:
      return {
          "version": "0.9.13",
          "ui": {
              "_pending_upgrade_from_version": "0.9.13",
              "_autogen": False,
          },
      }

    def save_cfg(cfg: dict) -> None:
        saved.clear()
        saved.update(cfg)

    monkeypatch.setattr(
        cfg_api,
        "_env",
        lambda: {
            "CW": None,
            "cfg_base": object(),
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

    res = cfg_api.api_config_migrate()

    assert res["ok"] is True
    assert "_pending_upgrade_from_version" not in (saved.get("ui") or {})
