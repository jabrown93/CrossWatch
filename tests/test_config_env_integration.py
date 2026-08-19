from __future__ import annotations

import json
from pathlib import Path

import pytest


def _write_cfg(config_base: Path, payload: dict) -> None:
    (config_base / "config.json").write_text(json.dumps(payload), encoding="utf-8")


def _raw_cfg(config_base: Path) -> dict:
    return json.loads((config_base / "config.json").read_text(encoding="utf-8"))


def test_env_beats_config_file(config_base: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cw_platform.config_base import load_config

    _write_cfg(config_base, {"app_auth": {"oidc": {"issuer": "https://from-file.example.com/"}}})
    monkeypatch.setenv("CW_OIDC_ISSUER", "https://from-env.example.com/")
    assert load_config()["app_auth"]["oidc"]["issuer"] == "https://from-env.example.com"


def test_env_values_are_still_normalized(config_base: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cw_platform.config_base import load_config

    monkeypatch.setenv("CW_OIDC_ISSUER", "  https://auth.example.com/o/cw/  ")
    monkeypatch.setenv("CW_OIDC_SCOPES", "profile email")
    monkeypatch.setenv("CW_OIDC_GROUPS_CLAIM", "")
    oidc = load_config()["app_auth"]["oidc"]
    # Issuer comparisons are slash-normalized everywhere, so the stored value is stripped.
    assert oidc["issuer"] == "https://auth.example.com/o/cw"
    assert oidc["scopes"].startswith("openid ")
    assert oidc["groups_claim"] == "groups"


def test_env_bool_and_int_parsing(config_base: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cw_platform.config_base import load_config

    monkeypatch.setenv("CW_OIDC_ENABLED", "true")
    monkeypatch.setenv("CW_OIDC_ISSUER", "https://auth.example.com/o/cw/")
    monkeypatch.setenv("CW_OIDC_CLIENT_ID", "crosswatch")
    oidc = load_config()["app_auth"]["oidc"]
    # enabled only sticks when issuer and client_id are present.
    assert oidc["enabled"] is True


@pytest.mark.parametrize("raw", ["admins,ops", '["admins","ops"]', "admins, ops"])
def test_allowed_groups_accepts_csv_and_json(
    config_base: Path, monkeypatch: pytest.MonkeyPatch, raw: str
) -> None:
    from cw_platform.config_base import load_config

    monkeypatch.setenv("CW_OIDC_ALLOWED_GROUPS", raw)
    assert load_config()["app_auth"]["oidc"]["allowed_groups"] == ["admins", "ops"]


def test_generic_override_reaches_any_path(config_base: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cw_platform.config_base import load_config

    monkeypatch.setenv("CW_CFG__plex__server_url", "http://plex.internal:32400")
    assert load_config()["plex"]["server_url"] == "http://plex.internal:32400"


def test_api_key_creates_missing_section(config_base: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cw_platform.config_base import load_config

    monkeypatch.setenv("CW_API_KEY", "machine-key")
    assert load_config()["security"]["api_key"] == "machine-key"


def test_save_leaves_env_path_untouched_on_disk(
    config_base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cw_platform.config_base import load_config, save_config

    _write_cfg(config_base, {"app_auth": {"oidc": {"issuer": "https://from-file.example.com/"}}})
    monkeypatch.setenv("CW_OIDC_ISSUER", "https://from-env.example.com/")
    save_config(load_config())
    assert _raw_cfg(config_base)["app_auth"]["oidc"]["issuer"] == "https://from-file.example.com/"


def test_save_omits_env_path_absent_from_disk(
    config_base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cw_platform.config_base import load_config, save_config

    monkeypatch.setenv("CW_API_KEY", "machine-key")
    save_config(load_config())
    assert "api_key" not in _raw_cfg(config_base).get("security", {})


def test_save_never_persists_env_secret(config_base: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from cw_platform.config_base import load_config, save_config

    monkeypatch.setenv("CW_OIDC_CLIENT_SECRET", "super-secret")
    save_config(load_config())
    assert "super-secret" not in (config_base / "config.json").read_text(encoding="utf-8")
    assert "client_secret" not in _raw_cfg(config_base).get("app_auth", {}).get("oidc", {})


def test_encrypted_file_secret_survives_save_under_env_lock(
    config_base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cw_platform.config_base import load_config, save_config

    _write_cfg(config_base, {"app_auth": {"oidc": {"client_secret": "file-secret"}}})
    save_config(load_config())
    stored = _raw_cfg(config_base)["app_auth"]["oidc"]["client_secret"]

    monkeypatch.setenv("CW_OIDC_CLIENT_SECRET", "env-secret")
    save_config(load_config())
    after = _raw_cfg(config_base)["app_auth"]["oidc"]["client_secret"]
    assert after == stored
    assert "env-secret" not in (config_base / "config.json").read_text(encoding="utf-8")


def test_unsetting_env_restores_file_value(
    config_base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from cw_platform.config_base import load_config, save_config

    _write_cfg(config_base, {"app_auth": {"oidc": {"issuer": "https://from-file.example.com/"}}})
    monkeypatch.setenv("CW_OIDC_ISSUER", "https://from-env.example.com/")
    save_config(load_config())

    monkeypatch.delenv("CW_OIDC_ISSUER")
    assert load_config()["app_auth"]["oidc"]["issuer"] == "https://from-file.example.com"


def test_save_does_not_mutate_callers_config(
    config_base: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The revert must not reach back into the dict the caller still holds."""
    from cw_platform.config_base import load_config, save_config

    monkeypatch.setenv("CW_OIDC_ISSUER", "https://from-env.example.com/")
    cfg = load_config()
    save_config(cfg)
    assert cfg["app_auth"]["oidc"]["issuer"] == "https://from-env.example.com"


def test_save_strips_env_locked_marker(config_base: Path) -> None:
    from cw_platform.config_base import load_config, save_config

    cfg = load_config()
    cfg["_env_locked"] = ["app_auth.oidc.issuer"]
    save_config(cfg)
    assert "_env_locked" not in _raw_cfg(config_base)
