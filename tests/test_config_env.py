from __future__ import annotations

import pytest

from cw_platform.config_env import (
    apply_env_overrides,
    env_locked_paths,
    env_overrides,
    env_var_for_path,
)


def test_alias_resolves_to_path() -> None:
    got = env_overrides({"CW_OIDC_ISSUER": "https://auth.example.com/o/cw/"})
    assert got == {("app_auth", "oidc", "issuer"): "https://auth.example.com/o/cw/"}


def test_generic_form_resolves_to_path() -> None:
    got = env_overrides({"CW_CFG__plex__server_url": "http://plex:32400"})
    assert got == {("plex", "server_url"): "http://plex:32400"}


def test_generic_form_lowercases_parts() -> None:
    got = env_overrides({"CW_CFG__PLEX__SERVER_URL": "http://plex:32400"})
    assert ("plex", "server_url") in got


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("true", True),
        ("false", False),
        ("12", 12),
        ('["admins","ops"]', ["admins", "ops"]),
        ("https://auth.example.com/o/cw/", "https://auth.example.com/o/cw/"),
        ("admins,ops", "admins,ops"),
        ("", ""),
    ],
)
def test_value_parsing(raw: str, expected: object) -> None:
    got = env_overrides({"CW_CFG__a__b": raw})
    assert got[("a", "b")] == expected


def test_empty_value_is_an_override_not_an_absence() -> None:
    assert ("app_auth", "oidc", "issuer") in env_overrides({"CW_OIDC_ISSUER": ""})


def test_alias_wins_over_conflicting_generic() -> None:
    got = env_overrides(
        {
            "CW_OIDC_ISSUER": "https://alias.example.com/",
            "CW_CFG__app_auth__oidc__issuer": "https://generic.example.com/",
        }
    )
    assert got[("app_auth", "oidc", "issuer")] == "https://alias.example.com/"


@pytest.mark.parametrize("name", ["CW_CFG__", "CW_CFG____", "CW_CFG"])
def test_malformed_generic_names_are_ignored(name: str) -> None:
    assert env_overrides({name: "x"}) == {}


def test_unrelated_vars_are_ignored() -> None:
    assert env_overrides({"PATH": "/usr/bin", "CONFIG_BASE": "/config"}) == {}


def test_env_locked_paths_are_dotted_and_sorted() -> None:
    got = env_locked_paths({"CW_OIDC_ISSUER": "x", "CW_API_KEY": "y"})
    assert got == ["app_auth.oidc.issuer", "security.api_key"]


def test_env_var_for_path_prefers_alias() -> None:
    assert env_var_for_path("app_auth.oidc.client_secret") == "CW_OIDC_CLIENT_SECRET"
    assert env_var_for_path(("security", "api_key")) == "CW_API_KEY"


def test_env_var_for_path_falls_back_to_generic() -> None:
    assert env_var_for_path("plex.server_url") == "CW_CFG__plex__server_url"


def test_apply_writes_values_and_reports_paths() -> None:
    cfg: dict[str, object] = {"app_auth": {"oidc": {"issuer": "from-file"}}}
    applied = apply_env_overrides(cfg, {"CW_OIDC_ISSUER": "from-env"})
    assert applied == [("app_auth", "oidc", "issuer")]
    assert cfg["app_auth"]["oidc"]["issuer"] == "from-env"  # type: ignore[index]


def test_apply_creates_missing_intermediate_dicts() -> None:
    cfg: dict[str, object] = {}
    apply_env_overrides(cfg, {"CW_API_KEY": "machine-key"})
    assert cfg == {"security": {"api_key": "machine-key"}}


def test_apply_replaces_non_dict_intermediate() -> None:
    cfg: dict[str, object] = {"security": "not-a-dict"}
    apply_env_overrides(cfg, {"CW_API_KEY": "machine-key"})
    assert cfg == {"security": {"api_key": "machine-key"}}
