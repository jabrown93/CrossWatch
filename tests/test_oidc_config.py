from __future__ import annotations


def _load(config_base):
    from cw_platform.config_base import load_config

    return load_config()


def test_oidc_defaults_present(config_base) -> None:
    cfg = _load(config_base)
    oidc = cfg["app_auth"]["oidc"]
    assert oidc["enabled"] is False
    assert oidc["issuer"] == ""
    assert oidc["client_id"] == ""
    assert oidc["client_secret"] == ""
    assert oidc["public_base_url"] == ""
    assert oidc["groups_claim"] == "groups"
    assert oidc["allowed_groups"] == []
    assert oidc["session_hours"] == 12


def test_oidc_normalization_clamps_and_cleans(config_base) -> None:
    import json

    (config_base / "config.json").write_text(
        json.dumps(
            {
                "app_auth": {
                    "oidc": {
                        "enabled": True,
                        "issuer": "  https://auth.example.com/application/o/cw/  ",
                        "public_base_url": "https://cw.example.com/",
                        "groups_claim": "",
                        "allowed_groups": "crosswatch-admins",
                        "session_hours": 9999,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    cfg = _load(config_base)
    oidc = cfg["app_auth"]["oidc"]
    # Trailing slash on the issuer is significant for Authentik: keep it.
    assert oidc["issuer"] == "https://auth.example.com/application/o/cw/"
    assert oidc["public_base_url"] == "https://cw.example.com"
    assert oidc["groups_claim"] == "groups"
    assert oidc["allowed_groups"] == ["crosswatch-admins"]
    assert oidc["session_hours"] == 168


def test_oidc_secret_and_api_key_redacted(config_base) -> None:
    from cw_platform.config_base import redact_config

    cfg = _load(config_base)
    cfg["app_auth"]["oidc"]["client_secret"] = "super-secret"
    cfg.setdefault("security", {})["api_key"] = "machine-key"
    red = redact_config(cfg)
    assert red["app_auth"]["oidc"]["client_secret"] != "super-secret"
    assert red["security"]["api_key"] != "machine-key"
