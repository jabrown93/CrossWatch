from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

OIDC_FIELDS = {
    "app_auth_oidc_enabled": "app_auth.oidc.enabled",
    "app_auth_oidc_issuer": "app_auth.oidc.issuer",
    "app_auth_oidc_client_id": "app_auth.oidc.client_id",
    "app_auth_oidc_client_secret": "app_auth.oidc.client_secret",
    "app_auth_oidc_public_base_url": "app_auth.oidc.public_base_url",
    "app_auth_oidc_groups_claim": "app_auth.oidc.groups_claim",
    "app_auth_oidc_allowed_groups": "app_auth.oidc.allowed_groups",
    "app_auth_oidc_session_hours": "app_auth.oidc.session_hours",
    "security_api_key": "security.api_key",
}


@pytest.fixture(scope="module")
def index_html() -> str:
    from ui_frontend import get_index_html

    return get_index_html()


@pytest.mark.parametrize(("elem_id", "cfg_path"), sorted(OIDC_FIELDS.items()))
def test_oidc_field_is_rendered_and_annotated(index_html: str, elem_id: str, cfg_path: str) -> None:
    match = re.search(rf'id="{re.escape(elem_id)}"[^>]*', index_html)
    assert match, f"{elem_id} is missing from the settings markup"
    assert f'data-cfg-path="{cfg_path}"' in match.group(0)


def test_oidc_secrets_are_password_inputs(index_html: str) -> None:
    for elem_id in ("app_auth_oidc_client_secret", "security_api_key"):
        match = re.search(rf'id="{re.escape(elem_id)}"[^>]*', index_html)
        assert match and 'type="password"' in match.group(0)


def test_empty_allowed_groups_denial_is_stated(index_html: str) -> None:
    """The one setting whose empty value denies rather than defaults."""
    assert "denies every OIDC login" in index_html


def test_save_treats_oidc_secrets_as_masked_fields() -> None:
    save_js = (ROOT / "assets" / "helpers" / "settings-save.js").read_text(encoding="utf-8")
    secret_ids = save_js.split("const _cwSecretIds = [", 1)[1].split("]", 1)[0]
    assert "app_auth_oidc_client_secret" in secret_ids
    assert "security_api_key" in secret_ids


def test_save_collects_every_oidc_field() -> None:
    save_js = (ROOT / "assets" / "helpers" / "settings-save.js").read_text(encoding="utf-8")
    for elem_id in OIDC_FIELDS:
        assert elem_id in save_js, f"{elem_id} is rendered but never collected on save"


def test_hydration_reads_every_oidc_field() -> None:
    ui_js = (ROOT / "assets" / "helpers" / "settings-ui.js").read_text(encoding="utf-8")
    for elem_id in OIDC_FIELDS:
        assert elem_id in ui_js, f"{elem_id} is rendered but never hydrated"
