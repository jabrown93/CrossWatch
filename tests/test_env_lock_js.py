"""Exercises assets/helpers/env-lock.js under node with a stub DOM.

The path resolution it does -- especially rewriting a provider path under the
selected instance -- has no other coverage, and a wrong result fails open: the
field looks editable and the save silently reverts.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "tests" / "data" / "env_lock_harness.js"
SOURCE = ROOT / "assets" / "helpers" / "env-lock.js"

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")


def _run(elements: list[dict], locked: list[str], instances: dict[str, str] | None = None) -> dict:
    spec = {
        "source": str(SOURCE),
        "elements": elements,
        "locked": locked,
        "instances": instances or {},
    }
    proc = subprocess.run(
        ["node", str(HARNESS), json.dumps(spec)],
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    )
    return {row["id"]: row for row in json.loads(proc.stdout)}


def _field(elem_id: str, path: str, instance_root: str | None = None) -> dict:
    attrs = {"data-cfg-path": path}
    if instance_root:
        attrs["data-cfg-instance-root"] = instance_root
    return {"id": elem_id, "attrs": attrs}


def test_locked_field_is_disabled_and_labelled() -> None:
    out = _run([_field("issuer", "app_auth.oidc.issuer")], ["app_auth.oidc.issuer"])
    assert out["issuer"]["disabled"] is True
    assert out["issuer"]["locked"] is True
    assert "CW_OIDC_ISSUER" in out["issuer"]["chip"]


def test_unlocked_field_is_left_alone() -> None:
    out = _run([_field("issuer", "app_auth.oidc.issuer")], ["security.api_key"])
    assert out["issuer"]["disabled"] is False
    assert out["issuer"]["chip"] is None


def test_generic_path_names_the_cw_cfg_variable() -> None:
    out = _run([_field("url", "plex.server_url")], ["plex.server_url"])
    assert "CW_CFG__plex__server_url" in out["url"]["chip"]


def test_default_instance_uses_the_bare_path() -> None:
    out = _run(
        [_field("url", "plex.server_url", "plex")],
        ["plex.server_url"],
        instances={"plex_instance": "default"},
    )
    assert out["url"]["disabled"] is True


def test_named_instance_resolves_under_instances() -> None:
    elements = [_field("url", "plex.server_url", "plex")]
    instances = {"plex_instance": "livingroom"}
    assert _run(elements, ["plex.instances.livingroom.server_url"], instances)["url"]["disabled"] is True
    # The default-instance path must not lock a named instance's field.
    assert _run(elements, ["plex.server_url"], instances)["url"]["disabled"] is False


def test_missing_instance_selector_falls_back_to_default() -> None:
    out = _run([_field("url", "plex.server_url", "plex")], ["plex.server_url"])
    assert out["url"]["disabled"] is True


def test_instance_root_that_does_not_prefix_the_path_is_ignored() -> None:
    out = _run(
        [_field("key", "security.api_key", "plex")],
        ["security.api_key"],
        instances={"plex_instance": "livingroom"},
    )
    assert out["key"]["disabled"] is True
