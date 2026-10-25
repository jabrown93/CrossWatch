from __future__ import annotations

import responses

from providers.auth import _auth_TRACEARR as tracearr


def test_validate_credentials_refuses_link_local_server() -> None:
    assert tracearr.validate_credentials("http://169.254.169.254", "key", timeout=1) == (False, "blocked_url")


@responses.activate
def test_validate_credentials_refuses_redirect_to_metadata_endpoint() -> None:
    responses.add(
        responses.GET,
        "http://192.168.1.10:3000/api/v2/public/users",
        status=302,
        headers={"Location": "http://169.254.169.254/latest/meta-data/"},
    )
    assert tracearr.validate_credentials("http://192.168.1.10:3000", "key", timeout=1) == (False, "blocked_url")
    assert len(responses.calls) == 1
