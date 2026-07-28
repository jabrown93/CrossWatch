from __future__ import annotations

import json
import time
from urllib.parse import parse_qs, urlsplit

import pytest
import responses
from authlib.jose import JsonWebKey, jwt as jose_jwt

ISSUER = "https://idp.test/application/o/crosswatch/"
DISCOVERY_URL = ISSUER + ".well-known/openid-configuration"
JWKS_URL = "https://idp.test/jwks"
TOKEN_URL = "https://idp.test/token"
AUTHZ_URL = "https://idp.test/authorize"

_KEY = JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "test-key"})


def _svc():
    from services import authOIDC

    return authOIDC


@pytest.fixture(autouse=True)
def _clear_caches():
    svc = _svc()
    svc._PENDING_FLOWS.clear()
    svc._DISCOVERY_CACHE.clear()
    svc._JWKS_CACHE.clear()
    yield


def _cfg() -> dict:
    return {
        "app_auth": {
            "oidc": {
                "enabled": True,
                "issuer": ISSUER,
                "client_id": "cw-client",
                "client_secret": "cw-secret",
                "public_base_url": "https://cw.test",
                "groups_claim": "groups",
                "allowed_groups": ["crosswatch"],
                "session_hours": 12,
            }
        }
    }


def _mock_discovery() -> None:
    responses.add(
        responses.GET,
        DISCOVERY_URL,
        json={
            "issuer": ISSUER,
            "authorization_endpoint": AUTHZ_URL,
            "token_endpoint": TOKEN_URL,
            "jwks_uri": JWKS_URL,
        },
    )


def _mock_jwks() -> None:
    responses.add(responses.GET, JWKS_URL, json={"keys": [_KEY.as_dict(is_private=False)]})


def _id_token(*, nonce: str, groups: list[str] | None = None, aud: str = "cw-client", iss: str = ISSUER) -> str:
    now = int(time.time())
    claims = {
        "iss": iss,
        "aud": aud,
        "sub": "user-1",
        "exp": now + 300,
        "iat": now,
        "nonce": nonce,
        "preferred_username": "jared",
        "email": "jared@example.com",
        "groups": ["crosswatch"] if groups is None else groups,
    }
    return jose_jwt.encode({"alg": "RS256", "kid": "test-key"}, claims, _KEY).decode("ascii")


def _mock_token_endpoint(id_token: str) -> None:
    responses.add(responses.POST, TOKEN_URL, json={"access_token": "at", "id_token": id_token, "token_type": "Bearer"})


def test_login_available_requires_all_fields() -> None:
    svc = _svc()
    cfg = _cfg()
    assert svc.login_available(cfg) is True
    cfg["app_auth"]["oidc"]["client_secret"] = ""
    assert svc.login_available(cfg) is False
    cfg = _cfg()
    cfg["app_auth"]["oidc"]["enabled"] = False
    assert svc.login_available(cfg) is False


def test_redirect_uri_built_from_public_base_url() -> None:
    assert _svc().redirect_uri(_cfg()) == "https://cw.test/api/app-auth/oidc/callback"


@responses.activate
def test_start_flow_builds_pkce_authorize_url() -> None:
    svc = _svc()
    _mock_discovery()
    data = svc.start_flow(_cfg(), next_path="/watchlist", flow_nonce_hash=svc._sha256_hex("cookie-nonce"))
    assert data["ok"] is True
    parts = urlsplit(data["auth_url"])
    q = parse_qs(parts.query)
    assert f"{parts.scheme}://{parts.netloc}{parts.path}" == AUTHZ_URL
    assert q["response_type"] == ["code"]
    assert q["client_id"] == ["cw-client"]
    assert q["redirect_uri"] == ["https://cw.test/api/app-auth/oidc/callback"]
    assert q["code_challenge_method"] == ["S256"]
    assert q["scope"] == ["openid profile email"]
    state = q["state"][0]
    assert data["state"] == state
    rec = svc._PENDING_FLOWS[state]
    assert rec["next"] == "/watchlist"
    assert rec["nonce"] == q["nonce"][0]


@responses.activate
def test_complete_flow_happy_path() -> None:
    svc = _svc()
    _mock_discovery()
    _mock_jwks()
    cfg = _cfg()
    data = svc.start_flow(cfg, next_path="/", flow_nonce_hash=svc._sha256_hex("cookie-nonce"))
    state = data["state"]
    nonce = svc._PENDING_FLOWS[state]["nonce"]
    _mock_token_endpoint(_id_token(nonce=nonce))

    res = svc.complete_flow(cfg, state=state, code="authcode")
    assert res["ok"] is True
    assert res["identity"]["sub"] == "user-1"
    assert res["identity"]["username"] == "jared"
    assert res["flow_nonce_hash"] == svc._sha256_hex("cookie-nonce")
    assert res["next"] == "/"
    assert state not in svc._PENDING_FLOWS

    token_req = [c for c in responses.calls if c.request.url == TOKEN_URL][0].request
    body = parse_qs(token_req.body)
    assert body["grant_type"] == ["authorization_code"]
    assert body["code"] == ["authcode"]
    assert body["code_verifier"][0]
    assert "Basic " in token_req.headers.get("Authorization", "")


@responses.activate
def test_complete_flow_rejects_wrong_group() -> None:
    svc = _svc()
    _mock_discovery()
    _mock_jwks()
    cfg = _cfg()
    data = svc.start_flow(cfg, next_path="/", flow_nonce_hash=svc._sha256_hex("n"))
    nonce = svc._PENDING_FLOWS[data["state"]]["nonce"]
    _mock_token_endpoint(_id_token(nonce=nonce, groups=["other-team"]))

    res = svc.complete_flow(cfg, state=data["state"], code="authcode")
    assert res["ok"] is False
    assert res["code"] == "denied"


@responses.activate
def test_complete_flow_rejects_empty_allowlist() -> None:
    svc = _svc()
    _mock_discovery()
    _mock_jwks()
    cfg = _cfg()
    cfg["app_auth"]["oidc"]["allowed_groups"] = []
    data = svc.start_flow(cfg, next_path="/", flow_nonce_hash=svc._sha256_hex("n"))
    nonce = svc._PENDING_FLOWS[data["state"]]["nonce"]
    _mock_token_endpoint(_id_token(nonce=nonce))

    res = svc.complete_flow(cfg, state=data["state"], code="authcode")
    assert res["ok"] is False
    assert res["code"] == "denied"


@responses.activate
def test_complete_flow_rejects_bad_nonce() -> None:
    svc = _svc()
    _mock_discovery()
    _mock_jwks()
    cfg = _cfg()
    data = svc.start_flow(cfg, next_path="/", flow_nonce_hash=svc._sha256_hex("n"))
    _mock_token_endpoint(_id_token(nonce="wrong-nonce"))

    res = svc.complete_flow(cfg, state=data["state"], code="authcode")
    assert res["ok"] is False
    assert res["code"] == "failed"


@responses.activate
def test_complete_flow_rejects_wrong_audience() -> None:
    svc = _svc()
    _mock_discovery()
    _mock_jwks()
    cfg = _cfg()
    data = svc.start_flow(cfg, next_path="/", flow_nonce_hash=svc._sha256_hex("n"))
    nonce = svc._PENDING_FLOWS[data["state"]]["nonce"]
    _mock_token_endpoint(_id_token(nonce=nonce, aud="other-client"))

    res = svc.complete_flow(cfg, state=data["state"], code="authcode")
    assert res["ok"] is False
    assert res["code"] == "failed"


@responses.activate
def test_complete_flow_rejects_unknown_state() -> None:
    svc = _svc()
    res = svc.complete_flow(_cfg(), state="nope", code="authcode")
    assert res["ok"] is False
    assert res["code"] == "failed"


@responses.activate
def test_issuer_reachable_true_and_false() -> None:
    svc = _svc()
    _mock_discovery()
    assert svc.issuer_reachable(_cfg()) is True
    svc._DISCOVERY_CACHE.clear()
    responses.reset()
    responses.add(responses.GET, DISCOVERY_URL, status=502)
    assert svc.issuer_reachable(_cfg()) is False


@responses.activate
def test_complete_flow_retries_jwks_on_key_rotation() -> None:
    """Test that JWKS key rotation is handled: first fetch has unknown key, retry succeeds."""
    svc = _svc()
    _mock_discovery()
    cfg = _cfg()
    data = svc.start_flow(cfg, next_path="/", flow_nonce_hash=svc._sha256_hex("n"))
    state = data["state"]
    nonce = svc._PENDING_FLOWS[state]["nonce"]

    # First JWKS response: key with different kid (not the one we need)
    other_key = JsonWebKey.generate_key("RSA", 2048, is_private=True, options={"kid": "other-key"})
    # Second JWKS response: correct key that signed the token
    responses.add(responses.GET, JWKS_URL, json={"keys": [other_key.as_dict(is_private=False)]})
    responses.add(responses.GET, JWKS_URL, json={"keys": [_KEY.as_dict(is_private=False)]})

    _mock_token_endpoint(_id_token(nonce=nonce))

    res = svc.complete_flow(cfg, state=state, code="authcode")
    assert res["ok"] is True
    assert res["identity"]["sub"] == "user-1"

    # Verify JWKS was fetched twice (once with cache miss, once with force refresh)
    jwks_calls = [c for c in responses.calls if c.request.url == JWKS_URL]
    assert len(jwks_calls) == 2


@responses.activate
def test_complete_flow_does_not_retry_jwks_for_expired_token() -> None:
    """Test that expired tokens fail WITHOUT triggering a JWKS force-refresh."""
    svc = _svc()
    _mock_discovery()
    _mock_jwks()
    cfg = _cfg()
    data = svc.start_flow(cfg, next_path="/", flow_nonce_hash=svc._sha256_hex("n"))
    state = data["state"]
    nonce = svc._PENDING_FLOWS[state]["nonce"]

    # Token that is already expired
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": "cw-client",
        "sub": "user-1",
        "exp": now - 300,  # Expired 5 minutes ago
        "iat": now - 600,
        "nonce": nonce,
        "preferred_username": "jared",
        "email": "jared@example.com",
        "groups": ["crosswatch"],
    }
    expired_token = jose_jwt.encode({"alg": "RS256", "kid": "test-key"}, claims, _KEY).decode("ascii")
    _mock_token_endpoint(expired_token)

    res = svc.complete_flow(cfg, state=state, code="authcode")
    assert res["ok"] is False
    assert res["code"] == "failed"

    # Verify JWKS was fetched ONLY ONCE (no retry for validation errors)
    jwks_calls = [c for c in responses.calls if c.request.url == JWKS_URL]
    assert len(jwks_calls) == 1
