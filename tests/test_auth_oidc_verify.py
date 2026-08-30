from __future__ import annotations

import base64
import json
import time

import pytest
from authlib.jose import JsonWebKey, JsonWebToken

from services import authOidc

ISSUER = "https://idp.example"
CLIENT_ID = "client-abc"
JWKS_URI = "https://idp.example/jwks"
NONCE = "nonce-1"

_KEY = JsonWebKey.generate_key("RSA", 2048, is_private=True)
_PUBLIC = {**_KEY.as_dict(is_private=False), "kid": "k1", "use": "sig"}
_PRIVATE = {**_KEY.as_dict(is_private=True), "kid": "k1"}

OIDC = {"issuer": ISSUER, "client_id": CLIENT_ID}
DISCO = {"jwks_uri": JWKS_URI}


@pytest.fixture(autouse=True)
def _seed_jwks():
    authOidc._JWKS_CACHE[JWKS_URI] = (
        authOidc._now() + 3600,
        {"keys": [_PUBLIC, {"kty": "oct", "k": "AAAA", "kid": "sym"}]},
    )
    yield
    authOidc._JWKS_CACHE.clear()


def _mint(*, alg: str = "RS256", key: object = None, **overrides) -> str:
    claims = {
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "user-1",
        "nonce": NONCE,
        "exp": int(time.time()) + 300,
        "iat": int(time.time()),
    }
    claims.update(overrides)
    token = JsonWebToken([alg]).encode(
        {"alg": alg, "kid": "k1"}, claims, key if key is not None else _PRIVATE
    )
    return token.decode()


def _verify(token: str) -> dict:
    return authOidc._verify_jwt(token, OIDC, DISCO, NONCE)


def test_valid_token_accepted():
    claims = _verify(_mint())
    assert claims["sub"] == "user-1"
    assert isinstance(claims, dict)


def test_expiry_within_leeway_accepted():
    # The gap this change closes: an IdP clock a few seconds fast must not reject a valid login.
    claims = _verify(_mint(exp=int(time.time()) - 30))
    assert claims["sub"] == "user-1"


def test_expired_beyond_leeway_rejected():
    with pytest.raises(RuntimeError, match="OIDC token expired"):
        _verify(_mint(exp=int(time.time()) - 600))


def test_missing_expiry_rejected():
    # authlib skips a claim that is absent, so exp must be declared essential.
    claims = {"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-1", "nonce": NONCE}
    token = JsonWebToken(["RS256"]).encode(
        {"alg": "RS256", "kid": "k1"}, claims, _PRIVATE
    ).decode()
    with pytest.raises(RuntimeError, match="OIDC token claims invalid"):
        _verify(token)


def test_audience_mismatch_rejected():
    with pytest.raises(RuntimeError, match="OIDC token audience mismatch"):
        _verify(_mint(aud="someone-else"))


def test_issuer_mismatch_rejected():
    with pytest.raises(RuntimeError, match="OIDC token issuer mismatch"):
        _verify(_mint(iss="https://evil.example"))


def test_nonce_mismatch_rejected():
    with pytest.raises(RuntimeError, match="OIDC nonce mismatch"):
        _verify(_mint(nonce="replayed"))


def test_missing_subject_rejected():
    with pytest.raises(RuntimeError, match="OIDC token subject missing"):
        _verify(_mint(sub=""))


def test_symmetric_alg_rejected():
    # HS256 outside the allowlist: a leaked client secret must not be able to mint an ID token.
    forged = JsonWebToken(["HS256"]).encode(
        {"alg": "HS256", "kid": "k1"},
        {"iss": ISSUER, "aud": CLIENT_ID, "sub": "user-1", "nonce": NONCE,
         "exp": int(time.time()) + 300},
        "shh",
    ).decode()
    with pytest.raises(RuntimeError, match="OIDC ID token signature invalid"):
        _verify(forged)


def test_tampered_signature_rejected():
    header, payload, signature = _mint().split(".")
    flipped = ("B" if signature[0] != "B" else "C") + signature[1:]
    with pytest.raises(RuntimeError, match="OIDC ID token signature invalid"):
        _verify(f"{header}.{payload}.{flipped}")


def test_unrecognised_crit_header_rejected():
    # RFC 7515 4.1.11: a crit entry we do not understand must be rejected.
    _, payload, signature = _mint().split(".")
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "kid": "k1", "crit": ["b64"]}).encode()
    ).rstrip(b"=").decode()
    with pytest.raises(RuntimeError, match="OIDC ID token signature invalid"):
        _verify(f"{header}.{payload}.{signature}")


def test_non_signing_keys_filtered_out():
    authOidc._JWKS_CACHE[JWKS_URI] = (
        authOidc._now() + 3600,
        {"keys": [{**_PUBLIC, "use": "enc"}]},
    )
    with pytest.raises(RuntimeError, match="OIDC signing key not found"):
        _verify(_mint())
