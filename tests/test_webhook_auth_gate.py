# tests/test_webhook_auth_gate.py
# /webhook/* is excluded from the app_auth middleware, so the URL token checked by
# _resolve_media_webhook_request is the only thing standing between the public
# internet and a forged scrobble. These pin that it fails closed on every path a
# caller controls: no token, wrong token, and an unprovisioned server-side token.
from __future__ import annotations

import pytest

from api import scrobbleAPI


class _FakeURL:
    def __init__(self, query: str) -> None:
        self.query = query


class _FakeRequest:
    def __init__(self, query: str = "") -> None:
        self.url = _FakeURL(query)


@pytest.fixture
def cfg(monkeypatch):
    """Config with webhooks enabled and a known legacy token per provider."""
    stored = {
        "scrobble": {"enabled": True, "sources": {"webhook": True}},
        "security": {
            "webhook_ids": {
                "plextrakt": "plex-token",
                "jellyfintrakt": "jf-token",
                "embytrakt": "emby-token",
            }
        },
    }
    monkeypatch.setattr(scrobbleAPI, "load_config", lambda: stored)
    monkeypatch.setattr(scrobbleAPI, "save_config", lambda _cfg: None)
    monkeypatch.setattr(scrobbleAPI, "scrobble_sources", lambda _cfg: {"webhook": True})
    monkeypatch.setattr(scrobbleAPI, "_ensure_media_profile_webhook_ids", lambda _cfg, regenerate=False: [])
    # Isolate the token check: a valid token should get past auth and fail later
    # (or pass) on its own merits, not because the gate let it through.
    monkeypatch.setattr(scrobbleAPI, "_webhook_profile_gate", lambda *_a, **_k: None)
    monkeypatch.setattr(scrobbleAPI, "apply_webhook_settings", lambda cfg, *_a, **_k: cfg)
    return stored


PROVIDERS = [("plex", "plextrakt", "plex-token"), ("jellyfin", "jellyfintrakt", "jf-token"), ("emby", "embytrakt", "emby-token")]


@pytest.mark.parametrize("provider,legacy_key,_token", PROVIDERS)
def test_missing_token_is_rejected(cfg, provider, legacy_key, _token):
    with pytest.raises(scrobbleAPI.WebhookAuthError):
        scrobbleAPI._resolve_media_webhook_request(_FakeRequest(""), provider, legacy_key)


@pytest.mark.parametrize("provider,legacy_key,_token", PROVIDERS)
def test_wrong_token_is_rejected(cfg, provider, legacy_key, _token):
    with pytest.raises(scrobbleAPI.WebhookAuthError):
        scrobbleAPI._resolve_media_webhook_request(_FakeRequest("token=not-the-token"), provider, legacy_key)


@pytest.mark.parametrize("provider,legacy_key,token", PROVIDERS)
def test_valid_token_is_accepted(cfg, provider, legacy_key, token):
    target_cfg, instance, error = scrobbleAPI._resolve_media_webhook_request(
        _FakeRequest(f"token={token}"), provider, legacy_key
    )
    assert error is None
    assert instance == "default"
    assert target_cfg is not None


@pytest.mark.parametrize("provider,legacy_key,_token", PROVIDERS)
def test_unprovisioned_server_token_rejects_even_a_blank_request_token(cfg, provider, legacy_key, _token):
    """An empty configured token must never match an empty supplied one."""
    cfg["security"]["webhook_ids"][legacy_key] = ""
    with pytest.raises(scrobbleAPI.WebhookAuthError):
        scrobbleAPI._resolve_media_webhook_request(_FakeRequest(""), provider, legacy_key)


@pytest.mark.parametrize("provider,legacy_key,_token", PROVIDERS)
def test_unmatched_profile_token_is_rejected_not_silently_ignored(cfg, provider, legacy_key, _token):
    """A ?profile= token matching no profile is an auth failure. Answering
    200/ignored would let it be brute-forced without ever being logged."""
    with pytest.raises(scrobbleAPI.WebhookAuthError):
        scrobbleAPI._resolve_media_webhook_request(_FakeRequest("profile=bogus"), provider, legacy_key)


@pytest.mark.parametrize("provider,legacy_key,_token", PROVIDERS)
def test_empty_profile_token_is_rejected(cfg, provider, legacy_key, _token):
    with pytest.raises(scrobbleAPI.WebhookAuthError):
        scrobbleAPI._resolve_media_webhook_request(_FakeRequest("profile="), provider, legacy_key)


@pytest.mark.parametrize("provider,legacy_key,token", PROVIDERS)
def test_legacy_token_does_not_satisfy_the_profile_parameter(cfg, provider, legacy_key, token):
    """The two token namespaces are distinct; a legacy token passed as ?profile=
    must not authenticate."""
    with pytest.raises(scrobbleAPI.WebhookAuthError):
        scrobbleAPI._resolve_media_webhook_request(_FakeRequest(f"profile={token}"), provider, legacy_key)


@pytest.mark.parametrize("provider,legacy_key,token", PROVIDERS)
def test_token_of_another_provider_is_rejected(cfg, provider, legacy_key, token):
    other = next(t for _p, _k, t in PROVIDERS if t != token)
    with pytest.raises(scrobbleAPI.WebhookAuthError):
        scrobbleAPI._resolve_media_webhook_request(_FakeRequest(f"token={other}"), provider, legacy_key)
