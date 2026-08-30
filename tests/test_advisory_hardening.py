"""Regression checks for the four security advisories fixed on 2026-08-29.

Each test pins the *behaviour* the advisory was about, not the shape of the fix,
so a future refactor that reopens the hole fails here.
"""
from __future__ import annotations

import types
from types import SimpleNamespace
from typing import Any

import pytest
import responses
from fastapi import HTTPException
from starlette.requests import Request


def _request(headers: dict[str, str] | None = None, *, client_ip: str = "127.0.0.1") -> Request:
    raw_headers = [(b"host", b"testserver")]
    for k, v in (headers or {}).items():
        raw_headers.append((str(k).lower().encode("latin-1"), str(v).encode("latin-1")))
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/api/watchlist",
            "raw_path": b"/api/watchlist",
            "query_string": b"",
            "headers": raw_headers,
            "client": (client_ip, 12345),
            "server": ("testserver", 80),
        }
    )


# --- GHSA-vrw5-p3r4-4927: static API key is unrestricted admin -----------------


def test_api_key_brute_force_is_rate_limited() -> None:
    """A wrong key must cost the caller the same lockout a wrong password does.

    Uses a dedicated client IP and restores the shared _LOGIN_FAILS bucket, so
    this cannot leak a lockout into the other auth tests.
    """
    from api import appAuthAPI as auth

    ip = "10.99.0.7"
    cfg = {"security": {"api_key": "k" * 40}}
    saved = dict(auth._LOGIN_FAILS)
    try:
        auth._LOGIN_FAILS.pop(ip, None)
        for _ in range(3):
            assert auth.api_key_authenticated(cfg, _request({"x-api-key": "wrong"}, client_ip=ip)) is False
        # Lockout is now active, so even the correct key is refused.
        assert auth.api_key_authenticated(cfg, _request({"x-api-key": "k" * 40}, client_ip=ip)) is False
    finally:
        auth._LOGIN_FAILS.clear()
        auth._LOGIN_FAILS.update(saved)


def test_api_key_absent_header_is_not_a_failed_attempt() -> None:
    """Not sending the header at all is a cookie-auth request, not a guess."""
    from api import appAuthAPI as auth

    ip = "10.99.0.8"
    cfg = {"security": {"api_key": "k" * 40}}
    saved = dict(auth._LOGIN_FAILS)
    try:
        auth._LOGIN_FAILS.pop(ip, None)
        for _ in range(10):
            assert auth.api_key_authenticated(cfg, _request(client_ip=ip)) is False
        assert ip not in auth._LOGIN_FAILS
        assert auth.api_key_authenticated(cfg, _request({"x-api-key": "k" * 40}, client_ip=ip)) is True
    finally:
        auth._LOGIN_FAILS.clear()
        auth._LOGIN_FAILS.update(saved)


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


def _stub_request() -> Any:
    """api_config_save only touches request.app; the checks under test run first."""
    return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace()))


def test_config_save_rejects_short_api_key(monkeypatch) -> None:
    from api import configAPI as cfg_api

    saved: dict = {}
    _stub_env(monkeypatch, cfg_api, lambda: {}, lambda cfg: saved.update(cfg))

    with pytest.raises(HTTPException) as exc:
        cfg_api.api_config_save(_stub_request(), {"security": {"api_key": "test"}})

    assert exc.value.status_code == 400
    assert "security.api_key" in str(exc.value.detail)
    assert not saved


def test_config_save_accepts_long_api_key(monkeypatch) -> None:
    from api import configAPI as cfg_api

    saved: dict = {}
    _stub_env(monkeypatch, cfg_api, lambda: {}, lambda cfg: saved.update(cfg))

    cfg_api.api_config_save(_stub_request(), {"security": {"api_key": "a" * 32}})
    assert saved["security"]["api_key"] == "a" * 32


def test_config_save_does_not_relitigate_an_existing_short_key(monkeypatch) -> None:
    """An already-set short key (or an env-locked one) must not wedge every
    unrelated config save — only a *changed* key is validated."""
    from api import configAPI as cfg_api

    current = {"security": {"api_key": "legacy-short"}}
    saved: dict = {}
    _stub_env(monkeypatch, cfg_api, lambda: dict(current), lambda cfg: saved.update(cfg))

    cfg_api.api_config_save(_stub_request(), {"runtime": {"debug": True}})
    assert saved["security"]["api_key"] == "legacy-short"


# --- GHSA-c24r-xxq7-rfq3: per-profile media-account visibility -----------------

_ITEM = {"source": "plex", "source_instance": "default", "account": "alice"}
_INSTANCES = {"PLEX": ["default"]}


def test_activity_hides_an_account_the_profile_may_not_see() -> None:
    from api.activityAPI import _matches_user_profile

    assert _matches_user_profile(dict(_ITEM), _INSTANCES, {"PLEX": {"default": ["bob"]}}) is False


def test_activity_shows_an_allowed_account() -> None:
    from api.activityAPI import _matches_user_profile

    assert _matches_user_profile(dict(_ITEM), _INSTANCES, {"PLEX": {"default": ["alice"]}}) is True


def test_activity_unscoped_instance_is_unaffected() -> None:
    """No account allowlist for that instance means the profile never scoped it."""
    from api.activityAPI import _matches_user_profile

    assert _matches_user_profile(dict(_ITEM), _INSTANCES, {}) is True
    assert _matches_user_profile(dict(_ITEM), _INSTANCES, None) is True


def test_activity_still_filters_by_instance() -> None:
    from api.activityAPI import _matches_user_profile

    assert _matches_user_profile(dict(_ITEM), {"PLEX": ["other"]}, {}) is False


def test_scrobble_and_activity_agree_on_account_scope() -> None:
    """The divergence the advisory was about: both surfaces answer via the same
    helper, so they cannot drift again."""
    from api.activityAPI import _matches_user_profile
    from api.scrobbleAPI import _currently_watching_matches_user

    denied = {"PLEX": {"default": ["bob"]}}
    scrobble_item = {"source": "plex", "provider_instance": "default", "account": "alice"}
    assert _currently_watching_matches_user(scrobble_item, {"instances": _INSTANCES, "accounts": denied}) is False
    assert _matches_user_profile(dict(_ITEM), _INSTANCES, denied) is False


# --- GHSA-m99r-g3q7-hf2f: avatar proxy SSRF -----------------------------------


def test_avatar_fetch_refuses_a_metadata_address() -> None:
    """An IdP-supplied picture claim pointing at cloud metadata must not be
    fetched; the endpoint falls back to the default avatar."""
    from api.profileAPI import _avatar_response

    raw = {"oidc_identity": {"picture": "https://169.254.169.254/latest/meta-data/", "linked_at": 1}}
    resp = _avatar_response(raw)
    assert resp.media_type == "image/svg+xml"


def test_guarded_request_is_what_blocks_the_hop() -> None:
    from cw_platform.url_validation import guarded_request

    with pytest.raises(ValueError):
        guarded_request("GET", "https://169.254.169.254/latest/meta-data/", field_name="avatar_url", timeout=1)


# --- GHSA-8w95-pmpp-pff2: OIDC group allowlist semantics ----------------------


def test_empty_oidc_allowlist_permits_every_authenticated_account() -> None:
    """Pins the behaviour the README used to describe backwards. If this ever
    becomes fail-closed, the README table must change in the same commit."""
    from services.authOidc import group_allowed

    assert group_allowed({}, {"groups": []}) is True
    assert group_allowed({"allowed_groups": []}, {"groups": ["anything"]}) is True


def test_populated_oidc_allowlist_still_restricts() -> None:
    from services.authOidc import group_allowed

    oidc = {"allowed_groups": ["crosswatch-admins"]}
    assert group_allowed(oidc, {"groups": ["crosswatch-admins"]}) is True
    assert group_allowed(oidc, {"groups": ["someone-else"]}) is False
    assert group_allowed(oidc, {"groups": []}) is False


# --- Codex PR #116 review follow-ups ------------------------------------------


class _ClosableStub:
    """Minimal requests.Response stand-in that records close()."""

    def __init__(self, content_type: str = "image/png", body: bytes = b"x") -> None:
        self.headers = {"Content-Type": content_type}
        self.closed = False
        self._body = body
        self.raw = SimpleNamespace(read=lambda *_a, **_k: self._body)

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def close(self) -> None:
        self.closed = True


def test_avatar_response_is_closed_on_unsupported_content_type(monkeypatch) -> None:
    """stream=True holds a socket; an unusable content type must still release it."""
    from api import profileAPI

    stub = _ClosableStub(content_type="text/html")
    monkeypatch.setattr(
        "cw_platform.url_validation.guarded_request", lambda *_a, **_k: stub
    )
    resp = profileAPI._avatar_response(
        {"oidc_identity": {"picture": "https://cdn.example.com/a.png", "linked_at": 1}}
    )
    assert stub.closed is True
    assert resp.media_type == "image/svg+xml"


def test_avatar_response_is_closed_when_image_is_oversized(monkeypatch) -> None:
    from api import profileAPI

    stub = _ClosableStub(body=b"x" * (profileAPI.MAX_AVATAR_BYTES + 1))
    monkeypatch.setattr(
        "cw_platform.url_validation.guarded_request", lambda *_a, **_k: stub
    )
    profileAPI._avatar_response(
        {"oidc_identity": {"picture": "https://cdn.example.com/a.png", "linked_at": 1}}
    )
    assert stub.closed is True


def test_api_key_success_clears_the_failure_record() -> None:
    """Mirrors the password success path: a working client's occasional typo
    must not accumulate toward a lockout, and must not spill onto login."""
    from api import appAuthAPI as auth

    ip = "10.99.0.9"
    cfg = {"security": {"api_key": "k" * 40}}
    saved = dict(auth._LOGIN_FAILS)
    try:
        auth._LOGIN_FAILS.pop(ip, None)
        assert auth.api_key_authenticated(cfg, _request({"x-api-key": "wrong"}, client_ip=ip)) is False
        assert ip in auth._LOGIN_FAILS
        assert auth.api_key_authenticated(cfg, _request({"x-api-key": "k" * 40}, client_ip=ip)) is True
        assert ip not in auth._LOGIN_FAILS
    finally:
        auth._LOGIN_FAILS.clear()
        auth._LOGIN_FAILS.update(saved)


class TestCrossHostRedirects:
    """allow_cross_host lifts the same-host rule for credential-free fetches
    (avatar CDNs) without lifting per-hop SSRF validation."""

    @responses.activate
    def test_cross_host_redirect_is_followed_when_allowed(self) -> None:
        from cw_platform.url_validation import guarded_request

        responses.add(
            responses.GET, "https://idp.example.com/pic",
            status=302, headers={"Location": "https://cdn.example.com/pic.png"},
        )
        responses.add(responses.GET, "https://cdn.example.com/pic.png", body=b"img", status=200)
        r = guarded_request("GET", "https://idp.example.com/pic", field_name="avatar_url", allow_cross_host=True)
        assert r.status_code == 200

    @responses.activate
    def test_cross_host_redirect_still_blocks_a_metadata_target(self) -> None:
        from cw_platform.url_validation import guarded_request

        responses.add(
            responses.GET, "https://idp.example.com/pic",
            status=302, headers={"Location": "http://169.254.169.254/latest/meta-data/"},
        )
        with pytest.raises(ValueError):
            guarded_request("GET", "https://idp.example.com/pic", field_name="avatar_url", allow_cross_host=True)

    @responses.activate
    def test_cross_host_hop_drops_credentials(self) -> None:
        """Opting into cross-host must not walk an Authorization header or
        query-string token to the new host."""
        from cw_platform.url_validation import guarded_request

        responses.add(
            responses.GET, "https://idp.example.com/pic",
            status=302, headers={"Location": "https://cdn.example.com/pic.png"},
        )
        responses.add(responses.GET, "https://cdn.example.com/pic.png", body=b"img", status=200)
        guarded_request(
            "GET", "https://idp.example.com/pic", field_name="avatar_url", allow_cross_host=True,
            headers={"Authorization": "Bearer secret", "User-Agent": "CrossWatch"},
            params={"apikey": "secret"},
        )
        second = responses.calls[1].request
        assert "authorization" not in {k.lower() for k in second.headers}
        assert "apikey" not in (second.url.split("?", 1)[1] if "?" in second.url else "")

    @responses.activate
    def test_default_still_refuses_cross_host(self) -> None:
        from cw_platform.url_validation import guarded_request

        responses.add(
            responses.GET, "https://media.example.com/x",
            status=302, headers={"Location": "https://other.example.com/x"},
        )
        with pytest.raises(ValueError, match="off the configured host"):
            guarded_request("GET", "https://media.example.com/x", field_name="test")


# --- Codex PR #116 second-pass follow-ups -------------------------------------


def test_activity_id_only_allowlist_denies_rather_than_falls_open() -> None:
    """The activity table stores only an account name, so an id:/uuid: entry can
    never be evaluated. A profile that scoped an instance purely by identifier
    gets nothing rather than everyone -- falling open would leak exactly what
    GHSA-c24r is about. The feed stays empty until identifiers are persisted."""
    from api.activityAPI import _matches_user_profile

    assert _matches_user_profile(dict(_ITEM), _INSTANCES, {"PLEX": {"default": ["id:42"]}}) is False
    assert _matches_user_profile(dict(_ITEM), _INSTANCES, {"PLEX": {"default": ["uuid:abc"]}}) is False


def test_activity_name_entries_still_filter_alongside_id_entries() -> None:
    """A mixed allowlist keeps filtering on the part that is evaluatable."""
    from api.activityAPI import _matches_user_profile

    mixed = {"PLEX": {"default": ["alice", "id:42"]}}
    assert _matches_user_profile(dict(_ITEM), _INSTANCES, mixed) is True
    bob = {**_ITEM, "account": "bob"}
    assert _matches_user_profile(bob, _INSTANCES, mixed) is False


def test_scrobble_still_enforces_id_form_allowlists() -> None:
    """currently-watching carries the identifiers, so it must NOT relax them."""
    from api.scrobbleAPI import _currently_watching_matches_user

    allowlist = {"instances": _INSTANCES, "accounts": {"PLEX": {"default": ["id:42"]}}}
    match = {"source": "plex", "provider_instance": "default", "account": "alice", "account_id": "42"}
    miss = {"source": "plex", "provider_instance": "default", "account": "bob", "account_id": "7"}
    assert _currently_watching_matches_user(match, allowlist) is True
    assert _currently_watching_matches_user(miss, allowlist) is False


def test_intermediate_redirect_responses_are_closed(monkeypatch) -> None:
    """stream=True hops hold their connection; guarded_request discards each
    redirect response while walking the chain, so it has to close them."""
    import requests

    from cw_platform.url_validation import guarded_request

    made: list[_ClosableStub] = []

    class _Hop(_ClosableStub):
        def __init__(self, status: int, location: str | None) -> None:
            super().__init__()
            self.status_code = status
            self.is_redirect = location is not None
            if location:
                self.headers = {"Location": location}

    def fake_request(_method, url, **_kw):
        hop = _Hop(302, "https://b.example.com/x") if "a.example.com" in url else _Hop(200, None)
        made.append(hop)
        return hop

    monkeypatch.setattr(requests, "request", fake_request)
    final = guarded_request("GET", "https://a.example.com/x", field_name="test", allow_cross_host=True, stream=True)

    assert len(made) == 2
    assert made[0].closed is True, "redirect hop leaked its connection"
    assert final is made[1] and made[1].closed is False, "final response must stay open for the caller"


# --- Codex PR #116 third-pass follow-ups --------------------------------------


def _fake_dns(monkeypatch, mapping: dict[str, str]) -> None:
    """Resolve only the hosts named; anything else raises like real DNS would."""
    import socket

    def fake_getaddrinfo(host, *_a, **_k):
        if host in mapping:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (mapping[host], 0))]
        raise socket.gaierror(f"no such host {host}")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)


class TestPublicOnlyFetch:
    """assert_server_url_safe permits RFC1918/loopback on purpose (media servers
    live there). A URL supplied by an untrusted IdP claim must not."""

    def test_loopback_is_refused(self, monkeypatch) -> None:
        from cw_platform.url_validation import assert_public_https_url

        _fake_dns(monkeypatch, {"evil.example.com": "127.0.0.1"})
        with pytest.raises(ValueError, match="non-public"):
            assert_public_https_url("https://evil.example.com/x", "avatar_url")

    def test_rfc1918_is_refused(self, monkeypatch) -> None:
        from cw_platform.url_validation import assert_public_https_url

        _fake_dns(monkeypatch, {"evil.example.com": "192.168.1.10"})
        with pytest.raises(ValueError, match="non-public"):
            assert_public_https_url("https://evil.example.com/x", "avatar_url")

    def test_http_is_refused(self, monkeypatch) -> None:
        from cw_platform.url_validation import assert_public_https_url

        _fake_dns(monkeypatch, {"cdn.example.com": "93.184.216.34"})
        with pytest.raises(ValueError, match="must be https"):
            assert_public_https_url("http://cdn.example.com/x", "avatar_url")

    def test_public_https_passes(self, monkeypatch) -> None:
        from cw_platform.url_validation import assert_public_https_url

        _fake_dns(monkeypatch, {"cdn.example.com": "93.184.216.34"})
        assert_public_https_url("https://cdn.example.com/x", "avatar_url")

    def test_unresolvable_is_refused(self, monkeypatch) -> None:
        from cw_platform.url_validation import assert_public_https_url

        _fake_dns(monkeypatch, {})
        with pytest.raises(ValueError, match="does not resolve"):
            assert_public_https_url("https://nope.example.com/x", "avatar_url")

    @responses.activate
    def test_redirect_to_private_address_is_blocked_mid_chain(self, monkeypatch) -> None:
        """The regression Codex caught: allow_cross_host alone would have
        followed this hop, because the server-URL check permits RFC1918."""
        from cw_platform.url_validation import guarded_request

        _fake_dns(monkeypatch, {"idp.example.com": "93.184.216.34", "internal.example.com": "10.0.0.5"})
        responses.add(
            responses.GET, "https://idp.example.com/pic",
            status=302, headers={"Location": "https://internal.example.com/admin"},
        )
        with pytest.raises(ValueError, match="non-public"):
            guarded_request(
                "GET", "https://idp.example.com/pic", field_name="avatar_url",
                allow_cross_host=True, require_public=True,
            )


# --- Codex PR #116 fourth-pass follow-ups -------------------------------------


def test_env_supplied_short_api_key_is_refused() -> None:
    """CW_API_KEY is injected straight into security.api_key and never passes
    through api_config_save(), so the length floor has to hold at the
    authentication choke point that every source routes through."""
    from api import appAuthAPI as auth

    assert auth.api_key_authenticated({"security": {"api_key": "test"}}, _request({"x-api-key": "test"})) is False
    ok = "k" * auth.MIN_API_KEY_LENGTH
    assert auth.api_key_authenticated({"security": {"api_key": ok}}, _request({"x-api-key": ok})) is True


def test_config_save_rejects_short_api_key_using_the_shared_floor(monkeypatch) -> None:
    from api import appAuthAPI as auth
    from api import configAPI as cfg_api

    saved: dict = {}
    _stub_env(monkeypatch, cfg_api, lambda: {}, lambda cfg: saved.update(cfg))
    short = "k" * (auth.MIN_API_KEY_LENGTH - 1)
    with pytest.raises(HTTPException) as exc:
        cfg_api.api_config_save(_stub_request(), {"security": {"api_key": short}})
    assert exc.value.status_code == 400
    assert not saved


class _Peer:
    """requests.Response stand-in exposing a peer address, as urllib3 does."""

    def __init__(self, ip: str) -> None:
        sock = SimpleNamespace(getpeername=lambda: (ip, 443))
        self.raw = SimpleNamespace(connection=SimpleNamespace(sock=sock))
        self.status_code = 200
        self.is_redirect = False
        self.headers: dict[str, str] = {}
        self.closed = False

    def close(self) -> None:
        self.closed = True


def test_dns_rebinding_is_caught_at_the_socket(monkeypatch) -> None:
    """DNS answers public during validation, then loopback when the socket is
    opened. Only the connected peer proves where the bytes came from."""
    import requests

    from cw_platform.url_validation import guarded_request

    _fake_dns(monkeypatch, {"rebind.example.com": "93.184.216.34"})
    rebound = _Peer("127.0.0.1")
    monkeypatch.setattr(requests, "request", lambda *_a, **_k: rebound)

    with pytest.raises(ValueError, match="non-public address"):
        guarded_request(
            "GET", "https://rebind.example.com/pic", field_name="avatar_url",
            allow_cross_host=True, require_public=True, stream=True,
        )
    assert rebound.closed is True, "refused response must not leak its socket"


def test_public_peer_is_accepted(monkeypatch) -> None:
    import requests

    from cw_platform.url_validation import guarded_request

    _fake_dns(monkeypatch, {"cdn.example.com": "93.184.216.34"})
    good = _Peer("93.184.216.34")
    monkeypatch.setattr(requests, "request", lambda *_a, **_k: good)
    assert guarded_request(
        "GET", "https://cdn.example.com/pic", field_name="avatar_url",
        allow_cross_host=True, require_public=True, stream=True,
    ) is good


def test_missing_peer_fails_closed(monkeypatch) -> None:
    """No socket to inspect means no proof; refuse rather than assume good."""
    import requests

    from cw_platform.url_validation import guarded_request

    _fake_dns(monkeypatch, {"cdn.example.com": "93.184.216.34"})
    blind = _Peer("93.184.216.34")
    blind.raw = SimpleNamespace(connection=None)
    monkeypatch.setattr(requests, "request", lambda *_a, **_k: blind)
    with pytest.raises(ValueError, match="peer unavailable"):
        guarded_request(
            "GET", "https://cdn.example.com/pic", field_name="avatar_url",
            allow_cross_host=True, require_public=True, stream=True,
        )
