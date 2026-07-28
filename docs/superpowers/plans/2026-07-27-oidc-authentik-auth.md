# OIDC (Authentik) SSO + API Key Auth Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add optional OIDC (Authentik) single sign-on to CrossWatch's existing local auth, plus a static API key for machine access, with local credentials kept as break-glass.

**Architecture:** Mirrors the existing Plex SSO pattern exactly: a service module (`services/authOIDC.py`, like `services/authPlex.py`) holds the flow logic; an API module (`api/authOIDCAPI.py`, like `api/authPlexAPI.py`) exposes endpoints under `/api/app-auth/oidc/` (already excluded from the auth middleware via the `/api/app-auth/` prefix — zero middleware changes for OIDC). Authorization-code flow with PKCE + state + nonce; ID token validated via Authlib against the issuer's JWKS; group-claim allowlist authorizes; successful login mints a normal local `cw_auth` session with a short OIDC-specific TTL. `/login` auto-redirects to Authentik when OIDC is available and the issuer is reachable; `/login?local=1` is the break-glass escape hatch. API key is a separate small hook in the auth middleware.

**Tech Stack:** Python 3, FastAPI, requests, Authlib (new dependency — JOSE/JWT validation only, no Starlette integration), pytest + responses.

## Global Constraints

- Local username/password auth stays mandatory (the app already enforces this: `_normalize_app_auth` forces `app_auth.enabled = True`). OIDC is additive; never weaken the setup-lock flow.
- All new config lives under `app_auth.oidc` and `security.api_key` in `config.json`. No UI settings page — config-file only, applied on restart.
- Authentik issuer URLs end with a trailing slash (`https://auth.example.com/application/o/<slug>/`) and the `iss` claim includes it. Never `rstrip("/")` the issuer; validate `iss` against the discovery document's `issuer` field.
- Secrets: config leaves named `client_secret` and `api_key` are auto-encrypted at rest by `_is_sensitive_path` in `cw_platform/config_base.py` — no encryption work needed. UI redaction DOES need explicit `_SECRET_PATHS` entries (Task 1).
- Error text shown on the login page must come from a fixed server-side code→text map. Never echo query-string text into HTML (XSS).
- Follow repo conventions: `from __future__ import annotations`, defensive `try/except` around config reads, `JSONResponse` with `{"ok": bool, ...}` and `Cache-Control: no-store`, logging via `_logging.log(msg, level=..., module="AUTH")` with the defensive import fallback used in `api/authPlexAPI.py`.
- Tests: pytest, style of `tests/test_auth_plex_api.py` — call endpoint functions directly with a hand-built `starlette.requests.Request`, monkeypatch module-level `load_config`/`save_config`. Use `responses` for HTTP. `pytest.ini` runs `-q --disable-warnings --maxfail=1`.
- Commits: conventional style (`feat(auth): ...`), signed, each ending with the Claude-Session trailer per session rules.
- Work happens on branch `oidc-authentik` in worktree `.worktrees/oidc-authentik` (create via superpowers:using-git-worktrees at execution start; pull latest `main` first). First commit on the branch adds this plan file.

---

## File Structure

- Create: `services/authOIDC.py` — discovery/JWKS caching, flow state, token exchange, ID-token + group validation
- Create: `api/authOIDCAPI.py` — `/api/app-auth/oidc/{status,login,callback}` endpoints, flow cookie, session mint
- Create: `tests/test_oidc_config.py`, `tests/test_auth_oidc_service.py`, `tests/test_auth_oidc_api.py`, `tests/test_api_key_auth.py`
- Modify: `cw_platform/config_base.py` — `DEFAULT_CFG` oidc block, `_normalize_app_auth`, `_SECRET_PATHS`
- Modify: `api/appAuthAPI.py` — `_issue_session` ttl param, `api_key_authenticated`, `ui_login` auto-redirect, login HTML OIDC button
- Modify: `crosswatch.py` — API-key check in `app_auth_gate` middleware
- Modify: `requirements.txt` — add `authlib`

---

### Task 1: Config defaults, normalization, redaction

**Files:**
- Modify: `cw_platform/config_base.py` (DEFAULT_CFG `app_auth` block ends ~line 764; `_SECRET_PATHS` ~line 775; `_normalize_app_auth` ~line 1603)
- Test: `tests/test_oidc_config.py`

**Interfaces:**
- Consumes: existing `load_config`, `redact_config`, `_ensure_dict`.
- Produces: `cfg["app_auth"]["oidc"]` dict with keys `enabled: bool`, `issuer: str`, `client_id: str`, `client_secret: str`, `public_base_url: str`, `groups_claim: str`, `allowed_groups: list[str]`, `session_hours: int (1–168, default 12)`. Later tasks read exactly these keys.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_oidc_config.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_oidc_config.py -v`
Expected: FAIL with `KeyError: 'oidc'`.

- [ ] **Step 3: Implement**

In `cw_platform/config_base.py`:

(a) Inside `DEFAULT_CFG["app_auth"]` (after the `"last_login_at": 0,` line, ~line 763), add:

```python
        # External OIDC SSO (e.g. Authentik). Local credentials stay required
        # as the break-glass login; OIDC only adds a second way in.
        "oidc": {
            "enabled": False,
            "issuer": "",                # e.g. https://auth.example.com/application/o/crosswatch/ (keep trailing slash)
            "client_id": "",
            "client_secret": "",
            "public_base_url": "",       # External base URL of CrossWatch, e.g. https://cw.example.com
            "groups_claim": "groups",
            "allowed_groups": [],        # Empty list denies every OIDC login
            "session_hours": 12,         # OIDC-minted session lifetime, 1-168
        },
```

(b) In `_SECRET_PATHS` (after the `("app_auth", "session", "token_hash"),` entry, ~line 830), add:

```python
    ("app_auth", "oidc", "client_secret"),
    # API key
    ("security", "api_key"),
```

(c) In `_normalize_app_auth` (after the `plex_sso` normalization block, before the `pwd = _ensure_dict(a, "password")` line, ~line 1637), add:

```python
    oidc = _ensure_dict(a, "oidc")
    oidc["enabled"] = bool(oidc.get("enabled", False))
    # Trailing slash is significant (Authentik issuers end with one) -- strip whitespace only.
    oidc["issuer"] = str(oidc.get("issuer", "") or "").strip()
    oidc["client_id"] = str(oidc.get("client_id", "") or "").strip()
    oidc["client_secret"] = str(oidc.get("client_secret", "") or "").strip()
    oidc["public_base_url"] = str(oidc.get("public_base_url", "") or "").strip().rstrip("/")
    oidc["groups_claim"] = str(oidc.get("groups_claim", "groups") or "").strip() or "groups"
    raw_groups = oidc.get("allowed_groups")
    items = raw_groups if isinstance(raw_groups, list) else ([raw_groups] if raw_groups else [])
    oidc["allowed_groups"] = [s for s in (str(x or "").strip() for x in items) if s]
    try:
        hours = int(oidc.get("session_hours", 12) or 12)
    except Exception:
        hours = 12
    oidc["session_hours"] = min(max(hours, 1), 168)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_oidc_config.py -v` then the full suite `pytest`
Expected: PASS, no regressions.

- [ ] **Step 5: Commit**

```bash
git add cw_platform/config_base.py tests/test_oidc_config.py docs/superpowers/plans/2026-07-27-oidc-authentik-auth.md
git commit -S -m "feat(auth): add oidc and api_key config plumbing"
```

---

### Task 2: OIDC service module

**Files:**
- Create: `services/authOIDC.py`
- Modify: `requirements.txt` (add `authlib` after `defusedxml`)
- Test: `tests/test_auth_oidc_service.py`

**Interfaces:**
- Consumes: `cfg["app_auth"]["oidc"]` from Task 1.
- Produces (used by Task 3 and 4):
  - `get_status(cfg: dict) -> dict` — `{"enabled": bool, "configured": bool, "login_available": bool}`
  - `login_available(cfg: dict) -> bool` — enabled AND issuer/client_id/client_secret/public_base_url all non-empty
  - `issuer_reachable(cfg: dict) -> bool` — discovery fetch succeeds (cached)
  - `redirect_uri(cfg: dict) -> str` — `<public_base_url>/api/app-auth/oidc/callback`
  - `session_ttl_sec(cfg: dict) -> int` — `session_hours * 3600`
  - `start_flow(cfg: dict, *, next_path: str, flow_nonce_hash: str) -> dict` — `{"ok": True, "auth_url": str, "state": str}`; raises on discovery failure
  - `complete_flow(cfg: dict, *, state: str, code: str) -> dict` — success: `{"ok": True, "flow_nonce_hash": str, "next": str, "identity": {"sub", "username", "email", "groups"}}`; failure: `{"ok": False, "error": str, "code": "failed"|"denied"}`
  - `_sha256_hex(value: str) -> str` (module-internal but used by Task 3 for the flow cookie, mirroring `authPlex._sha256_hex` usage)
  - Module caches `_PENDING_FLOWS`, `_DISCOVERY_CACHE`, `_JWKS_CACHE` (dicts; tests clear them)

- [ ] **Step 1: Add the dependency**

In `requirements.txt` add a line after `defusedxml`:

```
authlib
```

Run: `pip install authlib`

- [ ] **Step 2: Write the failing tests**

Create `tests/test_auth_oidc_service.py`:

```python
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
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_auth_oidc_service.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'services.authOIDC'` (import inside `_svc`).

- [ ] **Step 4: Implement**

Create `services/authOIDC.py`:

```python
# services/authOIDC.py
# CrossWatch - OIDC (e.g. Authentik) SSO authentication flow management
from __future__ import annotations

from typing import Any

import base64
import hashlib
import secrets
import time
from urllib.parse import urlencode

import requests
from authlib.jose import JsonWebKey, JsonWebToken
from authlib.jose.errors import JoseError

try:
    from _logging import log as _real_log
except ImportError:
    _real_log = None

DISCOVERY_TIMEOUT_SEC = 5
DISCOVERY_TTL_SEC = 300
TOKEN_TIMEOUT_SEC = 15
PENDING_TTL_SEC = 10 * 60
SCOPES = "openid profile email"

_PENDING_FLOWS: dict[str, dict[str, Any]] = {}
_DISCOVERY_CACHE: dict[str, dict[str, Any]] = {}
_JWKS_CACHE: dict[str, dict[str, Any]] = {}


def _log(msg: str, *, level: str = "INFO") -> None:
    try:
        if _real_log is not None:
            _real_log(msg, level=level, module="AUTH")
        else:
            print(f"[AUTH] {level}: {msg}")
    except Exception:
        pass


def _now() -> int:
    return int(time.time())


def _sha256_hex(value: str) -> str:
    return hashlib.sha256((value or "").encode("utf-8")).hexdigest()


def _b64url_nopad(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _oidc_cfg(cfg: dict[str, Any]) -> dict[str, Any]:
    a = cfg.get("app_auth")
    if not isinstance(a, dict):
        return {}
    o = a.get("oidc")
    return o if isinstance(o, dict) else {}


def get_status(cfg: dict[str, Any]) -> dict[str, Any]:
    o = _oidc_cfg(cfg)
    configured = all(str(o.get(k) or "").strip() for k in ("issuer", "client_id", "client_secret", "public_base_url"))
    enabled = bool(o.get("enabled"))
    return {
        "enabled": enabled,
        "configured": configured,
        "login_available": enabled and configured,
    }


def login_available(cfg: dict[str, Any]) -> bool:
    return bool(get_status(cfg)["login_available"])


def redirect_uri(cfg: dict[str, Any]) -> str:
    base = str(_oidc_cfg(cfg).get("public_base_url") or "").strip().rstrip("/")
    return f"{base}/api/app-auth/oidc/callback"


def session_ttl_sec(cfg: dict[str, Any]) -> int:
    try:
        hours = int(_oidc_cfg(cfg).get("session_hours") or 12)
    except Exception:
        hours = 12
    return min(max(hours, 1), 168) * 3600


def _discover(issuer: str) -> dict[str, Any]:
    key = str(issuer or "").strip()
    cached = _DISCOVERY_CACHE.get(key)
    if isinstance(cached, dict) and (_now() - int(cached.get("at") or 0)) < DISCOVERY_TTL_SEC:
        doc = cached.get("doc")
        if isinstance(doc, dict):
            return doc
    url = key.rstrip("/") + "/.well-known/openid-configuration"
    resp = requests.get(url, timeout=DISCOVERY_TIMEOUT_SEC)
    resp.raise_for_status()
    doc = resp.json() or {}
    for field in ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"):
        if not str(doc.get(field) or "").strip():
            raise RuntimeError(f"OIDC discovery document is missing {field}")
    _DISCOVERY_CACHE[key] = {"at": _now(), "doc": doc}
    return doc


def issuer_reachable(cfg: dict[str, Any]) -> bool:
    try:
        _discover(str(_oidc_cfg(cfg).get("issuer") or ""))
        return True
    except Exception:
        return False


def _jwks(jwks_uri: str, *, force: bool = False) -> dict[str, Any]:
    key = str(jwks_uri or "").strip()
    if not force:
        cached = _JWKS_CACHE.get(key)
        if isinstance(cached, dict) and (_now() - int(cached.get("at") or 0)) < DISCOVERY_TTL_SEC:
            doc = cached.get("doc")
            if isinstance(doc, dict):
                return doc
    resp = requests.get(key, timeout=DISCOVERY_TIMEOUT_SEC)
    resp.raise_for_status()
    doc = resp.json() or {}
    _JWKS_CACHE[key] = {"at": _now(), "doc": doc}
    return doc


def _prune_pending() -> None:
    now = _now()
    dead = [k for k, v in _PENDING_FLOWS.items() if int(v.get("expires_at") or 0) <= now]
    for key in dead:
        _PENDING_FLOWS.pop(key, None)


def start_flow(cfg: dict[str, Any], *, next_path: str, flow_nonce_hash: str) -> dict[str, Any]:
    _prune_pending()
    o = _oidc_cfg(cfg)
    doc = _discover(str(o.get("issuer") or ""))

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(48)
    challenge = _b64url_nopad(hashlib.sha256(verifier.encode("ascii")).digest())

    _PENDING_FLOWS[state] = {
        "nonce": nonce,
        "code_verifier": verifier,
        "flow_nonce_hash": str(flow_nonce_hash or "").strip(),
        "next": str(next_path or "/"),
        "expires_at": _now() + PENDING_TTL_SEC,
    }

    params = {
        "response_type": "code",
        "client_id": str(o.get("client_id") or "").strip(),
        "redirect_uri": redirect_uri(cfg),
        "scope": SCOPES,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    return {"ok": True, "state": state, "auth_url": f"{doc['authorization_endpoint']}?{urlencode(params)}"}


def _failed(error: str, *, code: str = "failed") -> dict[str, Any]:
    return {"ok": False, "error": error, "code": code}


def _decode_id_token(id_token: str, *, doc: dict[str, Any], client_id: str) -> Any:
    jwt = JsonWebToken(["RS256", "ES256"])
    options = {
        "iss": {"essential": True, "value": str(doc.get("issuer") or "")},
        "aud": {"essential": True, "value": client_id},
        "exp": {"essential": True},
    }

    def _attempt(force: bool) -> Any:
        key_set = JsonWebKey.import_key_set(_jwks(str(doc.get("jwks_uri") or ""), force=force))
        claims = jwt.decode(id_token, key_set, claims_options=options)
        claims.validate(leeway=60)
        return claims

    try:
        return _attempt(False)
    except (JoseError, ValueError):
        # Retry once with a fresh JWKS fetch so signing-key rotation does not
        # strand logins for the cache TTL.
        return _attempt(True)


def _extract_groups(claims: Any, groups_claim: str) -> list[str]:
    raw = claims.get(groups_claim)
    items = raw if isinstance(raw, list) else ([raw] if raw else [])
    return [s for s in (str(x or "").strip() for x in items) if s]


def complete_flow(cfg: dict[str, Any], *, state: str, code: str) -> dict[str, Any]:
    _prune_pending()
    rec = _PENDING_FLOWS.pop(str(state or "").strip(), None)
    if not isinstance(rec, dict):
        return _failed("Sign-in expired. Start again.")
    if not str(code or "").strip():
        return _failed("Missing authorization code")

    o = _oidc_cfg(cfg)
    client_id = str(o.get("client_id") or "").strip()
    try:
        doc = _discover(str(o.get("issuer") or ""))
        resp = requests.post(
            str(doc.get("token_endpoint") or ""),
            data={
                "grant_type": "authorization_code",
                "code": str(code).strip(),
                "redirect_uri": redirect_uri(cfg),
                "code_verifier": str(rec.get("code_verifier") or ""),
            },
            auth=(client_id, str(o.get("client_secret") or "")),
            timeout=TOKEN_TIMEOUT_SEC,
        )
        resp.raise_for_status()
        id_token = str((resp.json() or {}).get("id_token") or "").strip()
        if not id_token:
            return _failed("Token response contained no id_token")
        claims = _decode_id_token(id_token, doc=doc, client_id=client_id)
    except Exception as exc:
        _log(f"OIDC sign-in failed: {exc}", level="ERROR")
        return _failed("Sign-in failed")

    if str(claims.get("nonce") or "") != str(rec.get("nonce") or ""):
        return _failed("Sign-in failed")

    allowed = [str(g or "").strip() for g in (o.get("allowed_groups") or []) if str(g or "").strip()]
    groups = _extract_groups(claims, str(o.get("groups_claim") or "groups"))
    if not allowed:
        _log("OIDC login denied: allowed_groups is empty; refusing all OIDC logins", level="WARNING")
        return _failed("No groups are allowed to sign in", code="denied")
    if not any(g in allowed for g in groups):
        _log(f"OIDC login denied for sub={claims.get('sub')}: groups {groups} not in allowlist", level="WARNING")
        return _failed("Account is not allowed to sign in", code="denied")

    return {
        "ok": True,
        "flow_nonce_hash": str(rec.get("flow_nonce_hash") or "").strip(),
        "next": str(rec.get("next") or "/"),
        "identity": {
            "sub": str(claims.get("sub") or "").strip(),
            "username": str(claims.get("preferred_username") or claims.get("email") or "").strip(),
            "email": str(claims.get("email") or "").strip(),
            "groups": groups,
        },
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_auth_oidc_service.py -v` then `pytest`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add services/authOIDC.py tests/test_auth_oidc_service.py requirements.txt
git commit -S -m "feat(auth): add OIDC flow service with PKCE and group allowlist"
```

---

### Task 3: OIDC API endpoints + short-TTL session mint

**Files:**
- Create: `api/authOIDCAPI.py`
- Modify: `api/appAuthAPI.py` (`_issue_session` ~line 455; `register_app_auth` ~line 1311)
- Test: `tests/test_auth_oidc_api.py`

**Interfaces:**
- Consumes: `services.authOIDC` (Task 2 signatures), `appAuthAPI._issue_session`, `appAuthAPI._set_cookie`, `appAuthAPI._digest_eq`, `appAuthAPI.auth_required`, `appAuthAPI._effective_scheme_is_https`.
- Produces:
  - `GET /api/app-auth/oidc/status` → `{"enabled", "configured", "login_available"}`
  - `GET /api/app-auth/oidc/login?next=/x` → 302 to Authentik, sets flow cookie `cw_oidc_flow` (path `/api/app-auth/oidc`, 10 min)
  - `GET /api/app-auth/oidc/callback?code=..&state=..` → 302 to `next` on success (session cookie set) or `/login?local=1&oidc_error=<code>` on failure; `<code>` ∈ `{failed, denied, start_failed}` only
  - `register_auth_oidc(app)` — called from `register_app_auth`
  - `appAuthAPI._issue_session(cfg, request, *, ttl_sec: int | None = None)` — new keyword arg; `None` keeps existing remember-days behavior
- Note: these paths already pass the `crosswatch.py` middleware via the `startswith("/api/app-auth/")` exclusion — no middleware edits in this task.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_auth_oidc_api.py`:

```python
from __future__ import annotations

import json

from starlette.requests import Request


def _auth_cfg() -> dict:
    from api import appAuthAPI as auth

    salt = b"0123456789abcdef"
    return {
        "security": {},
        "app_auth": {
            "enabled": True,
            "username": "admin",
            "reset_required": False,
            "remember_session_enabled": False,
            "remember_session_days": 30,
            "oidc": {
                "enabled": True,
                "issuer": "https://idp.test/application/o/crosswatch/",
                "client_id": "cw-client",
                "client_secret": "cw-secret",
                "public_base_url": "https://cw.test",
                "groups_claim": "groups",
                "allowed_groups": ["crosswatch"],
                "session_hours": 2,
            },
            "password": {
                "scheme": "pbkdf2_sha256",
                "iterations": 260_000,
                "salt": auth._b64e(salt),
                "hash": auth._b64e(auth._pbkdf2_hash("secrett1", salt, iterations=260_000)),
            },
            "session": {"token_hash": "", "expires_at": 0},
            "sessions": [],
            "last_login_at": 0,
        },
    }


def _request(path: str, *, query: str = "", headers: dict[str, str] | None = None) -> Request:
    raw_headers = [(b"host", b"testserver")]
    for k, v in (headers or {}).items():
        raw_headers.append((str(k).lower().encode("latin-1"), str(v).encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("latin-1"),
        "query_string": query.encode("latin-1"),
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    return Request(scope)


def _all_set_cookie_headers(resp) -> str:
    return "\n".join(
        value.decode("latin-1")
        for key, value in getattr(resp, "raw_headers", [])
        if key.decode("latin-1").lower() == "set-cookie"
    )


def test_issue_session_honors_ttl_override() -> None:
    from api import appAuthAPI as auth

    cfg = _auth_cfg()
    req = _request("/api/app-auth/login")
    _token, exp = auth._issue_session(cfg, req, ttl_sec=7200)
    assert 0 < exp - auth._now() <= 7200


def test_oidc_login_redirects_to_idp_and_sets_flow_cookie(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)
    monkeypatch.setattr(
        oidc_api.authOIDC,
        "start_flow",
        lambda *_a, **_k: {"ok": True, "state": "st", "auth_url": "https://idp.test/authorize?x=1"},
    )

    resp = oidc_api.api_oidc_login(_request("/api/app-auth/oidc/login", query="next=/watchlist"))

    assert resp.status_code == 302
    assert resp.headers["location"] == "https://idp.test/authorize?x=1"
    assert f"{oidc_api.FLOW_COOKIE_NAME}=" in _all_set_cookie_headers(resp)


def test_oidc_login_falls_back_to_local_when_start_fails(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)

    def _boom(*_a, **_k):
        raise RuntimeError("idp down")

    monkeypatch.setattr(oidc_api.authOIDC, "start_flow", _boom)

    resp = oidc_api.api_oidc_login(_request("/api/app-auth/oidc/login"))
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login?local=1&oidc_error=start_failed"


def test_oidc_login_sanitizes_next(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)
    seen: dict = {}

    def _start(_cfg, *, next_path, flow_nonce_hash):
        seen["next"] = next_path
        return {"ok": True, "state": "st", "auth_url": "https://idp.test/authorize"}

    monkeypatch.setattr(oidc_api.authOIDC, "start_flow", _start)

    oidc_api.api_oidc_login(_request("/api/app-auth/oidc/login", query="next=https://evil.example"))
    assert seen["next"] == "/"
    oidc_api.api_oidc_login(_request("/api/app-auth/oidc/login", query="next=//evil.example"))
    assert seen["next"] == "/"


def test_oidc_callback_success_sets_session_cookie(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    saved: dict = {}
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)
    monkeypatch.setattr(oidc_api, "save_config", lambda c: saved.setdefault("cfg", c))
    monkeypatch.setattr(
        oidc_api.authOIDC,
        "complete_flow",
        lambda *_a, **_k: {
            "ok": True,
            "flow_nonce_hash": oidc_api.authOIDC._sha256_hex("flow-nonce"),
            "next": "/watchlist",
            "identity": {"sub": "user-1", "username": "jared", "email": "j@x.com", "groups": ["crosswatch"]},
        },
    )

    req = _request(
        "/api/app-auth/oidc/callback",
        query="code=abc&state=st",
        headers={"cookie": f"{oidc_api.FLOW_COOKIE_NAME}=flow-nonce"},
    )
    resp = oidc_api.api_oidc_callback(req)

    assert resp.status_code == 302
    assert resp.headers["location"] == "/watchlist"
    assert len(cfg["app_auth"]["sessions"]) == 1
    exp = int(cfg["app_auth"]["sessions"][0]["expires_at"])
    from api import appAuthAPI as auth

    assert 0 < exp - auth._now() <= 2 * 3600
    assert "cw_auth=" in _all_set_cookie_headers(resp)
    assert saved.get("cfg") is cfg


def test_oidc_callback_requires_matching_flow_cookie(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)
    monkeypatch.setattr(
        oidc_api.authOIDC,
        "complete_flow",
        lambda *_a, **_k: {
            "ok": True,
            "flow_nonce_hash": oidc_api.authOIDC._sha256_hex("expected"),
            "next": "/",
            "identity": {"sub": "user-1", "username": "jared", "email": "", "groups": []},
        },
    )

    resp = oidc_api.api_oidc_callback(_request("/api/app-auth/oidc/callback", query="code=abc&state=st"))
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login?local=1&oidc_error=failed"
    assert cfg["app_auth"]["sessions"] == []


def test_oidc_callback_denied_maps_to_denied_code(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)
    monkeypatch.setattr(
        oidc_api.authOIDC,
        "complete_flow",
        lambda *_a, **_k: {"ok": False, "error": "nope", "code": "denied"},
    )

    resp = oidc_api.api_oidc_callback(
        _request(
            "/api/app-auth/oidc/callback",
            query="code=abc&state=st",
            headers={"cookie": f"{oidc_api.FLOW_COOKIE_NAME}=n"},
        )
    )
    assert resp.headers["location"] == "/login?local=1&oidc_error=denied"


def test_oidc_callback_idp_error_redirects_local(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)

    resp = oidc_api.api_oidc_callback(_request("/api/app-auth/oidc/callback", query="error=access_denied"))
    assert resp.status_code == 302
    assert resp.headers["location"] == "/login?local=1&oidc_error=denied"


def test_oidc_status_reports_availability(monkeypatch) -> None:
    from api import authOIDCAPI as oidc_api

    cfg = _auth_cfg()
    monkeypatch.setattr(oidc_api, "load_config", lambda: cfg)
    resp = oidc_api.api_oidc_status(_request("/api/app-auth/oidc/status"))
    body = json.loads(resp.body.decode("utf-8"))
    assert body["login_available"] is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_auth_oidc_api.py -v`
Expected: FAIL — first on `_issue_session` unexpected keyword `ttl_sec`, then `ModuleNotFoundError: api.authOIDCAPI`.

- [ ] **Step 3: Implement `_issue_session` ttl override**

In `api/appAuthAPI.py` change the `_issue_session` signature and expiry line (~line 455):

```python
def _issue_session(cfg: dict[str, Any], request: Request, *, ttl_sec: int | None = None) -> tuple[str, int]:
    token = secrets.token_urlsafe(32)
    a = cfg.setdefault("app_auth", {})
    if not isinstance(a, dict):
        a = {}
        cfg["app_auth"] = a
    ttl = int(ttl_sec) if ttl_sec and int(ttl_sec) > 0 else _session_ttl_sec(a)
    exp = _now() + ttl
```

(rest of the function unchanged).

- [ ] **Step 4: Implement the API module**

Create `api/authOIDCAPI.py`:

```python
# api/authOIDCAPI.py
# CrossWatch - OIDC SSO authentication API endpoints
from __future__ import annotations

import secrets

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from cw_platform.config_base import load_config, save_config
from services import authOIDC

from . import appAuthAPI as app_auth

try:
    from _logging import log as _real_log
except ImportError:
    _real_log = None

router = APIRouter(prefix="/api/app-auth/oidc", tags=["app-auth"])
FLOW_COOKIE_NAME = "cw_oidc_flow"

# Fixed error codes -- the login page maps these to friendly text so raw
# query-string content never reaches the HTML.
ERROR_CODES = {"failed", "denied", "start_failed"}


def _log(msg: str, *, level: str = "INFO") -> None:
    try:
        if _real_log is not None:
            _real_log(msg, level=level, module="AUTH")
        else:
            print(f"[AUTH] {level}: {msg}")
    except Exception:
        pass


def _safe_next(raw: str) -> str:
    n = str(raw or "").strip()
    return n if (n.startswith("/") and not n.startswith("//")) else "/"


def _local_login_redirect(code: str) -> RedirectResponse:
    c = code if code in ERROR_CODES else "failed"
    return RedirectResponse(url=f"/login?local=1&oidc_error={c}", status_code=302, headers={"Cache-Control": "no-store"})


def _set_flow_cookie(resp: Response, nonce: str, request: Request) -> None:
    resp.set_cookie(
        FLOW_COOKIE_NAME,
        nonce,
        path="/api/app-auth/oidc",
        httponly=True,
        samesite="lax",
        secure=app_auth._effective_scheme_is_https(request),
        max_age=10 * 60,
    )


def _del_flow_cookie(resp: Response, request: Request) -> None:
    resp.delete_cookie(
        FLOW_COOKIE_NAME,
        path="/api/app-auth/oidc",
        httponly=True,
        samesite="lax",
        secure=app_auth._effective_scheme_is_https(request),
    )


def _flow_nonce_matches(request: Request, res: dict) -> bool:
    nonce = str(request.cookies.get(FLOW_COOKIE_NAME) or "").strip()
    want = str(res.get("flow_nonce_hash") or "").strip()
    if not nonce or not want:
        return False
    return app_auth._digest_eq(authOIDC._sha256_hex(nonce), want)


@router.get("/status")
def api_oidc_status(request: Request) -> JSONResponse:
    cfg = load_config()
    return JSONResponse(authOIDC.get_status(cfg), headers={"Cache-Control": "no-store"})


@router.get("/login")
def api_oidc_login(request: Request) -> Response:
    cfg = load_config()
    if not app_auth.auth_required(cfg):
        return RedirectResponse(url="/", status_code=302, headers={"Cache-Control": "no-store"})
    if not authOIDC.login_available(cfg):
        return _local_login_redirect("failed")

    next_path = _safe_next(request.query_params.get("next") or "/")
    flow_nonce = secrets.token_urlsafe(24)
    try:
        data = authOIDC.start_flow(cfg, next_path=next_path, flow_nonce_hash=authOIDC._sha256_hex(flow_nonce))
    except Exception as exc:
        _log(f"OIDC sign-in could not start: {exc}", level="ERROR")
        return _local_login_redirect("start_failed")

    resp = RedirectResponse(url=str(data.get("auth_url") or "/"), status_code=302, headers={"Cache-Control": "no-store"})
    _set_flow_cookie(resp, flow_nonce, request)
    return resp


@router.get("/callback")
def api_oidc_callback(request: Request) -> Response:
    cfg = load_config()
    if str(request.query_params.get("error") or "").strip():
        return _local_login_redirect("denied")
    if not authOIDC.login_available(cfg):
        return _local_login_redirect("failed")

    try:
        res = authOIDC.complete_flow(
            cfg,
            state=str(request.query_params.get("state") or "").strip(),
            code=str(request.query_params.get("code") or "").strip(),
        )
    except Exception as exc:
        _log(f"OIDC sign-in failed: {exc}", level="ERROR")
        return _local_login_redirect("failed")

    if not res.get("ok"):
        resp = _local_login_redirect(str(res.get("code") or "failed"))
        _del_flow_cookie(resp, request)
        return resp

    if not _flow_nonce_matches(request, res):
        resp = _local_login_redirect("failed")
        _del_flow_cookie(resp, request)
        return resp

    token, exp = app_auth._issue_session(cfg, request, ttl_sec=authOIDC.session_ttl_sec(cfg))
    save_config(cfg)
    identity = res.get("identity") or {}
    _log(f"OIDC sign-in ok for sub={identity.get('sub')} ({identity.get('username')})")

    resp = RedirectResponse(url=_safe_next(str(res.get("next") or "/")), status_code=302, headers={"Cache-Control": "no-store"})
    _del_flow_cookie(resp, request)
    # persistent=False: browser session cookie; the server-side expiry above
    # is the real bound so a stolen cookie dies with the short OIDC TTL.
    app_auth._set_cookie(resp, token, exp, request, persistent=False)
    return resp


def register_auth_oidc(app) -> None:
    app.include_router(router)
```

- [ ] **Step 5: Register the router**

In `api/appAuthAPI.py`, inside `register_app_auth` (~line 1311), after the Plex registration block, add:

```python
    try:
        from .authOIDCAPI import register_auth_oidc

        register_auth_oidc(app)
    except Exception:
        pass
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `pytest tests/test_auth_oidc_api.py tests/test_app_auth_api.py tests/test_auth_plex_api.py -v` then `pytest`
Expected: PASS (existing app-auth tests prove `_issue_session` default behavior unchanged).

- [ ] **Step 7: Commit**

```bash
git add api/authOIDCAPI.py api/appAuthAPI.py tests/test_auth_oidc_api.py
git commit -S -m "feat(auth): add OIDC login/callback endpoints with short-TTL sessions"
```

---

### Task 4: Login page auto-redirect + break-glass local form

**Files:**
- Modify: `api/appAuthAPI.py` (`_login_html` ~line 856; `ui_login` inside `register_app_auth` ~line 1320)
- Test: append to `tests/test_auth_oidc_api.py`

**Interfaces:**
- Consumes: `authOIDC.login_available`, `authOIDC.issuer_reachable` (Task 2).
- Produces:
  - `GET /login` → 302 to `/api/app-auth/oidc/login?next=...` when OIDC available AND issuer reachable AND no `local=1` AND no `oidc_error` param; otherwise renders the local form.
  - `_login_html(username, *, plex_sso_available=False, oidc_login_url="", oidc_error_text="")` — new keyword args; when `oidc_login_url` non-empty an "Sign in with SSO" link renders; when `oidc_error_text` non-empty it renders in the existing `#msg` error div.
  - Module constant `_OIDC_ERROR_TEXT: dict[str, str]` mapping `denied` / `start_failed` / `failed` to friendly sentences.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_auth_oidc_api.py`:

```python
def _login_route(monkeypatch, cfg):
    """Register routes on a throwaway FastAPI app and return the /login endpoint."""
    from fastapi import FastAPI

    from api import appAuthAPI as auth

    monkeypatch.setattr(auth, "load_config", lambda: cfg)
    monkeypatch.setattr(auth, "save_config", lambda *_a, **_k: None)
    app = FastAPI()
    auth.register_app_auth(app)
    for route in app.routes:
        if getattr(route, "path", "") == "/login" and "GET" in getattr(route, "methods", set()):
            return route.endpoint
    raise AssertionError("/login route not registered")


def test_login_auto_redirects_to_oidc(monkeypatch) -> None:
    from services import authOIDC

    cfg = _auth_cfg()
    monkeypatch.setattr(authOIDC, "issuer_reachable", lambda _cfg: True)
    endpoint = _login_route(monkeypatch, cfg)

    resp = endpoint(_request("/login", query="next=/watchlist"))
    assert resp.status_code == 302
    assert resp.headers["location"] == "/api/app-auth/oidc/login?next=%2Fwatchlist"


def test_login_local_escape_hatch_renders_form(monkeypatch) -> None:
    from services import authOIDC

    cfg = _auth_cfg()
    monkeypatch.setattr(authOIDC, "issuer_reachable", lambda _cfg: True)
    endpoint = _login_route(monkeypatch, cfg)

    resp = endpoint(_request("/login", query="local=1"))
    assert resp.status_code == 200
    body = resp.body.decode("utf-8")
    assert 'id="p"' in body
    assert "/api/app-auth/oidc/login" in body


def test_login_falls_back_to_form_when_issuer_down(monkeypatch) -> None:
    from services import authOIDC

    cfg = _auth_cfg()
    monkeypatch.setattr(authOIDC, "issuer_reachable", lambda _cfg: False)
    endpoint = _login_route(monkeypatch, cfg)

    resp = endpoint(_request("/login"))
    assert resp.status_code == 200
    assert 'id="p"' in resp.body.decode("utf-8")


def test_login_shows_mapped_error_not_raw_query(monkeypatch) -> None:
    from services import authOIDC

    cfg = _auth_cfg()
    monkeypatch.setattr(authOIDC, "issuer_reachable", lambda _cfg: True)
    endpoint = _login_route(monkeypatch, cfg)

    resp = endpoint(_request("/login", query="oidc_error=%3Cscript%3E"))
    assert resp.status_code == 200
    body = resp.body.decode("utf-8")
    assert "<script>alert" not in body
    assert "Single sign-on failed" in body


def test_login_no_redirect_when_oidc_disabled(monkeypatch) -> None:
    cfg = _auth_cfg()
    cfg["app_auth"]["oidc"]["enabled"] = False
    endpoint = _login_route(monkeypatch, cfg)

    resp = endpoint(_request("/login"))
    assert resp.status_code == 200
    body = resp.body.decode("utf-8")
    assert "/api/app-auth/oidc/login" not in body
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_auth_oidc_api.py -v -k login_`
Expected: FAIL — `ui_login` takes no request argument / no redirect happens (`TypeError` or 200 vs 302).

- [ ] **Step 3: Implement**

In `api/appAuthAPI.py`:

(a) Extend the import from `urllib.parse` (line 16):

```python
from urllib.parse import urlencode, urlsplit
```

(b) Above `_login_html` add the error-text map:

```python
_OIDC_ERROR_TEXT = {
    "denied": "Your account is not allowed to sign in to CrossWatch. Use local sign-in below.",
    "start_failed": "Single sign-on could not start. Use local sign-in below.",
    "failed": "Single sign-on failed. Use local sign-in below or try again.",
}
```

(c) Change `_login_html` signature and inject the SSO link + server-rendered error. Signature:

```python
def _login_html(username: str, *, plex_sso_available: bool = False, oidc_login_url: str = "", oidc_error_text: str = "") -> str:
```

After the existing `plex_html` block add:

```python
    oidc_html = ""
    if oidc_login_url:
        oidc_html = f"""
        <div class="cw-action-plex">
          <a class="btn" style="display:grid;place-items:center;text-decoration:none;width:100%;min-height:52px" href="{oidc_login_url}">Sign in with SSO</a>
        </div>
        """
    err = (oidc_error_text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    msg_cls = "cw-msg show" if err else "cw-msg"
```

In the returned HTML replace the `#msg` div line

```html
      <div id=\"msg\" class=\"cw-msg\" role=\"alert\" aria-live=\"assertive\"></div>
```

with

```html
      <div id=\"msg\" class=\"{msg_cls}\" role=\"alert\" aria-live=\"assertive\">{err}</div>
```

and inside the `cw-actions` div render `{oidc_html}` next to `{plex_html}`:

```html
        <div class=\"cw-actions\">
          <div class=\"cw-action-primary\">
            <button class=\"btn acc\" id=\"go\">Sign in</button>
          </div>
          {plex_html}
          {oidc_html}
        </div>
```

Also change `setMsg('')` behavior no further — the JS `setMsg` already toggles the `show` class, so a later local-login attempt clears the server-rendered error.

(d) Replace `ui_login` inside `register_app_auth`:

```python
    @app.get("/login", include_in_schema=False, tags=["ui"])
    def ui_login(request: Request) -> Response:
        cfg = load_config()
        if not auth_required(cfg):
            return RedirectResponse(url="/", status_code=302)

        qp = request.query_params
        force_local = str(qp.get("local") or "").strip().lower() in {"1", "true", "yes"}
        oidc_error = str(qp.get("oidc_error") or "").strip()
        next_path = str(qp.get("next") or "/")
        if not (next_path.startswith("/") and not next_path.startswith("//")):
            next_path = "/"

        oidc_available = False
        try:
            from services import authOIDC

            oidc_available = authOIDC.login_available(cfg)
        except Exception:
            oidc_available = False

        # oidc_error present means we just bounced back from a failed SSO
        # attempt -- rendering the form instead of redirecting again breaks
        # the redirect loop.
        if oidc_available and not force_local and not oidc_error:
            try:
                from services import authOIDC

                if authOIDC.issuer_reachable(cfg):
                    return RedirectResponse(
                        url="/api/app-auth/oidc/login?" + urlencode({"next": next_path}),
                        status_code=302,
                        headers={"Cache-Control": "no-store"},
                    )
            except Exception:
                pass

        a = _cfg_auth(cfg)
        username = str(a.get("username") or "")
        try:
            from services import authPlex

            plex_sso_available = authPlex.login_available(cfg)
        except Exception:
            plex_sso_available = False

        oidc_login_url = ""
        if oidc_available:
            oidc_login_url = "/api/app-auth/oidc/login?" + urlencode({"next": next_path})
        return HTMLResponse(
            _login_html(
                username,
                plex_sso_available=plex_sso_available,
                oidc_login_url=oidc_login_url,
                oidc_error_text=_OIDC_ERROR_TEXT.get(oidc_error, _OIDC_ERROR_TEXT["failed"]) if oidc_error else "",
            ),
            headers={"Cache-Control": "no-store"},
        )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_auth_oidc_api.py tests/test_app_auth_api.py -v` then `pytest`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add api/appAuthAPI.py tests/test_auth_oidc_api.py
git commit -S -m "feat(auth): auto-redirect /login to OIDC with local break-glass fallback"
```

---

### Task 5: Static API key for machine access

**Files:**
- Modify: `api/appAuthAPI.py` (new helper + `__all__` entry)
- Modify: `crosswatch.py` (import ~line 37; `app_auth_gate` ~line 508)
- Test: `tests/test_api_key_auth.py`

**Interfaces:**
- Consumes: `security.api_key` config value (encrypted at rest automatically; redacted via Task 1).
- Produces: `appAuthAPI.api_key_authenticated(cfg: dict, request: Request) -> bool` — True only when `security.api_key` is set AND the `X-API-Key` header matches (constant-time). Middleware accepts it as an alternative to the session cookie.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_api_key_auth.py`:

```python
from __future__ import annotations

from starlette.requests import Request


def _request(headers: dict[str, str] | None = None) -> Request:
    raw_headers = [(b"host", b"testserver")]
    for k, v in (headers or {}).items():
        raw_headers.append((str(k).lower().encode("latin-1"), str(v).encode("latin-1")))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/api/watchlist",
        "raw_path": b"/api/watchlist",
        "query_string": b"",
        "headers": raw_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
    }
    return Request(scope)


def test_api_key_matches() -> None:
    from api import appAuthAPI as auth

    cfg = {"security": {"api_key": "machine-key-123"}}
    assert auth.api_key_authenticated(cfg, _request({"x-api-key": "machine-key-123"})) is True


def test_api_key_rejects_wrong_or_missing() -> None:
    from api import appAuthAPI as auth

    cfg = {"security": {"api_key": "machine-key-123"}}
    assert auth.api_key_authenticated(cfg, _request({"x-api-key": "nope"})) is False
    assert auth.api_key_authenticated(cfg, _request()) is False


def test_api_key_disabled_when_unset() -> None:
    from api import appAuthAPI as auth

    for cfg in ({}, {"security": {}}, {"security": {"api_key": ""}}, {"security": {"api_key": "   "}}):
        assert auth.api_key_authenticated(cfg, _request({"x-api-key": ""})) is False
        assert auth.api_key_authenticated(cfg, _request({"x-api-key": "anything"})) is False


def test_middleware_accepts_api_key() -> None:
    # Guard the wiring, not just the helper: the gate must consult the API key
    # after the cookie check fails.
    import inspect

    import crosswatch

    src = inspect.getsource(crosswatch.app_auth_gate)
    assert "app_api_key_authenticated" in src
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_api_key_auth.py -v`
Expected: FAIL with `AttributeError: ... has no attribute 'api_key_authenticated'`.

- [ ] **Step 3: Implement the helper**

In `api/appAuthAPI.py`, after `is_authenticated` (~line 399), add:

```python
API_KEY_HEADER = "x-api-key"


def api_key_authenticated(cfg: dict[str, Any], request: Request) -> bool:
    sec = cfg.get("security") if isinstance(cfg, dict) else {}
    want = str((sec or {}).get("api_key") or "").strip() if isinstance(sec, dict) else ""
    if not want:
        return False
    got = str(request.headers.get(API_KEY_HEADER) or "").strip()
    if not got:
        return False
    return hmac.compare_digest(got.encode("utf-8"), want.encode("utf-8"))
```

Add `"api_key_authenticated"` to `__all__`.

- [ ] **Step 4: Wire the middleware**

In `crosswatch.py`:

(a) Extend the import block at line 37:

```python
from api.appAuthAPI import (
    COOKIE_NAME as APP_AUTH_COOKIE,
    api_key_authenticated as app_api_key_authenticated,
    auth_required as app_auth_required,
    is_authenticated as app_is_authenticated,
    setup_lock_required as app_auth_setup_lock_required,
)
```

(b) In `app_auth_gate`, after the cookie check (~line 509), add the API-key alternative:

```python
    token = request.cookies.get(APP_AUTH_COOKIE)
    if app_is_authenticated(cfg, token):
        return await call_next(request)

    if app_api_key_authenticated(cfg, request):
        return await call_next(request)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_api_key_auth.py -v` then the full suite `pytest`
Expected: PASS.

- [ ] **Step 6: Smoke test the app boots**

Run: `python -c "import crosswatch"` (import-time wiring check; full server not needed)
Expected: no traceback.

- [ ] **Step 7: Commit**

```bash
git add api/appAuthAPI.py crosswatch.py tests/test_api_key_auth.py
git commit -S -m "feat(auth): accept static X-API-Key for machine access"
```

---

## Post-implementation

- Run full suite: `pytest`. Run `npx eslint .` only if JS assets changed (they don't — login page HTML lives in Python).
- Manual verification checklist (documented for the user; needs a live Authentik):
  1. Authentik: create OAuth2/OIDC provider — Authorization Code + confidential client, redirect URI `https://<cw-host>/api/app-auth/oidc/callback`, signing key RS256, groups scope mapping included.
  2. `config.json`: fill `app_auth.oidc.*`, set `allowed_groups` to a real group, restart.
  3. `/login` → bounces to Authentik → back → app session valid ~`session_hours`.
  4. `/login?local=1` → local form works. Stop Authentik → `/login` falls back to local form after the discovery timeout (~5 s worst case).
  5. `curl -H "X-API-Key: <key>" https://<cw-host>/api/health` on a protected endpoint returns 200.
- Open PR against `main` on `jabrown93/crosswatch` (explicit `--repo`, repo is a fork), user merges.
