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
