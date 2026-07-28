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

    # Failure paths leave the flow cookie alone: with two flows in flight the
    # shared cookie holds the newer flow's nonce, so deleting it here would
    # break that still-pending login too. It expires on its own in 10 minutes.
    if not res.get("ok"):
        return _local_login_redirect(str(res.get("code") or "failed"))

    if not _flow_nonce_matches(request, res):
        return _local_login_redirect("failed")

    # Re-load: the cfg from the top of this handler is seconds stale by now
    # (discovery + token exchange + JWKS round-trips); writing it back would
    # clobber any settings saved during that window.
    fresh = load_config()
    identity = res.get("identity") or {}
    # A policy edit made during those round-trips must win over the snapshot
    # the token was authorized against: OIDC must still be enabled; the
    # issuer/client the token came from and the claim the groups were
    # extracted under must be unchanged; the identity must still pass the
    # group allowlist.
    if not authOIDC.login_available(fresh):
        return _local_login_redirect("failed")
    o_old, o_new = authOIDC._oidc_cfg(cfg), authOIDC._oidc_cfg(fresh)
    for field, default in (("issuer", ""), ("client_id", ""), ("groups_claim", "groups")):
        if str(o_new.get(field) or default).strip() != str(o_old.get(field) or default).strip():
            return _local_login_redirect("failed")
    if not authOIDC.identity_allowed(fresh, identity):
        return _local_login_redirect("denied")

    token, exp = app_auth._issue_session(fresh, request, ttl_sec=authOIDC.session_ttl_sec(fresh))
    save_config(fresh)
    _log(f"OIDC sign-in ok for sub={identity.get('sub')} ({identity.get('username')})")

    resp = RedirectResponse(url=_safe_next(str(res.get("next") or "/")), status_code=302, headers={"Cache-Control": "no-store"})
    _del_flow_cookie(resp, request)
    # persistent=False: browser session cookie; the server-side expiry above
    # is the real bound so a stolen cookie dies with the short OIDC TTL.
    app_auth._set_cookie(resp, token, exp, request, persistent=False)
    return resp


def register_auth_oidc(app) -> None:
    app.include_router(router)
