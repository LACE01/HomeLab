"""Authentication routes: login, logout, /me, Google OAuth session exchange,
Microsoft Entra ID SSO."""
import logging
import os
import secrets
import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr

from db import db
from auth_utils import (
    hash_password, verify_password, create_access_token, get_current_user, decode_token,
    create_mfa_pending_token, decode_mfa_pending_token,
)
from routes.common import now_iso

logger = logging.getLogger("vulnops.auth")

router = APIRouter()

# Login lockout / throttling -- two independent limits so both a targeted
# credential-guessing attempt against one account and a broad spray across many
# accounts from one source get caught. Window-based rather than a persistent
# "account locked" flag on purpose: it self-clears without needing an admin
# "unlock" action, and a legitimate user who mistypes their password a few times
# just waits out the window instead of being permanently locked out.
MAX_FAILED_PER_EMAIL = 5
MAX_FAILED_PER_IP = 20
LOCKOUT_WINDOW_MINUTES = 15
# Per-account lockout only counts attempts that prove the attacker actually has
# (or is guessing at) a password for that specific real account -- "account
# disabled" and "rate_limited" itself are excluded so they can't extend their own
# window indefinitely. Per-IP throttling additionally counts "no such user"
# since trying many different (mostly nonexistent) emails from one source is
# exactly what a spray/enumeration attempt looks like, and none of those would
# ever show up in the per-account count above.
LOCKOUT_REASONS_ACCOUNT = {"bad password", "bad mfa code"}
LOCKOUT_REASONS_IP = {"bad password", "bad mfa code", "no such user"}


async def _recent_failure_count(field: str, value: str, reasons: set) -> int:
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=LOCKOUT_WINDOW_MINUTES)).isoformat()
    return await db.login_audit.count_documents({
        field: value, "success": False, "reason": {"$in": list(reasons)},
        "timestamp": {"$gte": cutoff},
    })


def _client_ip(request: Request) -> str:
    # Prefer the original client IP from a reverse-proxy header (this app is
    # deployed behind nginx / Cloudflare in every self-hosted setup so far) --
    # request.client.host alone would just be the proxy's own address.
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "unknown"


async def _log_login_attempt(request: Request, email: str, success: bool, reason: str = None, user_id: str = None):
    """Records every login attempt, successful or not, with as much request metadata
    as a standard web login actually exposes. A MAC address is NOT reachable here --
    that's link-layer information stripped by every router/switch hop between the
    client and this server, and browsers have no API that exposes it either; IP +
    user-agent + these headers are the real ceiling for a web login, not an
    oversight. This is deliberately its own collection (not activity_log, which is
    keyed to an authenticated entity_id/entity_type) since a failed login has no
    user id to attach to."""
    await db.login_audit.insert_one({
        "id": str(uuid.uuid4()), "email": email.lower() if email else None,
        "user_id": user_id, "success": success, "reason": reason,
        "ip": _client_ip(request), "user_agent": request.headers.get("user-agent"),
        "accept_language": request.headers.get("accept-language"),
        "timestamp": now_iso(),
    })


class LoginBody(BaseModel):
    email: EmailStr
    password: str


async def _complete_login(request: Request, response: Response, user: dict, ip: str) -> dict:
    """Shared tail end of a login, whether it finished in one step (no MFA) or two
    (password then /auth/mfa/verify) -- creates the real session/cookie and returns
    the same user payload shape either way, so the frontend doesn't need to know or
    care which path it came through."""
    jti = uuid.uuid4().hex
    token = create_access_token(user["id"], user["email"], user["role"], jti=jti)
    await db.active_sessions.insert_one({
        "id": str(uuid.uuid4()), "jti": jti, "user_id": user["id"], "email": user["email"],
        "ip": ip, "user_agent": request.headers.get("user-agent"),
        "created_at": now_iso(), "revoked": False,
    })
    response.set_cookie(
        key="access_token", value=token, httponly=True, secure=False, samesite="lax",
        max_age=12 * 3600, path="/",
    )
    # UEBA (new-IP/new-country/impossible-travel) enrichment runs in the background --
    # it involves an external geolocation lookup, and a login response should never
    # wait on (or fail because of) that. See ueba.py's own docstring for why this is
    # best-effort and never blocks/breaks a login.
    import asyncio
    from ueba import check_login_signals
    asyncio.create_task(check_login_signals(db, user["id"], user["email"], ip, now_iso()))
    return {
        "token": token,
        "user": {"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"],
                 "must_change_password": bool(user.get("must_change_password"))},
    }


@router.post("/auth/login")
async def login(body: LoginBody, request: Request, response: Response):
    email = body.email.lower()
    ip = _client_ip(request)

    ip_failures = await _recent_failure_count("ip", ip, LOCKOUT_REASONS_IP)
    if ip_failures >= MAX_FAILED_PER_IP:
        await _log_login_attempt(request, email, False, reason="rate_limited (ip)")
        from security_events import emit_event
        await emit_event(db, source="login_audit", event_type="brute_force_ip", severity="High",
            title=f"Repeated failed logins from {ip}", entity_type="ip", entity_id=ip, entity_label=ip,
            description=f"{ip_failures}+ failed login attempts across multiple accounts from this IP in the last {LOCKOUT_WINDOW_MINUTES} minutes.")
        raise HTTPException(status_code=429,
            detail=f"Too many failed login attempts from this network. Try again in up to {LOCKOUT_WINDOW_MINUTES} minutes.")
    account_failures = await _recent_failure_count("email", email, LOCKOUT_REASONS_ACCOUNT)
    if account_failures >= MAX_FAILED_PER_EMAIL:
        await _log_login_attempt(request, email, False, reason="rate_limited (account)")
        from security_events import emit_event
        await emit_event(db, source="login_audit", event_type="brute_force_account", severity="High",
            title=f"Repeated failed logins for {email}", entity_type="user", entity_id=email, entity_label=email,
            description=f"{account_failures}+ failed login attempts against this account in the last {LOCKOUT_WINDOW_MINUTES} minutes.")
        raise HTTPException(status_code=429,
            detail=f"Too many failed login attempts for this account. Try again in up to {LOCKOUT_WINDOW_MINUTES} minutes.")

    user = await db.users.find_one({"email": email})
    if not user or not verify_password(body.password, user.get("password_hash") or ""):
        await _log_login_attempt(request, email, False,
                                  reason="no such user" if not user else "bad password")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.get("active") is False:
        await _log_login_attempt(request, email, False, reason="account disabled", user_id=user["id"])
        raise HTTPException(status_code=401, detail="Account disabled")

    if user.get("mfa_enabled"):
        # Password is correct, but that alone doesn't finish a login on an MFA
        # account -- no session/cookie/login_audit entry yet. This intentionally
        # isn't logged as a login_audit "success": it's only a completed login once
        # /auth/mfa/verify also succeeds, so login_audit's success/failure column
        # keeps meaning "was this account actually accessed", not "was one factor
        # of it correct."
        return {"mfa_required": True, "mfa_token": create_mfa_pending_token(user["id"])}

    await _log_login_attempt(request, email, True, user_id=user["id"])
    return await _complete_login(request, response, user, ip)


class ChangePasswordBody(BaseModel):
    current_password: str
    new_password: str


@router.post("/auth/change-password")
async def change_password(body: ChangePasswordBody, user: dict = Depends(get_current_user)):
    """Self-service password change -- covers both the voluntary "change my
    password" case and the forced first-login flow (a temp password set by an
    admin has must_change_password=True; the frontend redirects here until it's
    cleared). Always requires the current password, including the forced-change
    case -- the user just typed it to log in, so this isn't extra friction, and it
    stops someone who grabbed an unlocked, still-logged-in session from silently
    taking over the account by changing the password out from under its owner."""
    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    if not full_user or not verify_password(body.current_password, full_user.get("password_hash") or ""):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    if body.new_password == body.current_password:
        raise HTTPException(status_code=400, detail="New password must be different from the current one")
    await db.users.update_one({"id": user["id"]}, {"$set": {
        "password_hash": hash_password(body.new_password), "must_change_password": False,
    }})
    return {"ok": True}


# --------------------------- MFA (TOTP) ---------------------------
# Standard RFC 6238 time-based one-time codes (Google Authenticator, Authy, 1Password,
# etc. all speak this) -- pyotp handles the HMAC/time-step math, we just own the
# setup/confirm/disable lifecycle and where it plugs into login() above.

@router.post("/auth/mfa/setup")
async def mfa_setup(user: dict = Depends(get_current_user)):
    """Generates a new secret and returns it (plus the otpauth:// URI for a QR code)
    but does NOT enable MFA yet -- that only happens once /auth/mfa/confirm proves
    the user actually has it loaded into an authenticator app and can produce a
    valid code. Calling this again before confirming just replaces the pending
    secret, which is fine -- nothing is enabled until confirm succeeds."""
    import pyotp
    secret = pyotp.random_base32()
    await db.users.update_one({"id": user["id"]}, {"$set": {"mfa_secret": secret, "mfa_enabled": False}})
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name="VulnOps")
    return {"secret": secret, "otpauth_url": uri}


class MfaConfirmBody(BaseModel):
    code: str


@router.post("/auth/mfa/confirm")
async def mfa_confirm(body: MfaConfirmBody, user: dict = Depends(get_current_user)):
    import pyotp
    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    secret = full_user.get("mfa_secret") if full_user else None
    if not secret:
        raise HTTPException(400, "Call /auth/mfa/setup first")
    if not pyotp.TOTP(secret).verify(body.code, valid_window=1):
        raise HTTPException(401, "That code didn't match -- check your authenticator app's time is in sync and try again")
    # Recovery codes are the only way back in if the authenticator device is lost --
    # shown once, in plaintext, here; only their bcrypt hashes are ever stored, same
    # as a password, so even a full database dump doesn't hand them out.
    recovery_codes = [f"{secrets.token_hex(4)}-{secrets.token_hex(4)}" for _ in range(8)]
    hashed = [hash_password(c) for c in recovery_codes]
    await db.users.update_one({"id": user["id"]}, {"$set": {"mfa_enabled": True, "mfa_recovery_codes": hashed}})
    return {"ok": True, "recovery_codes": recovery_codes}


class MfaDisableBody(BaseModel):
    password: str


@router.post("/auth/mfa/disable")
async def mfa_disable(body: MfaDisableBody, user: dict = Depends(get_current_user)):
    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    if not full_user or not verify_password(body.password, full_user.get("password_hash") or ""):
        raise HTTPException(401, "Current password is incorrect")
    await db.users.update_one({"id": user["id"]}, {"$set": {"mfa_enabled": False},
                                                     "$unset": {"mfa_secret": "", "mfa_recovery_codes": ""}})
    return {"ok": True}


@router.get("/auth/mfa/status")
async def mfa_status(user: dict = Depends(get_current_user)):
    full_user = await db.users.find_one({"id": user["id"]}, {"_id": 0})
    return {"enabled": bool(full_user and full_user.get("mfa_enabled"))}


class MfaVerifyBody(BaseModel):
    mfa_token: str
    code: str


@router.post("/auth/mfa/verify")
async def mfa_verify(body: MfaVerifyBody, request: Request, response: Response):
    import pyotp
    ip = _client_ip(request)
    try:
        payload = decode_mfa_pending_token(body.mfa_token)
    except Exception:
        raise HTTPException(401, "MFA session expired -- please log in again")
    user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0})
    if not user or not user.get("mfa_enabled"):
        raise HTTPException(401, "MFA session expired -- please log in again")

    account_failures = await _recent_failure_count("email", user["email"], LOCKOUT_REASONS_ACCOUNT)
    if account_failures >= MAX_FAILED_PER_EMAIL:
        await _log_login_attempt(request, user["email"], False, reason="rate_limited (account)", user_id=user["id"])
        raise HTTPException(status_code=429,
            detail=f"Too many failed attempts for this account. Try again in up to {LOCKOUT_WINDOW_MINUTES} minutes.")

    secret = user.get("mfa_secret") or ""
    code_ok = bool(secret) and pyotp.TOTP(secret).verify(body.code, valid_window=1)
    used_recovery = False
    remaining_codes = user.get("mfa_recovery_codes") or []
    if not code_ok:
        for i, hashed in enumerate(remaining_codes):
            if verify_password(body.code, hashed):
                code_ok = True
                used_recovery = True
                remaining_codes = remaining_codes[:i] + remaining_codes[i + 1:]
                break
    if not code_ok:
        await _log_login_attempt(request, user["email"], False, reason="bad mfa code", user_id=user["id"])
        raise HTTPException(401, "Invalid code")
    if used_recovery:
        # A recovery code is single-use by design -- burn it the moment it's spent.
        await db.users.update_one({"id": user["id"]}, {"$set": {"mfa_recovery_codes": remaining_codes}})

    await _log_login_attempt(request, user["email"], True, user_id=user["id"])
    return await _complete_login(request, response, user, ip)


def _jti_from_request(request: Request) -> Optional[str]:
    """Best-effort decode of the current access token's jti, tolerant of a missing,
    expired, or already-invalid token -- used only to revoke/identify "this session",
    never to authenticate, so failing quietly (returning None) is the right behavior."""
    token = request.cookies.get("access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        return None
    try:
        return decode_token(token).get("jti")
    except Exception:
        return None


@router.post("/auth/logout")
async def logout(request: Request, response: Response):
    sess = request.cookies.get("session_token")
    if sess:
        await db.user_sessions.delete_many({"session_token": sess})
    jti = _jti_from_request(request)
    if jti:
        await db.active_sessions.update_one({"jti": jti}, {"$set": {"revoked": True, "revoked_at": now_iso(), "revoked_reason": "logout"}})
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("session_token", path="/")
    return {"ok": True}


@router.get("/v1/auth/sessions")
async def list_my_sessions(request: Request, user: dict = Depends(get_current_user)):
    """Every non-revoked session for the current user -- what device/browser, from
    what IP, since when -- so someone can spot a session they don't recognize and cut
    it off (see DELETE below) without an admin needing to get involved."""
    current_jti = _jti_from_request(request)
    items = await db.active_sessions.find(
        {"user_id": user["id"], "revoked": {"$ne": True}}, {"_id": 0},
    ).sort("created_at", -1).to_list(200)
    for it in items:
        it["is_current"] = bool(current_jti) and it.get("jti") == current_jti
        it.pop("jti", None)  # never hand the raw session token identifier back to the client
    return {"items": items}


@router.delete("/v1/auth/sessions/{session_id}")
async def revoke_my_session(session_id: str, user: dict = Depends(get_current_user)):
    res = await db.active_sessions.update_one(
        {"id": session_id, "user_id": user["id"]},
        {"$set": {"revoked": True, "revoked_at": now_iso(), "revoked_reason": "user_revoked"}},
    )
    if res.matched_count == 0:
        raise HTTPException(404, "Session not found")
    return {"ok": True}


@router.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


class GoogleSessionBody(BaseModel):
    session_id: str


@router.post("/auth/google/session")
async def google_session(body: GoogleSessionBody, response: Response):
    # Disabled by default in self-hosted deployments: this originally proxied through
    # Emergent's hosted OAuth relay (demobackend.emergentagent.com), which is not
    # something a self-hosted instance controls or can rely on staying available.
    # Set GOOGLE_OAUTH_RELAY_URL to your own OAuth relay/endpoint to re-enable, or
    # wire up real Google OAuth (google-auth) here instead. Email/password login
    # (see /auth/login above) works fully independently and is the default path.
    relay_url = os.environ.get("GOOGLE_OAUTH_RELAY_URL")
    if not relay_url:
        raise HTTPException(
            status_code=501,
            detail="Google sign-in is not configured on this deployment. Use email/password login, "
                   "or set GOOGLE_OAUTH_RELAY_URL to enable it.",
        )
    import requests as _requests
    try:
        r = _requests.get(
            relay_url,
            headers={"X-Session-ID": body.session_id},
            timeout=10,
        )
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Auth provider unreachable: {e}")
    if r.status_code != 200:
        raise HTTPException(status_code=401, detail="Invalid session_id")
    data = r.json()
    email = (data.get("email") or "").lower()
    name = data.get("name") or email
    picture = data.get("picture")
    session_token = data.get("session_token")
    if not email or not session_token:
        raise HTTPException(status_code=502, detail="Malformed session-data response")

    user = await db.users.find_one({"email": email})
    if user is None:
        user = {
            "id": str(uuid.uuid4()), "email": email, "name": name,
            "role": "analyst", "picture": picture, "auth_provider": "google",
            "created_at": now_iso(), "password_hash": None,
        }
        await db.users.insert_one(user)
    else:
        await db.users.update_one({"email": email}, {"$set": {"name": name, "picture": picture, "auth_provider": user.get("auth_provider", "google")}})

    expires_at = datetime.now(timezone.utc) + timedelta(days=7)
    await db.user_sessions.insert_one({
        "id": str(uuid.uuid4()), "user_id": user["id"], "session_token": session_token,
        "expires_at": expires_at, "created_at": datetime.now(timezone.utc),
    })

    response.set_cookie(
        key="session_token", value=session_token, httponly=True,
        secure=True, samesite="none", max_age=7 * 24 * 3600, path="/",
    )
    return {"user": {"id": user["id"], "email": user["email"], "name": user["name"],
                     "role": user["role"], "picture": picture}}


# --------------------------- Microsoft Entra ID SSO (login) ---------------------------
# Reuses the SAME Azure AD app registration as the "Microsoft Entra ID" connector
# (see entra_sync.py / msgraph.py) rather than requiring a second one -- the
# connector's tenant_id/client_id/client_secret already live in db.integrations,
# and a single Azure AD app registration can serve both the client-credentials grant
# (background directory sync) and the authorization-code grant (interactive login)
# at once, as long as a Web platform redirect URI is added to it in the Azure portal.
# SSO login is a separate opt-in from the connector being configured -- an org might
# sync directory data without wanting to allow logging into Nightwatch itself via
# SSO -- gated by ENTRA_SSO_ENABLED, same "quietly no-op until explicitly turned on"
# convention as BACKUP_SCHEDULE_ENABLED and every optional connector elsewhere here.
#
# The callback exchanges the authorization code for an access token server-side
# (the client_secret never reaches the browser) and then calls Microsoft Graph's
# /me endpoint with that token to get the signed-in user's profile -- this doubles
# as proof the token is genuine (Graph rejects anything invalid/expired/wrong-
# audience) without this app needing to independently verify an id_token's JWT
# signature against Microsoft's JWKS.
ENTRA_AUTHORIZE_URL_TMPL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/authorize"
ENTRA_TOKEN_URL_TMPL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
ENTRA_SCOPE = "openid profile email User.Read"


def _entra_sso_enabled() -> bool:
    return os.environ.get("ENTRA_SSO_ENABLED", "false").lower() in ("true", "1", "yes")


async def _entra_sso_app() -> dict:
    """Returns {tenant_id, client_id, client_secret, redirect_uri} or raises
    ValueError with a specific, actionable reason for whichever piece is missing."""
    if not _entra_sso_enabled():
        raise ValueError("Microsoft SSO login isn't enabled on this deployment (set ENTRA_SSO_ENABLED=true)")
    redirect_uri = os.environ.get("ENTRA_SSO_REDIRECT_URI")
    if not redirect_uri:
        raise ValueError(
            "ENTRA_SSO_REDIRECT_URI isn't set -- this must exactly match a redirect URI "
            "registered on the Azure AD app"
        )
    integration = await db.integrations.find_one({"name": "Microsoft Entra ID"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    tenant_id, client_id, client_secret = cfg.get("tenant_id"), cfg.get("client_id"), cfg.get("client_secret")
    if not (tenant_id and client_id and client_secret):
        raise ValueError(
            "The Microsoft Entra ID integration isn't configured yet -- add tenant ID, client ID, "
            "and client secret under Integrations -> Microsoft Entra ID (SSO login reuses that same "
            "app registration)."
        )
    return {"tenant_id": tenant_id, "client_id": client_id, "client_secret": client_secret, "redirect_uri": redirect_uri}


@router.get("/auth/entra/status")
async def entra_sso_status():
    """Public, unauthenticated -- the login page needs to know whether to show the
    "Sign in with Microsoft" button at all, before anyone has a session to check."""
    try:
        await _entra_sso_app()
        return {"configured": True}
    except ValueError as e:
        return {"configured": False, "reason": str(e)}


@router.get("/auth/entra/login")
async def entra_sso_login():
    try:
        app_cfg = await _entra_sso_app()
    except ValueError as e:
        raise HTTPException(501, str(e))
    from urllib.parse import urlencode
    state = secrets.token_urlsafe(24)
    params = {
        "client_id": app_cfg["client_id"], "response_type": "code", "redirect_uri": app_cfg["redirect_uri"],
        "response_mode": "query", "scope": ENTRA_SCOPE, "state": state,
    }
    url = ENTRA_AUTHORIZE_URL_TMPL.format(tenant_id=app_cfg["tenant_id"]) + "?" + urlencode(params)
    redirect = RedirectResponse(url, status_code=302)
    redirect.set_cookie(key="entra_oauth_state", value=state, httponly=True, secure=False,
                         samesite="lax", max_age=600, path="/")
    return redirect


def _entra_fail(reason: str) -> RedirectResponse:
    logger.info(f"Entra SSO login failed: {reason}")
    redirect = RedirectResponse("/login?error=entra_sso", status_code=302)
    redirect.delete_cookie("entra_oauth_state", path="/")
    return redirect


@router.get("/auth/entra/callback")
async def entra_sso_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None,
                              error: Optional[str] = None, error_description: Optional[str] = None):
    if error:
        return _entra_fail(error_description or error)
    if not code or not state:
        return _entra_fail("callback missing code/state")
    cookie_state = request.cookies.get("entra_oauth_state")
    if not cookie_state or cookie_state != state:
        return _entra_fail("state mismatch (possible CSRF, or the login attempt expired)")

    try:
        app_cfg = await _entra_sso_app()
    except ValueError as e:
        return _entra_fail(str(e))

    import httpx
    token_url = ENTRA_TOKEN_URL_TMPL.format(tenant_id=app_cfg["tenant_id"])
    data = {
        "client_id": app_cfg["client_id"], "client_secret": app_cfg["client_secret"],
        "grant_type": "authorization_code", "code": code, "redirect_uri": app_cfg["redirect_uri"],
        "scope": ENTRA_SCOPE,
    }
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            token_resp = await c.post(token_url, data=data)
        token_body = token_resp.json() if token_resp.content else {}
        if token_resp.status_code != 200:
            return _entra_fail(token_body.get("error_description") or token_body.get("error") or f"HTTP {token_resp.status_code}")
        access_token = token_body.get("access_token")
        if not access_token:
            return _entra_fail("Azure AD token response had no access_token")

        async with httpx.AsyncClient(timeout=20) as c:
            me_resp = await c.get("https://graph.microsoft.com/v1.0/me",
                                   headers={"Authorization": f"Bearer {access_token}"})
        if me_resp.status_code != 200:
            return _entra_fail(f"Couldn't fetch profile from Microsoft Graph: HTTP {me_resp.status_code}")
        profile = me_resp.json()
    except httpx.HTTPError as e:
        return _entra_fail(f"Couldn't reach Microsoft: {e}")

    # Azure AD accounts don't always have `mail` populated (common for accounts
    # created without an Exchange mailbox) -- userPrincipalName is the reliable
    # fallback and is itself an email-shaped identifier for nearly every tenant.
    email = (profile.get("mail") or profile.get("userPrincipalName") or "").lower()
    if not email:
        return _entra_fail("Microsoft didn't return an email or userPrincipalName for this account")

    allowed_domain = (os.environ.get("ENTRA_SSO_ALLOWED_DOMAIN") or "").strip().lstrip("@").lower()
    if allowed_domain and not email.endswith("@" + allowed_domain):
        return _entra_fail(f"'{email}' isn't in the domain allowed to sign in via SSO on this deployment")

    name = profile.get("displayName") or email
    oid = profile.get("id")
    ip = _client_ip(request)

    user = await db.users.find_one({"email": email})
    if user is None:
        user = {
            "id": str(uuid.uuid4()), "email": email, "name": name,
            "role": os.environ.get("ENTRA_SSO_DEFAULT_ROLE", "analyst"),
            "auth_provider": "entra", "entra_oid": oid,
            "created_at": now_iso(), "password_hash": None, "teams": [],
        }
        await db.users.insert_one(user)
    else:
        if user.get("active") is False:
            await _log_login_attempt(request, email, False, reason="account disabled", user_id=user["id"])
            return _entra_fail("this account is disabled")
        # Never touch role/teams on an existing user -- SSO only ever authenticates
        # who they are, it doesn't get to silently change what they're allowed to do.
        await db.users.update_one({"email": email}, {"$set": {"name": name, "entra_oid": oid}})
        user = await db.users.find_one({"email": email})

    await _log_login_attempt(request, email, True, reason="sso_entra", user_id=user["id"])
    redirect = RedirectResponse("/", status_code=302)
    await _complete_login(request, redirect, user, ip)
    redirect.delete_cookie("entra_oauth_state", path="/")
    return redirect


# `hash_password` is re-exported because admin.py user-create uses it; keep import here
__all__ = ["router", "hash_password"]
