"""Authentication routes: login, logout, /me, Google OAuth session exchange."""
import os
import uuid
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, EmailStr

from db import db
from auth_utils import (
    hash_password, verify_password, create_access_token, get_current_user,
)
from routes.common import now_iso

router = APIRouter()


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


@router.post("/auth/login")
async def login(body: LoginBody, request: Request, response: Response):
    user = await db.users.find_one({"email": body.email.lower()})
    if not user or not verify_password(body.password, user.get("password_hash") or ""):
        await _log_login_attempt(request, body.email, False,
                                  reason="no such user" if not user else "bad password")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if user.get("active") is False:
        await _log_login_attempt(request, body.email, False, reason="account disabled", user_id=user["id"])
        raise HTTPException(status_code=401, detail="Account disabled")
    await _log_login_attempt(request, body.email, True, user_id=user["id"])
    token = create_access_token(user["id"], user["email"], user["role"])
    response.set_cookie(
        key="access_token", value=token, httponly=True, secure=False, samesite="lax",
        max_age=12 * 3600, path="/",
    )
    return {
        "token": token,
        "user": {"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"],
                 "must_change_password": bool(user.get("must_change_password"))},
    }


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


@router.post("/auth/logout")
async def logout(request: Request, response: Response):
    sess = request.cookies.get("session_token")
    if sess:
        await db.user_sessions.delete_many({"session_token": sess})
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("session_token", path="/")
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


# `hash_password` is re-exported because admin.py user-create uses it; keep import here
__all__ = ["router", "hash_password"]
