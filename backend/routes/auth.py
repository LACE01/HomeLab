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


class LoginBody(BaseModel):
    email: EmailStr
    password: str


@router.post("/auth/login")
async def login(body: LoginBody, response: Response):
    user = await db.users.find_one({"email": body.email.lower()})
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(user["id"], user["email"], user["role"])
    response.set_cookie(
        key="access_token", value=token, httponly=True, secure=False, samesite="lax",
        max_age=12 * 3600, path="/",
    )
    return {
        "token": token,
        "user": {"id": user["id"], "email": user["email"], "name": user["name"], "role": user["role"]},
    }


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
