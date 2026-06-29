"""Auth utilities: bcrypt hashing, JWT tokens, current_user dependency."""
import os
import bcrypt
import jwt
from datetime import datetime, timezone, timedelta
from fastapi import HTTPException, Request, Depends
from typing import Optional

JWT_ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def _secret() -> str:
    return os.environ["JWT_SECRET"]


def create_access_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=12),
        "type": "access",
    }
    return jwt.encode(payload, _secret(), algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, _secret(), algorithms=[JWT_ALGORITHM])


async def get_current_user(request: Request) -> dict:
    from db import db
    # 1) Emergent Google session_token (cookie or Bearer)
    sess = request.cookies.get("session_token")
    if not sess:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            maybe = auth[7:]
            # Only treat as session token if it doesn't look like a JWT
            if maybe.count(".") != 2:
                sess = maybe
    if sess:
        s = await db.user_sessions.find_one({"session_token": sess}, {"_id": 0})
        if s:
            from datetime import datetime as _dt
            exp = s.get("expires_at")
            if isinstance(exp, str):
                exp = datetime.fromisoformat(exp)
            if exp and exp.tzinfo is None:
                exp = exp.replace(tzinfo=timezone.utc)
            if not exp or exp > datetime.now(timezone.utc):
                user = await db.users.find_one({"id": s["user_id"]}, {"_id": 0, "password_hash": 0})
                if user:
                    return user

    # 2) JWT access token (cookie or Bearer)
    token = request.cookies.get("access_token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = decode_token(token)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"id": payload["sub"]}, {"_id": 0, "password_hash": 0})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")


def require_role(*roles: str):
    async def checker(user: dict = Depends(get_current_user)):
        if user.get("role") not in roles and user.get("role") != "admin":
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user
    return checker


async def verify_api_key(request: Request) -> dict:
    """For ingestion endpoints — accepts X-API-Key header."""
    from db import db
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(status_code=401, detail="X-API-Key header required")
    key_doc = await db.api_keys.find_one({"key": api_key, "active": True}, {"_id": 0})
    if not key_doc:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return key_doc
