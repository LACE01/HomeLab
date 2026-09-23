"""WebAuthn / FIDO2 (#67): phishing-resistant MFA covering both hardware security
keys (YubiKeys) and platform passkeys in ONE ceremony. Built on py_webauthn.

RP ID is the USER-FACING domain (WEBAUTHN_RP_ID), not the container host, because a
WebAuthn assertion is cryptographically bound to the origin the browser sees -- and
behind the Cloudflare tunnel that's the public hostname. Set WEBAUTHN_RP_ID (and,
if it differs from https://<rp_id>, WEBAUTHN_ORIGIN) or the feature stays disabled.

Storage:
  db.webauthn_credentials  one per registered authenticator
  db.webauthn_challenges   short-lived per (user, purpose) challenge
"""
import os
import uuid
from datetime import datetime, timezone, timedelta

RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "VulnOps")
CHALLENGE_TTL_SECONDS = 300


def rp_id() -> str:
    return os.environ.get("WEBAUTHN_RP_ID", "").strip()


def origin() -> str:
    o = os.environ.get("WEBAUTHN_ORIGIN", "").strip()
    if o:
        return o.rstrip("/")
    r = rp_id()
    return f"https://{r}" if r else ""


def is_configured() -> bool:
    return bool(rp_id())


def _now():
    return datetime.now(timezone.utc)


async def _stash_challenge(db, user_id: str, purpose: str, challenge: bytes):
    from webauthn.helpers import bytes_to_base64url
    await db.webauthn_challenges.replace_one(
        {"user_id": user_id, "purpose": purpose},
        {"user_id": user_id, "purpose": purpose,
         "challenge": bytes_to_base64url(challenge), "created_at": _now().isoformat()},
        upsert=True)


async def _take_challenge(db, user_id: str, purpose: str) -> bytes:
    from webauthn.helpers import base64url_to_bytes
    doc = await db.webauthn_challenges.find_one({"user_id": user_id, "purpose": purpose}, {"_id": 0})
    if not doc:
        raise ValueError("No pending WebAuthn challenge — restart the ceremony")
    await db.webauthn_challenges.delete_one({"user_id": user_id, "purpose": purpose})
    created = datetime.fromisoformat(doc["created_at"])
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)
    if (_now() - created) > timedelta(seconds=CHALLENGE_TTL_SECONDS):
        raise ValueError("WebAuthn challenge expired — try again")
    return base64url_to_bytes(doc["challenge"])


async def _user_descriptors(db, user_id: str):
    from webauthn.helpers import base64url_to_bytes
    from webauthn.helpers.structs import PublicKeyCredentialDescriptor
    out = []
    async for c in db.webauthn_credentials.find({"user_id": user_id}, {"_id": 0}):
        out.append(PublicKeyCredentialDescriptor(id=base64url_to_bytes(c["credential_id"])))
    return out


async def begin_registration(db, user: dict) -> str:
    import webauthn
    from webauthn.helpers import options_to_json
    from webauthn.helpers.structs import AuthenticatorSelectionCriteria, UserVerificationRequirement
    opts = webauthn.generate_registration_options(
        rp_id=rp_id(), rp_name=RP_NAME,
        user_id=user["id"].encode("utf-8"),
        user_name=user["email"], user_display_name=user.get("name") or user["email"],
        exclude_credentials=await _user_descriptors(db, user["id"]),
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.PREFERRED),
    )
    await _stash_challenge(db, user["id"], "register", opts.challenge)
    return options_to_json(opts)


async def complete_registration(db, user: dict, credential: dict, name: str = None) -> dict:
    import webauthn
    from webauthn.helpers import bytes_to_base64url
    import json as _json
    expected = await _take_challenge(db, user["id"], "register")
    cred = _json.dumps(credential) if isinstance(credential, dict) else credential
    v = webauthn.verify_registration_response(
        credential=cred, expected_challenge=expected,
        expected_rp_id=rp_id(), expected_origin=origin())
    cred_id = bytes_to_base64url(v.credential_id)
    if await db.webauthn_credentials.find_one({"credential_id": cred_id}, {"_id": 0}):
        raise ValueError("That authenticator is already registered")
    doc = {"id": str(uuid.uuid4()), "user_id": user["id"], "credential_id": cred_id,
           "public_key": bytes_to_base64url(v.credential_public_key),
           "sign_count": v.sign_count, "name": (name or "Security key").strip()[:60],
           "created_at": _now().isoformat(), "last_used_at": None}
    await db.webauthn_credentials.insert_one(dict(doc))
    return {"id": doc["id"], "name": doc["name"]}


async def begin_authentication(db, user_id: str) -> str:
    import webauthn
    from webauthn.helpers import options_to_json
    from webauthn.helpers.structs import UserVerificationRequirement
    allow = await _user_descriptors(db, user_id)
    if not allow:
        raise ValueError("No security keys registered for this account")
    opts = webauthn.generate_authentication_options(
        rp_id=rp_id(), allow_credentials=allow,
        user_verification=UserVerificationRequirement.PREFERRED)
    await _stash_challenge(db, user_id, "auth", opts.challenge)
    return options_to_json(opts)


async def complete_authentication(db, user_id: str, credential: dict) -> bool:
    import webauthn
    from webauthn.helpers import base64url_to_bytes
    raw_id = credential.get("rawId") or credential.get("id")
    stored = await db.webauthn_credentials.find_one(
        {"user_id": user_id, "credential_id": raw_id}, {"_id": 0})
    if not stored:
        raise ValueError("Unknown security key for this account")
    import json as _json
    expected = await _take_challenge(db, user_id, "auth")
    cred = _json.dumps(credential) if isinstance(credential, dict) else credential
    v = webauthn.verify_authentication_response(
        credential=cred, expected_challenge=expected,
        expected_rp_id=rp_id(), expected_origin=origin(),
        credential_public_key=base64url_to_bytes(stored["public_key"]),
        credential_current_sign_count=stored.get("sign_count", 0))
    await db.webauthn_credentials.update_one(
        {"id": stored["id"]},
        {"$set": {"sign_count": v.new_sign_count, "last_used_at": _now().isoformat()}})
    return True


async def list_credentials(db, user_id: str) -> list:
    out = []
    async for c in db.webauthn_credentials.find({"user_id": user_id}, {"_id": 0}):
        out.append({"id": c["id"], "name": c.get("name"), "created_at": c.get("created_at"),
                    "last_used_at": c.get("last_used_at")})
    return out


async def delete_credential(db, user_id: str, cred_id: str) -> None:
    await db.webauthn_credentials.delete_one({"user_id": user_id, "id": cred_id})


async def has_webauthn(db, user_id: str) -> bool:
    return (await db.webauthn_credentials.count_documents({"user_id": user_id})) > 0
