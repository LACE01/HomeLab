"""Admin-configurable password policy + role-based MFA requirement (#67/#68).

Defaults favor NIST SP 800-63B (length over arbitrary complexity, screen against
known-breached passwords) with a CJIS-compliant FLOOR that cannot be configured
below (CJIS 5.9 requires >= 8 chars with complexity, or >= 20 without). The policy
is stored as a single doc in db.settings (id="password_policy") and read on every
password change and at login (to drive the forced-enrollment gate).
"""
import hashlib
import logging

logger = logging.getLogger("vulnops.password_policy")

DEFAULT_POLICY = {
    "min_length": 12,
    "require_upper": True,
    "require_lower": True,
    "require_digit": True,
    "require_symbol": False,
    "breached_check": True,           # HIBP Pwned Passwords k-anonymity screen
    "breached_fail_closed": False,    # if HIBP is unreachable: False=allow, True=block
    "mfa_required_roles": ["admin", "manager"],  # roles that MUST enroll MFA
    # phishing_resistant_roles is honored once WebAuthn lands; kept here so the
    # setting is stable across that upgrade.
    "phishing_resistant_roles": ["admin"],
}

# CJIS/NIST floor -- set_password_policy refuses anything weaker than this.
CJIS_MIN_WITH_COMPLEXITY = 8
NIST_MIN_WITHOUT_COMPLEXITY = 20
_SYMBOLS = set("!@#$%^&*()-_=+[]{};:,.<>?/|~`\"'\\")


async def get_password_policy(db) -> dict:
    doc = await db.settings.find_one({"id": "password_policy"}, {"_id": 0})
    pol = dict(DEFAULT_POLICY)
    if doc and isinstance(doc.get("policy"), dict):
        pol.update({k: v for k, v in doc["policy"].items() if k in DEFAULT_POLICY})
    return pol


def _has_complexity(pol: dict) -> bool:
    return any(pol.get(k) for k in ("require_upper", "require_lower", "require_digit", "require_symbol"))


async def set_password_policy(db, patch: dict, actor: str) -> dict:
    from routes.common import now_iso
    pol = await get_password_policy(db)
    pol.update({k: v for k, v in (patch or {}).items() if k in DEFAULT_POLICY})
    # Enforce the non-negotiable floor.
    complexity = _has_complexity(pol)
    floor = CJIS_MIN_WITH_COMPLEXITY if complexity else NIST_MIN_WITHOUT_COMPLEXITY
    if int(pol.get("min_length", 0)) < floor:
        raise ValueError(
            f"min_length must be at least {floor} "
            f"({'with' if complexity else 'without'} complexity requirements) to meet the CJIS/NIST floor")
    pol["min_length"] = int(pol["min_length"])
    await db.settings.update_one({"id": "password_policy"},
                                 {"$set": {"id": "password_policy", "policy": pol,
                                           "updated_at": now_iso(), "updated_by": actor}}, upsert=True)
    return pol


def validate_password(pw: str, policy: dict) -> list:
    """Synchronous structural checks. Returns a list of human-readable failures
    (empty = ok). The breached-password screen is separate (async, network)."""
    errs = []
    pw = pw or ""
    if len(pw) < policy.get("min_length", 12):
        errs.append(f"be at least {policy.get('min_length', 12)} characters")
    if policy.get("require_upper") and not any(c.isupper() for c in pw):
        errs.append("include an uppercase letter")
    if policy.get("require_lower") and not any(c.islower() for c in pw):
        errs.append("include a lowercase letter")
    if policy.get("require_digit") and not any(c.isdigit() for c in pw):
        errs.append("include a number")
    if policy.get("require_symbol") and not any(c in _SYMBOLS for c in pw):
        errs.append("include a symbol")
    return errs


async def is_breached(pw: str) -> bool:
    """HIBP Pwned Passwords range API via k-anonymity: only the first 5 chars of the
    SHA-1 ever leave the box, and Add-Padding hides the count of matches. Raises on
    network error so the caller can apply fail-open/closed per policy."""
    import httpx
    sha1 = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    async with httpx.AsyncClient(timeout=8) as c:
        r = await c.get(f"https://api.pwnedpasswords.com/range/{prefix}",
                        headers={"Add-Padding": "true"})
        r.raise_for_status()
    for line in r.text.splitlines():
        h, _, cnt = line.partition(":")
        if h.strip() == suffix and cnt.strip() not in ("0", "00000"):
            return True
    return False


async def check_password(db, pw: str, *, policy: dict = None) -> None:
    """Full check: structural policy + breached screen. Raises ValueError(message)
    on the first failing rule, ready to become an HTTP 400."""
    policy = policy or await get_password_policy(db)
    errs = validate_password(pw, policy)
    if errs:
        raise ValueError("Password must " + "; ".join(errs) + ".")
    if policy.get("breached_check"):
        try:
            if await is_breached(pw):
                raise ValueError("That password appears in known data breaches — choose a different one.")
        except ValueError:
            raise
        except Exception as e:
            logger.warning("HIBP breach check failed (%s); %s", e,
                           "blocking (fail-closed)" if policy.get("breached_fail_closed") else "allowing (fail-open)")
            if policy.get("breached_fail_closed"):
                raise ValueError("Could not verify the password against the breach database — try again shortly.")


def mfa_required_for(role: str, policy: dict) -> bool:
    return role in (policy.get("mfa_required_roles") or [])
