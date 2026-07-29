"""Shared certificate-transparency client (item 35).

Three places wanted CT data -- EASM subdomain discovery, the CTI hub's cert
monitoring, and External Checks' technical posture panel -- and each had (or was
about to grow) its own crt.sh call with its own failure behaviour. This is the
one client they all use.

What it fixes, concretely, from the reported EASM errors:

  * crt.sh rate-limits and 502s under load. A single attempt then hard-failing
    made "EASM Subdomain Discovery" look permanently broken when it was just
    busy. Now: retry with exponential backoff + jitter.
  * A domain with no certificates, or a query that legitimately returns nothing,
    is CLEAN (zero results) -- not an error. That distinction is now explicit in
    the return value so callers can report HEALTHY instead of ERROR.
  * crt.sh intermittently answers HTML (a maintenance page) with HTTP 200. That
    used to surface as an opaque JSON parse error; it's now recognized and
    retried, and falls back to a second source.
  * Errors carried a truncated message. CTError keeps the full text.

Fallback source: certspotter's public API covers the same logs with a different
front end, so a crt.sh outage degrades to reduced coverage rather than nothing.
"""
import asyncio
import logging
import random
from typing import Optional

logger = logging.getLogger("vulnops.ct_service")

CRTSH_URL = "https://crt.sh/"
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"

DEFAULT_ATTEMPTS = 3
BASE_BACKOFF = 2.0


class CTError(Exception):
    """Carries the FULL upstream message -- callers used to truncate this and
    leave operators guessing what actually went wrong."""

    def __init__(self, message: str, *, source: str = "", status_code: Optional[int] = None):
        super().__init__(message)
        self.message = message
        self.source = source
        self.status_code = status_code


def _normalize_crtsh(rows: list) -> list:
    out = []
    for r in rows:
        out.append({
            "id": str(r.get("id") or ""),
            "common_name": r.get("common_name"),
            "name_value": r.get("name_value") or "",
            "issuer_name": r.get("issuer_name"),
            "not_before": r.get("not_before"),
            "not_after": r.get("not_after"),
            "source": "crt.sh",
        })
    return out


def _normalize_certspotter(rows: list) -> list:
    out = []
    for r in rows:
        names = r.get("dns_names") or []
        issuer = (r.get("issuer") or {}).get("name")
        out.append({
            "id": str(r.get("id") or ""),
            "common_name": names[0] if names else None,
            "name_value": "\n".join(names),
            "issuer_name": issuer,
            "not_before": r.get("not_before"),
            "not_after": r.get("not_after"),
            "source": "certspotter",
        })
    return out


async def _try_crtsh(domain: str, timeout: float) -> list:
    import httpx
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                  headers={"User-Agent": "Nightwatch-CT/1.0 (self-hosted security platform)"}) as c:
        r = await c.get(CRTSH_URL, params={"q": f"%.{domain}", "output": "json"})
    if r.status_code == 404:
        return []                      # nothing logged for this domain -- clean, not an error
    if r.status_code in (429, 502, 503, 504):
        raise CTError(f"crt.sh is busy (HTTP {r.status_code}): {r.text[:500]}",
                      source="crt.sh", status_code=r.status_code)
    if r.status_code != 200:
        raise CTError(f"crt.sh HTTP {r.status_code}: {r.text[:1000]}",
                      source="crt.sh", status_code=r.status_code)
    body = (r.text or "").strip()
    if not body:
        return []
    if body[0] not in "[{":
        # HTML maintenance/error page served with a 200 -- retryable, and the
        # old code surfaced this as an unhelpful JSON decode error.
        raise CTError(f"crt.sh returned non-JSON (likely a maintenance page): {body[:500]}",
                      source="crt.sh", status_code=200)
    try:
        return _normalize_crtsh(r.json())
    except Exception as e:
        raise CTError(f"crt.sh returned unparseable JSON ({e}): {body[:500]}", source="crt.sh")


async def _try_certspotter(domain: str, timeout: float) -> list:
    import httpx
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                  headers={"User-Agent": "Nightwatch-CT/1.0"}) as c:
        r = await c.get(CERTSPOTTER_URL, params={
            "domain": domain, "include_subdomains": "true", "expand": "dns_names", "match_wildcards": "true"})
    if r.status_code == 404:
        return []
    if r.status_code == 429:
        raise CTError(f"certspotter rate limit (429): {r.text[:500]}", source="certspotter", status_code=429)
    if r.status_code != 200:
        raise CTError(f"certspotter HTTP {r.status_code}: {r.text[:1000]}",
                      source="certspotter", status_code=r.status_code)
    try:
        return _normalize_certspotter(r.json())
    except Exception as e:
        raise CTError(f"certspotter returned unparseable JSON ({e}): {r.text[:500]}", source="certspotter")


async def fetch_certificates(domain: str, *, attempts: int = DEFAULT_ATTEMPTS,
                              timeout: float = 45.0, use_fallback: bool = True) -> list:
    """Certificates for a domain, with retry/backoff and a fallback source.

    Returns a (possibly empty) list. An empty list means "no certificates found",
    which is a CLEAN result. Raises CTError only when every source and attempt
    genuinely failed -- and the message is complete, not truncated."""
    domain = (domain or "").strip().lower().lstrip("*.")
    if not domain:
        raise CTError("No domain supplied", source="ct_service")

    last: Optional[CTError] = None
    for attempt in range(1, attempts + 1):
        try:
            return await _try_crtsh(domain, timeout)
        except CTError as e:
            last = e
            logger.warning("crt.sh attempt %s/%s for %s failed: %s", attempt, attempts, domain, e.message)
            if attempt < attempts:
                # exponential backoff with jitter -- a fleet of domains retrying
                # in lockstep is how you turn a blip into a sustained outage
                await asyncio.sleep(BASE_BACKOFF * (2 ** (attempt - 1)) + random.uniform(0, 1.0))
        except Exception as e:  # transport-level
            last = CTError(f"crt.sh transport error: {type(e).__name__}: {e}", source="crt.sh")
            logger.warning("crt.sh attempt %s/%s for %s errored: %s", attempt, attempts, domain, last.message)
            if attempt < attempts:
                await asyncio.sleep(BASE_BACKOFF * (2 ** (attempt - 1)) + random.uniform(0, 1.0))

    if use_fallback:
        try:
            logger.info("crt.sh exhausted for %s -- falling back to certspotter", domain)
            return await _try_certspotter(domain, timeout)
        except CTError as e:
            raise CTError(
                f"All certificate-transparency sources failed for {domain}. "
                f"crt.sh: {last.message if last else 'n/a'} | certspotter: {e.message}",
                source="ct_service")
        except Exception as e:
            raise CTError(
                f"All certificate-transparency sources failed for {domain}. "
                f"crt.sh: {last.message if last else 'n/a'} | certspotter transport error: "
                f"{type(e).__name__}: {e}", source="ct_service")
    raise last or CTError(f"Certificate-transparency lookup failed for {domain}", source="ct_service")


async def fetch_hostnames(domain: str, **kwargs) -> list:
    """Just the distinct subdomain hostnames -- what EASM discovery wants."""
    certs = await fetch_certificates(domain, **kwargs)
    hosts = set()
    for c in certs:
        for n in (c.get("name_value") or "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n and n.endswith(domain) and n != domain:
                hosts.add(n)
    return sorted(hosts)
