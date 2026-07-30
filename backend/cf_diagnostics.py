"""Classify WHICH layer refused a request to a Cloudflare-fronted integration.

A request to something behind Cloudflare passes through several independent
gates, and each one fails in a way that looks superficially identical -- an HTTP
error with an HTML body. Dumping that body into a toast ("OpenCTI HTTP 403:
<!DOCTYPE html><html lang=...") tells the operator nothing about which gate said
no, so they end up re-checking Access service tokens when the request never
reached Access at all.

The gates, in the order a request meets them:

  1. CDN edge bot protection -- Super Bot Fight Mode, Browser Integrity Check,
     WAF managed/custom rules, or "I'm Under Attack" security level. Signature:
     an interstitial titled "Just a moment...", or a `cf-mitigated: challenge`
     header, usually with 403 or 503. THIS RUNS BEFORE ACCESS. No service token
     can satisfy it, because it wants a browser to execute JavaScript, and an
     API client never will.
  2. Cloudflare Access (Zero Trust) -- signature: a 302 to
     <team>.cloudflareaccess.com or /cdn-cgi/access/login, or a 403 whose body
     mentions Access. Fixed with a service token AND a policy whose action is
     Service Auth.
  3. The origin application -- a normal API response: JSON, a 401/403 from the
     app's own auth, or a GraphQL `errors` array. This is the only layer where
     the app's API key matters.

Getting this distinction right is the difference between a five-minute fix and
an afternoon of changing the wrong setting.
"""
import re
from typing import Optional

CHALLENGE_TITLES = (
    "just a moment",
    "attention required",
    "checking your browser",
    "please wait",
    "one more step",
    "enable javascript and cookies to continue",
)

CHALLENGE_MARKERS = (
    "cf-browser-verification",
    "cf_chl_opt",
    "challenge-platform",
    "/cdn-cgi/challenge-platform",
    "turnstile",
    "__cf_chl",
    "cf-please-wait",
    "ray id",
)

ACCESS_MARKERS = (
    "cloudflareaccess.com",
    "/cdn-cgi/access/login",
    "cf_authorization",
)

LAYER_EDGE = "cloudflare_edge_challenge"
LAYER_ACCESS = "cloudflare_access"
LAYER_ORIGIN = "origin_app"
LAYER_TRANSPORT = "transport"
LAYER_OK = "ok"


def _headers_lower(headers) -> dict:
    try:
        return {str(k).lower(): str(v) for k, v in dict(headers).items()}
    except Exception:
        return {}


def looks_like_challenge(status_code: int, body: str, headers: dict) -> bool:
    """Cloudflare's own challenge interstitial, as opposed to any other HTML error."""
    h = _headers_lower(headers)
    # The most reliable signal: Cloudflare sets this when it mitigates a request.
    if "challenge" in (h.get("cf-mitigated") or "").lower():
        return True
    text = (body or "")[:8000].lower()
    if not text:
        return False
    title = ""
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.S)
    if m:
        title = m.group(1).strip()
    if any(t in title for t in CHALLENGE_TITLES):
        return True
    # Body markers, but only when the response actually came from Cloudflare and
    # is an error -- otherwise a page that merely mentions "turnstile" would trip.
    served_by_cf = "cloudflare" in (h.get("server") or "").lower() or "cf-ray" in h
    if served_by_cf and status_code in (403, 429, 503) and any(k in text for k in CHALLENGE_MARKERS):
        return True
    return False


def looks_like_access_gate(status_code: int, body: str, headers: dict, location: str = "") -> bool:
    h = _headers_lower(headers)
    loc = (location or h.get("location") or "").lower()
    if any(m in loc for m in ACCESS_MARKERS):
        return True
    text = (body or "")[:8000].lower()
    if status_code in (401, 403) and any(m in text for m in ACCESS_MARKERS):
        return True
    return False


def classify_response(response, *, service_name: str = "the integration",
                       token_sent: bool = False, client_id: Optional[str] = None) -> dict:
    """Return {layer, ok, title, message, remediation[], evidence} for a response.

    `response` is anything with .status_code, .text and .headers (httpx/requests)."""
    status = getattr(response, "status_code", 0)
    headers = getattr(response, "headers", {}) or {}
    h = _headers_lower(headers)
    try:
        body = response.text or ""
    except Exception:
        body = ""
    location = h.get("location", "")
    cf_ray = h.get("cf-ray")
    evidence = {
        "status_code": status,
        "cf_ray": cf_ray,
        "cf_mitigated": h.get("cf-mitigated"),
        "server": h.get("server"),
        "content_type": h.get("content-type"),
        "location": location[:200] if location else None,
        "body_snippet": body[:300] if body else None,
    }

    # ---- 1. edge challenge: runs BEFORE Access, so tokens are irrelevant here
    if looks_like_challenge(status, body, headers):
        id_hint = (f" (a service token ending '{client_id[-8:]}' WAS sent, but it can't help here)"
                   if token_sent and client_id else "")
        return {
            "layer": LAYER_EDGE, "ok": False,
            "title": "Blocked by Cloudflare's bot protection, before it reached Access or the app",
            "message": (
                f"Cloudflare returned its browser-challenge page (\"Just a moment…\") with HTTP {status} "
                f"instead of passing the request to {service_name}{id_hint}. This challenge is served at "
                "the CDN edge and expects a real browser to run JavaScript, so an API client can never "
                "pass it — and it happens BEFORE Cloudflare Access evaluates any service token. Your "
                "Access policies are not the problem here; the request never got that far."),
            "remediation": [
                "In the Cloudflare dashboard for this zone: Security → Bots. If Super Bot Fight Mode has "
                "\"Definitely automated\" set to Block or Managed Challenge, that is almost certainly what "
                "is stopping this — an API client is by definition 'definitely automated'.",
                "Also check Security → Settings → Browser Integrity Check, and whether the zone's Security "
                "Level is set to 'I'm Under Attack'. Both challenge non-browser clients.",
                "Cleanest fix that keeps protection on: Security → WAF → Tools → IP Access Rules, add this "
                "server's public egress IP with action Allow. An IP Access Rule 'Allow' skips Bot Fight Mode "
                "and Browser Integrity Check but still leaves Cloudflare Access enforcing your service token.",
                "Alternative: Security → WAF → Custom rules → create a rule matching this hostname and path "
                "(e.g. http.host eq \"opencti.example.net\" and http.request.uri.path eq \"/graphql\") with "
                "action Skip, and tick Super Bot Fight Mode + Browser Integrity Check under the skip options.",
                "Verify from the server with: curl -sS -o /dev/null -w '%{http_code}\\n' -X POST "
                "https://<host>/graphql -H 'Content-Type: application/json' --data '{\"query\":\"{about{version}}\"}' "
                "— if you still get 403 with a 'Just a moment' body, it is still the edge, not Access.",
            ],
            "evidence": evidence,
        }

    # ---- 2. Access
    if status in (301, 302, 303, 307, 308) or looks_like_access_gate(status, body, headers, location):
        if token_sent:
            id_hint = f" ending '{client_id[-8:]}'" if client_id and len(client_id) > 8 else ""
            return {
                "layer": LAYER_ACCESS, "ok": False,
                "title": "Cloudflare Access rejected the service token",
                "message": (
                    f"A service token{id_hint} was sent, and Cloudflare Access still refused the request "
                    f"(HTTP {status}). The token existing under Access → Service Auth is not enough on its "
                    "own — a policy has to accept it."),
                "remediation": [
                    "Zero Trust → Access → Applications → your app → Policies: the policy must have an "
                    "Include rule of type 'Service Auth' selecting this token, and the policy ACTION must be "
                    "'Service Auth' — not 'Allow'. An Allow policy expects a human identity and will keep "
                    "bouncing a token.",
                    "Confirm the application's domain/path actually covers the URL being called "
                    "(a policy on example.net won't cover example.net/graphql if the app is scoped to a "
                    "different path).",
                    "Check the token hasn't expired: Zero Trust → Access → Service Auth shows an expiry date.",
                ],
                "evidence": evidence,
            }
        return {
            "layer": LAYER_ACCESS, "ok": False,
            "title": "Cloudflare Access is protecting this endpoint and no service token was sent",
            "message": (
                f"The request was sent to the Access login flow (HTTP {status}) and this integration has no "
                "CF-Access service token saved."),
            "remediation": [
                "Zero Trust → Access → Service Auth: create a service token, then paste its Client ID and "
                "Client Secret into this integration's configuration and save.",
                "Then add an Access policy on the application with an Include rule of type 'Service Auth' "
                "selecting that token, with the policy action set to 'Service Auth'.",
            ],
            "evidence": evidence,
        }

    # ---- 3. origin app
    if status == 200:
        ctype = (h.get("content-type") or "").lower()
        # Trust the BODY over the header: proxies and tunnels sometimes rewrite or
        # drop content-type, and refusing a response whose body is perfectly good
        # JSON would be a false alarm. Only complain when it genuinely isn't JSON.
        body_is_json = False
        if body:
            stripped = body.lstrip()
            if stripped[:1] in ("{", "["):
                try:
                    import json as _json
                    _json.loads(body)
                    body_is_json = True
                except Exception:
                    body_is_json = False
        if "json" not in ctype and not body_is_json:
            return {
                "layer": LAYER_EDGE if "cloudflare" in (h.get("server") or "").lower() else LAYER_ORIGIN,
                "ok": False,
                "title": "Got HTML where JSON was expected",
                "message": (
                    f"{service_name} answered HTTP 200 but with content-type '{ctype or 'unknown'}' rather "
                    "than JSON. That usually means something in front of the app (a login page, a proxy "
                    "error page, or a challenge served with a 200) answered instead of the API."),
                "remediation": [
                    "Confirm the endpoint URL points at the API path, not the web UI.",
                    "If the body looks like a Cloudflare page, treat this as edge filtering and follow the "
                    "bot-protection steps above.",
                ],
                "evidence": evidence,
            }
        return {"layer": LAYER_OK, "ok": True, "title": "Reachable",
                "message": f"{service_name} responded normally.", "remediation": [], "evidence": evidence}

    if status in (401, 403):
        return {
            "layer": LAYER_ORIGIN, "ok": False,
            "title": f"{service_name} itself rejected the credentials",
            "message": (
                f"The request reached {service_name} (HTTP {status}, and the response is not a Cloudflare "
                "page), so Cloudflare let it through and the application's own authentication refused it."),
            "remediation": [
                f"Check the API key/token configured for {service_name} — regenerate it if unsure.",
                "Confirm the account behind the token still has permission to read the data being requested.",
            ],
            "evidence": evidence,
        }

    if status in (502, 503, 504):
        return {
            "layer": LAYER_ORIGIN, "ok": False,
            "title": f"{service_name} is unreachable or unhealthy",
            "message": f"HTTP {status} — Cloudflare reached the origin but the application did not answer properly.",
            "remediation": [
                "Check the application is running and its tunnel/origin is healthy.",
                "If this is intermittent, retry — the platform's own callers back off automatically.",
            ],
            "evidence": evidence,
        }

    return {
        "layer": LAYER_ORIGIN, "ok": False,
        "title": f"{service_name} returned HTTP {status}",
        "message": f"HTTP {status}. {(body or '')[:200]}",
        "remediation": ["Check the endpoint URL and the application's own logs."],
        "evidence": evidence,
    }


def classify_exception(exc: Exception, *, service_name: str = "the integration") -> dict:
    return {
        "layer": LAYER_TRANSPORT, "ok": False,
        "title": f"Could not reach {service_name}",
        "message": f"{type(exc).__name__}: {exc}",
        "remediation": [
            "Check the endpoint hostname resolves and is reachable from this server.",
            "If the host is behind a Cloudflare Tunnel, confirm the tunnel is up.",
        ],
        "evidence": {"exception": type(exc).__name__},
    }


def summary_line(verdict: dict) -> str:
    """One-line form for logs and exception messages -- keeps the actionable part
    and drops the HTML that made the old errors useless."""
    first = (verdict.get("remediation") or [""])[0]
    return f"{verdict['title']}. {verdict['message']}" + (f" Start here: {first}" if first else "")


# Every outbound call should identify itself. httpx otherwise sends
# "python-httpx/x.y", which is exactly the kind of client bot protection blocks --
# a descriptive UA won't defeat a real challenge, but it stops us looking like a
# scraper to rules that key on a missing/default agent.
USER_AGENT = "Nightwatch-VulnMgmt/1.0 (+self-hosted security platform; API client)"


def api_headers(extra: Optional[dict] = None) -> dict:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if extra:
        headers.update(extra)
    return headers
