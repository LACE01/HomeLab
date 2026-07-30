"""One place that decides HOW to talk to OpenCTI.

There are four independent callers of OpenCTI in this codebase (the CTI hub
report sync, the recon per-target lookup, the threat-intel watchlist feed, and
the Test Connection ping). They were each building the URL and the headers
themselves, and they had drifted:

  * Test Connection respected an endpoint that already names the GraphQL path,
    e.g. "https://host/public/graphql".
  * The other three appended "/graphql" unconditionally, turning that same
    endpoint into "https://host/public/graphql/graphql" -- a path that does not
    exist.

That drift produces the worst possible failure mode: Test Connection goes green
and every actual sync fails, so the operator concludes the credentials are fine
and goes looking for the problem somewhere else entirely.

Every caller now builds its request here, so the URL and headers cannot diverge
again, and adding a header (a User-Agent, a new Access header) is one edit.
"""
from typing import Optional

from cf_diagnostics import api_headers

# The default GraphQL route in a stock OpenCTI install.
DEFAULT_PATH = "/graphql"

# Paths a real deployment might expose instead. A reverse proxy or Cloudflare
# Tunnel commonly forwards only one specific route, and it is not always the
# default one -- so if the configured endpoint already names a GraphQL path, it
# is the operator telling us where their API actually lives, and we must not
# "helpfully" append to it.
_GRAPHQL_SUFFIXES = ("/graphql", "/graphql/", "/public/graphql")


def graphql_url(endpoint: str) -> str:
    """The URL to POST a GraphQL query to, for a configured endpoint.

    Accepts either a bare base URL ("https://host") or a fully-specified GraphQL
    endpoint ("https://host/public/graphql"), and never double-appends.
    """
    endpoint = (endpoint or "").strip().rstrip("/")
    if not endpoint:
        return ""
    lowered = endpoint.lower()
    if any(lowered.endswith(s.rstrip("/")) for s in _GRAPHQL_SUFFIXES):
        return endpoint
    return endpoint + DEFAULT_PATH


def headers(cfg: dict) -> dict:
    """Auth + Cloudflare Access headers for an OpenCTI integration config.

    The descriptive User-Agent comes from cf_diagnostics: httpx's default
    ("python-httpx/x.y") is precisely what Cloudflare's "definitely automated"
    bot rules key on, and a request that looks like a scraper gets challenged
    before Access ever sees the service token.
    """
    h = api_headers({
        "Authorization": f"Bearer {cfg.get('api_key') or ''}",
        "Content-Type": "application/json",
    })
    if cfg.get("cf_access_client_id"):
        h["CF-Access-Client-Id"] = cfg["cf_access_client_id"]
    if cfg.get("cf_access_client_secret"):
        h["CF-Access-Client-Secret"] = cfg["cf_access_client_secret"]
    return h


def token_sent(cfg: dict) -> bool:
    """Whether a COMPLETE Access service token went out.

    Both halves are required — an ID with no secret is not a token, and
    reporting "a token was sent" when only half of one was configured sends the
    operator to inspect Access policies for a token Cloudflare never saw.
    """
    return bool(cfg.get("cf_access_client_id") and cfg.get("cf_access_client_secret"))


def request_parts(cfg: dict) -> tuple:
    """(url, headers, token_sent) for a config, so a caller is one line."""
    return graphql_url(cfg.get("endpoint") or ""), headers(cfg), token_sent(cfg)


def describe_target(cfg: dict) -> Optional[str]:
    """The exact URL being called, for diagnostics and log lines. Callers show
    this to the operator so they can match it against the path in their
    Cloudflare Security Events log -- which is how a path mismatch gets found."""
    url = graphql_url(cfg.get("endpoint") or "")
    return url or None
