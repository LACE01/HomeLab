"""recon-ng OSINT module runner -- broader threat-intel + passive-recon module support
on top of the existing EASM (crt.sh subdomain discovery) and Nmap/Nikto active-scan
integrations.

Architecture note up front, since this is the most "glue code shells out to a
whole external framework" integration in the app: recon-ng is a large, separately
versioned OSINT tool whose exact module catalog / CLI flags can drift release to
release, and it isn't installed in the sandbox this was built in -- so unlike the
Nmap/Nikto integrations (which reuse a pattern already proven against real running
containers in this app), the actual subprocess execution here has only been verified
with a mocked recon-cli, not a real one. The module catalog below is deliberately kept
to recon-ng's longest-standing, most commonly documented modules; treat the first
real run on your server as a smoke test, and check `recon-cli -m <module> --show`
inside the container if a specific module errors out, since the exact option name
recon-ng expects can vary by version.

Every module run happens in its own disposable workspace (named after the run id),
driven via recon-cli's real non-interactive flags -- NOT a `.rc` resource file passed
with `-r`, which was this module's original approach and is flatly wrong: `-r` is a
flag on the separate interactive `recon-ng` binary, not on `recon-cli` at all (confirmed
by reading recon-cli's actual argument parser). recon-cli's real flags, and the fixed
order it applies them in regardless of how they're interleaved on the command line:
`-C` global command (repeatable, runs before module load -- used here for `keys add`
and `marketplace install`) -> `-m` module (loads exactly ONE module per invocation,
so a module run and a report export are two separate recon-cli calls) -> `-c` module
command (repeatable) -> `-o name=value` module option (repeatable) -> `-x` execute.
So each module run is:
  1. Call 1: `-C keys add <name> <value>` (per required key) + `-C marketplace install
     <module_path>` + `-m <module_path>` + `-o SOURCE=<target>` + `-x`
  2. Call 2: `-C marketplace install reporting/json` + `-m reporting/json` +
     `-o FILENAME=<path>` + `-x` -- dumps the whole workspace db (hosts/contacts/
     credentials/etc.) to JSON
The workspace is deleted after the report is read back, win or lose.

Results get routed by which recon-ng db table the module populates:
  - "hosts"  -> fed into the same easm_candidates queue as the existing crt.sh-based
                EASM discovery, so a new subdomain shows up in one place to review/
                promote regardless of which tool found it.
  - "credentials"/"contacts" -> stored in db.osint_findings; a genuine breach/paste
                hit also dispatches the osint_exposure_found notification trigger,
                since that's actionable in a way "we found a WHOIS contact" isn't.
"""
import asyncio
import json
import os
import re
import shlex
import tempfile
import uuid
from datetime import datetime, timezone

MODULE_CATALOG = [
    {
        "id": "hackertarget", "module": "recon/domains-hosts/hackertarget",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "hosts", "label": "HackerTarget Host Search",
        "description": "Passive subdomain/host discovery via HackerTarget's free API.",
    },
    {
        "id": "bing_domain_web", "module": "recon/domains-hosts/bing_domain_web",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "hosts", "label": "Bing Domain Search",
        "description": "Subdomain discovery by scraping Bing search results for the domain.",
    },
    {
        "id": "resolve", "module": "recon/hosts-hosts/resolve",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "hosts", "label": "Resolve Hosts",
        "description": "Resolves hostnames already in the workspace to IP addresses.",
    },
    {
        "id": "whois_pocs", "module": "recon/domains-contacts/whois_pocs",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "contacts", "label": "WHOIS Contacts",
        "description": "Harvests point-of-contact names/emails from WHOIS registration records.",
    },
    # --- Additional free, no-key domain->hosts/contacts sources -- all confirmed
    # against the real recon-ng-marketplace module catalog (not guessed paths).
    {
        "id": "certificate_transparency", "module": "recon/domains-hosts/certificate_transparency",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "hosts", "label": "Certificate Transparency Search",
        "description": "Searches crt.sh certificate transparency logs for hosts on this domain -- recon-ng-native version of the same crt.sh source the EASM page already uses, so it shows up in one place either way.",
    },
    {
        "id": "google_site_web", "module": "recon/domains-hosts/google_site_web",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "hosts", "label": "Google Hostname Search",
        "description": "Harvests hosts from Google.com using the 'site:' search operator.",
    },
    {
        "id": "netcraft", "module": "recon/domains-hosts/netcraft",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "hosts", "label": "Netcraft Hostname Search",
        "description": "Harvests hosts for this domain from Netcraft.com.",
    },
    {
        "id": "threatcrowd", "module": "recon/domains-hosts/threatcrowd",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "hosts", "label": "ThreatCrowd DNS Lookup",
        "description": "Discovers hosts/subdomains via ThreatCrowd's passive DNS API.",
    },
    {
        "id": "threatminer", "module": "recon/domains-hosts/threatminer",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "hosts", "label": "ThreatMiner DNS Lookup",
        "description": "Discovers subdomains via the ThreatMiner passive-DNS API.",
    },
    {
        "id": "ssl_san", "module": "recon/domains-hosts/ssl_san",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "hosts", "label": "SSL SAN Lookup",
        "description": "Reads the Subject Alternative Names off this domain's TLS certificate to find related hostnames.",
    },
    {
        "id": "pgp_search", "module": "recon/domains-contacts/pgp_search",
        "category": "recon", "target_type": "domain", "requires_keys": [],
        "result_table": "contacts", "label": "PGP Key Owner Search",
        "description": "Searches public PGP key servers for email addresses registered under this domain.",
    },
    # --- IP-address targeted modules ---
    {
        "id": "reverse_resolve", "module": "recon/hosts-hosts/reverse_resolve",
        "category": "recon", "target_type": "ip", "requires_keys": [],
        "result_table": "hosts", "label": "Reverse DNS (PTR) Lookup",
        "description": "Resolves an IP address back to any hostname(s) pointing at it via a reverse DNS (PTR) query.",
    },
    # --- Threat intel: breach/paste exposure -- direct HaveIBeenPwned API calls
    # (previously routed through the flaky recon-cli subprocess like every other
    # entry in this catalog; upgraded to the same direct-API "source" pattern as
    # OpenCTI/GreyNoise/OTX/abuse.ch below, since HIBP's real v3 REST API is simple
    # enough not to need recon-ng's module wrapper at all. Reuses the api_key from
    # Integrations → HaveIBeenPwned -- the same connector hibp_domain.py's org-wide
    # domain sync uses -- instead of the old recon-ng-specific hibp_api_key.) ---
    {
        "id": "hibp_breach", "module": None, "source": "hibp_breach",
        "category": "threat-intel", "target_type": "email", "requires_keys": [],
        "result_table": "credentials", "label": "HaveIBeenPwned — Breaches",
        "description": "Checks a contact email against known breach databases via the HIBP API.",
    },
    {
        "id": "hibp_paste", "module": None, "source": "hibp_paste",
        "category": "threat-intel", "target_type": "email", "requires_keys": [],
        "result_table": "credentials", "label": "HaveIBeenPwned — Pastes",
        "description": "Checks a contact email against public paste-site exposure via the HIBP API.",
    },
    # --- Threat intel: sourced from our own OpenCTI instance, not recon-ng at all.
    # These reuse the OpenCTI connection already configured under Integrations ->
    # OpenCTI (endpoint/api_key/CF-Access token), so "ready" for these depends on
    # that integration being configured, not on a recon-ng API key.
    {
        "id": "opencti_domain", "module": None, "source": "opencti",
        "category": "threat-intel", "target_type": "domain", "requires_keys": [],
        "result_table": "credentials", "label": "OpenCTI — Domain/IOC Lookup",
        "description": "Checks this domain against observables and indicators already tracked in your OpenCTI instance.",
    },
    {
        "id": "opencti_ip", "module": None, "source": "opencti",
        "category": "threat-intel", "target_type": "ip", "requires_keys": [],
        "result_table": "credentials", "label": "OpenCTI — IP/IOC Lookup",
        "description": "Checks this IP address against observables and indicators already tracked in your OpenCTI instance.",
    },
    # --- Threat intel: three more direct-API lookups, same pattern as OpenCTI above --
    # not recon-ng modules, "ready" depends on that connector's own config under
    # Integrations rather than a recon-ng API key.
    {
        "id": "greynoise_ip", "module": None, "source": "greynoise",
        "category": "threat-intel", "target_type": "ip", "requires_keys": [],
        "result_table": "credentials", "label": "GreyNoise — IP Classification",
        "description": "Checks whether this IP is known internet-scanning noise or a legitimate business service (GreyNoise RIOT), via GreyNoise's Community API.",
    },
    {
        "id": "otx_domain", "module": None, "source": "otx",
        "category": "threat-intel", "target_type": "domain", "requires_keys": [],
        "result_table": "credentials", "label": "AlienVault OTX — Domain Pulses",
        "description": "Checks this domain against AlienVault OTX threat-intel pulses (community-submitted IOC reports).",
    },
    {
        "id": "otx_ip", "module": None, "source": "otx",
        "category": "threat-intel", "target_type": "ip", "requires_keys": [],
        "result_table": "credentials", "label": "AlienVault OTX — IP Pulses",
        "description": "Checks this IP address against AlienVault OTX threat-intel pulses (community-submitted IOC reports).",
    },
    {
        "id": "abusech_domain", "module": None, "source": "abusech",
        "category": "threat-intel", "target_type": "domain", "requires_keys": [],
        "result_table": "credentials", "label": "abuse.ch ThreatFox — Domain IOC Search",
        "description": "Searches ThreatFox for this domain as a known malware C2/delivery indicator.",
    },
    {
        "id": "abusech_ip", "module": None, "source": "abusech",
        "category": "threat-intel", "target_type": "ip", "requires_keys": [],
        "result_table": "credentials", "label": "abuse.ch ThreatFox — IP IOC Search",
        "description": "Searches ThreatFox for this IP address as a known malware C2/delivery indicator.",
    },
    # --- Threat intel: VirusTotal multi-engine reputation -- same direct-API "source"
    # pattern as OpenCTI/GreyNoise/OTX/abuse.ch above, not a recon-ng module. Requires
    # its own api_key under Integrations → VirusTotal.
    {
        "id": "vt_domain", "module": None, "source": "virustotal",
        "category": "threat-intel", "target_type": "domain", "requires_keys": [],
        "result_table": "credentials", "label": "VirusTotal — Domain Reputation",
        "description": "Checks this domain against VirusTotal's aggregated multi-engine detections.",
    },
    {
        "id": "vt_ip", "module": None, "source": "virustotal",
        "category": "threat-intel", "target_type": "ip", "requires_keys": [],
        "result_table": "credentials", "label": "VirusTotal — IP Reputation",
        "description": "Checks this IP address against VirusTotal's aggregated multi-engine detections.",
    },
    {
        "id": "vt_hash", "module": None, "source": "virustotal",
        "category": "threat-intel", "target_type": "hash", "requires_keys": [],
        "result_table": "credentials", "label": "VirusTotal — File Hash Reputation",
        "description": "Checks a file hash (MD5/SHA1/SHA256) against VirusTotal's aggregated multi-engine detections.",
    },
]

MODULE_BY_ID = {m["id"]: m for m in MODULE_CATALOG}
# Maps our config key name -> the key name recon-ng's own modules actually look up.
# recon-ng doesn't validate `keys add <name>` against anything, so a mismatched name
# here fails silently at module-run time instead of at config time.
RECON_KEY_NAME = {"hibp_api_key": "hibp_api"}
ALL_REQUIRED_KEYS = sorted({k for m in MODULE_CATALOG for k in m["requires_keys"]})
TARGET_TYPES = ["domain", "ip", "email", "hash"]

TARGET_RE = re.compile(r"^[a-zA-Z0-9.@_\-]{1,255}$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_target(target: str) -> str:
    target = (target or "").strip()
    if not target:
        raise ValueError("Target is required")
    if not TARGET_RE.match(target):
        raise ValueError(f"'{target}' doesn't look like a valid domain/email/hostname")
    return target


async def _run_recon_cli(args: list, timeout_sec: int = 300) -> str:
    """The one function that actually shells out to recon-ng, via `recon-cli <args>`.
    Kept tiny and isolated so tests can mock just this and exercise the real parsing/
    routing logic around it. Returns the combined stdout+stderr text -- previously
    this was captured and then thrown away entirely, so a failed run (bad module path,
    no network egress to the marketplace index, a crash on startup) produced zero
    diagnostic information: just a guessed list of possible causes with nothing to
    tell you which one it actually was. Callers should fold this into any error they
    raise. NOTE: `args` are real recon-cli flags (-w/-C/-m/-c/-o/-x) -- there is no
    `-r` resource-file flag on recon-cli (that's an interactive-`recon-ng`-only flag)."""
    cmd = ["recon-cli"] + args
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"recon-ng module exceeded {timeout_sec}s and was killed")
    combined = (stdout or b"").decode(errors="replace") + (stderr or b"").decode(errors="replace")
    if proc.returncode not in (0, None):
        # recon-ng returns non-zero on plenty of benign conditions (module warns,
        # zero results) -- only surface this as a hint, don't hard-fail on it,
        # since the real signal is whether the report file below is readable.
        pass
    return combined


async def _cleanup_workspace(workspace: str) -> None:
    try:
        cmd = ["recon-cli", "-C", f"workspaces remove {shlex.quote(workspace)}"]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(proc.communicate(), timeout=30)
    except Exception:
        pass  # best-effort -- a leftover workspace is harmless clutter, not a failure


async def run_opencti_lookup(target: str) -> list:
    """Queries our existing OpenCTI integration (Integrations -> OpenCTI -- same
    endpoint/api_key/CF-Access config already used by the CVE-driven threat-intel
    panel on Finding Detail) for any observable matching `target`, plus whatever
    indicators/threat actors are linked to it. This is NOT a recon-ng module -- it's
    a direct GraphQL call against OpenCTI, routed through the same osint_findings
    pipeline as the other threat-intel modules so results show up in one place
    regardless of which source found them.
    Raises ValueError if OpenCTI isn't configured, RuntimeError on a live API error."""
    import httpx
    from db import db as _db
    integration = await _db.integrations.find_one({"name": "OpenCTI"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint, api_key = cfg.get("endpoint"), cfg.get("api_key")
    if not endpoint or not api_key:
        raise ValueError("OpenCTI isn't configured yet -- add endpoint + api_key under Integrations → OpenCTI first.")

    query = (
        '{ stixCyberObservables(filters: {mode: and, filters: [{key: "value", values: ["'
        + target.replace('"', '')
        + '"]}], filterGroups: []}) { edges { node { id entity_type observable_value '
        'indicators { edges { node { name pattern valid_until } } } '
        'stixCoreRelationships { edges { node { relationship_type to { '
        '... on ThreatActor { name } ... on IntrusionSet { name } ... on Malware { name } } } } } '
        '} } } }'
    )
    from cf_diagnostics import api_headers, classify_response, classify_exception, summary_line
    headers = api_headers({"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
    if cfg.get("cf_access_client_id"):
        headers["CF-Access-Client-Id"] = cfg["cf_access_client_id"]
    if cfg.get("cf_access_client_secret"):
        headers["CF-Access-Client-Secret"] = cfg["cf_access_client_secret"]
    token_sent = bool(cfg.get("cf_access_client_id") and cfg.get("cf_access_client_secret"))

    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as c:
            r = await c.post(endpoint.rstrip("/") + "/graphql", headers=headers, json={"query": query})
    except httpx.HTTPError as e:
        raise RuntimeError(summary_line(classify_exception(e, service_name="OpenCTI")))
    verdict = classify_response(r, service_name="OpenCTI", token_sent=token_sent,
                                 client_id=cfg.get("cf_access_client_id"))
    if not verdict["ok"]:
        raise RuntimeError(summary_line(verdict))
    data = r.json()
    if data.get("errors"):
        raise RuntimeError(f"OpenCTI GraphQL error: {data['errors'][0].get('message', data['errors'])}")

    edges = ((data.get("data") or {}).get("stixCyberObservables") or {}).get("edges") or []
    rows = []
    for e in edges:
        node = e.get("node") or {}
        indicators = [
            (i["node"].get("name") or i["node"].get("pattern") or "")
            for i in (node.get("indicators") or {}).get("edges", [])
        ]
        rels = [
            f"{rr['node'].get('relationship_type')} → {(rr['node'].get('to') or {}).get('name', '?')}"
            for rr in (node.get("stixCoreRelationships") or {}).get("edges", [])
        ]
        if not indicators and not rels:
            continue  # a bare observable with no linked intel isn't actionable -- skip it
        rows.append({
            "table": "credentials",
            "resource": node.get("observable_value") or target,
            "name": f"OpenCTI: {node.get('entity_type', 'Observable')}",
            "password": None,
            "detail": f"Indicators: {', '.join(indicators) or 'none'}; Relationships: {', '.join(rels) or 'none'}",
        })
    return rows


async def run_greynoise_lookup(target: str) -> list:
    """GreyNoise Community API -- classifies an IP as internet-scanning "noise",
    a known-benign business service (RIOT), or neither. Free tier, no config beyond
    the API key (a 404 from GreyNoise just means "never observed", not an error)."""
    import httpx
    from db import db as _db
    integration = await _db.integrations.find_one({"name": "GreyNoise"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint, api_key = cfg.get("endpoint") or "https://api.greynoise.io", cfg.get("api_key")
    if not api_key:
        raise ValueError("GreyNoise isn't configured yet -- add an API key under Integrations → GreyNoise first.")

    url = f"{endpoint.rstrip('/')}/v3/community/{target}"
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(url, headers={"key": api_key})
    except httpx.HTTPError as e:
        raise RuntimeError(f"Could not reach GreyNoise: {e}")
    if r.status_code == 404:
        return []  # never observed by GreyNoise -- not an error, just nothing to report
    if r.status_code == 401:
        raise RuntimeError("GreyNoise rejected this API key (401) -- check it under Integrations → GreyNoise.")
    if r.status_code == 429:
        raise RuntimeError("GreyNoise community-tier rate limit hit (429) -- limited lookups per week on this plan.")
    if r.status_code != 200:
        raise RuntimeError(f"GreyNoise HTTP {r.status_code}: {r.text[:200]}")
    data = r.json()
    if not data.get("noise") and not data.get("riot"):
        return []  # explicitly "nothing known" -- don't manufacture a row for silence
    detail = f"classification={data.get('classification')}; last_seen={data.get('last_seen')}"
    if data.get("riot"):
        detail += f"; RIOT business service: {data.get('name')}"
    if data.get("noise"):
        detail += "; observed scanning the internet in the last 90 days"
    return [{
        "table": "credentials", "resource": target,
        "name": f"GreyNoise: {'RIOT/' if data.get('riot') else ''}{data.get('classification', 'unknown')}",
        "password": None, "detail": detail,
    }]


async def run_otx_lookup(target: str, target_type: str) -> list:
    """AlienVault OTX -- checks a domain/IP against community-submitted threat-intel
    "pulses" (IOC reports). Works unauthenticated at low rate limits, but reads the
    key from Integrations -> AlienVault OTX for better limits when configured."""
    import httpx
    from db import db as _db
    integration = await _db.integrations.find_one({"name": "AlienVault OTX"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint = cfg.get("endpoint") or "https://otx.alienvault.com"
    api_key = cfg.get("api_key")

    section = "domain" if target_type == "domain" else "IPv4"
    url = f"{endpoint.rstrip('/')}/api/v1/indicators/{section}/{target}/general"
    headers = {"X-OTX-API-KEY": api_key} if api_key else {}
    try:
        async with httpx.AsyncClient(timeout=15) as c:
            r = await c.get(url, headers=headers)
    except httpx.HTTPError as e:
        raise RuntimeError(f"Could not reach AlienVault OTX: {e}")
    if r.status_code == 403:
        raise RuntimeError("AlienVault OTX rejected this request (403) -- check the API key under Integrations → AlienVault OTX.")
    if r.status_code == 404:
        return []
    if r.status_code != 200:
        raise RuntimeError(f"AlienVault OTX HTTP {r.status_code}: {r.text[:200]}")
    data = r.json()
    pulse_info = data.get("pulse_info") or {}
    pulses = pulse_info.get("pulses") or []
    if not pulses:
        return []
    names = [p.get("name") for p in pulses[:10] if p.get("name")]
    return [{
        "table": "credentials", "resource": target,
        "name": f"AlienVault OTX: {pulse_info.get('count', len(pulses))} pulse(s)",
        "password": None,
        "detail": f"Referenced in threat-intel pulses: {', '.join(names) or 'unnamed'}",
    }]


async def run_abusech_lookup(target: str) -> list:
    """abuse.ch ThreatFox -- searches for a domain/IP as a known malware C2/delivery
    indicator. Requires an Auth-Key (abuse.ch moved to mandatory keys in 2023 --
    free to obtain, but no longer keyless like their older feeds)."""
    import httpx
    from db import db as _db
    integration = await _db.integrations.find_one({"name": "abuse.ch (ThreatFox)"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint = cfg.get("endpoint") or "https://threatfox-api.abuse.ch"
    auth_key = cfg.get("api_key")
    if not auth_key:
        raise ValueError("abuse.ch (ThreatFox) isn't configured yet -- add an Auth-Key under Integrations → abuse.ch "
                          "(get one free at https://auth.abuse.ch/) first.")

    url = f"{endpoint.rstrip('/')}/api/v1/"
    body = {"query": "search_ioc", "search_term": target, "exact_match": True}
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.post(url, headers={"Auth-Key": auth_key}, json=body)
    except httpx.HTTPError as e:
        raise RuntimeError(f"Could not reach abuse.ch ThreatFox: {e}")
    if r.status_code == 401:
        raise RuntimeError("abuse.ch rejected this Auth-Key (401) -- check it under Integrations → abuse.ch (ThreatFox).")
    if r.status_code != 200:
        raise RuntimeError(f"abuse.ch ThreatFox HTTP {r.status_code}: {r.text[:200]}")
    data = r.json()
    if data.get("query_status") != "ok":
        return []  # "no_result" -- clean, not an error
    rows = []
    for ioc in (data.get("data") or [])[:10]:
        rows.append({
            "table": "credentials", "resource": ioc.get("ioc", target),
            "name": f"ThreatFox: {ioc.get('malware_printable') or ioc.get('threat_type', 'IOC')}",
            "password": None,
            "detail": f"threat_type={ioc.get('threat_type')}; confidence={ioc.get('confidence_level')}; "
                      f"first_seen={ioc.get('first_seen')}",
        })
    return rows


async def run_virustotal_lookup(target: str, target_type: str) -> list:
    """VirusTotal file/domain/IP reputation -- checks a domain, IP, or file hash
    against VT's aggregated multi-engine detections. Requires an API key under
    Integrations → VirusTotal (the free tier works, rate-limited to ~4 req/min --
    fine for on-demand lookups from the Recon & OSINT hub, not meant for bulk
    scanning)."""
    import httpx
    from db import db as _db
    integration = await _db.integrations.find_one({"name": "VirusTotal"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint, api_key = cfg.get("endpoint") or "https://www.virustotal.com/api/v3", cfg.get("api_key")
    if not api_key:
        raise ValueError("VirusTotal isn't configured yet -- add an API key under Integrations → VirusTotal first.")

    path = {"domain": "domains", "ip": "ip_addresses", "hash": "files"}.get(target_type)
    if not path:
        raise ValueError(f"VirusTotal lookup doesn't support target type '{target_type}'.")

    url = f"{endpoint.rstrip('/')}/{path}/{target}"
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(url, headers={"x-apikey": api_key})
    except httpx.HTTPError as e:
        raise RuntimeError(f"Could not reach VirusTotal: {e}")
    if r.status_code == 404:
        return []  # VT has no data on this indicator -- not an error, just nothing to report
    if r.status_code == 401:
        raise RuntimeError("VirusTotal rejected this API key (401) -- check it under Integrations → VirusTotal.")
    if r.status_code == 429:
        raise RuntimeError("VirusTotal rate limit hit (429) -- the free tier allows about 4 requests/minute.")
    if r.status_code != 200:
        raise RuntimeError(f"VirusTotal HTTP {r.status_code}: {r.text[:200]}")
    data = (r.json() or {}).get("data") or {}
    attrs = data.get("attributes") or {}
    stats = attrs.get("last_analysis_stats") or {}
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    if malicious == 0 and suspicious == 0:
        return []  # clean across every engine that scanned it -- don't manufacture a row for silence
    label = attrs.get("meaningful_name") or attrs.get("type_description") or target
    detail = (f"{malicious} engine(s) flagged malicious, {suspicious} suspicious, "
              f"{stats.get('harmless', 0)} harmless, {stats.get('undetected', 0)} undetected")
    if "reputation" in attrs:
        detail += f"; VT reputation score={attrs['reputation']}"
    return [{
        "table": "credentials", "resource": target,
        "name": f"VirusTotal: {malicious} malicious detection(s)",
        "password": None, "detail": f"{label}: {detail}",
    }]


async def run_hibp_lookup(target: str, kind: str) -> list:
    """HaveIBeenPwned per-account breach/paste exposure check -- direct API call,
    same pattern as run_greynoise_lookup/run_otx_lookup/run_abusech_lookup above.
    Previously (hibp_breach/hibp_paste) this shelled out to a real recon-ng module
    via the flaky recon-cli subprocess route; HIBP's actual v3 REST API
    (GET /breachedaccount/{account} and GET /pasteaccount/{account}) is simple enough
    not to need that at all. Reuses the same Integrations → HaveIBeenPwned api_key
    the org-wide domain sync in hibp_domain.py uses -- one subscription key covers
    both use cases per HIBP's own docs."""
    import httpx
    from db import db as _db
    integration = await _db.integrations.find_one({"name": "HaveIBeenPwned"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    endpoint, api_key = cfg.get("endpoint") or "https://haveibeenpwned.com/api/v3", cfg.get("api_key")
    if not api_key:
        raise ValueError("HaveIBeenPwned isn't configured yet -- add an API key under Integrations → HaveIBeenPwned first.")

    path = "breachedaccount" if kind == "breach" else "pasteaccount"
    url = f"{endpoint.rstrip('/')}/{path}/{target}"
    headers = {"hibp-api-key": api_key, "user-agent": "Nightwatch-VulnMgmt"}
    params = {"truncateResponse": "false"} if kind == "breach" else None
    try:
        async with httpx.AsyncClient(timeout=20) as c:
            r = await c.get(url, headers=headers, params=params)
    except httpx.HTTPError as e:
        raise RuntimeError(f"Could not reach HaveIBeenPwned: {e}")
    if r.status_code == 404:
        return []  # not found in any breach/paste -- clean, not an error
    if r.status_code == 401:
        raise RuntimeError("HaveIBeenPwned rejected this API key (401) -- check it under Integrations → HaveIBeenPwned.")
    if r.status_code == 429:
        raise RuntimeError("HaveIBeenPwned rate limit hit (429) -- wait a moment and retry.")
    if r.status_code != 200:
        raise RuntimeError(f"HaveIBeenPwned HTTP {r.status_code}: {r.text[:200]}")
    data = r.json() or []
    if kind == "breach":
        names = [b.get("Name") or b.get("Title") for b in data if isinstance(b, dict)]
        return [{
            "table": "credentials", "resource": target,
            "name": f"HaveIBeenPwned: {len(names)} breach(es)",
            "password": None, "detail": f"Appears in: {', '.join(n for n in names if n) or 'unnamed breach(es)'}",
        }]
    sources = [p.get("Source") for p in data if isinstance(p, dict)]
    return [{
        "table": "credentials", "resource": target,
        "name": f"HaveIBeenPwned: {len(sources)} paste(s)",
        "password": None, "detail": f"Found in pastes on: {', '.join(s for s in sources if s) or 'unnamed source(s)'}",
    }]


async def run_module(db, module_id: str, target: str, timeout_sec: int = 300) -> dict:
    """Runs one recon-ng module (or, for source="opencti" entries, a direct OpenCTI
    lookup) against `target`, routes the results, and returns a summary dict. Raises
    ValueError for bad input, RuntimeError/TimeoutError for execution problems."""
    mod = MODULE_BY_ID.get(module_id)
    if not mod:
        raise ValueError(f"Unknown module '{module_id}'")
    target = validate_target(target)

    if mod.get("source") == "opencti":
        rows = await run_opencti_lookup(target)
        return await _route_results(db, mod, target, {"credentials": rows})
    if mod.get("source") == "greynoise":
        rows = await run_greynoise_lookup(target)
        return await _route_results(db, mod, target, {"credentials": rows})
    if mod.get("source") == "otx":
        rows = await run_otx_lookup(target, mod["target_type"])
        return await _route_results(db, mod, target, {"credentials": rows})
    if mod.get("source") == "abusech":
        rows = await run_abusech_lookup(target)
        return await _route_results(db, mod, target, {"credentials": rows})
    if mod.get("source") == "virustotal":
        rows = await run_virustotal_lookup(target, mod["target_type"])
        return await _route_results(db, mod, target, {"credentials": rows})
    if mod.get("source") == "hibp_breach":
        rows = await run_hibp_lookup(target, "breach")
        return await _route_results(db, mod, target, {"credentials": rows})
    if mod.get("source") == "hibp_paste":
        rows = await run_hibp_lookup(target, "paste")
        return await _route_results(db, mod, target, {"credentials": rows})

    integration = await db.integrations.find_one({"name": "recon-ng"}, {"_id": 0})
    cfg = (integration or {}).get("config") or {}
    missing_keys = [k for k in mod["requires_keys"] if not cfg.get(k)]
    if missing_keys:
        raise ValueError(f"Missing required API key(s) for this module: {', '.join(missing_keys)} — set them under Recon & OSINT → API Keys.")

    workspace = f"vulnops-{uuid.uuid4().hex[:12]}"
    with tempfile.TemporaryDirectory() as tmpdir:
        report_path = os.path.join(tmpdir, "report.json")
        # Call 1: install (if needed) + load + configure + run the actual module.
        # `-m` only loads a single module per recon-cli invocation, so this has to be
        # a separate call from the reporting/json export below. `-C` commands (keys,
        # marketplace install) run before the module load regardless of flag order,
        # per recon-cli's own fixed execution order. `marketplace install` is safe to
        # call every run -- it's a no-op (prints "already installed") if already present.
        run_args = ["-w", workspace]
        for key_name in mod["requires_keys"]:
            recon_key_name = RECON_KEY_NAME.get(key_name, key_name)
            run_args += ["-C", f"keys add {recon_key_name} {shlex.quote(cfg[key_name])}"]
        run_args += [
            "-C", f"marketplace install {mod['module']}",
            "-m", mod["module"],
            "-o", f"SOURCE={target}",
            "-x",
        ]
        # Call 2: load the reporting/json module and export the whole workspace db.
        report_args = [
            "-w", workspace,
            "-C", "marketplace install reporting/json",
            "-m", "reporting/json",
            "-o", f"FILENAME={report_path}",
            "-x",
        ]
        try:
            out1 = await _run_recon_cli(run_args, timeout_sec=timeout_sec)
            out2 = await _run_recon_cli(report_args, timeout_sec=timeout_sec)
            cli_output = out1 + "\n" + out2
            if not os.path.exists(report_path):
                # Surface recon-cli's actual output instead of guessing -- this is what
                # was silently discarded before. The last ~40 lines are almost always
                # enough to see the real cause (e.g. "invalid module name", a Python
                # traceback from a missing dependency, or a network timeout reaching
                # the marketplace index) without needing container log access.
                tail = "\n".join(cli_output.strip().splitlines()[-40:]) or "(no output at all -- recon-cli may have failed to start)"
                raise RuntimeError(
                    "recon-ng did not produce a report file. Last recon-cli output:\n"
                    f"{tail}"
                )
            with open(report_path) as f:
                report = json.load(f)
        finally:
            await _cleanup_workspace(workspace)

    return await _route_results(db, mod, target, report)


async def _route_results(db, mod: dict, target: str, report) -> dict:
    """recon-ng's JSON report export is a flat list of table rows tagged with which
    table they came from in real installs; to stay robust to minor shape differences
    across versions, this accepts either {"hosts": [...], "contacts": [...], ...} or a
    flat list of {"table": "...", ...} rows and normalizes both."""
    tables: dict = {}
    if isinstance(report, dict):
        tables = {k: v for k, v in report.items() if isinstance(v, list)}
    elif isinstance(report, list):
        for row in report:
            t = row.get("table") if isinstance(row, dict) else None
            if t:
                tables.setdefault(t, []).append(row)

    rows = tables.get(mod["result_table"], [])
    summary = {"module": mod["id"], "target": target, "result_table": mod["result_table"], "row_count": len(rows)}

    if mod["result_table"] == "hosts":
        created = await _ingest_hosts(db, rows, target)
        summary["easm_candidates_created"] = created
    elif mod["result_table"] in ("credentials", "contacts"):
        hits = await _ingest_osint_rows(db, mod, target, rows)
        summary["osint_findings_created"] = hits
    return summary


async def _ingest_hosts(db, rows: list, domain: str) -> int:
    """Feeds discovered hostnames into the same easm_candidates queue the crt.sh-based
    EASM discovery already uses, so review/promote works the same way regardless of
    which tool found the subdomain."""
    now = _now_iso()
    created = 0
    for row in rows:
        hostname = (row.get("host") or row.get("hostname") or "").strip().lower()
        if not hostname:
            continue
        existing = await db.easm_candidates.find_one({"hostname": hostname}, {"_id": 0})
        ip = row.get("ip_address") or row.get("ip")
        if existing:
            await db.easm_candidates.update_one({"id": existing["id"]}, {"$set": {
                "resolved_ip": ip or existing.get("resolved_ip"), "last_seen_at": now,
            }})
            continue
        await db.easm_candidates.insert_one({
            "id": str(uuid.uuid4()), "hostname": hostname, "domain": domain,
            "resolved_ip": ip, "live": bool(ip), "status": "new",
            "first_seen_at": now, "last_seen_at": now, "source": "recon-ng",
        })
        created += 1
    return created


BREACH_KEYWORDS = ("breach", "pwned", "compromise", "leak", "paste")


async def _ingest_osint_rows(db, mod: dict, target: str, rows: list) -> int:
    from notifier import dispatch
    now = _now_iso()
    created = 0
    for row in rows:
        label = row.get("name") or row.get("resource") or row.get("email") or mod["label"]
        # Some sources (e.g. the OpenCTI lookup above) already produce a human-readable
        # summary string in "detail" -- respect that instead of re-deriving one.
        if isinstance(row.get("detail"), str) and row["detail"]:
            detail = row["detail"]
        else:
            detail = row.get("password") and "credential exposed" or row.get("resource") or json.dumps(row)[:200]
        key = f"{mod['id']}:{target}:{label}"
        existing = await db.osint_findings.find_one({"key": key}, {"_id": 0})
        if existing:
            continue
        doc = {
            "id": str(uuid.uuid4()), "key": key, "module": mod["id"], "module_label": mod["label"],
            "target": target, "label": label, "detail": detail, "raw": row,
            "found_at": now, "acknowledged": False,
        }
        await db.osint_findings.insert_one(doc)
        created += 1
        is_breach = mod["category"] == "threat-intel" or any(k in (label or "").lower() for k in BREACH_KEYWORDS)
        if is_breach:
            await dispatch("osint_exposure_found", {
                "module": mod["label"], "target": target, "label": label,
                "detail": detail, "url": "/admin/recon-osint",
            }, db)
        # If this target happens to be a tracked vendor's domain (whether this run was
        # kicked off via a vendor's monitoring schedule or a plain manual recon-ng
        # lookup that happens to match one), also fire a vendor-branded notification so
        # it's immediately clear *which vendor* needs attention rather than just a bare
        # domain string -- dedicated trigger, opt-in via its own notification rule, so
        # this doesn't change behavior for anyone who hasn't configured one.
        vendor = await db.vendors.find_one({"domain": target}, {"_id": 0})
        if vendor:
            await dispatch("vendor_compromise_found", {
                "vendor_name": vendor["name"], "vendor_id": vendor["id"], "module": mod["label"],
                "target": target, "label": label, "detail": detail, "url": f"/vendors/{vendor['id']}",
            }, db)
    return created
