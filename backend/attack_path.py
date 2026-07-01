"""Attack Path Analysis — given a CVE or finding, synthesize a plausible lateral movement
path through the asset inventory. Heuristic-based: starts from internet-exposed assets and
walks through assets that share the same CVE, ending at crown-jewel/critical hosts.

Techniques are chosen per-hop based on the target asset's platform/OS and its position in
the chain (credential access right after initial compromise, then lateral movement, then
privilege escalation, then exfiltration) so a path doesn't just repeat "Lateral movement"
for every hop — it mirrors how a real intrusion diversifies techniques as it progresses.
"""
from typing import Optional

# MITRE ATT&CK technique pools, keyed by target platform. Rotated by hop index within a
# path so consecutive hops don't repeat the same technique even on long chains.
CREDENTIAL_ACCESS = {
    "windows": [("LSASS Memory Dump", "T1003.001"), ("DCSync", "T1003.006"), ("Cached Credentials", "T1003.005")],
    "linux": [("/etc/shadow Dump", "T1003.008"), ("SSH Private Key Theft", "T1552.004")],
    "cloud": [("Cloud Instance Metadata API", "T1552.005"), ("Access Key Theft", "T1528")],
    "default": [("Unsecured Credentials", "T1552"), ("Credential Dumping", "T1003")],
}

LATERAL_MOVEMENT = {
    "windows": [("Pass-the-Hash", "T1550.002"), ("RDP Hijacking", "T1021.001"),
                ("SMB Admin Shares", "T1021.002"), ("Kerberoasting", "T1558.003"),
                ("WMI Lateral Movement", "T1047")],
    "linux": [("SSH Key Reuse", "T1021.004"), ("Sudo Session Reuse", "T1548.003")],
    "cloud": [("Valid Cloud Account", "T1078.004"), ("IAM Role Assumption", "T1550.001")],
    "default": [("Remote Services", "T1021"), ("Valid Accounts", "T1078")],
}

PRIV_ESCALATION = {
    "windows": [("Token Impersonation", "T1134"), ("UAC Bypass", "T1548.002"), ("DLL Hijacking", "T1574.001")],
    "linux": [("SUID Binary Abuse", "T1548.001"), ("Kernel Exploit", "T1068")],
    "cloud": [("IAM Policy Escalation", "T1078.004")],
    "default": [("Exploitation for Privilege Escalation", "T1068")],
}

EXFILTRATION = [("Exfiltration Over C2 Channel", "T1041"), ("Exfiltration to Cloud Storage", "T1567.002"),
                ("Data Staged then Exfiltrated", "T1074")]


def _platform_key(asset: dict) -> str:
    text = f"{asset.get('platform') or ''} {asset.get('operating_system') or ''}".lower()
    if any(k in text for k in ("windows", "win32", "win10", "win11", "server 20")):
        return "windows"
    if any(k in text for k in ("linux", "ubuntu", "debian", "centos", "rhel", "amazon linux")):
        return "linux"
    if any(k in text for k in ("aws", "azure", "gcp", "cloud", "kubernetes", "k8s", "container")):
        return "cloud"
    return "default"


def _pick(pool_by_platform: dict, asset: dict, index: int) -> tuple:
    pool = pool_by_platform.get(_platform_key(asset)) or pool_by_platform["default"]
    return pool[index % len(pool)]


def _node(asset: dict, role: str, sev_or_risk: str = "") -> dict:
    return {
        "id": asset["id"],
        "label": asset["hostname"],
        "role": role,  # source|pivot|target|internet
        "criticality": asset.get("criticality"),
        "exposure": asset.get("exposure"),
        "platform": asset.get("platform"),
        "os": asset.get("operating_system"),
        "owner_team": asset.get("owner_team"),
        "risk": sev_or_risk,
    }


def _edge(src: str, dst: str, label: str, technique: str = "", category: str = "lateral_movement") -> dict:
    return {"id": f"{src}->{dst}", "source": src, "target": dst, "label": label,
            "technique": technique, "category": category}


async def build_attack_path(db, cve: Optional[str] = None, finding_id: Optional[str] = None) -> dict:
    """Return {nodes, edges, summary, remediation_options}"""
    if finding_id:
        seed = await db.findings.find_one({"id": finding_id}, {"_id": 0})
        cve = seed.get("cve") if seed else cve
    if not cve:
        return {"nodes": [], "edges": [], "summary": "Provide a CVE or finding_id", "remediation_options": []}

    # Find every finding for that CVE (each represents a vulnerable host)
    findings = await db.findings.find({"cve": cve, "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]}}, {"_id": 0}).to_list(500)
    if not findings:
        return {"nodes": [], "edges": [], "summary": f"No open findings for {cve}", "remediation_options": []}

    asset_ids = list({f["asset_id"] for f in findings if f.get("asset_id")})
    assets = await db.assets.find({"id": {"$in": asset_ids}}, {"_id": 0}).to_list(500)
    assets_by_id = {a["id"]: a for a in assets}

    # Categorize:
    internet = [a for a in assets if a.get("exposure") in ("internet", "external")]
    crown = [a for a in assets if a.get("criticality") == "crown_jewel"]
    critical = [a for a in assets if a.get("criticality") == "critical" and a not in crown]
    pivots = [a for a in assets if a not in internet and a not in crown and a not in critical]

    # If no crown_jewel in CVE-matched assets, use any crown_jewel in inventory as the "target"
    if not crown:
        crown = await db.assets.find({"criticality": "crown_jewel"}, {"_id": 0}).limit(3).to_list(3)

    # Build a simple chain: Internet -> exposed asset -> pivot -> critical -> crown_jewel
    nodes: list = []
    edges: list = []

    # Internet origin pseudo-node
    inet_id = "_internet"
    nodes.append({"id": inet_id, "label": "Internet Exposure", "role": "internet",
                  "criticality": None, "exposure": "internet", "platform": "—", "os": "—",
                  "owner_team": "—", "risk": "high"})

    # Source: pick the most exposed internet asset, or any from the list
    sources = internet[:3] if internet else (assets[:1] if assets else [])
    for src in sources:
        nodes.append(_node(src, "source", "exploited"))
        edges.append(_edge(inet_id, src["id"], f"Exploit {cve}",
                            "T1190 Exploit Public-Facing Application", "initial_access"))

    # Pivots: first hop after compromise is credential access, subsequent hops are lateral
    # movement -- each using a technique picked for that specific asset's platform, rotated
    # by index so a long chain doesn't repeat the same technique twice in a row.
    for i, p in enumerate(pivots[:4]):
        nodes.append(_node(p, "pivot"))
        parent = sources[0]["id"] if sources else inet_id
        if i == 0:
            name, mitre = _pick(CREDENTIAL_ACCESS, p, i)
            edges.append(_edge(parent, p["id"], name, mitre, "credential_access"))
        else:
            name, mitre = _pick(LATERAL_MOVEMENT, p, i)
            edges.append(_edge(parent, p["id"], name, mitre, "lateral_movement"))

    # Critical assets in path — privilege escalation, technique varies by that asset's platform
    for i, c in enumerate(critical[:3]):
        nodes.append(_node(c, "pivot"))
        parent = pivots[0]["id"] if pivots else (sources[0]["id"] if sources else inet_id)
        name, mitre = _pick(PRIV_ESCALATION, c, i)
        edges.append(_edge(parent, c["id"], name, mitre, "privilege_escalation"))

    # Target: crown jewels — exfiltration technique rotates too
    for i, t in enumerate(crown[:3]):
        nodes.append(_node(t, "target", "objective"))
        parent = critical[0]["id"] if critical else (pivots[0]["id"] if pivots else (sources[0]["id"] if sources else inet_id))
        name, mitre = EXFILTRATION[i % len(EXFILTRATION)]
        edges.append(_edge(parent, t["id"], name, mitre, "exfiltration"))

    # Remediation options
    remediation_options = []
    if sources:
        remediation_options.append({
            "id": "patch_sources",
            "description": f"Patch source assets ({len(sources)})",
            "assets": len(sources),
            "remediations": len([f for f in findings if f["asset_id"] in [s["id"] for s in sources]]),
            "risk_reduction": 75,
        })
    if pivots:
        remediation_options.append({
            "id": "segment_pivots",
            "description": "Network segmentation between pivot hosts",
            "assets": len(pivots),
            "remediations": 4,
            "risk_reduction": 55,
        })
    if crown:
        remediation_options.append({
            "id": "harden_crown",
            "description": "Harden crown-jewel destinations (MFA, JIT access, EDR)",
            "assets": len(crown),
            "remediations": 6,
            "risk_reduction": 35,
        })

    summary = (f"{cve} is open on {len(findings)} asset(s). "
               f"Attack chain: Internet → {len(sources)} exposed source(s) → "
               f"{len(pivots)} pivot(s) → {len(critical)} critical → {len(crown)} crown-jewel target(s).")

    return {
        "cve": cve, "nodes": nodes, "edges": edges, "summary": summary,
        "remediation_options": remediation_options,
        "stats": {"affected_assets": len(asset_ids), "internet_sources": len(sources),
                  "pivots": len(pivots), "critical": len(critical), "crown_jewels": len(crown)},
    }
