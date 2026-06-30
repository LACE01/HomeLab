"""Attack Path Analysis — given a CVE or finding, synthesize a plausible lateral movement
path through the asset inventory. Heuristic-based: starts from internet-exposed assets and
walks through assets that share the same CVE, ending at crown-jewel/critical hosts."""
from typing import Optional


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


def _edge(src: str, dst: str, label: str, technique: str = "") -> dict:
    return {"id": f"{src}->{dst}", "source": src, "target": dst, "label": label, "technique": technique}


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
        edges.append(_edge(inet_id, src["id"],
                           f"Exploit {cve}",
                           "T1190 Exploit Public-Facing Application"))

    # Pivots
    for p in pivots[:4]:
        nodes.append(_node(p, "pivot"))
        # Connect from a source if any, else from internet
        parent = sources[0]["id"] if sources else inet_id
        edges.append(_edge(parent, p["id"], "Lateral movement", "T1021 Remote Services"))

    # Critical assets in path
    for c in critical[:3]:
        nodes.append(_node(c, "pivot"))
        parent = pivots[0]["id"] if pivots else (sources[0]["id"] if sources else inet_id)
        edges.append(_edge(parent, c["id"], "Privilege escalation", "T1068 Exploitation for Privilege Escalation"))

    # Target: crown jewels
    for t in crown[:3]:
        nodes.append(_node(t, "target", "objective"))
        parent = critical[0]["id"] if critical else (pivots[0]["id"] if pivots else (sources[0]["id"] if sources else inet_id))
        edges.append(_edge(parent, t["id"], "Data exfiltration", "T1041 Exfiltration Over C2 Channel"))

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
