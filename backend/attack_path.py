"""Attack Path Analysis -- given a CVE or finding, synthesize a plausible lateral
movement path through the asset inventory.

Rewritten from a first version that, when a CVE hit dozens/hundreds of identical
hosts, drew one long undifferentiated chain (host1 -> host2 -> host3 -> ...) — every
edge in that version actually originated from the same source node, but because all
same-role nodes were stacked in a single column, the rendering made it *look* like a
serial chain, and the underlying logic didn't distinguish "these hosts are plausibly
reachable from each other" from "these hosts just happen to share a CVE". Real lateral
movement fans out across network segments and only actually crosses between two hosts
when there's a real foothold (an exposed admin-ish service) on the target -- it doesn't
march through a vulnerable fleet in list order.

This version:
  1. Segments assets by subnet (IPv4 /24) when an IP is known, falling back to
     (environment, owner_team) when it isn't -- and fans the graph out across
     segments instead of chaining every affected host in a straight line.
  2. Only draws a *confirmed* (solid) edge between two hosts when there's a real
     reachability signal: the target exposes a classic lateral-movement service
     (RDP/SSH/SMB/WinRM/VNC). Hosts that just happen to share a CVE or a subnet but
     have no such exposed service are still shown (so blast radius isn't hidden) but
     the edge to them is marked speculative, same convention the UI already uses for
     "same network segment, unconfirmed" edges.
  3. Picks the entry point(s) and prioritizes segments/targets by actual
     exploitability (KEV > EPSS > CVSS) instead of "first N in query order" --
     so the path reflects which host an attacker would actually go for first.
"""
import ipaddress
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

# Ports that plausibly give an attacker a real foothold to pivot FROM once they land on
# a host -- i.e. a genuine reachability signal, not just "this host is also vulnerable".
LATERAL_PORT_TECHNIQUES = {
    3389: ("RDP Hijacking", "T1021.001"),
    22: ("SSH Key Reuse", "T1021.004"),
    445: ("SMB Admin Shares", "T1021.002"),
    139: ("SMB Admin Shares", "T1021.002"),
    5985: ("WinRM Lateral Movement", "T1021.006"),
    5986: ("WinRM Lateral Movement", "T1021.006"),
    5900: ("VNC Session Reuse", "T1021.005"),
}


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


def _lateral_technique_for_asset(asset: dict) -> Optional[tuple]:
    """Returns (name, mitre_id) for the first classic lateral-movement service found
    open on this asset, or None if it doesn't expose one -- this is the "real
    reachability signal" that decides whether an edge into this host is confirmed or
    just a same-subnet guess."""
    for p in (asset.get("open_ports") or []):
        try:
            port_num = int(p.get("port"))
        except (TypeError, ValueError):
            continue
        if port_num in LATERAL_PORT_TECHNIQUES:
            return LATERAL_PORT_TECHNIQUES[port_num]
    return None


def _ipv4_subnet(ip: Optional[str]) -> Optional[str]:
    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            return None
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return None


def _segment_key(asset: dict) -> str:
    """Groups assets the way an attacker's actual reachability would -- same /24
    subnet if we know the IP, otherwise the closest proxy we have (environment +
    owning team), rather than treating "affected by the same CVE" as if it implied
    "on the same network segment"."""
    subnet = _ipv4_subnet(asset.get("ip"))
    if subnet:
        return f"subnet:{subnet}"
    env = asset.get("environment") or "unknown-env"
    team = asset.get("owner_team") or "unassigned"
    return f"env:{env}|team:{team}"


def _exploitability_score(finding: dict) -> float:
    """Ranks how likely a real attacker is to actually use this finding as an entry
    point -- KEV (confirmed active exploitation) dominates, then EPSS (probability of
    exploitation in the next 30 days), then raw CVSS as a tiebreaker. Used to pick
    which hosts lead the path instead of "whichever came back first from the query"."""
    score = 0.0
    if finding.get("kev_flag"):
        score += 50
    epss = finding.get("epss_score") or 0
    score += float(epss) * 30
    cvss = finding.get("cvss_score") or 0
    score += min(float(cvss), 10) * 2
    return score


def _node(asset: dict, role: str, sev_or_risk: str = "", findings_count: int = 0, speculative: bool = False) -> dict:
    return {
        "id": asset["id"],
        "label": asset["hostname"],
        "role": role,  # source|pivot|target|internet
        "criticality": asset.get("criticality"),
        "exposure": asset.get("exposure"),
        "platform": asset.get("platform"),
        "os": asset.get("operating_system"),
        "owner_team": asset.get("owner_team"),
        "tags": asset.get("tags") or [],
        "segment": _segment_key(asset),
        "risk": sev_or_risk,
        "findings_count": findings_count,
        "speculative": speculative,
    }


def _summary_node(segment_key: str, count: int, role: str = "pivot") -> dict:
    """A non-clickable placeholder representing "N more hosts in this segment" --
    used so a CVE affecting hundreds of identical hosts doesn't get rendered as
    hundreds of nodes (unreadable) while still being honest about blast radius,
    instead of silently only showing 3-4 hosts with no indication more exist."""
    label = segment_key.split(":", 1)[-1]
    return {
        "id": f"_more:{segment_key}", "label": f"+{count} more host(s) in {label}",
        "role": role, "criticality": None, "exposure": None, "platform": "—", "os": "—",
        "owner_team": "—", "tags": [], "segment": segment_key, "risk": "", "findings_count": 0,
        "speculative": True, "is_summary": True,
    }


def _edge(src: str, dst: str, label: str, technique: str = "", category: str = "lateral_movement", speculative: bool = False) -> dict:
    return {"id": f"{src}->{dst}", "source": src, "target": dst, "label": label,
            "technique": technique, "category": category, "speculative": speculative}


MAX_SEGMENTS = 4
MAX_MEMBERS_PER_SEGMENT = 3


async def build_attack_path(db, cve: Optional[str] = None, finding_id: Optional[str] = None) -> dict:
    """Return {nodes, edges, summary, remediation_options, stats}"""
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
    # Best (highest-exploitability) finding per asset, for ranking sources/targets.
    best_finding_by_asset: dict = {}
    for f in findings:
        aid = f.get("asset_id")
        if not aid:
            continue
        if aid not in best_finding_by_asset or _exploitability_score(f) > _exploitability_score(best_finding_by_asset[aid]):
            best_finding_by_asset[aid] = f

    # Categorize by tier
    internet = [a for a in assets if a.get("exposure") in ("internet", "external")]
    crown = [a for a in assets if a.get("criticality") == "crown_jewel"]
    critical = [a for a in assets if a.get("criticality") == "critical" and a not in crown]
    pivot_pool = [a for a in assets if a not in internet and a not in crown and a not in critical]

    if not crown:
        crown = await db.assets.find({"criticality": "crown_jewel"}, {"_id": 0}).limit(3).to_list(3)

    # Blast-radius figure per node -- how much else is wrong on this box, not just this CVE.
    all_node_asset_ids = list({a["id"] for a in (internet + crown + critical + pivot_pool)})
    findings_count_by_asset: dict = {}
    if all_node_asset_ids:
        async for row in db.findings.aggregate([
            {"$match": {"asset_id": {"$in": all_node_asset_ids},
                        "status": {"$in": ["New", "Needs triage", "Valid", "Reopened"]}}},
            {"$group": {"_id": "$asset_id", "n": {"$sum": 1}}},
        ]):
            findings_count_by_asset[row["_id"]] = row["n"]

    nodes: list = []
    edges: list = []
    placed_ids: set = set()

    def _rank_key(a):
        f = best_finding_by_asset.get(a["id"])
        return -(_exploitability_score(f) if f else 0)

    # --- Entry point(s): rank internet-facing candidates by real exploitability
    # (KEV/EPSS/CVSS) instead of taking whichever 3 the DB query happened to return
    # first, so the path leads with the host an attacker would actually go for.
    internet_sorted = sorted(internet, key=_rank_key) if internet else sorted(assets, key=_rank_key)[:1]
    sources = internet_sorted[:3]

    inet_id = "_internet"
    nodes.append({"id": inet_id, "label": "Internet Exposure", "role": "internet",
                  "criticality": None, "exposure": "internet", "platform": "—", "os": "—",
                  "owner_team": "—", "risk": "high", "tags": [], "segment": None,
                  "findings_count": 0, "speculative": False})

    for src in sources:
        nodes.append(_node(src, "source", "exploited", findings_count_by_asset.get(src["id"], 0)))
        placed_ids.add(src["id"])
        edges.append(_edge(inet_id, src["id"], f"Exploit {cve}",
                            "T1190 Exploit Public-Facing Application", "initial_access"))

    beachhead = sources[0]["id"] if sources else inet_id

    # --- Segment the remaining pool (pivots + critical) by subnet/env-team so the
    # graph fans out across distinct network segments instead of chaining every
    # affected host in list order. Segments are ranked by how many hosts they
    # contain (bigger blast radius surfaces first) and capped for readability.
    segment_members: dict = {}
    for a in pivot_pool:
        if a["id"] in placed_ids:
            continue
        segment_members.setdefault(_segment_key(a), []).append(a)

    ranked_segments = sorted(segment_members.items(), key=lambda kv: -len(kv[1]))[:MAX_SEGMENTS]
    entry_by_segment: dict = {}  # seg_key -> asset_id of the node other tiers should escalate/pivot from

    for seg_idx, (seg_key, members) in enumerate(ranked_segments):
        # Within a segment, the "entry" host is whichever member actually exposes a
        # lateral-movement service (a real foothold) -- falling back to the
        # highest-exploitability member if none do, since the attacker has to land
        # somewhere in the segment even without a clean signal.
        members_sorted = sorted(members, key=_rank_key)
        entry = next((m for m in members_sorted if _lateral_technique_for_asset(m)), members_sorted[0])

        nodes.append(_node(entry, "pivot", findings_count=findings_count_by_asset.get(entry["id"], 0)))
        placed_ids.add(entry["id"])
        entry_by_segment[seg_key] = entry["id"]
        if seg_idx == 0:
            name, mitre = _pick(CREDENTIAL_ACCESS, entry, seg_idx)
            edges.append(_edge(beachhead, entry["id"], name, mitre, "credential_access"))
        else:
            lat = _lateral_technique_for_asset(entry)
            name, mitre = lat if lat else _pick(LATERAL_MOVEMENT, entry, seg_idx)
            # Crossing into a *different* segment without a confirmed exposed service
            # on the entry host is a guess, not a confirmed hop -- mark it as such.
            edges.append(_edge(beachhead, entry["id"], name, mitre, "lateral_movement", speculative=lat is None))

        shown_others = 0
        for m in members_sorted:
            if m["id"] == entry["id"]:
                continue
            if shown_others >= MAX_MEMBERS_PER_SEGMENT - 1:
                break
            lat = _lateral_technique_for_asset(m)
            nodes.append(_node(m, "pivot", findings_count=findings_count_by_asset.get(m["id"], 0), speculative=lat is None))
            placed_ids.add(m["id"])
            if lat:
                name, mitre = lat
                edges.append(_edge(entry["id"], m["id"], name, mitre, "lateral_movement"))
            else:
                edges.append(_edge(entry["id"], m["id"], "Same network segment",
                                    "T1021 Remote Services (unconfirmed)", "lateral_movement", speculative=True))
            shown_others += 1

        remaining = len(members_sorted) - 1 - shown_others
        if remaining > 0:
            summary_node = _summary_node(seg_key, remaining)
            nodes.append(summary_node)
            edges.append(_edge(entry["id"], summary_node["id"], f"{remaining} more on this subnet",
                                "", "lateral_movement", speculative=True))

    # --- Critical-tier assets: escalate from whichever segment entry actually shares a
    # segment with them (a real link); if none do, connect from the beachhead directly
    # but mark it speculative since we're inferring a hop with no supporting evidence.
    critical_sorted = sorted(critical, key=_rank_key)[:3]
    for i, c in enumerate(critical_sorted):
        nodes.append(_node(c, "pivot", findings_count=findings_count_by_asset.get(c["id"], 0)))
        seg = _segment_key(c)
        parent = entry_by_segment.get(seg)
        speculative = parent is None
        if parent is None:
            parent = beachhead
        name, mitre = _pick(PRIV_ESCALATION, c, i)
        edges.append(_edge(parent, c["id"], name, mitre, "privilege_escalation", speculative=speculative))

    # --- Crown jewels: prefer a real link from a critical/pivot asset sharing
    # environment or tags; otherwise fall back to the nearest crown jewel by shared
    # environment, clearly marked as an unconfirmed/nearest-match hop.
    placed_non_source = [assets_by_id[nid] for nid in placed_ids if nid in assets_by_id and assets_by_id[nid].get("criticality") != "crown_jewel"]
    crown_sorted = sorted(crown, key=_rank_key)[:3] if crown else []
    for i, t in enumerate(crown_sorted):
        nodes.append(_node(t, "target", "objective", findings_count_by_asset.get(t["id"], 0)))
        linked_parent = None
        for cand in placed_non_source:
            shared_env = cand.get("environment") and cand.get("environment") == t.get("environment")
            shared_tag = set(cand.get("tags") or []) & set(t.get("tags") or [])
            if shared_env or shared_tag:
                linked_parent = cand["id"]
                break
        speculative = linked_parent is None
        parent = linked_parent or (critical_sorted[0]["id"] if critical_sorted else beachhead)
        name, mitre = EXFILTRATION[i % len(EXFILTRATION)]
        edges.append(_edge(parent, t["id"], name, mitre, "exfiltration", speculative=speculative))

    # When the chain is genuinely thin (a single vulnerable host, nothing else sharing
    # this CVE, no segments to fan into), the graph would otherwise be just
    # Internet -> one box. Pull in real neighbors -- other assets in the same
    # environment/tags -- as clearly-labeled *potential* lateral movement targets.
    if sources and not ranked_segments and not critical_sorted:
        seed = sources[0]
        neighbor_flt = {
            "id": {"$nin": [a["id"] for a in assets]},
            "$or": [
                {"environment": seed.get("environment")} if seed.get("environment") else {"id": None},
                {"tags": {"$in": seed.get("tags") or ["__none__"]}},
            ],
        }
        neighbors = await db.assets.find(neighbor_flt, {"_id": 0}).limit(4).to_list(4)
        for n in neighbors:
            nodes.append(_node(n, "pivot", findings_count=findings_count_by_asset.get(n["id"], 0), speculative=True))
            edges.append(_edge(sources[0]["id"], n["id"], "Same network segment",
                                "T1021 Remote Services (unconfirmed)", "lateral_movement", speculative=True))

    # --- Remediation options, ordered by estimated real-world risk reduction.
    confirmed_hops = sum(1 for e in edges if not e.get("speculative") and e["category"] != "initial_access")
    total_hops = sum(1 for e in edges if e["category"] != "initial_access")
    remediation_options = []
    if sources:
        remediation_options.append({
            "id": "patch_sources",
            "description": f"Patch source assets ({len(sources)})",
            "assets": len(sources),
            "remediations": len([f for f in findings if f["asset_id"] in [s["id"] for s in sources]]),
            "risk_reduction": 75,
        })
    if ranked_segments:
        biggest = max(len(m) for _, m in ranked_segments)
        remediation_options.append({
            "id": "segment_network",
            "description": f"Network segmentation across {len(ranked_segments)} affected subnet(s)/segment(s)",
            "assets": sum(len(m) for _, m in ranked_segments),
            "remediations": len(ranked_segments) * 2,
            "risk_reduction": min(65, 30 + biggest),
        })
    if confirmed_hops:
        remediation_options.append({
            "id": "close_lateral_ports",
            "description": "Restrict RDP/SSH/SMB/WinRM between segments (removes the confirmed foothold(s) this path relies on)",
            "assets": confirmed_hops,
            "remediations": confirmed_hops,
            "risk_reduction": 50,
        })
    if crown_sorted:
        remediation_options.append({
            "id": "harden_crown",
            "description": "Harden crown-jewel destinations (MFA, JIT access, EDR)",
            "assets": len(crown_sorted),
            "remediations": 6,
            "risk_reduction": 35,
        })
    remediation_options.sort(key=lambda r: -r["risk_reduction"])

    n_segments = len(ranked_segments)
    confirmed_note = f"{confirmed_hops}/{total_hops} hop(s) have a confirmed exposed service backing them" if total_hops else "no lateral hops beyond the entry point"
    summary = (f"{cve} is open on {len(findings)} asset(s) across {n_segments or 1} network segment(s). "
               f"Attack chain: Internet → {len(sources)} exposed source(s), fanning out into each segment "
               f"({confirmed_note}) → {len(critical_sorted)} critical asset(s) → {len(crown_sorted)} crown-jewel target(s).")

    return {
        "cve": cve, "nodes": nodes, "edges": edges, "summary": summary,
        "remediation_options": remediation_options,
        "stats": {"affected_assets": len(asset_ids), "internet_sources": len(sources),
                  "pivots": sum(len(m) for _, m in ranked_segments), "critical": len(critical_sorted),
                  "crown_jewels": len(crown_sorted), "segments": n_segments,
                  "confirmed_hops": confirmed_hops, "total_hops": total_hops},
    }
