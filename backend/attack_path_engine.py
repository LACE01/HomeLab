"""Attack Path Analysis, rebuilt as a path-ENUMERATION engine.

The previous implementation was CVE-centric: pick a CVE, see every host that has
it. That answers "who is affected by this bug" (blast radius) -- useful, but it
isn't attack path analysis. It can't answer the question a security team actually
brings: "what are the ways an attacker gets from the internet to something that
matters, and which single fix kills the most of them?"

This engine models the environment as a graph and ENUMERATES discrete paths:

    Internet ──exposed_service──▶ web01 ──exploitable(KEV CVE)──▶ web01
             ──lateral(SMB)──▶ fileshare ──reaches──▶ sql01 [CROWN JEWEL]

Each enumerated path is its own triageable record with:
  * a typed node chain (internet / host / segment / data store / identity)
  * typed, EVIDENCED edges -- every edge cites the fact that justifies it
    (an open port from Shodan, a KEV finding, a shared subnet, a criticality tag)
  * a plain-English narrative of why the path exists
  * a risk score built from exploitability x target value x path friction
  * remediation options ranked by how many paths each one breaks

Design rules, learned from the previous version's mistakes:
  1. NEVER invent reachability. Every edge names its evidence and carries a
     confidence. "Same subnet" is a real but WEAK signal and is labelled as such;
     an open SMB/RDP port backed by a scan is a strong one. Paths built only from
     weak edges are marked speculative rather than presented as fact.
  2. A path must END somewhere that matters. If nothing in the environment is
     marked crown-jewel/critical, the engine says so instead of inventing a
     target -- an attack path to nothing in particular is noise.
  3. Rank by what an attacker would actually do (exploitability first), not by
     query order.

CHOKE POINTS are the payoff: because paths are enumerated rather than drawn
ad hoc, the engine can count how many distinct paths traverse a given node or
edge, which turns "you have 300 vulnerabilities" into "patch these two hosts and
41 of your 47 internet-to-crown-jewel paths disappear."
"""
import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Optional

OPEN_STATES = ["New", "Needs triage", "Valid", "Reopened", "Fixed pending validation"]

# Services that genuinely let an attacker pivot INTO a host once they have a
# foothold elsewhere. Presence of one of these (from a scan) is what upgrades an
# edge from "same network" to "reachable".
LATERAL_SERVICES = {
    22: ("SSH", "T1021.004"), 23: ("Telnet", "T1021"), 135: ("RPC", "T1021.003"),
    139: ("NetBIOS", "T1021.002"), 445: ("SMB", "T1021.002"), 3389: ("RDP", "T1021.001"),
    5985: ("WinRM", "T1021.006"), 5986: ("WinRM/TLS", "T1021.006"), 5900: ("VNC", "T1021.005"),
    1433: ("MSSQL", "T1210"), 3306: ("MySQL", "T1210"), 5432: ("PostgreSQL", "T1210"),
    27017: ("MongoDB", "T1210"), 6379: ("Redis", "T1210"), 9200: ("Elasticsearch", "T1210"),
    2049: ("NFS", "T1021"), 5432: ("PostgreSQL", "T1210"),
}

# Services that make a host an internet ENTRY POINT.
ENTRY_SERVICES = {
    80: "HTTP", 443: "HTTPS", 8080: "HTTP-alt", 8443: "HTTPS-alt",
    21: "FTP", 22: "SSH", 25: "SMTP", 3389: "RDP", 445: "SMB",
    1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB",
    6379: "Redis", 9200: "Elasticsearch", 111: "RPC", 161: "SNMP",
}

# Ports that should essentially never face the internet -- their presence is
# itself a finding, and makes an entry point far more attractive.
NEVER_INTERNET = {445, 3389, 1433, 3306, 5432, 27017, 6379, 9200, 23, 111, 161, 2049, 5900}

NODE_TYPES = ["internet", "host", "segment", "datastore", "identity"]

EDGE_KINDS = {
    "exposed_service":  {"label": "exposed to internet", "confidence": "confirmed",  "tactic": "Initial Access"},
    "exploitable":      {"label": "exploitable via",     "confidence": "confirmed",  "tactic": "Initial Access"},
    "lateral_service":  {"label": "can reach",           "confidence": "confirmed",  "tactic": "Lateral Movement"},
    "credential_reuse": {"label": "shared credentials",  "confidence": "likely",     "tactic": "Credential Access"},
    "same_segment":     {"label": "same network segment", "confidence": "possible",  "tactic": "Discovery"},
    "holds_data":       {"label": "holds sensitive data", "confidence": "confirmed", "tactic": "Collection"},
}

CONFIDENCE_WEIGHT = {"confirmed": 1.0, "likely": 0.6, "possible": 0.3}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _edge_id(kind: str, src: str, dst: str, discriminator: str = "") -> str:
    """Deterministic edge id.

    These were random UUIDs, regenerated on every graph build -- which meant a
    path stored on Monday could never be correlated with the graph built on
    Tuesday, so the full-graph view could not highlight which edges were on a
    path, and nothing about an edge was stable enough to reference. Deriving the
    id from what the edge actually IS makes it stable across runs and identical
    for identical facts."""
    import hashlib
    basis = f"{kind}|{src}|{dst}|{discriminator}"
    return "e-" + hashlib.sha1(basis.encode()).hexdigest()[:16]


def _segment_of(asset: dict) -> str:
    """Network segment: /24 when we know the IP, otherwise environment+team, which
    is the best available proxy for 'these machines can probably see each other'."""
    ip = (asset.get("ip") or "").strip()
    if ip:
        try:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        except ValueError:
            pass
    return f"{asset.get('environment') or 'unknown-env'}/{asset.get('owner_team') or 'unassigned'}"


def _asset_ports(asset: dict) -> list:
    """Observed open ports. Sources, in order of trust: Shodan enrichment, the
    Qualys/GAV open-port list, then nmap results stored on the asset."""
    ports = set()
    for key in ("shodan_ports", "open_ports_list", "nmap_ports"):
        for p in asset.get(key) or []:
            try:
                ports.add(int(p))
            except (TypeError, ValueError):
                continue
    for entry in asset.get("open_ports") or []:
        if isinstance(entry, dict) and entry.get("port"):
            try:
                ports.add(int(entry["port"]))
            except (TypeError, ValueError):
                continue
        elif isinstance(entry, (int, str)):
            try:
                ports.add(int(entry))
            except (TypeError, ValueError):
                continue
    return sorted(ports)


def is_internet_facing(asset: dict) -> bool:
    if asset.get("internet_facing") is True:
        return True
    if (asset.get("exposure") or "").lower() in ("internet", "public", "external", "dmz"):
        return True
    ip = (asset.get("ip") or "").strip()
    if ip:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_global:
                return True
        except ValueError:
            pass
    return False


CROWN_TAGS = {"crown_jewel", "crown-jewel", "pii", "phi", "pci", "cjis", "elections",
              "sensitive", "regulated", "confidential"}


def crown_jewel_reason(asset: dict) -> Optional[str]:
    """Why this asset is worth reaching. Returns None if it isn't -- an attack
    path that ends nowhere valuable isn't worth an analyst's attention."""
    crit = (asset.get("criticality") or "").lower()
    if crit in ("crown_jewel", "crown jewel"):
        return "explicitly tagged a crown jewel"
    tags = {str(t).lower() for t in (asset.get("tags") or [])}
    hit = tags & CROWN_TAGS
    if hit:
        return f"tagged {', '.join(sorted(hit))}"
    if asset.get("data_classifications"):
        return f"holds {', '.join(asset['data_classifications'][:3])} data"
    if crit == "critical":
        return "rated business-critical"
    return None


def _exploit_weight(f: dict) -> float:
    """How attractive a vulnerability is to an actual attacker."""
    if f.get("kev_flag"):
        return 1.0
    epss = f.get("epss_score")
    if isinstance(epss, (int, float)) and epss > 0:
        return min(0.95, 0.35 + float(epss))
    cvss = f.get("cvss_score") or 0
    sev = {"Critical": 0.6, "High": 0.45, "Medium": 0.25, "Low": 0.1}.get(f.get("severity"), 0.15)
    return max(sev, min(0.8, float(cvss) / 12.0))


# =========================================================================
# Graph construction
# =========================================================================

async def build_environment_graph(db, max_assets: int = 2000) -> dict:
    """One pass over the inventory + findings, producing typed nodes and evidenced
    edges. Everything downstream (enumeration, choke points, narratives) reads
    this, so the expensive queries happen exactly once."""
    assets = await db.assets.find({}, {"_id": 0}).to_list(max_assets)
    by_id = {a["id"]: a for a in assets}

    findings = await db.findings.find(
        {"status": {"$in": OPEN_STATES}, "asset_id": {"$ne": None}},
        {"_id": 0, "id": 1, "asset_id": 1, "cve": 1, "title": 1, "severity": 1,
         "cvss_score": 1, "epss_score": 1, "kev_flag": 1, "cwe": 1},
    ).to_list(20000)

    findings_by_asset: dict = {}
    for f in findings:
        findings_by_asset.setdefault(f["asset_id"], []).append(f)

    nodes: dict = {}
    edges: list = []

    nodes["internet"] = {"id": "internet", "type": "internet", "label": "Internet",
                          "sublabel": "untrusted", "risk_factors": []}

    segments: dict = {}
    for a in assets:
        seg = _segment_of(a)
        segments.setdefault(seg, []).append(a["id"])

    for a in assets:
        af = findings_by_asset.get(a["id"], [])
        crit_high = [f for f in af if f.get("severity") in ("Critical", "High")]
        kev = [f for f in af if f.get("kev_flag")]
        ports = _asset_ports(a)
        exposed = is_internet_facing(a)
        crown = crown_jewel_reason(a)

        risk_factors = []
        if exposed:
            risk_factors.append("internet-exposed")
        if kev:
            risk_factors.append(f"{len(kev)} actively-exploited CVE(s)")
        if crit_high:
            risk_factors.append(f"{len(crit_high)} critical/high finding(s)")
        dangerous = [p for p in ports if p in NEVER_INTERNET]
        if exposed and dangerous:
            risk_factors.append(f"admin/database port(s) {', '.join(str(p) for p in dangerous)} on the internet")
        if crown:
            risk_factors.append(crown)

        nodes[a["id"]] = {
            "id": a["id"], "type": "host", "label": a.get("hostname") or a.get("ip") or a["id"],
            "sublabel": " · ".join(x for x in [a.get("os"), a.get("owner_team")] if x),
            "ip": a.get("ip"), "os": a.get("os"), "owner_team": a.get("owner_team"),
            "criticality": a.get("criticality"), "segment": _segment_of(a),
            "internet_facing": exposed, "ports": ports,
            "crown_jewel": bool(crown), "crown_reason": crown,
            "finding_count": len(af), "critical_high": len(crit_high), "kev_count": len(kev),
            "top_findings": sorted(af, key=_exploit_weight, reverse=True)[:5],
            "risk_factors": risk_factors,
        }

        # --- internet -> host, when a real service faces outward ---
        if exposed:
            entry_ports = [p for p in ports if p in ENTRY_SERVICES] or None
            svc = (", ".join(f"{ENTRY_SERVICES[p]}/{p}" for p in entry_ports[:4])
                   if entry_ports else "listed as internet-facing")
            edges.append({
                "id": _edge_id("exposed_service", "internet", a["id"]),
                "from": "internet", "to": a["id"],
                "kind": "exposed_service",
                "evidence": f"Reachable from the internet ({svc}).",
                "confidence": "confirmed" if entry_ports else "likely",
                "technique": "T1190" if entry_ports else "T1133",
                "dangerous_ports": [p for p in (entry_ports or []) if p in NEVER_INTERNET],
            })

        # --- host -> itself: the vulnerability that gives code execution ---
        for f in sorted(af, key=_exploit_weight, reverse=True)[:3]:
            if f.get("severity") not in ("Critical", "High") and not f.get("kev_flag"):
                continue
            edges.append({
                "id": _edge_id("exploitable", a["id"], a["id"], f["id"]),
                "from": a["id"], "to": a["id"],
                "kind": "exploitable",
                "evidence": (f"{f.get('cve') or f.get('title')} "
                             + ("— on the CISA KEV list (actively exploited in the wild)"
                                if f.get("kev_flag") else f"— {f.get('severity')} severity")),
                "confidence": "confirmed", "technique": "T1190",
                "finding_id": f["id"], "cve": f.get("cve"),
                "exploit_weight": round(_exploit_weight(f), 2),
            })

    # --- host -> host ---
    for seg, member_ids in segments.items():
        if len(member_ids) < 2:
            continue
        for src_id in member_ids:
            src = by_id[src_id]
            for dst_id in member_ids:
                if src_id == dst_id:
                    continue
                dst = by_id[dst_id]
                dst_ports = _asset_ports(dst)
                pivot = [p for p in dst_ports if p in LATERAL_SERVICES]
                if pivot:
                    svc_name, tech = LATERAL_SERVICES[pivot[0]]
                    edges.append({
                        "id": _edge_id("lateral_service", src_id, dst_id, str(pivot[0])),
                        "from": src_id, "to": dst_id,
                        "kind": "lateral_service", "confidence": "confirmed",
                        "evidence": (f"{dst.get('hostname')} exposes {svc_name} (port {pivot[0]}) "
                                     f"on the same segment {seg}."),
                        "technique": tech, "segment": seg, "port": pivot[0], "service": svc_name,
                    })
                elif src.get("owner_team") and src.get("owner_team") == dst.get("owner_team"):
                    # Same team usually means shared admin accounts -- a real
                    # signal, but an inference, so it is labelled as one.
                    edges.append({
                        "id": _edge_id("credential_reuse", src_id, dst_id),
                        "from": src_id, "to": dst_id,
                        "kind": "credential_reuse", "confidence": "likely",
                        "evidence": (f"Both managed by {src.get('owner_team')} on segment {seg} — "
                                     f"administrative credentials are commonly shared across a team's hosts."),
                        "technique": "T1078", "segment": seg,
                    })
                else:
                    edges.append({
                        "id": _edge_id("same_segment", src_id, dst_id),
                        "from": src_id, "to": dst_id,
                        "kind": "same_segment", "confidence": "possible",
                        "evidence": f"Same network segment ({seg}) — reachable in principle, no confirmed service.",
                        "technique": "T1046", "segment": seg,
                    })

    return {"nodes": nodes, "edges": edges, "segments": segments,
            "assets_scanned": len(assets), "findings_considered": len(findings),
            "built_at": _now_iso()}


# =========================================================================
# Path enumeration
# =========================================================================

def _edge_cost(edge: dict) -> float:
    """Lower = easier for the attacker. Used to prefer the path of least
    resistance, which is the one an attacker actually takes."""
    base = {"exposed_service": 0.2, "exploitable": 0.1, "lateral_service": 0.5,
            "credential_reuse": 0.9, "same_segment": 1.6}.get(edge["kind"], 1.0)
    if edge.get("dangerous_ports"):
        base *= 0.6
    if edge.get("exploit_weight"):
        base *= max(0.3, 1.0 - edge["exploit_weight"])
    return base


def enumerate_paths(graph: dict, max_hops: int = 4, max_paths: int = 200) -> list:
    """Every route from the internet to a crown jewel, up to max_hops.

    Breadth-first with a visited-set per path so a host can't appear twice in the
    same chain (an attacker doesn't loop). Paths are scored and the cheapest
    routes to each distinct target are kept -- ten variations on the same
    two-hop path is noise, the shortest one is the finding."""
    nodes, edges = graph["nodes"], graph["edges"]

    out_edges: dict = {}
    for e in edges:
        if e["from"] == e["to"]:
            continue                      # self-edges are annotations, not hops
        out_edges.setdefault(e["from"], []).append(e)

    exploit_by_host: dict = {}
    for e in edges:
        if e["kind"] == "exploitable":
            exploit_by_host.setdefault(e["from"], []).append(e)

    crown_ids = {nid for nid, n in nodes.items() if n.get("crown_jewel")}
    if not crown_ids:
        return []

    results: list = []
    # queue entries: (current_node, [edges so far], visited set, accumulated cost)
    queue = [(e["to"], [e], {"internet", e["to"]}, _edge_cost(e))
             for e in out_edges.get("internet", [])]

    while queue and len(results) < max_paths * 4:
        current, chain, visited, cost = queue.pop(0)
        if current in crown_ids and len(chain) >= 1:
            results.append({"chain": list(chain), "cost": cost, "target": current})
            continue                       # don't route THROUGH a crown jewel
        if len(chain) >= max_hops:
            continue
        for e in out_edges.get(current, []):
            if e["to"] in visited:
                continue
            # Prefer hops from a host we can actually take over: if the current
            # host has no exploitable finding and the hop is only "same segment",
            # the story is too thin to be worth enumerating.
            if e["kind"] == "same_segment" and current not in exploit_by_host:
                continue
            queue.append((e["to"], chain + [e], visited | {e["to"]}, cost + _edge_cost(e)))

    # keep the cheapest route per (entry, target) pair
    best: dict = {}
    for r in results:
        key = (r["chain"][0]["to"], r["target"])
        if key not in best or r["cost"] < best[key]["cost"]:
            best[key] = r
    ranked = sorted(best.values(), key=lambda r: r["cost"])[:max_paths]

    return [_materialize_path(graph, r, exploit_by_host) for r in ranked]


def _materialize_path(graph: dict, raw: dict, exploit_by_host: dict) -> dict:
    """Turn a raw edge chain into the triageable record the UI and API expose."""
    nodes = graph["nodes"]
    chain, target_id = raw["chain"], raw["target"]
    entry_id = chain[0]["to"]
    entry, target = nodes[entry_id], nodes[target_id]

    hop_nodes = [nodes["internet"]] + [nodes[e["to"]] for e in chain]
    host_ids = [e["to"] for e in chain]

    exploits = []
    for hid in host_ids:
        exploits.extend(exploit_by_host.get(hid, []))

    kev_used = [e for e in exploits if "KEV" in (e.get("evidence") or "")]
    weakest = min((CONFIDENCE_WEIGHT[e["confidence"]] for e in chain), default=1.0)

    # How does the attacker get ONTO the entry host in the first place? Being
    # internet-exposed is necessary but not sufficient -- something has to give
    # them execution. Three honest answers, and we say which one applies rather
    # than quietly implying the first:
    #   exploit               -- a known exploitable vulnerability on that host
    #   exposed_admin_service -- an admin/database port facing the internet, which
    #                            is an entry point in its own right
    #   unproven              -- it's exposed, but we have no evidence of a way in.
    #                            Still worth showing (the exposure is real), but
    #                            labelled and scored down rather than presented as
    #                            a confirmed path.
    entry_exploits = [e for e in exploits if e["from"] == entry_id]
    entry_dangerous = chain[0].get("dangerous_ports") or []
    if entry_exploits:
        entry_vector = "exploit"
    elif entry_dangerous:
        entry_vector = "exposed_admin_service"
    else:
        entry_vector = "unproven"
    speculative = weakest < 0.6 or entry_vector == "unproven"

    # --- score ---
    exploitability = max([e.get("exploit_weight", 0) for e in exploits], default=0.0)
    if not exploitability:
        exploitability = 0.25 if entry.get("internet_facing") else 0.1
    target_value = 1.0 if target.get("criticality") in ("crown_jewel", "crown jewel") else 0.75
    friction = sum(_edge_cost(e) for e in chain)
    score = int(max(0, min(100, round(
        (exploitability * 45) + (target_value * 30) + (weakest * 15) +
        (10 / (1 + friction))
    ))))
    if kev_used:
        score = min(100, score + 10)
    if entry_vector == "unproven":
        # exposure without a demonstrated way in is a real concern, not a
        # confirmed path -- cap it below the confirmed band
        score = min(score, 45)

    tactics = []
    for e in chain:
        t = EDGE_KINDS.get(e["kind"], {}).get("tactic")
        if t and t not in tactics:
            tactics.append(t)
    if exploits and "Execution" not in tactics:
        tactics.insert(1, "Execution")
    if target.get("crown_jewel"):
        tactics.append("Collection")

    return {
        "id": f"ap-{entry_id[:8]}-{target_id[:8]}",
        "entry_node_id": entry_id, "entry_label": entry["label"],
        "target_node_id": target_id, "target_label": target["label"],
        "target_reason": target.get("crown_reason"),
        "hops": len(chain),
        "nodes": hop_nodes,
        "edges": chain,
        "exploits": exploits,
        "risk_score": score,
        "severity": ("Critical" if score >= 80 else "High" if score >= 60
                     else "Medium" if score >= 40 else "Low"),
        "confidence": ("confirmed" if weakest >= 1.0 and entry_vector != "unproven"
                       else "likely" if weakest >= 0.6 and entry_vector != "unproven"
                       else "possible"),
        "speculative": speculative,
        "entry_vector": entry_vector,
        "uses_kev": bool(kev_used),
        "tactics": tactics,
        "risk_factors": sorted({rf for n in hop_nodes for rf in n.get("risk_factors", [])}),
        "narrative": _narrative(nodes, chain, exploits, target),
        "cost": round(raw["cost"], 2),
    }


def _narrative(nodes: dict, chain: list, exploits: list, target: dict) -> str:  # noqa: C901
    """The plain-English 'why this path exists' paragraph. Written the way an
    analyst would brief it, not as a field dump."""
    entry = nodes[chain[0]["to"]]
    parts = []

    entry_bits = []
    if entry.get("internet_facing"):
        dangerous = chain[0].get("dangerous_ports") or []
        if dangerous:
            entry_bits.append(f"is reachable from the public internet on port(s) "
                              f"{', '.join(str(p) for p in dangerous)} — ports that should not be "
                              f"internet-facing")
        else:
            entry_bits.append("is reachable from the public internet")
    entry_exploits = [e for e in exploits if e["from"] == entry["id"]]
    if entry_exploits:
        top = entry_exploits[0]
        if "KEV" in (top.get("evidence") or ""):
            entry_bits.append(f"is vulnerable to {top.get('cve') or 'a known flaw'}, which is being "
                              f"actively exploited in the wild")
        else:
            entry_bits.append(f"is vulnerable to {top.get('cve') or 'a high-severity flaw'}")
    if entry_bits:
        parts.append(f"{entry['label']} " + ", and ".join(entry_bits) + ".")
    else:
        parts.append(f"{entry['label']} is the entry point.")
    if not entry_exploits:
        parts.append("No specific way in to that host has been confirmed, so the first hop is "
                     "the weakest link in this chain — treat it as exposure to investigate "
                     "rather than a proven route.")

    for e in chain[1:]:
        nxt = nodes[e["to"]]
        if e["kind"] == "lateral_service":
            parts.append(f"From there an attacker can reach {nxt['label']} over "
                         f"{e.get('service')} (port {e.get('port')}).")
        elif e["kind"] == "credential_reuse":
            parts.append(f"{nxt['label']} is administered by the same team, so credentials "
                         f"harvested on the way are likely to work there too.")
        else:
            parts.append(f"{nxt['label']} sits on the same network segment and is reachable "
                         f"in principle, though no specific service was confirmed.")

    parts.append(f"The path ends at {target['label']}, which is "
                 f"{target.get('crown_reason') or 'a high-value asset'}.")
    return " ".join(parts)


# =========================================================================
# Choke points -- the "one fix kills the most paths" analysis
# =========================================================================

def choke_points(paths: list, graph: dict) -> list:
    """Rank remediations by how many enumerated paths each one BREAKS.

    This is the whole point of enumerating paths rather than drawing them: with
    a full set you can ask "if I did exactly one thing, what would it be?" and
    answer it with a count instead of an opinion."""
    nodes = graph["nodes"]
    by_action: dict = {}

    def _add(key, action_type, title, detail, node_id, path_id, score):
        entry = by_action.setdefault(key, {
            "id": key, "action_type": action_type, "title": title, "detail": detail,
            "node_id": node_id, "paths_broken": set(), "score_removed": 0,
        })
        entry["paths_broken"].add(path_id)
        entry["score_removed"] += score

    for p in paths:
        # patching the exploited vulnerability
        for ex in p["exploits"]:
            host = nodes.get(ex["from"], {})
            key = f"patch:{ex.get('cve') or ex.get('finding_id')}:{ex['from']}"
            _add(key, "patch",
                 f"Patch {ex.get('cve') or 'the vulnerability'} on {host.get('label')}",
                 ex.get("evidence") or "", ex["from"], p["id"], p["risk_score"])

        # closing the internet exposure at the entry point
        first = p["edges"][0]
        if first["kind"] == "exposed_service":
            host = nodes.get(first["to"], {})
            dangerous = first.get("dangerous_ports") or []
            if dangerous:
                title = (f"Remove internet exposure of port(s) "
                         f"{', '.join(str(d) for d in dangerous)} on {host.get('label')}")
            else:
                title = f"Restrict internet access to {host.get('label')}"
            _add(f"expose:{first['to']}", "network", title,
                 first.get("evidence") or "", first["to"], p["id"], p["risk_score"])

        # segmenting away the pivot
        for e in p["edges"][1:]:
            if e["kind"] == "lateral_service":
                host = nodes.get(e["to"], {})
                _add(f"segment:{e['to']}:{e.get('port')}", "segmentation",
                     f"Block {e.get('service')} (port {e.get('port')}) to {host.get('label')} "
                     f"from within {e.get('segment')}",
                     e.get("evidence") or "", e["to"], p["id"], p["risk_score"])
            elif e["kind"] == "credential_reuse":
                host = nodes.get(e["to"], {})
                _add(f"creds:{e.get('segment')}", "identity",
                     f"Stop sharing local admin credentials across {host.get('owner_team')} hosts "
                     f"(LAPS or equivalent)",
                     e.get("evidence") or "", e["to"], p["id"], p["risk_score"])

    out = []
    total = len(paths) or 1
    for entry in by_action.values():
        broken = len(entry["paths_broken"])
        out.append({
            **{k: v for k, v in entry.items() if k != "paths_broken"},
            "paths_broken": broken,
            "paths_broken_pct": round(100 * broken / total, 1),
            "path_ids": sorted(entry["paths_broken"] if isinstance(entry["paths_broken"], set) else []),
        })
    out.sort(key=lambda x: (-x["paths_broken"], -x["score_removed"]))
    return out[:25]


# =========================================================================
# Top-level analysis + persistence
# =========================================================================

async def run_attack_path_analysis(db, max_hops: int = 4, max_paths: int = 200) -> dict:
    """Build the graph, enumerate paths, compute choke points, and persist the
    result so triage state survives across runs."""
    graph = await build_environment_graph(db)
    paths = enumerate_paths(graph, max_hops=max_hops, max_paths=max_paths)
    chokes = choke_points(paths, graph)

    existing = {p["id"]: p for p in await db.attack_paths.find({}, {"_id": 0}).to_list(2000)}
    now = _now_iso()
    kept_ids = set()
    for p in paths:
        kept_ids.add(p["id"])
        prior = existing.get(p["id"])
        doc = {
            **p,
            "status": (prior or {}).get("status", "open"),
            "analyst_note": (prior or {}).get("analyst_note"),
            "first_seen_at": (prior or {}).get("first_seen_at", now),
            "last_seen_at": now,
        }
        await db.attack_paths.replace_one({"id": p["id"]}, doc, upsert=True)

    # paths that no longer exist were remediated (or the data changed) -- mark
    # them resolved rather than deleting, so "we fixed 12 paths" is provable
    stale = [pid for pid in existing if pid not in kept_ids]
    if stale:
        await db.attack_paths.update_many(
            {"id": {"$in": stale}, "status": {"$ne": "resolved"}},
            {"$set": {"status": "resolved", "resolved_at": now,
                       "resolution_note": "No longer reachable in the current environment graph."}})

    summary = {
        "paths_found": len(paths),
        "critical_paths": len([p for p in paths if p["severity"] == "Critical"]),
        "confirmed_paths": len([p for p in paths if not p["speculative"]]),
        "kev_paths": len([p for p in paths if p["uses_kev"]]),
        "crown_jewels_reachable": len({p["target_node_id"] for p in paths}),
        "entry_points": len({p["entry_node_id"] for p in paths}),
        "resolved_since_last_run": len(stale),
        "assets_scanned": graph["assets_scanned"],
        "findings_considered": graph["findings_considered"],
        "crown_jewels_defined": len([n for n in graph["nodes"].values() if n.get("crown_jewel")]),
        "generated_at": now,
    }
    await db.attack_path_runs.insert_one({
        "id": str(uuid.uuid4()), **summary,
        "top_choke_points": chokes[:5],
    })
    return {"summary": summary, "paths": paths, "choke_points": chokes, "graph_stats": {
        "nodes": len(graph["nodes"]), "edges": len(graph["edges"]),
        "segments": len(graph["segments"])}}
