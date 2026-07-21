"""YARA rule matching -- upload a file (or paste raw bytes/text) and check it against
your own library of YARA rules. This is deliberately scoped to "bring your own rules":
VulnOps doesn't bundle a third-party rule pack (licensing varies rule-set to rule-set,
and a stale bundled copy would be worse than none) -- it ships with two small example
rules so the pipeline is provably working the moment you open the page, and you paste
in real rules from wherever you already trust (your own IR team, YARA-Rules, Florian
Roth's signature-base, vendor advisories, etc.).

Rules compile individually rather than as one batch: if one rule has a syntax error, the
rest still run, and the invalid one is reported back instead of silently blocking the
whole scan.
"""
import hashlib
import uuid
from datetime import datetime, timezone

import yara

MAX_MATCH_STRINGS = 25       # cap per-rule match evidence so one greedy rule can't blow up the response
MAX_STRING_SNIPPET = 120     # bytes of context kept per matched string instance
SCAN_TIMEOUT_SEC = 20


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_rule_source(source: str) -> dict:
    """Compiles a single rule source in isolation. Returns {"ok": True} or
    {"ok": False, "error": "..."} -- used both by the explicit /validate endpoint and
    before saving a rule, so a broken rule can't silently stop matching without you
    knowing why."""
    if not source or not source.strip():
        return {"ok": False, "error": "Rule source can't be empty"}
    try:
        yara.compile(source=source)
        return {"ok": True, "error": None}
    except yara.SyntaxError as e:
        return {"ok": False, "error": str(e)}
    except yara.Error as e:
        return {"ok": False, "error": f"YARA error: {e}"}


async def compile_enabled_rules(db) -> tuple[list[tuple[dict, "yara.Rules"]], list[dict]]:
    """Compiles every enabled rule individually. Returns (compiled, broken) where
    compiled is a list of (rule_doc, yara.Rules) pairs ready to match against, and
    broken is a list of {id, name, error} for enabled rules that failed to compile
    (skipped, not fatal to the rest of the scan)."""
    rules = await db.yara_rules.find({"enabled": True}, {"_id": 0}).to_list(500)
    compiled, broken = [], []
    for r in rules:
        try:
            obj = yara.compile(source=r["source"])
            compiled.append((r, obj))
        except yara.Error as e:
            broken.append({"id": r["id"], "name": r["name"], "error": str(e)})
    return compiled, broken


def _decode_snippet(data: bytes) -> str:
    snippet = data[:MAX_STRING_SNIPPET]
    try:
        return snippet.decode("utf-8")
    except UnicodeDecodeError:
        return snippet.hex()


def _serialize_match(rule_doc: dict, match) -> dict:
    """yara-python >= 4.3's Match.strings is a list of StringMatch objects, each with
    .identifier and .instances (offset + matched_data per hit) -- flattened here into
    plain dicts so this is JSON-serializable without the caller needing to know the
    yara-python version's object model."""
    strings = []
    for sm in (match.strings or [])[:MAX_MATCH_STRINGS]:
        for inst in (getattr(sm, "instances", None) or []):
            strings.append({
                "identifier": sm.identifier,
                "offset": inst.offset,
                "snippet": _decode_snippet(inst.matched_data),
            })
            if len(strings) >= MAX_MATCH_STRINGS:
                break
        if len(strings) >= MAX_MATCH_STRINGS:
            break
    meta = dict(match.meta) if match.meta else {}
    return {
        "rule_id": rule_doc["id"], "rule_name": rule_doc["name"], "matched_rule": match.rule,
        "tags": list(match.tags or []), "meta": meta,
        "severity": str(meta.get("severity") or meta.get("Severity") or "Medium").title(),
        "strings": strings,
    }


def scan_bytes(data: bytes, compiled: list[tuple[dict, "yara.Rules"]]) -> list[dict]:
    matches = []
    for rule_doc, obj in compiled:
        for m in obj.match(data=data, timeout=SCAN_TIMEOUT_SEC):
            matches.append(_serialize_match(rule_doc, m))
    return matches


async def _create_yara_finding(db, match: dict, filename: str, sha256: str,
                                asset: dict | None, asset_id: str | None, source_label: str) -> bool:
    canonical_key = f"yara:{sha256}:{match['rule_name']}"
    existing = await db.findings.find_one({"canonical_key": canonical_key}, {"_id": 0})
    if existing:
        if existing.get("status") not in ("Fixed validated", "Closed administratively", "False positive"):
            await db.findings.update_one({"id": existing["id"]}, {"$set": {"last_seen_at": _now_iso()}})
        return False
    now = _now_iso()
    string_note = "; ".join(
        f"{s['identifier']} @ offset {s['offset']}: {s['snippet']!r}" for s in match["strings"][:5]
    ) or "no string-level detail captured"
    finding = {
        "id": str(uuid.uuid4()), "canonical_key": canonical_key,
        "title": f"YARA match: {match['rule_name']} in {filename}",
        "description": (match["meta"].get("description") or match["meta"].get("Description") or
                         f"File {filename} (sha256:{sha256[:16]}…) matched YARA rule '{match['rule_name']}'.")
                        + f" Matched string(s): {string_note}",
        "severity": match["severity"], "status": "New", "cve": None, "cwe": "CWE-506",
        "source_tool": "YARA", "source_tool_type": "Malware / Pattern Scanning",
        "detection_channel": "yara_scan", "tags": match["tags"],
        "asset_id": asset_id, "asset_hostname": (asset or {}).get("hostname") or source_label,
        "asset_ip": (asset or {}).get("ip"), "asset_criticality": (asset or {}).get("criticality"),
        "asset_exposure": (asset or {}).get("exposure"),
        "yara_rule_id": match["rule_id"], "yara_filename": filename, "yara_sha256": sha256,
        "first_seen_at": now, "last_seen_at": now, "rti": [],
    }
    await db.findings.insert_one(finding)
    return True


async def run_yara_scan(db, filename: str, content: bytes, label: str | None = None,
                         asset_id: str | None = None) -> dict:
    compiled, broken = await compile_enabled_rules(db)
    if not compiled:
        if broken:
            raise ValueError(
                f"No usable YARA rules -- {len(broken)} enabled rule(s) failed to compile "
                f"(check Rules tab), and there are no other enabled rules to scan with."
            )
        raise ValueError("No enabled YARA rules to scan with -- add or enable a rule first.")

    sha256 = hashlib.sha256(content).hexdigest()
    matches = scan_bytes(content, compiled)

    asset = await db.assets.find_one({"id": asset_id}, {"_id": 0}) if asset_id else None
    source_label = (asset or {}).get("hostname") or label or filename or "YARA upload"

    findings_created = 0
    for m in matches:
        created = await _create_yara_finding(db, m, filename, sha256, asset, asset_id, source_label)
        if created:
            findings_created += 1

    record = {
        "id": str(uuid.uuid4()), "filename": filename, "label": label, "asset_id": asset_id,
        "asset_hostname": (asset or {}).get("hostname"), "size_bytes": len(content), "sha256": sha256,
        "rules_checked": len(compiled), "rules_broken": len(broken),
        "matched_rule_count": len(matches), "findings_created": findings_created,
        "matches": matches, "scanned_at": _now_iso(),
    }
    await db.yara_scan_history.insert_one(dict(record))

    # Check the file hash against the threat intel watchlist regardless of whether
    # a YARA rule itself matched -- a known-bad hash is worth flagging even if no
    # local rule happens to cover it yet.
    from threat_intel_watchlist import check_and_emit
    await check_and_emit(db, sha256, entity_type="asset" if asset_id else "file",
                          entity_id=asset_id or sha256, entity_label=source_label)

    # Also automatically check the hash against VirusTotal's live multi-engine
    # reputation -- the local watchlist above only catches hashes someone has
    # already seen and added/synced; this catches hashes VT itself already
    # knows about even if this is the first time this app has ever seen them.
    from feature_flags import is_enabled
    hash_intel_result = None
    if await is_enabled(db, "auto_hash_virustotal_check"):
        from hash_intel import check_hash_virustotal
        hash_intel_result = await check_hash_virustotal(
            db, sha256, entity_type="asset" if asset_id else "file",
            entity_id=asset_id or sha256, entity_label=source_label)

    if matches:
        from security_events import emit_event
        rule_names = ", ".join(sorted({m.get("rule_name", "unknown") for m in matches})[:5])
        entity_id = asset_id or sha256
        await emit_event(db, source="yara", event_type="yara_match", severity="High",
            title=f"YARA match on {source_label}: {rule_names}",
            entity_type="asset" if asset_id else "file", entity_id=entity_id, entity_label=source_label,
            description=f"{len(matches)} rule(s) matched scanning {filename} (sha256 {sha256[:16]}...).",
            raw={"scan_id": record["id"], "sha256": sha256, "matched_rules": rule_names})

    return {
        "id": record["id"], "filename": filename, "sha256": sha256,
        "rules_checked": len(compiled), "rules_broken": broken,
        "matched_rule_count": len(matches), "findings_created": findings_created,
        "matches": matches, "virustotal": hash_intel_result,
    }
