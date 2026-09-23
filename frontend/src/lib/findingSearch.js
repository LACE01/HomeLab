// Client-side mirror of the backend advanced search (#58): field-scoped operators
// (qid: cve: owner:/team: source: entity:) plus free text over title/cve/hostname/qid,
// and multi-select severity/status facets. "Build once, reuse" -- used by the
// campaign Findings tab to filter already-loaded findings with the same semantics as
// the main Findings page, without another server round-trip.

export function parseSearch(q) {
  const extra = [];
  const free = [];
  for (const tok of String(q || "").trim().split(/\s+/).filter(Boolean)) {
    const i = tok.indexOf(":");
    if (i > 0) {
      const field = tok.slice(0, i).toLowerCase();
      const val = tok.slice(i + 1).trim().toLowerCase();
      if (val) {
        const contains = (key) => (f) => String(f[key] ?? "").toLowerCase().includes(val);
        if (field === "qid") { extra.push(contains("qid")); continue; }
        if (field === "cve") { extra.push(contains("cve")); continue; }
        if (field === "owner" || field === "team") { extra.push(contains("owner_team")); continue; }
        if (field === "source") { extra.push(contains("source_tool")); continue; }
        if (field === "entity") { extra.push(contains("entity_name")); continue; }
      }
    }
    free.push(tok);
  }
  return { extra, freeText: free.join(" ").toLowerCase() };
}

export function matchFinding(f, parsed) {
  for (const fn of parsed.extra) if (!fn(f)) return false;
  if (parsed.freeText) {
    const hay = [f.title, f.cve, f.asset_hostname, f.qid, f.plugin_id]
      .map((x) => String(x ?? "").toLowerCase());
    if (!hay.some((h) => h.includes(parsed.freeText))) return false;
  }
  return true;
}

export function facetMatch(f, { severities = [], statuses = [] } = {}) {
  if (severities.length && !severities.includes(f.severity)) return false;
  if (statuses.length && !statuses.includes(f.status)) return false;
  return true;
}

export const SEARCH_OPERATOR_HINT = "Search title/CVE/host/QID — or use cve: qid: owner: source: entity:";
