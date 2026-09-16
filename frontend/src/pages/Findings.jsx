import { useEffect, useState, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { usePreferences } from "@/lib/usePreferences";
import Layout from "@/components/Layout";
import { SevBadge, Chip, RiskBar } from "@/components/Badges";
import { fmtRel, isOverdue } from "@/lib/utils-fmt";
import { Link } from "react-router-dom";
import { MagnifyingGlass, FileArrowDown, FunnelSimple, CaretDown, CaretRight, CaretLeft, StackSimple, ListBullets, GridFour, Sparkle, X, SortAscending, SortDescending } from "@phosphor-icons/react";
import TeamCombobox from "@/components/TeamCombobox";

const VIEWS = [
  { id: "", label: "All Open" },
  { id: "highest_risk", label: "Highest Risk" },
  { id: "kev", label: "KEV (Exploited)" },
  { id: "internet_facing_critical", label: "Internet-Facing Critical" },
  { id: "overdue", label: "Overdue (SLA)" },
  { id: "reopened", label: "Reopened" },
  { id: "patch_unavailable", label: "Patch Unavailable" },
];

const STATUSES = ["New","Needs triage","Valid","False positive","Duplicate","Mitigated","Accepted risk","Fixed pending validation","Fixed validated","Reopened"];

const GROUP_OPTIONS = [
  { id: "none", label: "Flat list" },
  { id: "cve", label: "by CVE-ID" },
  { id: "os", label: "by Operating System" },
  { id: "title", label: "by Title" },
  { id: "severity", label: "by Severity" },
  { id: "asset", label: "by Asset" },
];

const SORT_OPTIONS = [
  { id: "risk_score", label: "Risk score" },
  { id: "cvss_score", label: "CVSS" },
  { id: "epss_score", label: "EPSS" },
  { id: "due_at", label: "Due date" },
  { id: "first_seen_at", label: "First seen" },
  { id: "last_seen_at", label: "Last seen" },
];

const PAGE_SIZE = 100;

const EXPLOIT_OPTIONS = [
  { id: "kev", label: "KEV (exploited)" },
  { id: "active_attacks", label: "Active attacks (EPSS)" },
  { id: "public_exploit", label: "Public exploit" },
  { id: "epss_high", label: "EPSS ≥ 0.5" },
];

function MultiSelect({ label, options, selected, onChange, width = "w-52" }) {
  const [open, setOpen] = useState(false);
  const toggle = (id) => {
    const set = new Set(selected);
    set.has(id) ? set.delete(id) : set.add(id);
    onChange([...set]);
  };
  const count = selected.length;
  return (
    <div className="relative">
      <button onClick={() => setOpen(o => !o)}
        className={`h-8 px-2.5 text-[12px] rounded border inline-flex items-center gap-1.5 ${count ? "border-blue-500/40 bg-blue-500/10 text-blue-200" : "border-[#30363D] text-slate-300 hover:border-[#484F58]"}`}>
        {label}{count > 0 && <span className="text-[10px] bg-blue-500/30 text-blue-100 rounded-full px-1.5">{count}</span>}
        <CaretDown size={12} />
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className={`absolute z-20 mt-1 ${width} max-h-64 overflow-y-auto bg-[#161B22] border border-[#30363D] rounded-md shadow-lg p-1`}>
            {options.length === 0 && <div className="px-2 py-1.5 text-[11.5px] text-slate-500">No options</div>}
            {options.map(o => {
              const id = typeof o === "string" ? o : o.id;
              const lbl = typeof o === "string" ? o : o.label;
              const on = selected.includes(id);
              return (
                <label key={id} className="flex items-center gap-2 px-2 py-1.5 text-[12px] cursor-pointer hover:bg-slate-800/40 rounded">
                  <input type="checkbox" checked={on} onChange={() => toggle(id)} />
                  <span className={on ? "text-blue-200" : "text-slate-300"}>{lbl}</span>
                </label>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
}


export default function Findings() {
  const { user } = useAuth();
  const { prefs, setSection } = usePreferences();
  const [searchParams, setSearchParams] = useSearchParams();
  const cweParam = searchParams.get("cwe");
  const cveParam = searchParams.get("cve");
  // Deep-link support: dashboard/operational tiles link here with filters pre-applied,
  // e.g. /findings?view=kev&owner_team=IT%20Ops -- these seed initial state below and
  // are otherwise ordinary filters the user can then change.
  const ownerTeamParam = searchParams.get("owner_team");
  // Also supports ?q=<text> for deep links from YARA/SBOM scan results ("view the
  // finding(s) this scan created") -- reuses the same free-text search the box
  // already does (title/CVE/hostname/QID regex match on the backend).
  const qParam = searchParams.get("q");
  const sourceToolParam = searchParams.get("source_tool");
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [q, setQ] = useState(qParam || "");
  const [view, setView] = useState(searchParams.get("view") || "");
  const [severities, setSeverities] = useState(searchParams.getAll("severity"));
  const [statuses, setStatuses] = useState(searchParams.getAll("status"));
  // Item: flexible multi-select facets on the Findings tab.
  const [exploitability, setExploitability] = useState([]);   // kev|active_attacks|public_exploit|epss_high
  const [assetTypes, setAssetTypes] = useState([]);           // server|workstation|...
  const [tagFilter, setTagFilter] = useState([]);            // asset tags
  const [kevOnly, setKevOnly] = useState(false);
  const [internetOnly, setInternetOnly] = useState(false);
  const [facetOpts, setFacetOpts] = useState({ available_tags: [], available_asset_types: [] });
  const [selected, setSelected] = useState(new Set());
  const [bulkStatus, setBulkStatus] = useState("Valid");
  const [bulkAssignee, setBulkAssignee] = useState("");
  const [bulkOwnerTeam, setBulkOwnerTeam] = useState("");
  const [loading, setLoading] = useState(false);
  const [myQueue, setMyQueue] = useState(!!user?.team && !ownerTeamParam);
  const [groups, setGroups] = useState([]);
  const [expanded, setExpanded] = useState(new Set());
  const [groupChildren, setGroupChildren] = useState({}); // key → finding[]
  const [nlMode, setNlMode] = useState(false);
  const [nlInterpreted, setNlInterpreted] = useState(null);
  const [nlLoading, setNlLoading] = useState(false);
  const [sort, setSort] = useState("risk_score");
  const [order, setOrder] = useState("desc");
  const [page, setPage] = useState(0);

  const groupBy = prefs?.findings?.group_by || "none";
  const viewMode = prefs?.findings?.view_mode || "by_asset";

  const load = async () => {
    setLoading(true);
    if (groupBy !== "none" && !cweParam && !cveParam && !sourceToolParam) {
      const params = { group_by: groupBy, view_mode: viewMode, limit: 100 };
      if (q) params.q = q; // search box now applies in grouped view too (title/CVE/hostname/QID)
      if (severities.length === 1) params.severity = severities[0];
      if (statuses.length === 1) params.status = statuses[0];
      if (myQueue && user?.team) params.owner_team = user.team;
      else if (ownerTeamParam) params.owner_team = ownerTeamParam; // grouped view previously dropped team deep-links
      const r = await api.get("/v1/findings-groups", { params });
      setGroups(r.data.groups || []);
      setExpanded(new Set());
      setGroupChildren({});
      setLoading(false);
      return;
    }
    const usp = new URLSearchParams();
    usp.set("limit", PAGE_SIZE); usp.set("offset", page * PAGE_SIZE); usp.set("sort", sort); usp.set("order", order);
    if (q) usp.set("q", q);
    if (view) usp.set("view", view);
    severities.forEach(v => usp.append("severity", v));
    statuses.forEach(v => usp.append("status", v));
    exploitability.forEach(v => usp.append("exploitability", v));
    assetTypes.forEach(v => usp.append("asset_type", v));
    tagFilter.forEach(v => usp.append("tags", v));
    if (kevOnly) usp.set("kev", "true");
    if (internetOnly) usp.set("internet_facing", "true");
    if (cweParam) usp.set("cwe", cweParam);
    if (cveParam) usp.set("cve", cveParam);
    if (myQueue && user?.team) usp.set("owner_team", user.team);
    else if (ownerTeamParam) usp.set("owner_team", ownerTeamParam);
    if (sourceToolParam) usp.set("source_tool", sourceToolParam);
    const r = await api.get("/v1/findings", { params: usp });
    setItems(r.data.items || []); setTotal(r.data.total);
    setLoading(false); setSelected(new Set());
  };
  const facetKey = [severities.join(","), statuses.join(","), exploitability.join(","), assetTypes.join(","), tagFilter.join(","), kevOnly, internetOnly].join("|");
  useEffect(() => { if (prefs) load(); /* eslint-disable-next-line */ }, [prefs, view, facetKey, myQueue, groupBy, viewMode, cweParam, cveParam, sourceToolParam, sort, order, page]);
  // Any filter change (other than paging itself) should reset back to page 1 --
  // otherwise you can land on an empty page 5 after narrowing a filter down.
  useEffect(() => { setPage(0); }, [view, facetKey, myQueue, sort, order, q]);
  useEffect(() => { api.get("/v1/findings/stats").then(r => setFacetOpts(r.data)).catch(() => {}); }, []);

  // Keep the URL in sync with the current filters (replace, not push, so we don't
  // pollute history). This is what makes the back arrow from a Finding Detail
  // return to the exact filtered view (e.g. a Team Dashboard drill-down's
  // owner_team scope) instead of resetting to the default all-findings list.
  useEffect(() => {
    const p = new URLSearchParams();
    if (view) p.set("view", view);
    severities.forEach(v => p.append("severity", v));
    statuses.forEach(v => p.append("status", v));
    if (q) p.set("q", q);
    if (ownerTeamParam) p.set("owner_team", ownerTeamParam);
    if (cweParam) p.set("cwe", cweParam);
    if (cveParam) p.set("cve", cveParam);
    if (sourceToolParam) p.set("source_tool", sourceToolParam);
    if (p.toString() !== searchParams.toString()) setSearchParams(p, { replace: true });
    // eslint-disable-next-line
  }, [view, facetKey, q]);

  const runNlSearch = async () => {
    if (!q.trim()) return;
    setNlLoading(true);
    try {
      const r = await api.get("/v1/findings/nl-search", { params: { q } });
      setItems(r.data.items || []); setTotal(r.data.total);
      setNlInterpreted(r.data.interpreted || []);
      setGroups([]); setSelected(new Set());
    } finally {
      setNlLoading(false);
    }
  };

  const clearNlSearch = () => {
    setNlInterpreted(null);
    setQ("");
    load();
  };

  const setGroupBy = (id) => setSection("findings", { group_by: id });
  const setViewMode = (id) => setSection("findings", { view_mode: id });

  const bulkAssignOwner = async () => {
    if (!bulkOwnerTeam || selected.size === 0) return;
    const r = await api.post("/v1/findings/bulk-owner", { ids: Array.from(selected), owner_team: bulkOwnerTeam });
    if (r.data?.updated) { /* sonner already shows toast elsewhere; minimal feedback */ }
    setBulkOwnerTeam("");
    await load();
  };

  const expandGroup = async (key) => {
    const next = new Set(expanded);
    if (next.has(key)) { next.delete(key); setExpanded(next); return; }
    next.add(key); setExpanded(next);
    if (groupChildren[key]) return;
    // Fetch children matching this group key
    const params = { limit: 50 };
    if (groupBy === "cve") params.cve = key;
    else if (groupBy === "severity") params.severity = key;
    else if (groupBy === "asset") params.q = key;
    else if (groupBy === "os") params.q = key;
    else if (groupBy === "title") params.q = key;
    const r = await api.get("/v1/findings", { params });
    setGroupChildren(prev => ({ ...prev, [key]: r.data.items || [] }));
  };

  const exportCsv = async () => {
    const params = {};
    if (severities.length === 1) params.severity = severities[0];
    if (status) params.status = status;
    const r = await api.get("/v1/reports/csv/findings", { params, responseType: "blob" });
    const url = URL.createObjectURL(r.data);
    const a = document.createElement("a"); a.href = url; a.download = "findings.csv"; a.click();
    URL.revokeObjectURL(url);
  };

  const toggleAll = (checked) => setSelected(checked ? new Set(items.map(i=>i.id)) : new Set());
  const toggleOne = (id) => { const n = new Set(selected); n.has(id) ? n.delete(id) : n.add(id); setSelected(n); };

  const doBulk = async () => {
    if (!selected.size) return;
    await api.post("/v1/findings/bulk-status", { ids: [...selected], status: bulkStatus });
    await load();
  };
  const doBulkAssign = async () => {
    if (!selected.size || !bulkAssignee) return;
    await api.post("/v1/findings/bulk-assign", { ids: [...selected], assignee: bulkAssignee });
    await load();
  };

  const counter = useMemo(() => `${items.length} of ${total}`, [items, total]);

  return (
    <Layout title="Findings Workbench" subtitle="Triage, prioritize, assign, and remediate vulnerabilities at scale"
      actions={<>
        {user?.team && (
          <div className="flex items-center border border-[#30363D] rounded overflow-hidden" data-testid="queue-toggle">
            <button data-testid="queue-mine" onClick={()=>setMyQueue(true)} className={`px-3 h-8 text-[12px] ${myQueue?"bg-blue-500/15 text-blue-300":"text-slate-400 hover:bg-slate-800/40"}`}>My Team ({user.team})</button>
            <button data-testid="queue-all" onClick={()=>setMyQueue(false)} className={`px-3 h-8 text-[12px] ${!myQueue?"bg-blue-500/15 text-blue-300":"text-slate-400 hover:bg-slate-800/40"}`}>All Teams</button>
          </div>
        )}
        <button data-testid="export-csv" onClick={exportCsv}
          className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] hover:bg-slate-800/40 rounded inline-flex items-center gap-1.5 text-slate-300">
          <FileArrowDown size={14}/> Export CSV
        </button>
      </>}>

      {nlInterpreted && (
        <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2 mb-3 flex items-center justify-between gap-3">
          <div className="flex items-center gap-1.5 flex-wrap text-[11.5px]">
            <span className="text-blue-300 font-medium inline-flex items-center gap-1"><Sparkle size={12}/> Interpreted as:</span>
            {nlInterpreted.map((i, idx) => <Chip key={idx} color="blue">{i}</Chip>)}
          </div>
          <button onClick={clearNlSearch} className="text-slate-500 hover:text-slate-300 shrink-0"><X size={14}/></button>
        </div>
      )}

      {/* Filters bar */}
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md mb-3">
        <div className="px-3 py-2 flex flex-wrap gap-2 items-center border-b border-[#30363D]">
          <div className={`flex items-center gap-1.5 border rounded px-2 h-8 flex-1 min-w-[260px] ${nlMode ? "bg-blue-500/5 border-blue-500/40" : "bg-[#161B22] border-[#30363D]"}`}>
            {nlMode ? <Sparkle size={14} className="text-blue-300"/> : <MagnifyingGlass size={14} className="text-slate-500" />}
            <input data-testid="search-input" value={q} onChange={(e)=>setQ(e.target.value)}
              onKeyDown={(e)=>e.key==='Enter'&&(nlMode ? runNlSearch() : load())}
              placeholder={nlMode ? 'Try "critical kev findings on windows owned by AppSec"…' : "Search title, CVE, hostname, QID…"}
              className="bg-transparent flex-1 outline-none text-[12.5px] text-slate-200 placeholder:text-slate-600" />
          </div>
          <button data-testid="nl-toggle" onClick={()=>{ if (nlMode) clearNlSearch(); setNlMode(!nlMode); }}
            title="Natural language search — no AI tokens, just pattern matching"
            className={`h-8 px-2.5 text-[12px] rounded border inline-flex items-center gap-1.5 ${nlMode ? "bg-blue-500/15 border-blue-500/40 text-blue-300" : "border-[#30363D] text-slate-400 hover:border-[#484F58]"}`}>
            <Sparkle size={13}/> Ask
          </button>
          <MultiSelect label="Severity" options={["Critical","High","Medium","Low","Info"]} selected={severities} onChange={setSeverities} width="w-44"/>
          <MultiSelect label="Status" options={STATUSES} selected={statuses} onChange={setStatuses} width="w-56"/>
          <MultiSelect label="Exploitability" options={EXPLOIT_OPTIONS} selected={exploitability} onChange={setExploitability} width="w-56"/>
          <MultiSelect label="Device type" options={facetOpts.available_asset_types || []} selected={assetTypes} onChange={setAssetTypes} width="w-48"/>
          <MultiSelect label="Tags" options={facetOpts.available_tags || []} selected={tagFilter} onChange={setTagFilter} width="w-52"/>
          <button onClick={()=>setKevOnly(v=>!v)}
            className={`h-8 px-2.5 text-[12px] rounded border ${kevOnly ? "border-red-500/40 bg-red-500/10 text-red-200" : "border-[#30363D] text-slate-300 hover:border-[#484F58]"}`}>KEV</button>
          <button onClick={()=>setInternetOnly(v=>!v)}
            className={`h-8 px-2.5 text-[12px] rounded border ${internetOnly ? "border-amber-500/40 bg-amber-500/10 text-amber-200" : "border-[#30363D] text-slate-300 hover:border-[#484F58]"}`}>Internet-facing</button>
          {(severities.length||statuses.length||exploitability.length||assetTypes.length||tagFilter.length||kevOnly||internetOnly) > 0 && (
            <button onClick={()=>{ setSeverities([]); setStatuses([]); setExploitability([]); setAssetTypes([]); setTagFilter([]); setKevOnly(false); setInternetOnly(false); }}
              className="h-8 px-2.5 text-[12px] rounded border border-[#30363D] text-slate-400 hover:text-slate-200 inline-flex items-center gap-1"><X size={12}/> Clear</button>
          )}
          <select data-testid="filter-sort" value={sort} onChange={(e)=>setSort(e.target.value)} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200">
            {SORT_OPTIONS.map(o => <option key={o.id} value={o.id}>Sort: {o.label}</option>)}
          </select>
          <button data-testid="sort-order-toggle" onClick={()=>setOrder(order === "desc" ? "asc" : "desc")}
            title={order === "desc" ? "Highest first — click for lowest first" : "Lowest first — click for highest first"}
            className="h-8 px-2.5 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300">
            {order === "desc" ? <><SortDescending size={14}/> Highest first</> : <><SortAscending size={14}/> Lowest first</>}
          </button>
          <button data-testid="search-go" onClick={()=> nlMode ? runNlSearch() : load()} disabled={nlLoading}
            className="h-8 px-3 text-[12px] bg-blue-500/15 text-blue-300 border border-blue-500/30 rounded hover:bg-blue-500/25 disabled:opacity-50">
            <FunnelSimple size={14} className="inline mr-1"/> {nlMode ? (nlLoading ? "Thinking…" : "Ask") : "Apply"}
          </button>
        </div>
        <div className="px-3 py-1.5 flex flex-wrap gap-1.5 items-center">
          <span className="text-[10px] uppercase tracking-wider font-mono text-slate-500 mr-1">Saved Views</span>
          {VIEWS.map(v => (
            <button key={v.id} data-testid={`view-${v.id||'all'}`} onClick={()=>setView(v.id)}
              className={`px-2 py-1 text-[11.5px] rounded-sm border ${view===v.id?"border-blue-500/40 bg-blue-500/10 text-blue-300":"border-[#30363D] text-slate-400 hover:text-slate-200 hover:border-[#484F58]"}`}>
              {v.label}
            </button>
          ))}
        </div>
        {/* Grouping & view-mode controls (Iteration 3c) */}
        <div className="px-3 py-1.5 flex flex-wrap gap-2 items-center border-t border-[#30363D]">
          <span className="text-[10px] uppercase tracking-wider font-mono text-slate-500 mr-1 inline-flex items-center gap-1">
            <StackSimple size={11}/> Group
          </span>
          <select
            data-testid="group-by"
            value={groupBy}
            onChange={(e)=>setGroupBy(e.target.value)}
            className="h-7 bg-[#161B22] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-200"
          >
            {GROUP_OPTIONS.map(o => <option key={o.id} value={o.id}>{o.label}</option>)}
          </select>
          <div className="flex items-center border border-[#30363D] rounded overflow-hidden ml-2" data-testid="view-mode-toggle">
            <button
              data-testid="view-mode-by-asset"
              onClick={() => {
                setViewMode("by_asset");
                // "by Asset" always groups by asset hostname (overrides prior cve grouping).
                if (groupBy !== "asset") setGroupBy("asset");
              }}
              className={`px-2.5 h-7 text-[11.5px] inline-flex items-center gap-1 ${viewMode==="by_asset" && groupBy!=="none" ?"bg-blue-500/15 text-blue-300":"text-slate-400 hover:bg-slate-800/40"}`}
            >
              <ListBullets size={11}/> by Asset
            </button>
            <button
              data-testid="view-mode-by-vulnerability"
              onClick={() => {
                setViewMode("by_vulnerability");
                // "by Vulnerability" always groups by CVE (overrides prior asset grouping).
                if (groupBy !== "cve") setGroupBy("cve");
              }}
              className={`px-2.5 h-7 text-[11.5px] inline-flex items-center gap-1 ${viewMode==="by_vulnerability" && groupBy!=="none" ?"bg-blue-500/15 text-blue-300":"text-slate-400 hover:bg-slate-800/40"}`}
            >
              <GridFour size={11}/> by Vulnerability
            </button>
          </div>
          {groupBy !== "none" && (
            <span className="text-[10.5px] font-mono text-slate-500 ml-auto">
              {groups.length} group{groups.length===1?"":"s"}
            </span>
          )}
        </div>
      </div>

      {/* Bulk actions */}
      {selected.size > 0 && (
        <div data-testid="bulk-bar" className="border border-blue-500/40 bg-blue-500/5 rounded-md px-3 py-2 mb-3 flex flex-wrap items-center gap-3">
          <div className="text-[12px] text-blue-300 font-mono">{selected.size} selected</div>
          <select data-testid="bulk-status" value={bulkStatus} onChange={(e)=>setBulkStatus(e.target.value)} className="h-7 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]">
            {STATUSES.map(s=> <option key={s}>{s}</option>)}
          </select>
          <button data-testid="bulk-apply" onClick={doBulk} className="h-7 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Update Status</button>
          <div className="h-5 w-px bg-blue-500/40"/>
          <input data-testid="bulk-assignee" placeholder="Reassign to user (email)…" value={bulkAssignee} onChange={(e)=>setBulkAssignee(e.target.value)}
            className="h-7 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] w-56"/>
          <button data-testid="bulk-assign-apply" onClick={doBulkAssign} className="h-7 px-3 text-[12px] bg-emerald-500/20 border border-emerald-500/40 text-emerald-300 rounded hover:bg-emerald-500/30">Reassign</button>
          <div className="h-5 w-px bg-blue-500/40"/>
          <TeamCombobox value={bulkOwnerTeam} onChange={setBulkOwnerTeam} testid="bulk-owner" placeholder="Owner team…" />
          <button data-testid="bulk-owner-apply" onClick={bulkAssignOwner} disabled={!bulkOwnerTeam} className="h-7 px-3 text-[12px] bg-amber-500/20 border border-amber-500/40 text-amber-300 rounded hover:bg-amber-500/30 disabled:opacity-40">Set Owner</button>
          <button data-testid="bulk-clear" onClick={()=>setSelected(new Set())} className="text-[12px] text-slate-400 hover:text-slate-200 ml-auto">Clear</button>
        </div>
      )}

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <div className="px-3 py-2 flex items-center justify-between border-b border-[#30363D]">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500">
            {loading ? "Loading…" : (groupBy !== "none" ? `${groups.length} groups · ${viewMode === "by_vulnerability" ? "by vulnerability" : "by asset"}` : counter)}
          </div>
        </div>

        {groupBy !== "none" ? (
          <div className="divide-y divide-[#30363D]" data-testid="findings-grouped">
            {groups.map((g) => {
              const isOpen = expanded.has(g.key);
              const children = groupChildren[g.key] || [];
              return (
                <div key={g.key} data-testid={`group-${g.key}`}>
                  <button
                    onClick={() => expandGroup(g.key)}
                    data-testid={`group-toggle-${g.key}`}
                    className="w-full px-3 py-2 flex items-center gap-2 hover:bg-slate-800/30 text-left"
                  >
                    {isOpen ? <CaretDown size={12} className="text-slate-400"/> : <CaretRight size={12} className="text-slate-500"/>}
                    <RiskBar score={g.max_risk}/>
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {(g.severities || []).slice(0,3).map(s => <SevBadge key={s} severity={s}/>)}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-[12.5px] text-slate-200 font-mono truncate">{g.key}</div>
                      {g.sample_title && <div className="text-[11px] text-slate-500 truncate">{g.sample_title}</div>}
                    </div>
                    <div className="flex items-center gap-2 text-[11px] font-mono">
                      {g.kev === 1 && <Chip color="red">KEV</Chip>}
                      {g.asset_count != null && <span className="text-slate-400">{g.asset_count} asset{g.asset_count===1?"":"s"}</span>}
                      <span className="text-slate-300">{g.count} finding{g.count===1?"":"s"}</span>
                    </div>
                  </button>
                  {isOpen && (
                    <div className="bg-[#0a0d12] border-t border-[#30363D]">
                      <div className="px-3 py-1.5 text-[11px] text-slate-500 flex items-center gap-2 border-b border-[#30363D]">
                        <input
                          type="checkbox"
                          data-testid={`group-selectall-${g.key}`}
                          checked={children.length > 0 && children.every(c => selected.has(c.id))}
                          onChange={(e) => {
                            const n = new Set(selected);
                            if (e.target.checked) children.forEach(c => n.add(c.id));
                            else children.forEach(c => n.delete(c.id));
                            setSelected(n);
                          }}
                        />
                        <span>Select all in group</span>
                      </div>
                      <table className="dense w-full">
                        <tbody>
                          {children.map(f => (
                            <tr key={f.id} className="border-t border-[#30363D] hover:bg-slate-800/30">
                              <td className="pl-3 w-7">
                                <input
                                  type="checkbox"
                                  data-testid={`group-row-cb-${f.id}`}
                                  checked={selected.has(f.id)}
                                  onChange={() => toggleOne(f.id)}
                                />
                              </td>
                              <td className="w-[60px]"><RiskBar score={f.risk_score}/></td>
                              <td className="w-[80px]"><SevBadge severity={f.severity}/></td>
                              <td>
                                <Link to={`/findings/${f.id}`} data-testid={`grouped-finding-${f.id}`} className="text-blue-300 hover:underline text-[12px]">{f.title}</Link>
                                <div className="flex gap-1 mt-0.5 flex-wrap">
                                  {f.kev_flag && <Chip color="red">KEV</Chip>}
                                  {f.cve && <Chip color="slate">{f.cve}</Chip>}
                                  {f.internet_facing && <Chip color="orange">EXPOSED</Chip>}
                                </div>
                              </td>
                              <td><Link to={`/assets/${f.asset_id}`} className="font-mono text-[11.5px] text-slate-300 hover:text-blue-300">{f.asset_hostname}</Link></td>
                              <td><Chip color={f.status === "Reopened" ? "orange" : f.status?.includes("Fixed") ? "green" : f.status === "New" ? "blue" : "slate"}>{f.status}</Chip></td>
                              <td className="text-slate-400 text-[11.5px]">{f.owner_team}</td>
                              <td className={isOverdue(f.due_at) ? "text-red-300 text-[11px]" : "text-slate-500 text-[11px]"}>{fmtRel(f.due_at)}</td>
                            </tr>
                          ))}
                          {children.length === 0 && (
                            <tr><td colSpan={8} className="px-8 py-2 text-[11px] text-slate-500">Loading findings…</td></tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              );
            })}
            {!loading && groups.length === 0 && (
              <div className="px-4 py-6 text-center text-[12px] text-slate-500">No groups match current filters.</div>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table data-testid="findings-table" className="dense w-full">
              <thead>
                <tr>
                  <th className="w-7"><input type="checkbox" data-testid="select-all" onChange={(e)=>toggleAll(e.target.checked)} /></th>
                  <th className="text-left">Risk</th><th className="text-left">Severity</th>
                  <th className="text-left">Title / CVE</th><th className="text-left">Asset</th>
                  <th className="text-left">CVSS</th><th className="text-left">EPSS</th>
                  <th className="text-left">Status</th><th className="text-left">Owner</th>
                  <th className="text-left">Source</th><th className="text-left">SLA</th>
                </tr>
              </thead>
              <tbody>
                {items.map(f => (
                  <tr key={f.id} className="border-t border-[#30363D] hover:bg-slate-800/30">
                    <td><input type="checkbox" data-testid={`select-${f.id}`} checked={selected.has(f.id)} onChange={()=>toggleOne(f.id)} /></td>
                    <td><RiskBar score={f.risk_score} /></td>
                    <td><SevBadge severity={f.severity} /></td>
                    <td className="max-w-[420px]">
                      <Link to={`/findings/${f.id}`} data-testid={`finding-link-${f.id}`} className="text-blue-300 hover:underline">{f.title}</Link>
                      <div className="flex gap-1 mt-0.5 flex-wrap">
                        {f.kev_flag && <Chip color="red">KEV</Chip>}
                        {f.cve && <Chip color="slate">{f.cve}</Chip>}
                        {f.rti?.includes("active_attacks") && <Chip color="red">ACTIVE</Chip>}
                        {f.rti?.includes("zero_day") && <Chip color="purple">0-DAY</Chip>}
                        {f.rti?.includes("wormable") && <Chip color="orange">WORM</Chip>}
                        {f.internet_facing && <Chip color="orange">EXPOSED</Chip>}
                        {f.patch_available === false && <Chip color="amber">NO PATCH</Chip>}
                      </div>
                    </td>
                    <td><Link to={`/assets/${f.asset_id}`} className="font-mono text-[11.5px] text-slate-300 hover:text-blue-300">{f.asset_hostname}</Link>
                      <div className="text-[10.5px] text-slate-600 font-mono">{f.asset_ip || "—"}</div>
                    </td>
                    <td className="font-mono text-[11.5px]">{f.cvss_score?.toFixed?.(1) ?? "—"}</td>
                    <td className="font-mono text-[11.5px]">{f.epss_score != null ? (f.epss_score*100).toFixed(1)+"%" : "—"}</td>
                    <td><Chip color={f.status === "Reopened" ? "orange" : f.status?.includes("Fixed") ? "green" : f.status === "New" ? "blue" : "slate"}>{f.status}</Chip></td>
                    <td className="text-slate-400 text-[11.5px]">{f.owner_team}</td>
                    <td className="text-slate-500 text-[11px]">{f.source_tool}</td>
                    <td className={isOverdue(f.due_at) ? "text-red-300 text-[11px]" : "text-slate-500 text-[11px]"}>{fmtRel(f.due_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {groupBy === "none" && (
        <div className="flex items-center justify-between mt-3 px-1">
          <div className="text-[11px] text-slate-500">
            Showing {items.length === 0 ? 0 : page * PAGE_SIZE + 1}–{page * PAGE_SIZE + items.length} of {total}
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
              data-testid="findings-prev-page"
              className="h-8 w-8 flex items-center justify-center text-slate-400 hover:text-slate-200 disabled:opacity-30 rounded border border-[#30363D]">
              <CaretLeft size={14}/>
            </button>
            <span className="text-[11.5px] text-slate-500">Page {page + 1} of {Math.max(1, Math.ceil(total / PAGE_SIZE))}</span>
            <button onClick={() => setPage(p => (p + 1) * PAGE_SIZE < total ? p + 1 : p)} disabled={(page + 1) * PAGE_SIZE >= total}
              data-testid="findings-next-page"
              className="h-8 w-8 flex items-center justify-center text-slate-400 hover:text-slate-200 disabled:opacity-30 rounded border border-[#30363D]">
              <CaretRight size={14}/>
            </button>
          </div>
        </div>
      )}
    </Layout>
  );
}
