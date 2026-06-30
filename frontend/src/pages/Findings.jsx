import { useEffect, useState, useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { usePreferences } from "@/lib/usePreferences";
import Layout from "@/components/Layout";
import { SevBadge, Chip, RiskBar } from "@/components/Badges";
import { fmtRel, isOverdue } from "@/lib/utils-fmt";
import { Link } from "react-router-dom";
import { MagnifyingGlass, FileArrowDown, FunnelSimple, CaretDown, CaretRight, StackSimple, ListBullets, GridFour } from "@phosphor-icons/react";
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

export default function Findings() {
  const { user } = useAuth();
  const { prefs, setSection } = usePreferences();
  const [searchParams] = useSearchParams();
  const cweParam = searchParams.get("cwe");
  const cveParam = searchParams.get("cve");
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [q, setQ] = useState("");
  const [view, setView] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [selected, setSelected] = useState(new Set());
  const [bulkStatus, setBulkStatus] = useState("Valid");
  const [bulkAssignee, setBulkAssignee] = useState("");
  const [bulkOwnerTeam, setBulkOwnerTeam] = useState("");
  const [loading, setLoading] = useState(false);
  const [myQueue, setMyQueue] = useState(!!user?.team);
  const [groups, setGroups] = useState([]);
  const [expanded, setExpanded] = useState(new Set());
  const [groupChildren, setGroupChildren] = useState({}); // key → finding[]

  const groupBy = prefs?.findings?.group_by || "none";
  const viewMode = prefs?.findings?.view_mode || "by_asset";

  const load = async () => {
    setLoading(true);
    if (groupBy !== "none" && !cweParam && !cveParam) {
      const params = { group_by: groupBy, view_mode: viewMode, limit: 100 };
      if (severity) params.severity = severity;
      if (status) params.status = status;
      if (myQueue && user?.team) params.owner_team = user.team;
      const r = await api.get("/v1/findings-groups", { params });
      setGroups(r.data.groups || []);
      setExpanded(new Set());
      setGroupChildren({});
      setLoading(false);
      return;
    }
    const params = { limit: 200 };
    if (q) params.q = q;
    if (view) params.view = view;
    if (severity) params.severity = severity;
    if (status) params.status = status;
    if (cweParam) params.cwe = cweParam;
    if (cveParam) params.cve = cveParam;
    if (myQueue && user?.team) params.owner_team = user.team;
    const r = await api.get("/v1/findings", { params });
    setItems(r.data.items || []); setTotal(r.data.total);
    setLoading(false); setSelected(new Set());
  };
  useEffect(() => { if (prefs) load(); /* eslint-disable-next-line */ }, [prefs, view, severity, status, myQueue, groupBy, viewMode, cweParam, cveParam]);

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
    if (severity) params.severity = severity;
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

      {/* Filters bar */}
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md mb-3">
        <div className="px-3 py-2 flex flex-wrap gap-2 items-center border-b border-[#30363D]">
          <div className="flex items-center gap-1.5 bg-[#161B22] border border-[#30363D] rounded px-2 h-8 flex-1 min-w-[260px]">
            <MagnifyingGlass size={14} className="text-slate-500" />
            <input data-testid="search-input" value={q} onChange={(e)=>setQ(e.target.value)} onKeyDown={(e)=>e.key==='Enter'&&load()}
              placeholder="Search title, CVE, hostname, QID…"
              className="bg-transparent flex-1 outline-none text-[12.5px] text-slate-200 placeholder:text-slate-600" />
          </div>
          <select data-testid="filter-severity" value={severity} onChange={(e)=>setSeverity(e.target.value)} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200">
            <option value="">All severities</option>
            {["Critical","High","Medium","Low","Info"].map(s=> <option key={s}>{s}</option>)}
          </select>
          <select data-testid="filter-status" value={status} onChange={(e)=>setStatus(e.target.value)} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200">
            <option value="">All statuses</option>
            {STATUSES.map(s=> <option key={s}>{s}</option>)}
          </select>
          <button data-testid="search-go" onClick={load} className="h-8 px-3 text-[12px] bg-blue-500/15 text-blue-300 border border-blue-500/30 rounded hover:bg-blue-500/25">
            <FunnelSimple size={14} className="inline mr-1"/> Apply
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
                    <td className="font-mono text-[11.5px]">{f.epss_score ? (f.epss_score*100).toFixed(1)+"%" : "—"}</td>
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
    </Layout>
  );
}
