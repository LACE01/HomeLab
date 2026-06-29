import { useEffect, useState, useMemo } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { SevBadge, Chip, RiskBar } from "@/components/Badges";
import { fmtRel, isOverdue } from "@/lib/utils-fmt";
import { Link } from "react-router-dom";
import { MagnifyingGlass, FileArrowDown, FunnelSimple } from "@phosphor-icons/react";

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

export default function Findings() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [q, setQ] = useState("");
  const [view, setView] = useState("");
  const [severity, setSeverity] = useState("");
  const [status, setStatus] = useState("");
  const [selected, setSelected] = useState(new Set());
  const [bulkStatus, setBulkStatus] = useState("Valid");
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    const params = { limit: 200 };
    if (q) params.q = q;
    if (view) params.view = view;
    if (severity) params.severity = severity;
    if (status) params.status = status;
    const r = await api.get("/v1/findings", { params });
    setItems(r.data.items); setTotal(r.data.total); setLoading(false); setSelected(new Set());
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [view, severity, status]);

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

  const counter = useMemo(() => `${items.length} of ${total}`, [items, total]);

  return (
    <Layout title="Findings Workbench" subtitle="Triage, prioritize, assign, and remediate vulnerabilities at scale"
      actions={<button data-testid="export-csv" onClick={exportCsv}
        className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] hover:bg-slate-800/40 rounded inline-flex items-center gap-1.5 text-slate-300">
        <FileArrowDown size={14}/> Export CSV
      </button>}>

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
      </div>

      {/* Bulk actions */}
      {selected.size > 0 && (
        <div data-testid="bulk-bar" className="border border-blue-500/40 bg-blue-500/5 rounded-md px-3 py-2 mb-3 flex items-center gap-3">
          <div className="text-[12px] text-blue-300 font-mono">{selected.size} selected</div>
          <select data-testid="bulk-status" value={bulkStatus} onChange={(e)=>setBulkStatus(e.target.value)} className="h-7 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]">
            {STATUSES.map(s=> <option key={s}>{s}</option>)}
          </select>
          <button data-testid="bulk-apply" onClick={doBulk} className="h-7 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Apply</button>
          <button data-testid="bulk-clear" onClick={()=>setSelected(new Set())} className="text-[12px] text-slate-400 hover:text-slate-200">Clear</button>
        </div>
      )}

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <div className="px-3 py-2 flex items-center justify-between border-b border-[#30363D]">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500">{loading ? "Loading…" : counter}</div>
        </div>
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
      </div>
    </Layout>
  );
}
