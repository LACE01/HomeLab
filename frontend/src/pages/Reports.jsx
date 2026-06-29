import { useEffect, useState } from "react";
import { api, API } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { FileArrowDown, FilePdf, FileCsv, Sparkle, Funnel } from "@phosphor-icons/react";
import { toast } from "sonner";

const CATEGORY_COLORS = { executive: "blue", operational: "green", security: "red", compliance: "purple" };
const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];
const STATUSES = ["New","Needs triage","Valid","False positive","Duplicate","Mitigated","Accepted risk","Fixed pending validation","Fixed validated","Reopened"];

const downloadBlob = async (path, params = {}, method = "get", body = null, filename = "report") => {
  const cfg = { params, responseType: "blob" };
  let r;
  if (method === "post") r = await api.post(path, body, cfg);
  else r = await api.get(path, cfg);
  const url = URL.createObjectURL(r.data);
  const a = document.createElement("a"); a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
};

export default function Reports() {
  const [catalog, setCatalog] = useState({ items: [], group_fields: [], filter_fields: [], metrics: [], date_fields: [] });
  const [busy, setBusy] = useState(null);

  // Builder state
  const [b, setB] = useState({
    fmt: "pdf", group_by: "severity", metric: "count",
    severity: [], status: [], kev_flag: null, internet_facing: null,
    owner_team: "", product_name: "", asset_environment: "",
    date_field: "first_seen_at", date_from: "", date_to: "",
  });

  useEffect(() => { api.get("/v1/reports/catalog").then(r => setCatalog(r.data)); }, []);

  const runPrebuilt = async (report, fmt) => {
    setBusy(`${report.id}:${fmt}`);
    try {
      await downloadBlob(`/v1/reports/run/${report.id}?fmt=${fmt}`, {}, "get", null, `${report.id}.${fmt}`);
      toast.success(`Generated ${report.name}`);
    } catch { toast.error("Failed to generate report"); }
    finally { setBusy(null); }
  };

  const runCustom = async () => {
    setBusy("custom");
    try {
      const filters = {};
      if (b.severity?.length) filters.severity = b.severity;
      if (b.status?.length) filters.status = b.status;
      if (b.kev_flag !== null) filters.kev_flag = b.kev_flag;
      if (b.internet_facing !== null) filters.internet_facing = b.internet_facing;
      if (b.owner_team) filters.owner_team = b.owner_team;
      if (b.product_name) filters.product_name = b.product_name;
      if (b.asset_environment) filters.asset_environment = b.asset_environment;
      const payload = { fmt: b.fmt, group_by: b.group_by, metric: b.metric, filters,
        date_field: b.date_field, date_from: b.date_from || null, date_to: b.date_to || null };
      await downloadBlob("/v1/reports/run-custom", {}, "post", payload, `custom-report.${b.fmt}`);
      toast.success("Custom report generated");
    } catch (e) { toast.error(e.response?.data?.detail || "Custom report failed"); }
    finally { setBusy(null); }
  };

  const toggleArr = (arr, val) => arr.includes(val) ? arr.filter(x=>x!==val) : [...arr, val];

  return (
    <Layout title="Reports" subtitle="Pre-built reports and a dynamic report builder — export to PDF or CSV">
      {/* Pre-built catalog */}
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-3">
          <Sparkle size={16} className="text-blue-400"/>
          <h2 className="text-[13px] uppercase tracking-wider font-mono text-slate-300">Pre-built Reports</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {catalog.items.map(r => (
            <div key={r.id} data-testid={`report-${r.id}`} className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 flex flex-col">
              <div className="flex items-start justify-between gap-2 mb-1">
                <div className="text-[14px] font-medium text-slate-100">{r.name}</div>
                <Chip color={CATEGORY_COLORS[r.category]}>{r.category}</Chip>
              </div>
              <div className="text-[12px] text-slate-500 flex-1 mb-3">{r.description}</div>
              <div className="flex gap-2 mt-auto">
                <button data-testid={`dl-${r.id}-pdf`} disabled={busy===`${r.id}:pdf`} onClick={()=>runPrebuilt(r, "pdf")}
                  className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1 disabled:opacity-50">
                  <FilePdf size={13}/> PDF
                </button>
                <button data-testid={`dl-${r.id}-csv`} disabled={busy===`${r.id}:csv`} onClick={()=>runPrebuilt(r, "csv")}
                  className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-emerald-500/50 hover:text-emerald-300 rounded inline-flex items-center gap-1">
                  <FileCsv size={13}/> CSV
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Dynamic builder */}
      <div className="border border-blue-500/30 bg-[#0D1117] rounded-md">
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center gap-2">
          <Funnel size={16} className="text-blue-400"/>
          <h2 className="text-[13px] uppercase tracking-wider font-mono text-slate-300">Dynamic Report Builder</h2>
        </div>
        <div className="p-4 grid grid-cols-1 lg:grid-cols-3 gap-5">

          {/* Column 1 — Metric & group */}
          <div className="space-y-3">
            <div>
              <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Metric</label>
              <select data-testid="b-metric" value={b.metric} onChange={(e)=>setB({...b, metric:e.target.value})} className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px]">
                {catalog.metrics.map(m => <option key={m.id} value={m.id}>{m.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Group By</label>
              <select data-testid="b-group" value={b.group_by} onChange={(e)=>setB({...b, group_by:e.target.value})} className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px]">
                {catalog.group_fields.map(g => <option key={g} value={g}>{g}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Format</label>
              <div className="mt-1 flex gap-1">
                <button data-testid="b-fmt-pdf" onClick={()=>setB({...b, fmt:"pdf"})} className={`flex-1 h-9 text-[12px] rounded border ${b.fmt==='pdf'?"border-blue-500/50 bg-blue-500/10 text-blue-300":"border-[#30363D] text-slate-400"}`}>PDF</button>
                <button data-testid="b-fmt-csv" onClick={()=>setB({...b, fmt:"csv"})} className={`flex-1 h-9 text-[12px] rounded border ${b.fmt==='csv'?"border-emerald-500/50 bg-emerald-500/10 text-emerald-300":"border-[#30363D] text-slate-400"}`}>CSV</button>
              </div>
            </div>
          </div>

          {/* Column 2 — Filters */}
          <div className="space-y-3">
            <div>
              <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Severity</label>
              <div className="mt-1 flex flex-wrap gap-1">
                {SEVERITIES.map(s => (
                  <button key={s} data-testid={`b-sev-${s}`} onClick={()=>setB({...b, severity: toggleArr(b.severity, s)})}
                    className={`px-2 py-1 text-[11px] rounded border ${b.severity.includes(s)?"border-blue-500/50 bg-blue-500/10 text-blue-300":"border-[#30363D] text-slate-400"}`}>{s}</button>
                ))}
              </div>
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Status</label>
              <select data-testid="b-status" multiple value={b.status} onChange={(e)=>setB({...b, status: Array.from(e.target.selectedOptions, o=>o.value)})}
                className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] py-1 h-[88px]">
                {STATUSES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <label className="flex items-center gap-1.5 text-[12px]">
                <input type="checkbox" data-testid="b-kev" checked={b.kev_flag === true} onChange={(e)=>setB({...b, kev_flag: e.target.checked ? true : null})}/>
                KEV only
              </label>
              <label className="flex items-center gap-1.5 text-[12px]">
                <input type="checkbox" data-testid="b-internet" checked={b.internet_facing === true} onChange={(e)=>setB({...b, internet_facing: e.target.checked ? true : null})}/>
                Internet-facing
              </label>
            </div>
          </div>

          {/* Column 3 — Scope & dates */}
          <div className="space-y-3">
            <div>
              <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Owner Team</label>
              <input data-testid="b-team" value={b.owner_team} onChange={(e)=>setB({...b, owner_team:e.target.value})} placeholder="exact team name" className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px]"/>
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Product / Business Unit</label>
              <input data-testid="b-product" value={b.product_name} onChange={(e)=>setB({...b, product_name:e.target.value})} placeholder="exact product name" className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px]"/>
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Environment</label>
              <select data-testid="b-env" value={b.asset_environment} onChange={(e)=>setB({...b, asset_environment:e.target.value})} className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px]">
                <option value="">Any</option><option>production</option><option>staging</option><option>development</option><option>corporate</option>
              </select>
            </div>
            <div>
              <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Date Field</label>
              <select data-testid="b-datefield" value={b.date_field} onChange={(e)=>setB({...b, date_field:e.target.value})} className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px]">
                {catalog.date_fields.map(f => <option key={f} value={f}>{f}</option>)}
              </select>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div>
                <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">From</label>
                <input data-testid="b-datefrom" type="date" value={b.date_from} onChange={(e)=>setB({...b, date_from:e.target.value ? e.target.value+"T00:00:00+00:00" : ""})} className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"/>
              </div>
              <div>
                <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">To</label>
                <input data-testid="b-dateto" type="date" value={(b.date_to||"").slice(0,10)} onChange={(e)=>setB({...b, date_to:e.target.value ? e.target.value+"T23:59:59+00:00" : ""})} className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]"/>
              </div>
            </div>
          </div>

        </div>
        <div className="px-4 py-3 border-t border-[#30363D] flex items-center justify-between">
          <div className="text-[11px] text-slate-500 font-mono">
            {b.metric === "count" ? "Counting findings" : "Summing risk score"} by <span className="text-slate-300">{b.group_by}</span>
            {b.severity.length ? <> · severity={b.severity.join("|")}</> : null}
            {b.kev_flag ? <> · KEV</> : null}
            {b.owner_team ? <> · team={b.owner_team}</> : null}
          </div>
          <button data-testid="b-run" disabled={busy==='custom'} onClick={runCustom}
            className="h-9 px-4 text-[13px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5 disabled:opacity-50">
            <FileArrowDown size={14}/> {busy==='custom' ? "Generating…" : `Run & Download ${b.fmt.toUpperCase()}`}
          </button>
        </div>
      </div>
    </Layout>
  );
}
