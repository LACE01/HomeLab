import { useEffect, useState } from "react";
import TrendChart from "@/components/TrendChart";
import { api, API } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { FileArrowDown, FilePdf, FileCsv, Sparkle, Funnel, Clock, PaperPlaneTilt, Trash, ToggleLeft, ToggleRight } from "@phosphor-icons/react";
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

  const [preview, setPreview] = useState(null); // {count} | null while unknown
  const [previewLoading, setPreviewLoading] = useState(false);

  // Scheduled reports
  const [schedules, setSchedules] = useState([]);
  const [scheduleBusy, setScheduleBusy] = useState(null);
  const [newSchedule, setNewSchedule] = useState({
    name: "", source: "prebuilt", report_id: "", fmt: "pdf", frequency: "weekly", recipientsText: "",
  });

  const loadSchedules = () => api.get("/v1/reports/scheduled").then(r => setSchedules(r.data.items)).catch(() => setSchedules([]));

  useEffect(() => { api.get("/v1/reports/catalog").then(r => setCatalog(r.data)); loadSchedules(); }, []);

  const previewPayload = () => {
    const filters = {};
    if (b.severity?.length) filters.severity = b.severity;
    if (b.status?.length) filters.status = b.status;
    if (b.kev_flag !== null) filters.kev_flag = b.kev_flag;
    if (b.internet_facing !== null) filters.internet_facing = b.internet_facing;
    if (b.owner_team) filters.owner_team = b.owner_team;
    if (b.product_name) filters.product_name = b.product_name;
    if (b.asset_environment) filters.asset_environment = b.asset_environment;
    return { fmt: b.fmt, group_by: b.group_by, metric: b.metric, filters,
      date_field: b.date_field, date_from: b.date_from || null, date_to: b.date_to || null };
  };

  useEffect(() => {
    setPreviewLoading(true);
    const t = setTimeout(() => {
      api.post("/v1/reports/custom-preview", previewPayload())
        .then(r => setPreview(r.data)).catch(() => setPreview(null)).finally(() => setPreviewLoading(false));
    }, 350);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [b.severity, b.status, b.kev_flag, b.internet_facing, b.owner_team, b.product_name, b.asset_environment, b.date_field, b.date_from, b.date_to]);

  const runPrebuilt = async (report, fmt) => {
    setBusy(`${report.id}:${fmt}`);
    try {
      await downloadBlob(`/v1/reports/run/${report.id}?fmt=${fmt}`, {}, "get", null, `${report.id}.${fmt}`);
      toast.success(`Generated ${report.name}`);
    } catch { toast.error("Failed to generate report"); }
    finally { setBusy(null); }
  };

  const runCustom = async () => {
    if (preview && preview.count === 0) {
      toast.error("No findings match these filters — adjust them before exporting.");
      return;
    }
    setBusy("custom");
    try {
      await downloadBlob("/v1/reports/run-custom", {}, "post", previewPayload(), `custom-report.${b.fmt}`);
      toast.success("Custom report generated");
    } catch (e) { toast.error(e.response?.data?.detail || "Custom report failed"); }
    finally { setBusy(null); }
  };

  const toggleArr = (arr, val) => arr.includes(val) ? arr.filter(x=>x!==val) : [...arr, val];

  const createSchedule = async () => {
    const recipients = newSchedule.recipientsText.split(",").map(s => s.trim()).filter(Boolean);
    if (!newSchedule.name.trim()) { toast.error("Give this schedule a name"); return; }
    if (newSchedule.source === "prebuilt" && !newSchedule.report_id) { toast.error("Pick a report"); return; }
    if (recipients.length === 0) { toast.error("Add at least one recipient email"); return; }
    setScheduleBusy("create");
    try {
      const body = newSchedule.source === "prebuilt"
        ? { name: newSchedule.name, source: "prebuilt", report_id: newSchedule.report_id, fmt: newSchedule.fmt, frequency: newSchedule.frequency, recipients }
        : { name: newSchedule.name, source: "custom", custom_config: previewPayload(), fmt: newSchedule.fmt, frequency: newSchedule.frequency, recipients };
      await api.post("/v1/reports/scheduled", body);
      toast.success("Scheduled report created");
      setNewSchedule({ name: "", source: "prebuilt", report_id: "", fmt: "pdf", frequency: "weekly", recipientsText: "" });
      await loadSchedules();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to create schedule"); }
    finally { setScheduleBusy(null); }
  };

  const sendScheduleNow = async (s) => {
    setScheduleBusy(s.id);
    try {
      const r = await api.post(`/v1/reports/scheduled/${s.id}/send-now`);
      if (r.data.ok) toast.success(`Sent to ${r.data.sent_to.join(", ")}`);
      else toast.error(`Some recipients failed: ${r.data.errors.join("; ")}`);
      await loadSchedules();
    } catch (e) { toast.error(e.response?.data?.detail || "Send failed"); }
    finally { setScheduleBusy(null); }
  };

  const toggleSchedule = async (s) => {
    setScheduleBusy(s.id);
    try {
      await api.patch(`/v1/reports/scheduled/${s.id}`, { enabled: !s.enabled });
      await loadSchedules();
    } catch (e) { toast.error("Failed to update schedule"); }
    finally { setScheduleBusy(null); }
  };

  const deleteSchedule = async (s) => {
    setScheduleBusy(s.id);
    try {
      await api.delete(`/v1/reports/scheduled/${s.id}`);
      toast.success("Schedule deleted");
      await loadSchedules();
    } catch (e) { toast.error("Failed to delete schedule"); }
    finally { setScheduleBusy(null); }
  };

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

      {/* Scheduled reports */}
      <div className="mb-6">
        <div className="flex items-center gap-2 mb-3">
          <Clock size={16} className="text-amber-400"/>
          <h2 className="text-[13px] uppercase tracking-wider font-mono text-slate-300">Scheduled Reports</h2>
        </div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          {schedules.length === 0 ? (
            <div className="text-[12px] text-slate-500 mb-4">No scheduled reports yet — set one up below to have a report emailed automatically on a cadence.</div>
          ) : (
            <div className="space-y-2 mb-4">
              {schedules.map(s => (
                <div key={s.id} data-testid={`schedule-${s.id}`} className="flex items-center justify-between gap-3 border border-[#21262D] rounded px-3 py-2">
                  <div className="min-w-0">
                    <div className="text-[13px] text-slate-200 flex items-center gap-2">
                      {s.name}
                      <Chip color={s.enabled ? "green" : "slate"}>{s.enabled ? "enabled" : "paused"}</Chip>
                      <span className="text-[10.5px] text-slate-500 font-mono">{s.frequency} · {s.fmt.toUpperCase()}</span>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-0.5">
                      {s.source === "prebuilt" ? s.report_id : "custom builder config"} → {s.recipients.join(", ")}
                    </div>
                    <div className="text-[10px] text-slate-600 mt-0.5">
                      {s.last_sent_at ? `Last sent ${new Date(s.last_sent_at).toLocaleString()}` : "Never sent yet"}
                      {s.last_send_error ? <span className="text-red-400 ml-1.5">· {s.last_send_error}</span> : null}
                    </div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <button data-testid={`schedule-send-${s.id}`} disabled={scheduleBusy===s.id} onClick={()=>sendScheduleNow(s)}
                      title="Send now" className="h-7 w-7 flex items-center justify-center border border-[#30363D] hover:border-blue-500/50 hover:text-blue-300 text-slate-400 rounded disabled:opacity-50">
                      <PaperPlaneTilt size={13}/>
                    </button>
                    <button data-testid={`schedule-toggle-${s.id}`} disabled={scheduleBusy===s.id} onClick={()=>toggleSchedule(s)}
                      title={s.enabled ? "Pause" : "Resume"} className="h-7 w-7 flex items-center justify-center border border-[#30363D] hover:border-amber-500/50 hover:text-amber-300 text-slate-400 rounded disabled:opacity-50">
                      {s.enabled ? <ToggleRight size={15}/> : <ToggleLeft size={15}/>}
                    </button>
                    <button data-testid={`schedule-delete-${s.id}`} disabled={scheduleBusy===s.id} onClick={()=>deleteSchedule(s)}
                      title="Delete" className="h-7 w-7 flex items-center justify-center border border-[#30363D] hover:border-red-500/50 hover:text-red-300 text-slate-400 rounded disabled:opacity-50">
                      <Trash size={13}/>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
          <div className="border-t border-[#30363D] pt-3">
            <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-2">New schedule</div>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-6 gap-2 items-end">
              <div className="lg:col-span-2">
                <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Name</label>
                <input data-testid="sched-name" value={newSchedule.name} onChange={(e)=>setNewSchedule({...newSchedule, name: e.target.value})}
                  placeholder="e.g. Weekly exec summary" className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px]"/>
              </div>
              <div>
                <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Report</label>
                <select data-testid="sched-source" value={newSchedule.source === "custom" ? "__custom__" : newSchedule.report_id}
                  onChange={(e)=> e.target.value === "__custom__"
                    ? setNewSchedule({...newSchedule, source: "custom", report_id: ""})
                    : setNewSchedule({...newSchedule, source: "prebuilt", report_id: e.target.value})}
                  className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px]">
                  <option value="">Pick a report…</option>
                  {catalog.items.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                  <option value="__custom__">— Current builder config below —</option>
                </select>
              </div>
              <div>
                <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Format</label>
                <select data-testid="sched-fmt" value={newSchedule.fmt} onChange={(e)=>setNewSchedule({...newSchedule, fmt: e.target.value})}
                  className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px]">
                  <option value="pdf">PDF</option><option value="csv">CSV</option>
                </select>
              </div>
              <div>
                <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Frequency</label>
                <select data-testid="sched-freq" value={newSchedule.frequency} onChange={(e)=>setNewSchedule({...newSchedule, frequency: e.target.value})}
                  className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px]">
                  <option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option>
                </select>
              </div>
              <div className="lg:col-span-2">
                <label className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Recipients (comma-separated)</label>
                <input data-testid="sched-recipients" value={newSchedule.recipientsText} onChange={(e)=>setNewSchedule({...newSchedule, recipientsText: e.target.value})}
                  placeholder="ciso@example.com, soc@example.com" className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px]"/>
              </div>
              <div className="lg:col-span-4 text-[10.5px] text-slate-600">
                &ldquo;— Current builder config below —&rdquo; schedules whatever filters/group-by are currently set in the Dynamic Report Builder further down the page.
              </div>
              <button data-testid="sched-create" disabled={scheduleBusy==='create'} onClick={createSchedule}
                className="h-9 px-3 text-[12.5px] bg-amber-500/90 hover:bg-amber-400 text-black font-medium rounded inline-flex items-center justify-center gap-1.5 disabled:opacity-50">
                <Clock size={13}/> {scheduleBusy==='create' ? "Creating…" : "Schedule"}
              </button>
            </div>
          </div>
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
        <div className="px-4 py-3 border-t border-[#30363D] flex items-center justify-between flex-wrap gap-2">
          <div className="text-[11px] text-slate-500 font-mono">
            {b.metric === "count" ? "Counting findings" : "Summing risk score"} by <span className="text-slate-300">{b.group_by}</span>
            {b.severity.length ? <> · severity={b.severity.join("|")}</> : null}
            {b.kev_flag ? <> · KEV</> : null}
            {b.owner_team ? <> · team={b.owner_team}</> : null}
            <span className="ml-2" data-testid="b-preview-count">
              {previewLoading ? "· checking matches…" : preview ? (
                <span className={preview.count === 0 ? "text-amber-400" : "text-emerald-400"}>
                  · {preview.count} finding{preview.count === 1 ? "" : "s"} match{preview.count === 1 ? "es" : ""}
                </span>
              ) : null}
            </span>
          </div>
          <button data-testid="b-run" disabled={busy==='custom' || (preview && preview.count === 0)} onClick={runCustom}
            className="h-9 px-4 text-[13px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5 disabled:opacity-50">
            <FileArrowDown size={14}/> {busy==='custom' ? "Generating…" : `Run & Download ${b.fmt.toUpperCase()}`}
          </button>
        </div>
      </div>

      <div className="mt-4">
        <TrendChart
          title="Visualize — Vulnerabilities Over Time"
          filters={b.owner_team ? { owner_team: b.owner_team } : {}}
          defaultDays={90}
        />
        <div className="text-[10.5px] text-slate-500 mt-1.5">
          Scoped to the Team filter above (if set) — an ad-hoc way to look at trends before committing to a full export.
        </div>
      </div>
    </Layout>
  );
}
