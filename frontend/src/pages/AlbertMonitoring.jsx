import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { SevBadge, Chip } from "@/components/Badges";
import {
  ResponsiveContainer, BarChart, Bar, AreaChart, Area, XAxis, YAxis,
  CartesianGrid, Tooltip, Cell, ReferenceLine,
} from "recharts";
import {
  Broadcast, UploadSimple, Warning, ChartLine, Desktop, ShieldWarning,
  MagnifyingGlass, X, ArrowSquareOut,
} from "@phosphor-icons/react";

const RANGE_OPTIONS = [7, 30, 90];
const SEV_COLOR = { Critical: "#f87171", High: "#fb923c", Medium: "#fbbf24", Low: "#60a5fa" };

function StatCard({ label, value, sub, icon: Icon, tone = "slate" }) {
  const toneMap = {
    slate: "text-slate-200", red: "text-red-300", orange: "text-orange-300",
    amber: "text-amber-300", blue: "text-blue-300",
  };
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
      <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-2">
        {Icon && <Icon size={13} />} {label}
      </div>
      <div className={`text-[26px] font-semibold tabular-nums ${toneMap[tone]}`}>{value}</div>
      {sub && <div className="text-[11px] text-slate-500 mt-1">{sub}</div>}
    </div>
  );
}

function Panel({ title, actions, children }) {
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
      <div className="px-4 py-2.5 border-b border-[#30363D] flex items-center justify-between">
        <h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">{title}</h3>
        {actions}
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

export default function AlbertMonitoring() {
  const fileRef = useRef(null);
  const [uploading, setUploading] = useState(false);
  const [imports, setImports] = useState([]);
  const [stats, setStats] = useState(null);
  const [signatures, setSignatures] = useState([]);
  const [days, setDays] = useState(30);
  const [loading, setLoading] = useState(true);

  const [alerts, setAlerts] = useState({ items: [], total: 0, page: 1, page_size: 25 });
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [device, setDevice] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState(null);

  const loadDashboard = async (rangeDays) => {
    setLoading(true);
    try {
      const [statsR, sigR, impR] = await Promise.all([
        api.get("/v1/admin/albert/stats", { params: { days: rangeDays } }),
        api.get("/v1/admin/albert/signatures", { params: { days: rangeDays } }),
        api.get("/v1/admin/albert/imports"),
      ]);
      setStats(statsR.data);
      setSignatures(sigR.data);
      setImports(impR.data);
    } catch (e) {
      // non-fatal -- no data yet is a valid empty state
    } finally {
      setLoading(false);
    }
  };

  const loadAlerts = async () => {
    try {
      const params = { page, page_size: 25 };
      if (q) params.q = q;
      if (severity) params.severity = severity;
      if (category) params.category = category;
      if (device) params.device = device;
      const r = await api.get("/v1/admin/albert/alerts", { params });
      setAlerts(r.data);
    } catch (e) { /* non-fatal */ }
  };

  useEffect(() => { loadDashboard(days); }, [days]);
  useEffect(() => { loadAlerts(); }, [page, q, severity, category, device]);

  const upload = async (file) => {
    setUploading(true);
    try {
      const fd = new FormData();
      fd.append("file", file);
      const r = await api.post("/v1/admin/albert/upload", fd, { headers: { "Content-Type": "multipart/form-data" } });
      const wl = r.data.watchlist_matches ? `, ${r.data.watchlist_matches} watchlist match(es)` : "";
      toast.success(`Imported ${r.data.rows_parsed} alerts (${r.data.disposition})${wl}`);
      loadDashboard(days);
      loadAlerts();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Import failed -- check this is an Albert alert export");
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const categories = Object.keys(stats?.category_counts || {});
  const devices = Object.keys(stats?.device_counts || {});
  const severityData = Object.entries(stats?.severity_counts || {}).map(([name, count]) => ({ name, count }));
  const categoryData = Object.entries(stats?.category_counts || {}).map(([name, count]) => ({ name, count }));
  const deviceData = Object.entries(stats?.device_counts || {}).map(([name, count]) => ({ name, count }));
  const anomalyDays = new Set((stats?.anomalies || []).map(a => a.day));

  return (
    <Layout title="Albert Network Monitoring" subtitle="CIS/MS-ISAC network sensor alert exports — trends, breakdowns, and plain-English signature explanations">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 mb-5 flex items-center justify-between gap-4 flex-wrap">
        <div className="text-[12px] text-slate-400 max-w-2xl leading-relaxed">
          Upload the .xlsx alert export from the CIS ANET portal. Each row's source/destination IP is checked against the
          existing <span className="text-slate-200">Threat Intel Watchlist</span> and any match raises a Security Alert automatically.
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <input ref={fileRef} type="file" accept=".xlsx" className="hidden"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) upload(f); }} />
          <button onClick={() => fileRef.current?.click()} disabled={uploading}
            className="h-9 px-4 text-[12.5px] bg-blue-500 hover:bg-blue-400 disabled:opacity-40 text-white rounded inline-flex items-center gap-2">
            <UploadSimple size={15} /> {uploading ? "Importing…" : "Upload Albert Export (.xlsx)"}
          </button>
        </div>
      </div>

      {!loading && (!stats || stats.total_alerts === 0) ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-10 text-center">
          <Broadcast size={32} className="text-slate-600 mx-auto mb-3" />
          <div className="text-[13px] text-slate-300 mb-1">No Albert alerts imported yet</div>
          <div className="text-[12px] text-slate-500">Upload an alert export above to see trends and breakdowns.</div>
        </div>
      ) : (
        <>
          <div className="flex items-center justify-end gap-1.5 mb-3">
            {RANGE_OPTIONS.map(d => (
              <button key={d} onClick={() => setDays(d)}
                className={`h-7 px-3 text-[11.5px] rounded border ${days === d ? "bg-blue-500/20 border-blue-500/40 text-blue-300" : "border-[#30363D] text-slate-400 hover:border-[#484F58]"}`}>
                {d}d
              </button>
            ))}
          </div>

          <div className="grid grid-cols-4 gap-3 mb-4">
            <StatCard label="Total Alerts" value={stats?.total_alerts ?? "—"} sub={`last ${stats?.range_days ?? days} days`} icon={Broadcast} />
            <StatCard label="High Severity" value={stats?.severity_counts?.High ?? 0} icon={ShieldWarning} tone="orange" />
            <StatCard label="Sensors Reporting" value={deviceData.length} icon={Desktop} />
            <StatCard label="Anomaly Days Flagged" value={stats?.anomalies?.length ?? 0} icon={Warning} tone={(stats?.anomalies?.length ?? 0) > 0 ? "red" : "slate"} />
          </div>

          {stats?.anomalies?.length > 0 && (
            <div className="border border-red-500/30 bg-red-500/5 rounded-md p-3.5 mb-4">
              <div className="flex items-center gap-1.5 text-[11.5px] text-red-300 font-medium mb-2">
                <Warning size={14} /> Above-baseline activity detected
              </div>
              <div className="text-[11.5px] text-red-200/80 mb-2 leading-relaxed">
                These days had a category's alert volume well above its historical daily average — worth a closer look, not necessarily malicious on its own.
              </div>
              <div className="space-y-1">
                {stats.anomalies.map((a, i) => (
                  <div key={i} className="text-[12px] text-slate-300 font-mono">
                    {a.day} — <span className="text-red-300">{a.category}</span>: {a.count} alerts (baseline avg {a.baseline_mean} ± {a.baseline_stddev})
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4 mb-4">
            <Panel title="Alert Volume Over Time">
              <ResponsiveContainer width="100%" height={220}>
                <AreaChart data={stats?.daily_trend || []}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262D" />
                  <XAxis dataKey="day" tick={{ fontSize: 10, fill: "#8B949E" }} tickFormatter={(s) => s?.slice(5)} />
                  <YAxis tick={{ fontSize: 10, fill: "#8B949E" }} allowDecimals={false} />
                  <Tooltip contentStyle={{ background: "#161B22", border: "1px solid #30363D", fontSize: 12 }} />
                  <Area type="monotone" dataKey="count" stroke="#60a5fa" fill="#60a5fa22" />
                  {(stats?.daily_trend || []).filter(d => anomalyDays.has(d.day)).map(d => (
                    <ReferenceLine key={d.day} x={d.day} stroke="#f87171" strokeDasharray="3 3" />
                  ))}
                </AreaChart>
              </ResponsiveContainer>
            </Panel>

            <Panel title="Severity Breakdown">
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={severityData} layout="vertical" margin={{ left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262D" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: "#8B949E" }} allowDecimals={false} />
                  <YAxis dataKey="name" type="category" tick={{ fontSize: 11, fill: "#C9D1D9" }} width={70} />
                  <Tooltip contentStyle={{ background: "#161B22", border: "1px solid #30363D", fontSize: 12 }} />
                  <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                    {severityData.map((d, i) => <Cell key={i} fill={SEV_COLOR[d.name] || "#8B949E"} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </Panel>
          </div>

          <div className="grid grid-cols-2 gap-4 mb-4">
            <Panel title="Category Breakdown">
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={categoryData} layout="vertical" margin={{ left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262D" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: "#8B949E" }} allowDecimals={false} />
                  <YAxis dataKey="name" type="category" tick={{ fontSize: 10, fill: "#C9D1D9" }} width={150} />
                  <Tooltip contentStyle={{ background: "#161B22", border: "1px solid #30363D", fontSize: 12 }} />
                  <Bar dataKey="count" fill="#a78bfa" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </Panel>

            <Panel title="Per-Sensor / Site Comparison">
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={deviceData} layout="vertical" margin={{ left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262D" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: "#8B949E" }} allowDecimals={false} />
                  <YAxis dataKey="name" type="category" tick={{ fontSize: 10, fill: "#C9D1D9" }} width={150} />
                  <Tooltip contentStyle={{ background: "#161B22", border: "1px solid #30363D", fontSize: 12 }} />
                  <Bar dataKey="count" fill="#34d399" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </Panel>
          </div>

          <div className="grid grid-cols-2 gap-4 mb-4">
            <Panel title="Top Source IPs">
              <div className="space-y-1.5">
                {(stats?.top_source_ips || []).slice(0, 8).map((ip, i) => (
                  <div key={i} className="flex items-center justify-between text-[12px]">
                    <span className="font-mono text-slate-300">{ip.value}</span>
                    <span className="text-slate-500">{ip.count}</span>
                  </div>
                ))}
                {(!stats?.top_source_ips || stats.top_source_ips.length === 0) && <div className="text-[12px] text-slate-500">No data</div>}
              </div>
            </Panel>
            <Panel title="Top Destination IPs">
              <div className="space-y-1.5">
                {(stats?.top_destination_ips || []).slice(0, 8).map((ip, i) => (
                  <div key={i} className="flex items-center justify-between text-[12px]">
                    <span className="font-mono text-slate-300">{ip.value}</span>
                    <span className="text-slate-500">{ip.count}</span>
                  </div>
                ))}
                {(!stats?.top_destination_ips || stats.top_destination_ips.length === 0) && <div className="text-[12px] text-slate-500">No data</div>}
              </div>
            </Panel>
          </div>

          <Panel title="Alert Signatures Explained" actions={<span className="text-[10.5px] text-slate-500">what each alert type actually means</span>}>
            <div className="space-y-2.5">
              {signatures.map((s, i) => (
                <div key={i} className="border border-[#21262D] rounded p-3">
                  <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                    <SevBadge severity={s.severity} />
                    <Chip color="slate">{s.category}</Chip>
                    <span className="text-[12px] text-slate-200 font-medium">{s.alert_message}</span>
                    <span className="text-[10.5px] text-slate-500 ml-auto">{s.count} occurrence{s.count === 1 ? "" : "s"}</span>
                  </div>
                  <div className="text-[12px] text-slate-400 leading-relaxed">{s.explanation}</div>
                  {s.mitre_technique && (
                    <div className="text-[10.5px] text-slate-500 font-mono mt-1.5">MITRE ATT&CK: {s.mitre_technique}</div>
                  )}
                </div>
              ))}
              {signatures.length === 0 && <div className="text-[12px] text-slate-500">No signatures seen in this range yet.</div>}
            </div>
          </Panel>
        </>
      )}

      <div className="mt-4">
        <Panel title="Alerts"
          actions={
            <div className="flex items-center gap-1.5">
              <div className="relative">
                <MagnifyingGlass size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-slate-500" />
                <input value={q} onChange={(e) => { setPage(1); setQ(e.target.value); }} placeholder="Search message/IP…"
                  className="h-7 w-48 bg-[#161B22] border border-[#30363D] rounded pl-6 pr-2 text-[11.5px] text-slate-200" />
              </div>
              <select value={severity} onChange={(e) => { setPage(1); setSeverity(e.target.value); }}
                className="h-7 bg-[#161B22] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-300">
                <option value="">All severities</option>
                {["Critical", "High", "Medium", "Low"].map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <select value={category} onChange={(e) => { setPage(1); setCategory(e.target.value); }}
                className="h-7 bg-[#161B22] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-300">
                <option value="">All categories</option>
                {categories.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
              <select value={device} onChange={(e) => { setPage(1); setDevice(e.target.value); }}
                className="h-7 bg-[#161B22] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-300">
                <option value="">All sensors</option>
                {devices.map(d => <option key={d} value={d}>{d}</option>)}
              </select>
            </div>
          }
        >
          {alerts.items.length === 0 ? (
            <div className="text-center py-8 text-[12.5px] text-slate-500">No alerts match these filters.</div>
          ) : (
            <div className="border border-[#21262D] rounded overflow-hidden">
              <table className="w-full text-[12px]">
                <thead>
                  <tr className="border-b border-[#21262D] text-[10px] uppercase tracking-wider text-slate-500">
                    <th className="text-left px-3 py-2 font-mono">Time (GMT)</th>
                    <th className="text-left px-3 py-2 font-mono">Sensor</th>
                    <th className="text-left px-3 py-2 font-mono">Alert</th>
                    <th className="text-left px-3 py-2 font-mono">Source → Destination</th>
                    <th className="text-left px-3 py-2 font-mono">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#21262D]">
                  {alerts.items.map(a => (
                    <tr key={a.id} onClick={() => setSelected(a)} className="cursor-pointer hover:bg-[#161B22]">
                      <td className="px-3 py-2 font-mono text-slate-400 whitespace-nowrap">{a.time_gmt ? new Date(a.time_gmt).toLocaleString() : "—"}</td>
                      <td className="px-3 py-2 text-slate-300">{a.device}</td>
                      <td className="px-3 py-2 text-slate-200 max-w-[280px] truncate">{a.alert_message}</td>
                      <td className="px-3 py-2 font-mono text-slate-400 whitespace-nowrap">{a.source_ip}:{a.source_port} → {a.destination_ip}:{a.destination_port}</td>
                      <td className="px-3 py-2"><SevBadge severity={a.severity} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {alerts.total > alerts.page_size && (
            <div className="flex items-center justify-between mt-3 text-[11.5px] text-slate-500">
              <span>{alerts.total} total alerts</span>
              <div className="flex items-center gap-2">
                <button disabled={page <= 1} onClick={() => setPage(p => p - 1)} className="px-2 py-1 border border-[#30363D] rounded disabled:opacity-30">Prev</button>
                <span>Page {alerts.page}</span>
                <button disabled={page * alerts.page_size >= alerts.total} onClick={() => setPage(p => p + 1)} className="px-2 py-1 border border-[#30363D] rounded disabled:opacity-30">Next</button>
              </div>
            </div>
          )}
        </Panel>
      </div>

      {imports.length > 0 && (
        <div className="mt-4">
          <Panel title="Import History">
            <div className="divide-y divide-[#21262D]">
              {imports.map(h => (
                <div key={h.id} className="py-2.5 flex items-center justify-between gap-3 text-[12px]">
                  <div className="min-w-0">
                    <div className="text-slate-200 truncate">{h.filename}</div>
                    <div className="text-[10.5px] text-slate-500 font-mono">{new Date(h.uploaded_at).toLocaleString()} · {h.disposition}</div>
                  </div>
                  <div className="text-slate-400 shrink-0">{h.rows_parsed} rows{h.watchlist_matches ? ` · ${h.watchlist_matches} watchlist match(es)` : ""}</div>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      )}

      {selected && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-6" onClick={() => setSelected(null)}>
          <div className="bg-[#0D1117] border border-[#30363D] rounded-md max-w-2xl w-full max-h-[85vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="px-5 py-3.5 border-b border-[#30363D] flex items-center justify-between">
              <div className="flex items-center gap-2">
                <ChartLine size={16} className="text-slate-400" />
                <span className="text-[13px] text-slate-200 font-medium">Alert Detail</span>
              </div>
              <button onClick={() => setSelected(null)} className="text-slate-500 hover:text-slate-300"><X size={16} /></button>
            </div>
            <div className="p-5 space-y-4">
              <div className="flex items-center gap-2 flex-wrap">
                <SevBadge severity={selected.severity} />
                <Chip color="slate">{selected.category}</Chip>
                <span className="text-[13px] text-slate-100 font-medium">{selected.alert_message}</span>
              </div>
              <div className="text-[12.5px] text-slate-300 leading-relaxed border border-[#21262D] rounded p-3">{selected.explanation}</div>
              {selected.mitre_technique && (
                <div className="text-[11.5px] text-slate-500 font-mono">MITRE ATT&CK: {selected.mitre_technique}</div>
              )}
              <div className="grid grid-cols-2 gap-3 text-[12px]">
                <div><div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Time (GMT)</div><div className="font-mono text-slate-300">{selected.time_gmt ? new Date(selected.time_gmt).toLocaleString() : "—"}</div></div>
                <div><div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Sensor</div><div className="text-slate-300">{selected.device}</div></div>
                <div><div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Source</div><div className="font-mono text-slate-300">{selected.source_ip}:{selected.source_port}</div></div>
                <div><div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Destination</div><div className="font-mono text-slate-300">{selected.destination_ip}:{selected.destination_port}</div></div>
                <div><div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Protocol</div><div className="text-slate-300">{selected.protocol_name || selected.protocol}</div></div>
                <div><div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Disposition</div><div className="text-slate-300 capitalize">{selected.disposition}</div></div>
              </div>
              {selected.source_ip && (
                <a href={`/admin/threat-intel?value=${selected.source_ip}`} className="inline-flex items-center gap-1 text-[11.5px] text-blue-300 hover:text-blue-200">
                  <ArrowSquareOut size={12} /> Check source IP against Threat Intel Watchlist
                </a>
              )}
              {selected.stream_data && (
                <div>
                  <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1.5">Stream Data</div>
                  <pre className="text-[10.5px] font-mono text-slate-400 bg-black/30 rounded p-2.5 overflow-x-auto whitespace-pre-wrap max-h-40 overflow-y-auto">{selected.stream_data}</pre>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
}
