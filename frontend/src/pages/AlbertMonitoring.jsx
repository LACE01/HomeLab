import { useEffect, useRef, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { SevBadge, Chip } from "@/components/Badges";
import NewRiskModal from "@/components/NewRiskModal";
import {
  ResponsiveContainer, BarChart, Bar, AreaChart, Area, XAxis, YAxis,
  CartesianGrid, Tooltip, Cell, ReferenceLine, Sankey, Layer, Rectangle,
} from "recharts";
import {
  Broadcast, UploadSimple, Warning, ChartLine, Desktop, ShieldWarning,
  MagnifyingGlass, X, ArrowSquareOut, ArrowsClockwise, CaretRight,
  CheckSquare, Square, ShieldStar, Flag, FirstAidKit, HardDrive, ListChecks,
} from "@phosphor-icons/react";

const RANGE_OPTIONS = [7, 30, 90];
const SEV_COLOR = { Critical: "#f87171", High: "#fb923c", Medium: "#fbbf24", Low: "#60a5fa" };
const SANKEY_NODE_COLORS = ["#60a5fa", "#a78bfa", "#34d399", "#fbbf24", "#f472b6", "#38bdf8"];
const ENRICH_STATUS_COLOR = { found: "text-red-300 border-red-500/30 bg-red-500/5", clean: "text-emerald-300 border-emerald-500/30 bg-emerald-500/5", not_configured: "text-slate-500 border-[#21262D]", error: "text-amber-300 border-amber-500/30 bg-amber-500/5" };
const ENRICH_STATUS_LABEL = { found: "Hit", clean: "Clean", not_configured: "Not set up", error: "Error" };

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

function SankeyNode({ x, y, width, height, index, payload, containerWidth }) {
  const color = SEV_COLOR[payload.name] || SANKEY_NODE_COLORS[index % SANKEY_NODE_COLORS.length];
  const isOut = x + width + 6 > containerWidth - 4;
  return (
    <Layer key={`sankey-node-${index}`}>
      <Rectangle x={x} y={y} width={width} height={height} fill={color} fillOpacity={0.9} />
      <text x={isOut ? x - 6 : x + width + 6} y={y + height / 2} textAnchor={isOut ? "end" : "start"}
        dominantBaseline="middle" fontSize={11} fill="#C9D1D9">
        {payload.name}
      </text>
    </Layer>
  );
}

function IpIntelPanel({ ip, label }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [checking, setChecking] = useState(false);

  const load = () => {
    setLoading(true);
    api.get(`/v1/admin/albert/enrichment/${encodeURIComponent(ip)}`)
      .then(r => setData(r.data))
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  };

  useEffect(() => { if (ip) load(); }, [ip]); // eslint-disable-line

  const checkNow = async () => {
    setChecking(true);
    try {
      const r = await api.post(`/v1/admin/albert/enrichment/${encodeURIComponent(ip)}/refresh`);
      setData(r.data);
      const hits = (r.data.results || []).filter(x => x.status === "found").length;
      toast[hits > 0 ? "warning" : "success"](hits > 0 ? `${hits} connector(s) flagged ${ip}` : `${ip} came back clean`);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Enrichment failed");
    } finally { setChecking(false); }
  };

  if (!ip) return null;

  return (
    <div className="border border-[#21262D] rounded p-3">
      <div className="flex items-center justify-between mb-2">
        <div className="text-[11.5px] text-slate-300 font-mono">{label}: {ip}</div>
        <button onClick={checkNow} disabled={checking}
          className="h-6 px-2 text-[10.5px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 disabled:opacity-40 text-slate-400 rounded inline-flex items-center gap-1">
          <ArrowsClockwise size={11} className={checking ? "animate-spin" : ""} /> {data?.checked_at ? "Recheck" : "Check now"}
        </button>
      </div>
      {loading ? (
        <div className="text-[11px] text-slate-500">Loading…</div>
      ) : !data?.checked_at ? (
        <div className="text-[11px] text-slate-500">Not checked yet against threat-intel connectors.</div>
      ) : (
        <div className="space-y-1.5">
          {(data.results || []).map((r, i) => (
            <div key={i} className={`text-[11px] border rounded px-2 py-1 flex items-center justify-between ${ENRICH_STATUS_COLOR[r.status] || "text-slate-400 border-[#21262D]"}`}>
              <span>{r.source}</span>
              <span className="font-mono">{ENRICH_STATUS_LABEL[r.status] || r.status}</span>
            </div>
          ))}
          {(data.results || []).some(r => r.status === "found") && (
            <div className="text-[10.5px] text-slate-500 mt-1">
              {(data.results || []).filter(r => r.status === "found").flatMap(r => r.rows).map((row, i) => (
                <div key={i} className="mt-1">{row.name}: {row.detail}</div>
              ))}
            </div>
          )}
          <div className="text-[10px] text-slate-600">Last checked {new Date(data.checked_at).toLocaleString()}</div>
        </div>
      )}
    </div>
  );
}

export default function AlbertMonitoring() {
  const fileRef = useRef(null);
  const alertsRef = useRef(null);
  const [uploading, setUploading] = useState(false);
  const [imports, setImports] = useState([]);
  const [stats, setStats] = useState(null);
  const [signatures, setSignatures] = useState([]);
  const [sankey, setSankey] = useState(null);
  const [days, setDays] = useState(30);
  const [loading, setLoading] = useState(true);

  const [alerts, setAlerts] = useState({ items: [], total: 0, page: 1, page_size: 25 });
  const [q, setQ] = useState("");
  const [severity, setSeverity] = useState("");
  const [category, setCategory] = useState("");
  const [device, setDevice] = useState("");
  const [alertMessage, setAlertMessage] = useState("");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState(null);
  const [showRawStream, setShowRawStream] = useState(false);
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);
  const [showRiskModal, setShowRiskModal] = useState(false);
  const [allowlist, setAllowlist] = useState([]);
  const [showAllowlist, setShowAllowlist] = useState(false);
  const [newAllowlistSourceIp, setNewAllowlistSourceIp] = useState("");
  const [newAllowlistDestIp, setNewAllowlistDestIp] = useState("");
  const [includeSuppressed, setIncludeSuppressed] = useState(false);
  const [assetLinkField, setAssetLinkField] = useState(null); // "source" | "destination" | null
  const [assetSearchQ, setAssetSearchQ] = useState("");
  const [assetSearchResults, setAssetSearchResults] = useState([]);
  const [assetSearchBusy, setAssetSearchBusy] = useState(false);
  const navigate = useNavigate();

  const loadDashboard = async (rangeDays) => {
    setLoading(true);
    try {
      const [statsR, sigR, impR, sankeyR] = await Promise.all([
        api.get("/v1/admin/albert/stats", { params: { days: rangeDays } }),
        api.get("/v1/admin/albert/signatures", { params: { days: rangeDays } }),
        api.get("/v1/admin/albert/imports"),
        api.get("/v1/admin/albert/sankey", { params: { days: rangeDays } }),
      ]);
      setStats(statsR.data);
      setSignatures(sigR.data);
      setImports(impR.data);
      setSankey(sankeyR.data);
    } catch (e) {
      // non-fatal -- no data yet is a valid empty state
    } finally {
      setLoading(false);
    }
  };

  const loadAlerts = async () => {
    try {
      const params = { page, page_size: 25, include_suppressed: includeSuppressed };
      if (q) params.q = q;
      if (severity) params.severity = severity;
      if (category) params.category = category;
      if (device) params.device = device;
      if (alertMessage) params.alert_message = alertMessage;
      const r = await api.get("/v1/admin/albert/alerts", { params });
      setAlerts(r.data);
      setSelectedIds(new Set());
    } catch (e) { /* non-fatal */ }
  };

  const loadAllowlist = async () => {
    try {
      const r = await api.get("/v1/admin/albert/allowlist");
      setAllowlist(r.data);
    } catch (e) { /* non-fatal */ }
  };

  useEffect(() => { loadDashboard(days); }, [days]);
  useEffect(() => { loadAlerts(); }, [page, q, severity, category, device, alertMessage, includeSuppressed]);
  useEffect(() => { loadAllowlist(); }, []);

  const scrollToAlerts = () => {
    setTimeout(() => alertsRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 50);
  };

  const filterBy = (setter, value, resetOthers = true) => {
    setPage(1);
    if (resetOthers) { setQ(""); setSeverity(""); setCategory(""); setDevice(""); setAlertMessage(""); }
    setter(value);
    scrollToAlerts();
  };

  const clearFilters = () => { setQ(""); setSeverity(""); setCategory(""); setDevice(""); setAlertMessage(""); setPage(1); };

  const upload = async (file) => {
    setUploading(true);
    try {
      const fd = new FormData();
      fd.append("file", file);
      const r = await api.post("/v1/admin/albert/upload", fd, { headers: { "Content-Type": "multipart/form-data" } });
      const wl = r.data.watchlist_matches ? `, ${r.data.watchlist_matches} watchlist match(es)` : "";
      const enr = r.data.auto_enrichment_queued?.length ? ` — checking ${r.data.auto_enrichment_queued.length} destination IP(s) against threat intel in the background` : "";
      toast.success(`Imported ${r.data.rows_parsed} alerts (${r.data.disposition})${wl}${enr}`);
      loadDashboard(days);
      loadAlerts();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Import failed -- check this is an Albert alert export");
    } finally {
      setUploading(false);
      if (fileRef.current) fileRef.current.value = "";
    }
  };

  const openAlert = async (a) => {
    setShowRawStream(false);
    setSelected(a);
    try {
      const r = await api.get(`/v1/admin/albert/alerts/${a.id}`);
      setSelected(r.data);
    } catch (e) { /* keep the row data we already have */ }
  };

  const toggleSelect = (id) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const toggleSelectAll = () => {
    setSelectedIds(prev => prev.size === alerts.items.length ? new Set() : new Set(alerts.items.map(a => a.id)));
  };

  const openAssetPicker = (field) => {
    setAssetLinkField(field);
    setAssetSearchQ("");
    setAssetSearchResults([]);
  };

  const searchAssetsForLink = async (query) => {
    setAssetSearchQ(query);
    if (!query.trim()) { setAssetSearchResults([]); return; }
    setAssetSearchBusy(true);
    try {
      const r = await api.get("/v1/assets", { params: { q: query.trim(), limit: 10 } });
      setAssetSearchResults(r.data.items || r.data || []);
    } catch (e) { /* non-fatal */ } finally { setAssetSearchBusy(false); }
  };

  const linkAssetOverride = async (assetId) => {
    if (!selected || !assetLinkField) return;
    try {
      const r = await api.post(`/v1/admin/albert/alerts/${selected.id}/link-asset`, { field: assetLinkField, asset_id: assetId });
      setSelected(r.data);
      setAssetLinkField(null);
      loadAlerts();
      toast.success("Asset linked");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to link asset");
    }
  };

  const unlinkAssetOverride = async (field) => {
    if (!selected) return;
    try {
      const r = await api.post(`/v1/admin/albert/alerts/${selected.id}/link-asset`, { field, asset_id: null });
      setSelected(r.data);
      loadAlerts();
    } catch (e) {
      toast.error("Failed to unlink");
    }
  };

  const bulkAcknowledge = async () => {
    if (selectedIds.size === 0) return;
    setBulkBusy(true);
    try {
      await api.post("/v1/admin/albert/alerts/bulk-acknowledge", { alert_ids: [...selectedIds] });
      toast.success(`Acknowledged ${selectedIds.size} alert(s)`);
      loadAlerts();
    } catch (e) {
      toast.error("Bulk acknowledge failed");
    } finally { setBulkBusy(false); }
  };

  const bulkWatchlist = async (field) => {
    if (selectedIds.size === 0) return;
    setBulkBusy(true);
    try {
      const r = await api.post("/v1/admin/albert/alerts/bulk-watchlist", { alert_ids: [...selectedIds], field, severity: "High" });
      toast.success(r.data.added.length > 0 ? `Added ${r.data.added.length} IP(s) to the Threat Intel Watchlist` : "No public IPs found in the selection");
    } catch (e) {
      toast.error("Bulk watchlist add failed");
    } finally { setBulkBusy(false); }
  };

  const addAllowlistEntry = async () => {
    const source_ip = newAllowlistSourceIp.trim();
    const destination_ip = newAllowlistDestIp.trim();
    if (!source_ip && !destination_ip) {
      toast.error("Enter a source IP and/or destination IP");
      return;
    }
    try {
      await api.post("/v1/admin/albert/allowlist", { source_ip: source_ip || null, destination_ip: destination_ip || null });
      setNewAllowlistSourceIp("");
      setNewAllowlistDestIp("");
      loadAllowlist();
      toast.success("Added to allowlist -- click \"Re-apply to existing alerts\" to suppress past matches too");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to add");
    }
  };

  const removeAllowlistEntry = async (id) => {
    try {
      await api.delete(`/v1/admin/albert/allowlist/${id}`);
      loadAllowlist();
    } catch (e) { toast.error("Failed to remove"); }
  };

  const reapplyAllowlist = async () => {
    try {
      const r = await api.post("/v1/admin/albert/allowlist/reapply");
      toast.success(`${r.data.suppressed} suppressed, ${r.data.unsuppressed} un-suppressed`);
      loadDashboard(days);
      loadAlerts();
    } catch (e) { toast.error("Re-apply failed"); }
  };

  const openIrCase = async () => {
    if (!selected) return;
    try {
      const r = await api.post("/v1/ir/cases", {
        title: `Albert alert: ${selected.alert_message} on ${selected.device}`,
        classification: selected.severity === "High" || selected.severity === "Critical" ? "Moderate" : "Minor",
        initial_intake: `Detected by Albert (CIS/MS-ISAC) sensor ${selected.device} at ${selected.time_gmt}.\n\n`
          + `${selected.explanation}\n\nSource: ${selected.source_ip}:${selected.source_port} -> Destination: ${selected.destination_ip}:${selected.destination_port}`,
      });
      toast.success(`IR case ${r.data.case_number} opened`);
      navigate(`/ir/cases/${r.data.id}`);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to open IR case");
    }
  };

  const riskPrefillFromAlert = () => {
    if (!selected) return {};
    const asset = selected.destination_asset || selected.source_asset;
    return {
      title: `${selected.alert_message} (${selected.device})`,
      description: `${selected.explanation}\n\nSource: ${selected.source_ip}:${selected.source_port} -> Destination: ${selected.destination_ip}:${selected.destination_port}`,
      category: "Technical",
      likelihood: selected.severity === "High" ? 3 : 2,
      impact: selected.severity === "High" ? 4 : 2,
      linked_asset_ids: asset ? [asset.id] : [],
      linked_albert_alert_ids: [selected.id],
      external_reference: asset ? "" : (selected.destination_ip || selected.source_ip || ""),
      tags: ["albert"],
      contextLabel: `From Albert alert on ${selected.device}${asset ? ` -- linked to asset ${asset.hostname}` : ""}`,
    };
  };

  const categories = Object.keys(stats?.category_counts || {});
  const devices = Object.keys(stats?.device_counts || {});
  const severityData = Object.entries(stats?.severity_counts || {}).map(([name, count]) => ({ name, count }));
  const categoryData = Object.entries(stats?.category_counts || {}).map(([name, count]) => ({ name, count }));
  const deviceData = Object.entries(stats?.device_counts || {}).map(([name, count]) => ({ name, count }));
  const anomalyDays = new Set((stats?.anomalies || []).map(a => a.day));
  const anyFilterActive = q || severity || category || device || alertMessage;

  return (
    <Layout title="Albert Network Monitoring" subtitle="CIS/MS-ISAC network sensor alert exports — trends, breakdowns, and plain-English signature explanations">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 mb-5 flex items-center justify-between gap-4 flex-wrap">
        <div className="text-[12px] text-slate-400 max-w-2xl leading-relaxed">
          Upload the .xlsx alert export from the CIS ANET portal. Each row's source/destination IP is checked against the
          existing <span className="text-slate-200">Threat Intel Watchlist</span>, and the busiest public destination IPs are
          automatically checked against <span className="text-slate-200">OpenCTI, GreyNoise, AlienVault OTX, and abuse.ch</span>.
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

            <Panel title="Severity Breakdown" actions={<span className="text-[10px] text-slate-500">click to filter</span>}>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={severityData} layout="vertical" margin={{ left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262D" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: "#8B949E" }} allowDecimals={false} />
                  <YAxis dataKey="name" type="category" tick={{ fontSize: 11, fill: "#C9D1D9" }} width={70} />
                  <Tooltip contentStyle={{ background: "#161B22", border: "1px solid #30363D", fontSize: 12 }} />
                  <Bar dataKey="count" radius={[0, 3, 3, 0]} cursor="pointer" onClick={(d) => filterBy(setSeverity, d.name)}>
                    {severityData.map((d, i) => <Cell key={i} fill={SEV_COLOR[d.name] || "#8B949E"} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </Panel>
          </div>

          <div className="grid grid-cols-2 gap-4 mb-4">
            <Panel title="Category Breakdown" actions={<span className="text-[10px] text-slate-500">click to filter</span>}>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={categoryData} layout="vertical" margin={{ left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262D" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: "#8B949E" }} allowDecimals={false} />
                  <YAxis dataKey="name" type="category" tick={{ fontSize: 10, fill: "#C9D1D9" }} width={150} />
                  <Tooltip contentStyle={{ background: "#161B22", border: "1px solid #30363D", fontSize: 12 }} />
                  <Bar dataKey="count" fill="#a78bfa" radius={[0, 3, 3, 0]} cursor="pointer" onClick={(d) => filterBy(setCategory, d.name)} />
                </BarChart>
              </ResponsiveContainer>
            </Panel>

            <Panel title="Per-Sensor / Site Comparison" actions={<span className="text-[10px] text-slate-500">click to filter</span>}>
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={deviceData} layout="vertical" margin={{ left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262D" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: "#8B949E" }} allowDecimals={false} />
                  <YAxis dataKey="name" type="category" tick={{ fontSize: 10, fill: "#C9D1D9" }} width={150} />
                  <Tooltip contentStyle={{ background: "#161B22", border: "1px solid #30363D", fontSize: 12 }} />
                  <Bar dataKey="count" fill="#34d399" radius={[0, 3, 3, 0]} cursor="pointer" onClick={(d) => filterBy(setDevice, d.name)} />
                </BarChart>
              </ResponsiveContainer>
            </Panel>
          </div>

          {sankey && sankey.nodes?.length > 0 && (
            <div className="mb-4">
              <Panel title="Sensor → Category → Severity Flow">
                <div className="overflow-x-auto">
                  <Sankey width={1040} height={Math.max(240, sankey.nodes.length * 26)} data={sankey}
                    node={<SankeyNode />} nodePadding={18} margin={{ top: 10, right: 140, bottom: 10, left: 140 }}
                    link={{ stroke: "#484F58", strokeOpacity: 0.35 }}>
                    <Tooltip contentStyle={{ background: "#161B22", border: "1px solid #30363D", fontSize: 12 }} />
                  </Sankey>
                </div>
              </Panel>
            </div>
          )}

          <div className="grid grid-cols-2 gap-4 mb-4">
            <Panel title="Top Source IPs">
              <div className="space-y-1.5">
                {(stats?.top_source_ips || []).slice(0, 8).map((ip, i) => (
                  <div key={i} className="flex items-center justify-between text-[12px] cursor-pointer hover:text-blue-300"
                    onClick={() => filterBy(setQ, ip.value)}>
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
                  <div key={i} className="flex items-center justify-between text-[12px] cursor-pointer hover:text-blue-300"
                    onClick={() => filterBy(setQ, ip.value)}>
                    <span className="font-mono text-slate-300">{ip.value}</span>
                    <span className="text-slate-500">{ip.count}</span>
                  </div>
                ))}
                {(!stats?.top_destination_ips || stats.top_destination_ips.length === 0) && <div className="text-[12px] text-slate-500">No data</div>}
              </div>
            </Panel>
          </div>

          <Panel title="Alert Signatures Explained" actions={<span className="text-[10.5px] text-slate-500">click a signature to see its alerts</span>}>
            <div className="space-y-2.5">
              {signatures.map((s, i) => (
                <div key={i} onClick={() => filterBy(setAlertMessage, s.alert_message)}
                  className="border border-[#21262D] rounded p-3 cursor-pointer hover:border-blue-500/40 hover:bg-blue-500/5 transition-colors group">
                  <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                    <SevBadge severity={s.severity} />
                    <Chip color="slate">{s.category}</Chip>
                    <span className="text-[12px] text-slate-200 font-medium">{s.alert_message}</span>
                    <span className="text-[10.5px] text-slate-500 ml-auto flex items-center gap-1">
                      {s.count} occurrence{s.count === 1 ? "" : "s"}
                      <CaretRight size={11} className="text-slate-600 group-hover:text-blue-300" />
                    </span>
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

      <div className="mt-4" ref={alertsRef}>
        <Panel title="Alerts"
          actions={
            <div className="flex items-center gap-1.5">
              <div className="relative">
                <MagnifyingGlass size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-slate-500" />
                <input value={q} onChange={(e) => { setPage(1); setAlertMessage(""); setQ(e.target.value); }} placeholder="Search message/IP…"
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
              <label className="flex items-center gap-1 text-[11px] text-slate-400 cursor-pointer">
                <input type="checkbox" checked={includeSuppressed} onChange={(e) => { setPage(1); setIncludeSuppressed(e.target.checked); }} />
                Show suppressed
              </label>
              <button onClick={() => setShowAllowlist(v => !v)}
                className="h-7 px-2 text-[11px] border border-[#30363D] hover:border-[#484F58] text-slate-400 rounded">
                Allowlist ({allowlist.length})
              </button>
              {anyFilterActive && (
                <button onClick={clearFilters} className="h-7 px-2 text-[11px] text-slate-500 hover:text-slate-300 inline-flex items-center gap-1">
                  <X size={11} /> Clear
                </button>
              )}
            </div>
          }
        >
          {showAllowlist && (
            <div className="mb-3 border border-[#21262D] rounded p-3 bg-[#161B22]">
              <div className="text-[11.5px] text-slate-300 mb-2 leading-relaxed">
                Known-good traffic (patch management, automation, admin jump hosts) -- suppressed from stats and hidden from the table
                by default. Set a source IP to allow that host no matter where it talks to; set a destination IP to allow traffic to a
                known-good target no matter which host initiates it (useful if an automation account's source address changes); set
                both for a tighter, specific pair.
              </div>
              <div className="flex items-center gap-2 mb-2">
                <input value={newAllowlistSourceIp} onChange={(e) => setNewAllowlistSourceIp(e.target.value)} placeholder="Source IP (optional)"
                  className="h-7 flex-1 bg-[#0D1117] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-200" />
                <input value={newAllowlistDestIp} onChange={(e) => setNewAllowlistDestIp(e.target.value)} placeholder="Destination IP (optional)"
                  className="h-7 flex-1 bg-[#0D1117] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-200" />
                <button onClick={addAllowlistEntry} className="h-7 px-3 text-[11px] bg-blue-500/20 border border-blue-500/40 text-blue-200 rounded">Add</button>
                <button onClick={reapplyAllowlist} className="h-7 px-3 text-[11px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 text-slate-300 rounded">
                  Re-apply to existing alerts
                </button>
              </div>
              <div className="space-y-1">
                {allowlist.map(e => (
                  <div key={e.id} className="flex items-center justify-between text-[11.5px] text-slate-300 font-mono">
                    <span>
                      {e.source_ip && <>src {e.source_ip}</>}
                      {e.source_ip && e.destination_ip && " + "}
                      {e.destination_ip && <>dst {e.destination_ip}</>}
                      {" "}{e.notes && <span className="text-slate-500 font-sans">— {e.notes}</span>}
                    </span>
                    <button onClick={() => removeAllowlistEntry(e.id)} className="text-red-400 hover:text-red-300"><X size={12} /></button>
                  </div>
                ))}
                {allowlist.length === 0 && <div className="text-[11px] text-slate-500">No allowlist entries yet.</div>}
              </div>
            </div>
          )}

          {alertMessage && (
            <div className="mb-2 text-[11.5px] text-blue-300 flex items-center gap-1.5">
              <CaretRight size={11} /> Showing alerts for signature: <span className="font-medium">{alertMessage}</span>
            </div>
          )}

          {selectedIds.size > 0 && (
            <div className="mb-2 flex items-center gap-2 text-[11.5px] bg-blue-500/5 border border-blue-500/30 rounded px-3 py-2">
              <span className="text-blue-300">{selectedIds.size} selected</span>
              <button disabled={bulkBusy} onClick={bulkAcknowledge} className="h-6 px-2 border border-[#30363D] hover:border-blue-500/40 text-slate-300 rounded">Acknowledge</button>
              <button disabled={bulkBusy} onClick={() => bulkWatchlist("destination_ip")} className="h-6 px-2 border border-[#30363D] hover:border-blue-500/40 text-slate-300 rounded">Watchlist destination IPs</button>
              <button disabled={bulkBusy} onClick={() => bulkWatchlist("source_ip")} className="h-6 px-2 border border-[#30363D] hover:border-blue-500/40 text-slate-300 rounded">Watchlist source IPs</button>
            </div>
          )}

          {alerts.items.length === 0 ? (
            <div className="text-center py-8 text-[12.5px] text-slate-500">No alerts match these filters.</div>
          ) : (
            <div className="border border-[#21262D] rounded overflow-hidden">
              <table className="w-full text-[12px]">
                <thead>
                  <tr className="border-b border-[#21262D] text-[10px] uppercase tracking-wider text-slate-500">
                    <th className="text-left px-3 py-2 w-8">
                      <button onClick={toggleSelectAll} className="text-slate-500 hover:text-slate-300">
                        {selectedIds.size === alerts.items.length ? <CheckSquare size={14} /> : <Square size={14} />}
                      </button>
                    </th>
                    <th className="text-left px-3 py-2 font-mono">Time (GMT)</th>
                    <th className="text-left px-3 py-2 font-mono">Sensor</th>
                    <th className="text-left px-3 py-2 font-mono">Alert</th>
                    <th className="text-left px-3 py-2 font-mono">Source → Destination</th>
                    <th className="text-left px-3 py-2 font-mono">Severity</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#21262D]">
                  {alerts.items.map(a => (
                    <tr key={a.id} className={`hover:bg-[#161B22] ${a.suppressed ? "opacity-50" : ""}`}>
                      <td className="px-3 py-2" onClick={(e) => { e.stopPropagation(); toggleSelect(a.id); }}>
                        <button className="text-slate-500 hover:text-slate-300">
                          {selectedIds.has(a.id) ? <CheckSquare size={14} /> : <Square size={14} />}
                        </button>
                      </td>
                      <td className="px-3 py-2 font-mono text-slate-400 whitespace-nowrap cursor-pointer" onClick={() => openAlert(a)}>{a.time_gmt ? new Date(a.time_gmt).toLocaleString() : "—"}</td>
                      <td className="px-3 py-2 text-slate-300 cursor-pointer" onClick={() => openAlert(a)}>{a.device}</td>
                      <td className="px-3 py-2 text-slate-200 max-w-[280px] truncate cursor-pointer" onClick={() => openAlert(a)}>
                        {a.alert_message} {a.acknowledged && <Chip color="green">ack'd</Chip>} {a.suppressed && <Chip color="slate">suppressed</Chip>}
                      </td>
                      <td className="px-3 py-2 font-mono text-slate-400 whitespace-nowrap cursor-pointer" onClick={() => openAlert(a)}>{a.source_ip}:{a.source_port} → {a.destination_ip}:{a.destination_port}</td>
                      <td className="px-3 py-2 cursor-pointer" onClick={() => openAlert(a)}><SevBadge severity={a.severity} /></td>
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

              <div className="flex items-center gap-2 flex-wrap">
                <button onClick={() => setShowRiskModal(true)}
                  className="h-7 px-2.5 text-[11.5px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 text-slate-300 rounded inline-flex items-center gap-1.5">
                  <Flag size={13} /> Add to Risk Register
                </button>
                <button onClick={openIrCase}
                  className="h-7 px-2.5 text-[11.5px] border border-[#30363D] hover:border-red-500/40 hover:text-red-300 text-slate-300 rounded inline-flex items-center gap-1.5">
                  <FirstAidKit size={13} /> Open IR case
                </button>
              </div>

              <div className="text-[12.5px] text-slate-300 leading-relaxed border border-[#21262D] rounded p-3">{selected.explanation}</div>
              {selected.mitre_technique && (
                <div className="text-[11.5px] text-slate-500 font-mono">MITRE ATT&CK: {selected.mitre_technique}</div>
              )}
              <div className="grid grid-cols-2 gap-3 text-[12px]">
                <div><div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Time (GMT)</div><div className="font-mono text-slate-300">{selected.time_gmt ? new Date(selected.time_gmt).toLocaleString() : "—"}</div></div>
                <div><div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Sensor</div><div className="text-slate-300">{selected.device}</div></div>
                <div>
                  <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Source</div>
                  <div className="font-mono text-slate-300">{selected.source_ip}:{selected.source_port}</div>
                  {selected.source_asset ? (
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <Link to={`/assets/${selected.source_asset.id}`} className="text-[10.5px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1">
                        <HardDrive size={10} /> {selected.source_asset.hostname}
                      </Link>
                      <button onClick={() => openAssetPicker("source")} className="text-[10px] text-slate-500 hover:text-slate-300">Change</button>
                      {selected.source_asset.manually_linked && (
                        <button onClick={() => unlinkAssetOverride("source")} className="text-[10px] text-red-400 hover:text-red-300">Unlink</button>
                      )}
                    </div>
                  ) : (
                    <button onClick={() => openAssetPicker("source")} className="text-[10.5px] text-slate-500 hover:text-blue-300 mt-0.5">+ Link asset</button>
                  )}
                </div>
                <div>
                  <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Destination</div>
                  <div className="font-mono text-slate-300">{selected.destination_ip}:{selected.destination_port}</div>
                  {selected.destination_asset ? (
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <Link to={`/assets/${selected.destination_asset.id}`} className="text-[10.5px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1">
                        <HardDrive size={10} /> {selected.destination_asset.hostname}
                      </Link>
                      <button onClick={() => openAssetPicker("destination")} className="text-[10px] text-slate-500 hover:text-slate-300">Change</button>
                      {selected.destination_asset.manually_linked && (
                        <button onClick={() => unlinkAssetOverride("destination")} className="text-[10px] text-red-400 hover:text-red-300">Unlink</button>
                      )}
                    </div>
                  ) : (
                    <button onClick={() => openAssetPicker("destination")} className="text-[10.5px] text-slate-500 hover:text-blue-300 mt-0.5">+ Link asset</button>
                  )}
                </div>
                <div><div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Protocol</div><div className="text-slate-300">{selected.protocol_name || selected.protocol}</div></div>
                <div><div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Disposition</div><div className="text-slate-300 capitalize">{selected.disposition}</div></div>
              </div>

              {assetLinkField && (
                <div className="border border-blue-500/30 rounded p-3 bg-blue-500/5">
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="text-[11px] text-blue-200">
                      Link {assetLinkField} asset manually — use this when the IP doesn&#39;t auto-match (stale/missing Assets IP data)
                    </div>
                    <button onClick={() => setAssetLinkField(null)} className="text-slate-500 hover:text-slate-300"><X size={12} /></button>
                  </div>
                  <input
                    value={assetSearchQ}
                    onChange={(e) => searchAssetsForLink(e.target.value)}
                    placeholder="Search assets by hostname, IP, tag..."
                    className="h-7 w-full bg-[#0D1117] border border-[#30363D] rounded px-2 text-[11.5px] text-slate-200 mb-1.5"
                    autoFocus
                  />
                  <div className="space-y-1 max-h-40 overflow-y-auto">
                    {assetSearchBusy && <div className="text-[11px] text-slate-500">Searching…</div>}
                    {!assetSearchBusy && assetSearchQ && assetSearchResults.length === 0 && (
                      <div className="text-[11px] text-slate-500">No matching assets.</div>
                    )}
                    {assetSearchResults.map(a => (
                      <button key={a.id} onClick={() => linkAssetOverride(a.id)}
                        className="w-full text-left px-2 py-1 text-[11.5px] text-slate-300 hover:bg-[#161B22] rounded flex items-center justify-between">
                        <span className="inline-flex items-center gap-1.5"><HardDrive size={11} /> {a.hostname}</span>
                        <span className="text-slate-500 font-mono text-[10.5px]">{a.ip}</span>
                      </button>
                    ))}
                  </div>
                </div>
              )}

              <div>
                <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1.5">Threat Intel</div>
                <div className="space-y-2">
                  {selected.destination_ip && <IpIntelPanel ip={selected.destination_ip} label="Destination" />}
                  {selected.source_ip && <IpIntelPanel ip={selected.source_ip} label="Source" />}
                </div>
                <a href={`/admin/threat-intel?value=${selected.source_ip}`} className="inline-flex items-center gap-1 text-[11px] text-blue-300 hover:text-blue-200 mt-2">
                  <ArrowSquareOut size={11} /> Also check the local Threat Intel Watchlist
                </a>
              </div>

              {(selected.stream_data || selected.stream_data_raw) && (
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="text-slate-500 text-[10px] uppercase tracking-wider">Stream Data</div>
                    <button onClick={() => setShowRawStream(v => !v)} className="text-[10.5px] text-blue-300 hover:text-blue-200">
                      {showRawStream ? "Show cleaned" : "Show raw bytes"}
                    </button>
                  </div>
                  <pre className="text-[10.5px] font-mono text-slate-400 bg-black/30 rounded p-2.5 overflow-x-auto whitespace-pre-wrap max-h-40 overflow-y-auto">
                    {showRawStream ? selected.stream_data_raw : selected.stream_data}
                  </pre>
                  {!showRawStream && (
                    <div className="text-[10px] text-slate-600 mt-1">Non-printable bytes collapsed to ⋯ for readability -- binary protocols like SMB naturally contain these.</div>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {showRiskModal && (
        <NewRiskModal onClose={() => setShowRiskModal(false)} prefill={riskPrefillFromAlert()}
          onCreated={() => { setShowRiskModal(false); toast.success("Linked to Risk Register"); navigate("/risk-register"); }} />
      )}
    </Layout>
  );
}
