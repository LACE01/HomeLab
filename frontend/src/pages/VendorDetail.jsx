import { useEffect, useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip, RiskBar, SevBadge } from "@/components/Badges";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell,
  LineChart, Line,
} from "recharts";
import {
  ArrowLeft, PencilSimple, Trash, HardDrive, Warning,
  ArrowsClockwise, CheckCircle, XCircle, MinusCircle, Globe, FloppyDisk, X, CalendarBlank,
} from "@phosphor-icons/react";

const BAND_CHIP = { Critical: "red", High: "orange", Medium: "amber", Low: "blue" };
const BAND_COLOR = { Critical: "#f87171", High: "#fb923c", Medium: "#fbbf24", Low: "#60a5fa" };
const SEV_COLOR = { Critical: "#f87171", High: "#fb923c", Medium: "#fbbf24", Low: "#60a5fa", Unknown: "#8B949E" };
const STATUS_LABEL = { active: "Active", inactive: "Inactive", under_review: "Under Review" };
const STATUS_OPTIONS = ["active", "inactive", "under_review"];
const DPA_STATUSES = ["not_required", "requested", "in_review", "signed"];
const DPA_LABEL = { not_required: "Not required", requested: "Requested", in_review: "In review", signed: "Signed" };
const DPA_CHIP = { not_required: "slate", requested: "amber", in_review: "amber", signed: "green" };
const QUESTIONNAIRE_STATUSES = ["not_started", "in_progress", "completed"];
const QUESTIONNAIRE_LABEL = { not_started: "Not started", in_progress: "In progress", completed: "Completed" };
const QUESTIONNAIRE_CHIP = { not_started: "slate", in_progress: "amber", completed: "green" };
const MONITOR_STATUS_META = {
  found: { label: "Hit", icon: Warning, cls: "text-red-300 border-red-500/30 bg-red-500/5" },
  clean: { label: "Clean", icon: CheckCircle, cls: "text-emerald-300 border-emerald-500/30 bg-emerald-500/5" },
  not_configured: { label: "Not set up", icon: MinusCircle, cls: "text-slate-500 border-[#21262D]" },
  error: { label: "Error", icon: XCircle, cls: "text-amber-300 border-amber-500/30 bg-amber-500/5" },
};

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

export default function VendorDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [vendor, setVendor] = useState(null);
  const [meta, setMeta] = useState({ categories: [], criticality_levels: [] });
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState(null);
  const [checking, setChecking] = useState(false);
  const [checkResults, setCheckResults] = useState(null);
  const [riskHistory, setRiskHistory] = useState([]);

  const load = async () => {
    const [vR, metaR, historyR] = await Promise.all([
      api.get(`/v1/vendors/${id}`), api.get("/v1/vendors/meta"), api.get(`/v1/vendors/${id}/risk-history`),
    ]);
    setVendor(vR.data);
    setMeta(metaR.data);
    setRiskHistory(historyR.data.items);
  };

  useEffect(() => { load(); }, [id]);

  if (!vendor) {
    return <Layout title="Vendor" subtitle="Loading…"><div className="text-slate-500 text-[12px]">Loading…</div></Layout>;
  }

  const startEdit = () => {
    setForm({
      name: vendor.name, category: vendor.category, domain: vendor.domain || "", website: vendor.website || "",
      description: vendor.description || "", match_terms: (vendor.match_terms || []).join(", "),
      org_criticality: vendor.org_criticality, status: vendor.status, tags: (vendor.tags || []).join(", "),
      notes: vendor.notes || "",
      contract_start_date: vendor.contract_start_date || "", contract_end_date: vendor.contract_end_date || "",
      renewal_date: vendor.renewal_date || "", contract_owner: vendor.contract_owner || "",
      dpa_status: vendor.dpa_status || "not_required",
      security_questionnaire_status: vendor.security_questionnaire_status || "not_started",
    });
    setEditing(true);
  };

  const saveEdit = async () => {
    try {
      const body = {
        ...form,
        match_terms: form.match_terms.split(",").map(s => s.trim()).filter(Boolean),
        tags: form.tags.split(",").map(s => s.trim()).filter(Boolean),
        org_criticality: Number(form.org_criticality),
      };
      await api.patch(`/v1/vendors/${id}`, body);
      toast.success("Vendor updated");
      setEditing(false);
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Update failed");
    }
  };

  const deleteVendor = async () => {
    if (!window.confirm(`Remove vendor "${vendor.name}"? This also disables compromise monitoring.`)) return;
    try {
      await api.delete(`/v1/vendors/${id}`);
      toast.success("Vendor removed");
      navigate("/vendors");
    } catch (e) {
      toast.error(e.response?.data?.detail || "Delete failed");
    }
  };

  const toggleMonitoring = async () => {
    if (!vendor.domain) { toast.error("Set a domain on this vendor first"); return; }
    try {
      await api.post(`/v1/vendors/${id}/monitor`, { enabled: !vendor.monitoring_enabled });
      toast.success(vendor.monitoring_enabled ? "Monitoring disabled" : "Monitoring enabled");
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to update monitoring");
    }
  };

  const checkNow = async () => {
    if (!vendor.domain) { toast.error("Set a domain on this vendor first"); return; }
    setChecking(true);
    setCheckResults(null);
    try {
      const r = await api.post(`/v1/vendors/${id}/check-now`);
      setCheckResults(r.data.results);
      const hits = r.data.results.filter(x => x.status === "found").length;
      if (hits > 0) toast.warning(`${hits} monitoring module(s) found new exposure`);
      else toast.success("Compromise check complete — no new exposure found");
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Check failed");
    } finally {
      setChecking(false);
    }
  };

  const severityData = Object.entries(vendor.severity_counts || {}).map(([name, count]) => ({ name, count }));

  return (
    <Layout
      title={vendor.name}
      subtitle={vendor.description || `${vendor.category} vendor`}
      actions={
        <div className="flex items-center gap-2">
          <button onClick={() => navigate("/vendors")} className="h-8 px-3 text-[12px] text-slate-400 hover:text-slate-200 inline-flex items-center gap-1.5">
            <ArrowLeft size={14} /> Back
          </button>
          <button onClick={startEdit} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 text-slate-300 rounded inline-flex items-center gap-1.5">
            <PencilSimple size={13} /> Edit
          </button>
          <button onClick={deleteVendor} className="h-8 px-3 text-[12px] border border-red-500/30 hover:bg-red-500/10 text-red-300 rounded inline-flex items-center gap-1.5">
            <Trash size={13} /> Remove
          </button>
        </div>
      }>

      <div className="flex items-center gap-2 flex-wrap mb-5">
        <Chip color="slate">{vendor.category}</Chip>
        <Chip color={BAND_CHIP[vendor.risk_band] || "slate"}>{vendor.risk_band} risk · {vendor.risk_score}</Chip>
        <Chip color={vendor.status === "active" ? "green" : vendor.status === "under_review" ? "amber" : "slate"}>{STATUS_LABEL[vendor.status] || vendor.status}</Chip>
        {vendor.domain && (
          <a href={vendor.website || `https://${vendor.domain}`} target="_blank" rel="noreferrer"
            className="text-[11.5px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1">
            <Globe size={12} /> {vendor.domain}
          </a>
        )}
        {(vendor.tags || []).map(t => <Chip key={t} color="slate">{t}</Chip>)}
      </div>

      <div className="grid grid-cols-3 gap-4 mb-5">
        <Panel title="Vendor Risk Score">
          <div className="flex items-center justify-between mb-3">
            <div>
              <div className="text-[26px] font-semibold tabular-nums" style={{ color: BAND_COLOR[vendor.risk_band] || "#94a3b8" }}>{vendor.risk_score}</div>
              <div className="text-[11px] text-slate-500">{vendor.risk_band} · likelihood {vendor.inherent_likelihood} × org criticality {vendor.org_criticality}</div>
            </div>
          </div>
          <RiskBar score={vendor.risk_score * 4} />
          <div className="text-[10.5px] text-slate-500 mt-2 leading-relaxed">
            Likelihood is derived from this vendor&#8217;s own open finding severity mix (Critical/KEV findings score highest).
            Impact is the org criticality you set below &#8212; how much this vendor matters to your organization specifically.
          </div>
        </Panel>
        <Panel title="Exposure Summary">
          <div className="grid grid-cols-2 gap-2 text-[12px]">
            <div><div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Linked Assets</div><div className="text-slate-200 font-mono text-[16px]">{vendor.asset_count}</div></div>
            <div><div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Linked Findings</div><div className="text-slate-200 font-mono text-[16px]">{vendor.finding_count}</div></div>
          </div>
          {severityData.length > 0 && (
            <ResponsiveContainer width="100%" height={100}>
              <BarChart data={severityData} layout="vertical" margin={{ left: 10, top: 8 }}>
                <XAxis type="number" hide allowDecimals={false} />
                <YAxis type="category" dataKey="name" tick={{ fill: "#8B949E", fontSize: 10 }} width={55} />
                <Tooltip contentStyle={{ background: "#161B22", border: "1px solid #30363D", fontSize: 12 }} />
                <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                  {severityData.map((d, i) => <Cell key={i} fill={SEV_COLOR[d.name] || "#8B949E"} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </Panel>
        <Panel title="Compromise Monitoring" actions={
          vendor.domain ? (
            <button onClick={toggleMonitoring} className={`h-6 px-2 text-[10.5px] rounded border ${vendor.monitoring_enabled ? "border-emerald-500/40 text-emerald-300 bg-emerald-500/10" : "border-[#30363D] text-slate-400"}`}>
              {vendor.monitoring_enabled ? "Enabled" : "Disabled"}
            </button>
          ) : null
        }>
          {!vendor.domain ? (
            <div className="text-[11.5px] text-slate-500">Set a domain on this vendor to enable OSINT compromise monitoring (OTX, abuse.ch, OpenCTI, certificate transparency).</div>
          ) : (
            <>
              <button onClick={checkNow} disabled={checking}
                className="h-7 px-2.5 text-[11.5px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 text-slate-300 rounded inline-flex items-center gap-1.5 mb-2 disabled:opacity-50">
                <ArrowsClockwise size={12} className={checking ? "animate-spin" : ""} /> {checking ? "Checking…" : "Check now"}
              </button>
              {checkResults && (
                <div className="space-y-1 mt-1">
                  {checkResults.map(r => {
                    const meta_ = MONITOR_STATUS_META[r.status] || MONITOR_STATUS_META.error;
                    const Icon = meta_.icon;
                    return (
                      <div key={r.module_id} className={`flex items-center justify-between px-2 py-1 rounded border text-[11px] ${meta_.cls}`}>
                        <span>{r.module_label}</span>
                        <span className="inline-flex items-center gap-1"><Icon size={11} /> {meta_.label}</span>
                      </div>
                    );
                  })}
                </div>
              )}
              {vendor.exposure.length > 0 && (
                <div className="mt-2 text-[10.5px] text-slate-500">{vendor.exposure.length} historical OSINT finding(s) on this domain &#8212; see Exposure below.</div>
              )}
            </>
          )}
        </Panel>
      </div>

      <div className="grid grid-cols-2 gap-4 mb-5">
        <Panel title="Risk Score Trend">
          {riskHistory.length < 2 ? (
            <div className="text-[11.5px] text-slate-500 py-6 text-center">
              Not enough history yet &#8212; a nightly snapshot builds one point per day. Check back after a day or two.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height={160}>
              <LineChart data={riskHistory} margin={{ left: -10, top: 8 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#21262D" />
                <XAxis dataKey="date" tick={{ fill: "#8B949E", fontSize: 10 }} tickFormatter={(s) => s ? s.slice(5) : s} />
                <YAxis domain={[0, 25]} tick={{ fill: "#8B949E", fontSize: 10 }} allowDecimals={false} />
                <Tooltip contentStyle={{ background: "#161B22", border: "1px solid #30363D", fontSize: 12 }} />
                <Line type="monotone" dataKey="risk_score" stroke="#60a5fa" strokeWidth={2} dot={{ r: 2 }} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </Panel>
        <Panel title="Contract & Compliance">
          <div className="grid grid-cols-2 gap-3 text-[12px]">
            <div>
              <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Renewal Date</div>
              <div className="text-slate-200 font-mono flex items-center gap-1.5">
                <CalendarBlank size={12} className="text-slate-500" />
                {vendor.renewal_date ? new Date(vendor.renewal_date).toLocaleDateString() : "—"}
                {vendor.renewal_date && vendor.renewal_date < new Date().toISOString().slice(0, 10) && (
                  <Warning size={12} className="text-amber-400" />
                )}
              </div>
            </div>
            <div>
              <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Contract Owner</div>
              <div className="text-slate-200">{vendor.contract_owner || "—"}</div>
            </div>
            <div>
              <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Contract Term</div>
              <div className="text-slate-300 text-[11px]">
                {vendor.contract_start_date ? new Date(vendor.contract_start_date).toLocaleDateString() : "—"}
                {" – "}
                {vendor.contract_end_date ? new Date(vendor.contract_end_date).toLocaleDateString() : "—"}
              </div>
            </div>
            <div>
              <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">DPA Status</div>
              <Chip color={DPA_CHIP[vendor.dpa_status] || "slate"}>{DPA_LABEL[vendor.dpa_status] || vendor.dpa_status}</Chip>
            </div>
            <div className="col-span-2">
              <div className="text-slate-500 text-[10px] uppercase tracking-wider mb-1">Security Questionnaire</div>
              <Chip color={QUESTIONNAIRE_CHIP[vendor.security_questionnaire_status] || "slate"}>
                {QUESTIONNAIRE_LABEL[vendor.security_questionnaire_status] || vendor.security_questionnaire_status}
              </Chip>
            </div>
          </div>
        </Panel>
      </div>

      {vendor.exposure.length > 0 && (
        <Panel title="OSINT Exposure History" actions={<Warning size={13} className="text-amber-400" />}>
          <div className="space-y-1.5">
            {vendor.exposure.map((e, i) => (
              <div key={e.id || i} className="flex items-center justify-between px-2.5 py-1.5 rounded border border-amber-500/20 bg-amber-500/5 text-[11.5px]">
                <div className="flex items-center gap-2">
                  <Chip color="amber">{e.module_id || e.source}</Chip>
                  <span className="text-slate-300">{e.summary || e.indicator || e.title || "Exposure finding"}</span>
                </div>
                <span className="font-mono text-[10.5px] text-slate-500">{e.found_at ? new Date(e.found_at).toLocaleDateString() : ""}</span>
              </div>
            ))}
          </div>
        </Panel>
      )}
      {vendor.exposure.length > 0 && <div className="mb-5" />}

      <div className="grid grid-cols-2 gap-4">
        <Panel title={`Linked Assets (${vendor.assets.length})`}>
          {vendor.assets.length === 0 ? (
            <div className="text-[11.5px] text-slate-500">No assets link to this vendor via hardware, OS, or hostname match.</div>
          ) : (
            <div className="space-y-1 max-h-[320px] overflow-y-auto">
              {vendor.assets.map(a => (
                <Link key={a.id} to={`/assets/${a.id}`} className="flex items-center justify-between px-2.5 py-1.5 rounded border border-[#21262D] hover:border-blue-500/30 text-[11.5px]">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <HardDrive size={12} className="text-slate-500 shrink-0" />
                    <span className="text-slate-200 truncate">{a.hostname}</span>
                  </div>
                  <span className="text-slate-500 text-[10.5px] truncate ml-2">{a.hardware_info || a.os}</span>
                </Link>
              ))}
            </div>
          )}
        </Panel>
        <Panel title={`Linked Findings — Vulnerability History (${vendor.findings.length})`}>
          {vendor.findings.length === 0 ? (
            <div className="text-[11.5px] text-slate-500">No findings currently link to this vendor.</div>
          ) : (
            <div className="space-y-1 max-h-[320px] overflow-y-auto">
              {vendor.findings.map(f => (
                <Link key={f.id} to={`/findings/${f.id}`} className="flex items-center justify-between gap-2 px-2.5 py-1.5 rounded border border-[#21262D] hover:border-blue-500/30 text-[11.5px]">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <SevBadge severity={f.severity} />
                    <span className="text-slate-300 truncate">{f.title}</span>
                  </div>
                  <span className="text-slate-500 text-[10.5px] whitespace-nowrap">{f.status}</span>
                </Link>
              ))}
            </div>
          )}
        </Panel>
      </div>

      {editing && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-6" onClick={() => setEditing(false)}>
          <div className="bg-[#0D1117] border border-[#30363D] rounded-md max-w-lg w-full max-h-[85vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <div className="px-5 py-3.5 border-b border-[#30363D] flex items-center justify-between">
              <span className="text-[13px] text-slate-200 font-medium">Edit vendor</span>
              <button onClick={() => setEditing(false)} className="text-slate-500 hover:text-slate-300"><X size={16} /></button>
            </div>
            <div className="p-5 space-y-3">
              <div>
                <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Name</label>
                <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
                  className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2.5 text-[12px] text-slate-200" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Category</label>
                  <select value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })}
                    className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-300">
                    {meta.categories.map(c => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Status</label>
                  <select value={form.status} onChange={(e) => setForm({ ...form, status: e.target.value })}
                    className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-300">
                    {STATUS_OPTIONS.map(s => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
                  </select>
                </div>
              </div>
              <div>
                <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Org criticality (1-5) &#8212; how much this vendor matters to your org</label>
                <select value={form.org_criticality} onChange={(e) => setForm({ ...form, org_criticality: e.target.value })}
                  className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-300">
                  {meta.criticality_levels.map(n => <option key={n} value={n}>{n}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Domain</label>
                <input value={form.domain} onChange={(e) => setForm({ ...form, domain: e.target.value })}
                  className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2.5 text-[12px] text-slate-200" />
              </div>
              <div>
                <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Match terms (comma-separated)</label>
                <input value={form.match_terms} onChange={(e) => setForm({ ...form, match_terms: e.target.value })}
                  className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2.5 text-[12px] text-slate-200" />
              </div>
              <div>
                <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Tags (comma-separated)</label>
                <input value={form.tags} onChange={(e) => setForm({ ...form, tags: e.target.value })}
                  className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2.5 text-[12px] text-slate-200" />
              </div>
              <div>
                <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Notes</label>
                <textarea value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })} rows={3}
                  className="w-full bg-[#161B22] border border-[#30363D] rounded px-2.5 py-1.5 text-[12px] text-slate-200" />
              </div>
              <div className="border-t border-[#21262D] pt-3">
                <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-2">Contract &amp; Compliance</div>
                <div className="grid grid-cols-2 gap-3 mb-3">
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Contract start</label>
                    <input type="date" value={form.contract_start_date} onChange={(e) => setForm({ ...form, contract_start_date: e.target.value })}
                      className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2.5 text-[12px] text-slate-200" />
                  </div>
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Contract end</label>
                    <input type="date" value={form.contract_end_date} onChange={(e) => setForm({ ...form, contract_end_date: e.target.value })}
                      className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2.5 text-[12px] text-slate-200" />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3 mb-3">
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Renewal date</label>
                    <input type="date" value={form.renewal_date} onChange={(e) => setForm({ ...form, renewal_date: e.target.value })}
                      className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2.5 text-[12px] text-slate-200" />
                  </div>
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Contract owner</label>
                    <input value={form.contract_owner} onChange={(e) => setForm({ ...form, contract_owner: e.target.value })}
                      className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2.5 text-[12px] text-slate-200" />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">DPA status</label>
                    <select value={form.dpa_status} onChange={(e) => setForm({ ...form, dpa_status: e.target.value })}
                      className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-300">
                      {DPA_STATUSES.map(s => <option key={s} value={s}>{DPA_LABEL[s]}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Security questionnaire</label>
                    <select value={form.security_questionnaire_status} onChange={(e) => setForm({ ...form, security_questionnaire_status: e.target.value })}
                      className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-300">
                      {QUESTIONNAIRE_STATUSES.map(s => <option key={s} value={s}>{QUESTIONNAIRE_LABEL[s]}</option>)}
                    </select>
                  </div>
                </div>
              </div>
            </div>
            <div className="px-5 py-3.5 border-t border-[#30363D] flex justify-end gap-2">
              <button onClick={() => setEditing(false)} className="h-8 px-3 text-[12px] text-slate-400 hover:text-slate-200">Cancel</button>
              <button onClick={saveEdit} className="h-8 px-3 text-[12px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 text-blue-300 rounded inline-flex items-center gap-1.5">
                <FloppyDisk size={13} /> Save
              </button>
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
}
