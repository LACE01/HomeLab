import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell,
} from "recharts";
import {
  Plus, X, Sparkle, Trash, CheckSquare, Square, MagnifyingGlass, Buildings, CalendarBlank, Warning, ArrowsClockwise,
} from "@phosphor-icons/react";

const BAND_CHIP = { Critical: "red", High: "orange", Medium: "amber", Low: "blue" };
const BAND_COLOR = { Critical: "#f87171", High: "#fb923c", Medium: "#fbbf24", Low: "#60a5fa" };
const STATUS_CHIP = { active: "green", inactive: "slate", under_review: "amber" };
const STATUS_LABEL = { active: "Active", inactive: "Inactive", under_review: "Under Review" };
const STATUS_OPTIONS = ["active", "inactive", "under_review"];
const DPA_LABEL = { not_required: "DPA not required", requested: "DPA requested", in_review: "DPA in review", signed: "DPA signed" };
const QUESTIONNAIRE_LABEL = { not_started: "Questionnaire not started", in_progress: "Questionnaire in progress", completed: "Questionnaire completed" };

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

function StatCard({ label, value, sub, tone = "slate" }) {
  const toneMap = { slate: "text-slate-200", red: "text-red-300", amber: "text-amber-300", blue: "text-blue-300" };
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
      <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-2">{label}</div>
      <div className={`text-[26px] font-semibold tabular-nums ${toneMap[tone]}`}>{value}</div>
      {sub && <div className="text-[11px] text-slate-500 mt-1">{sub}</div>}
    </div>
  );
}

function NewVendorModal({ meta, onClose, onCreated }) {
  const [form, setForm] = useState({
    name: "", category: meta.categories[0] || "Software", domain: "", website: "",
    description: "", match_terms: "", org_criticality: 3, status: "active", tags: "", notes: "",
  });
  const [saving, setSaving] = useState(false);

  const submit = async () => {
    if (!form.name.trim()) { toast.error("Vendor name is required"); return; }
    setSaving(true);
    try {
      const body = {
        ...form,
        match_terms: form.match_terms.split(",").map(s => s.trim()).filter(Boolean),
        tags: form.tags.split(",").map(s => s.trim()).filter(Boolean),
        org_criticality: Number(form.org_criticality),
      };
      const r = await api.post("/v1/vendors", body);
      toast.success(`Vendor "${r.data.name}" added`);
      onCreated(r.data);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to add vendor");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-6" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md max-w-lg w-full max-h-[85vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        <div className="px-5 py-3.5 border-b border-[#30363D] flex items-center justify-between">
          <span className="text-[13px] text-slate-200 font-medium">Add vendor</span>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16} /></button>
        </div>
        <div className="p-5 space-y-3">
          <div>
            <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Name *</label>
            <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. Adobe, HP, Microsoft"
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
              <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Org criticality (1-5)</label>
              <select value={form.org_criticality} onChange={(e) => setForm({ ...form, org_criticality: e.target.value })}
                className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-300">
                {meta.criticality_levels.map(n => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Domain (enables compromise monitoring)</label>
            <input value={form.domain} onChange={(e) => setForm({ ...form, domain: e.target.value })} placeholder="adobe.com"
              className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2.5 text-[12px] text-slate-200" />
          </div>
          <div>
            <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Match terms (comma-separated, for linking assets/findings)</label>
            <input value={form.match_terms} onChange={(e) => setForm({ ...form, match_terms: e.target.value })} placeholder="Adobe Acrobat, Adobe Reader"
              className="h-8 w-full bg-[#161B22] border border-[#30363D] rounded px-2.5 text-[12px] text-slate-200" />
          </div>
          <div>
            <label className="text-[10px] uppercase tracking-wider text-slate-500 mb-1 block">Description</label>
            <textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} rows={2}
              className="w-full bg-[#161B22] border border-[#30363D] rounded px-2.5 py-1.5 text-[12px] text-slate-200" />
          </div>
        </div>
        <div className="px-5 py-3.5 border-t border-[#30363D] flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 text-[12px] text-slate-400 hover:text-slate-200">Cancel</button>
          <button onClick={submit} disabled={saving}
            className="h-8 px-3 text-[12px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 text-blue-300 rounded disabled:opacity-50">
            {saving ? "Adding…" : "Add vendor"}
          </button>
        </div>
      </div>
    </div>
  );
}

function ApprovalQueueModal({ onClose, onDecided }) {
  const [candidates, setCandidates] = useState([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [selected, setSelected] = useState(new Set());
  const [busyId, setBusyId] = useState(null);
  const [bulkBusy, setBulkBusy] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const r = await api.get("/v1/vendors/candidates", { params: { status: "pending" } });
      setCandidates(r.data.items);
      setSelected(new Set());
    } finally {
      setLoading(false);
    }
  };

  const rescan = async () => {
    setScanning(true);
    try {
      const r = await api.post("/v1/vendors/candidates/scan");
      if (r.data.created > 0) toast.success(`Found ${r.data.created} new candidate(s)`);
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Scan failed");
    } finally {
      setScanning(false);
    }
  };

  useEffect(() => { rescan(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

  const toggle = (id) => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };
  const toggleAll = () => {
    setSelected(prev => prev.size === candidates.length ? new Set() : new Set(candidates.map(c => c.id)));
  };

  const approveOne = async (id) => {
    setBusyId(id);
    try {
      await api.post(`/v1/vendors/candidates/${id}/approve`);
      await load();
      onDecided();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Approve failed");
    } finally {
      setBusyId(null);
    }
  };

  const denyOne = async (id) => {
    setBusyId(id);
    try {
      await api.post(`/v1/vendors/candidates/${id}/deny`);
      await load();
      onDecided();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Deny failed");
    } finally {
      setBusyId(null);
    }
  };

  const bulkApprove = async () => {
    if (selected.size === 0) return;
    setBulkBusy(true);
    try {
      const r = await api.post("/v1/vendors/candidates/bulk-approve", { ids: [...selected] });
      toast.success(`Approved ${r.data.approved} vendor(s)`);
      await load();
      onDecided();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Bulk approve failed");
    } finally {
      setBulkBusy(false);
    }
  };

  const bulkDeny = async () => {
    if (selected.size === 0) return;
    setBulkBusy(true);
    try {
      const r = await api.post("/v1/vendors/candidates/bulk-deny", { ids: [...selected] });
      toast.success(`Denied ${r.data.denied} candidate(s)`);
      await load();
      onDecided();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Bulk deny failed");
    } finally {
      setBulkBusy(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-6" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md max-w-2xl w-full max-h-[85vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        <div className="px-5 py-3.5 border-b border-[#30363D] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Sparkle size={15} className="text-amber-300" />
            <span className="text-[13px] text-slate-200 font-medium">Vendor approval queue</span>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16} /></button>
        </div>
        <div className="p-5">
          <div className="text-[11.5px] text-slate-500 mb-3">
            Auto-detected from your asset inventory&#8217;s hardware manufacturer and OS fields. Approve to add as a tracked
            vendor with a computed risk profile, or deny to dismiss it for good &#8212; a denied candidate won&#8217;t
            resurface on future scans.
          </div>
          <div className="flex items-center justify-between mb-2">
            <button onClick={toggleAll} disabled={candidates.length === 0} className="text-[11px] text-slate-500 hover:text-slate-300 inline-flex items-center gap-1.5 disabled:opacity-40">
              {selected.size > 0 && selected.size === candidates.length ? <CheckSquare size={13} /> : <Square size={13} />} Select all
            </button>
            <button onClick={rescan} disabled={scanning} className="text-[11px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1.5 disabled:opacity-40">
              {scanning ? "Scanning…" : "Re-scan inventory"}
            </button>
          </div>
          {loading && <div className="text-[12px] text-slate-500 py-4 text-center">Loading…</div>}
          {!loading && candidates.length === 0 && (
            <div className="text-[12px] text-slate-500 py-4 text-center">No pending candidates &#8212; every detected manufacturer/OS vendor is already tracked or has been reviewed.</div>
          )}
          <div className="space-y-1.5 max-h-[40vh] overflow-y-auto">
            {candidates.map(c => (
              <div key={c.id} className="flex items-center justify-between px-2.5 py-1.5 rounded border border-[#21262D]">
                <div className="flex items-center gap-2 min-w-0 cursor-pointer" onClick={() => toggle(c.id)}>
                  {selected.has(c.id) ? <CheckSquare size={14} className="text-blue-300 shrink-0" /> : <Square size={14} className="text-slate-500 shrink-0" />}
                  <span className="text-[12.5px] text-slate-200 truncate">{c.name}</span>
                  <Chip color="slate">{c.category}</Chip>
                  <span className="text-[11px] text-slate-500 font-mono shrink-0">{c.asset_count} asset{c.asset_count === 1 ? "" : "s"}</span>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <button onClick={() => approveOne(c.id)} disabled={busyId === c.id}
                    className="h-6 px-2 text-[10.5px] border border-emerald-500/30 hover:bg-emerald-500/10 text-emerald-300 rounded disabled:opacity-40">
                    Approve
                  </button>
                  <button onClick={() => denyOne(c.id)} disabled={busyId === c.id}
                    className="h-6 px-2 text-[10.5px] border border-red-500/30 hover:bg-red-500/10 text-red-300 rounded disabled:opacity-40">
                    Deny
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
        {candidates.length > 0 && (
          <div className="px-5 py-3.5 border-t border-[#30363D] flex items-center justify-between gap-2">
            <span className="text-[11px] text-slate-500">{selected.size} selected</span>
            <div className="flex items-center gap-2">
              <button onClick={bulkDeny} disabled={bulkBusy || selected.size === 0}
                className="h-8 px-3 text-[12px] border border-red-500/30 hover:bg-red-500/10 text-red-300 rounded disabled:opacity-40">
                Deny selected
              </button>
              <button onClick={bulkApprove} disabled={bulkBusy || selected.size === 0}
                className="h-8 px-3 text-[12px] bg-emerald-500/15 border border-emerald-500/40 hover:bg-emerald-500/25 text-emerald-300 rounded disabled:opacity-40">
                Approve selected
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function VendorManagement() {
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [stats, setStats] = useState(null);
  const [meta, setMeta] = useState({ categories: [], criticality_levels: [] });
  const [category, setCategory] = useState("");
  const [status, setStatus] = useState("");
  const [band, setBand] = useState("");
  const [q, setQ] = useState("");
  const [showNew, setShowNew] = useState(false);
  const [showApprovalQueue, setShowApprovalQueue] = useState(false);
  const [recomputing, setRecomputing] = useState(false);
  const [selectedIds, setSelectedIds] = useState(new Set());
  const [renewals, setRenewals] = useState([]);

  const loadMeta = async () => {
    const [metaR, statsR, renewalsR] = await Promise.all([
      api.get("/v1/vendors/meta"), api.get("/v1/vendors/stats"), api.get("/v1/vendors/renewals"),
    ]);
    setMeta(metaR.data);
    setStats(statsR.data);
    setRenewals(renewalsR.data.items);
  };

  const loadItems = async () => {
    const params = {};
    if (category) params.category = category;
    if (status) params.status = status;
    if (band) params.band = band;
    if (q) params.q = q;
    const r = await api.get("/v1/vendors", { params });
    setItems(r.data.items);
  };

  useEffect(() => { loadMeta(); }, []);
  useEffect(() => { loadItems(); }, [category, status, band, q]);

  const refreshAll = () => { loadMeta(); loadItems(); };

  const recomputeRisk = async () => {
    setRecomputing(true);
    try {
      const r = await api.post("/v1/vendors/recompute-risk");
      toast.success(`Refreshed risk for ${r.data.vendors_refreshed} vendor(s).`);
      refreshAll();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Recompute failed");
    } finally { setRecomputing(false); }
  };

  const toggleSelect = (id) => {
    setSelectedIds(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };
  const toggleSelectAll = () => {
    setSelectedIds(prev => prev.size === items.length ? new Set() : new Set(items.map(i => i.id)));
  };

  const bulkDelete = async () => {
    if (selectedIds.size === 0) return;
    if (!window.confirm(`Remove ${selectedIds.size} vendor(s)? This also disables compromise monitoring for them.`)) return;
    try {
      const r = await api.post("/v1/vendors/bulk-delete", { ids: [...selectedIds] });
      toast.success(`Removed ${r.data.deleted} vendor(s)`);
      setSelectedIds(new Set());
      refreshAll();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Bulk delete failed");
    }
  };

  const categoryData = stats ? Object.entries(stats.by_category).map(([name, count]) => ({ name, count })) : [];
  const bandData = stats ? ["Critical", "High", "Medium", "Low"].map(b => ({ name: b, count: stats.by_band[b] || 0 })) : [];

  return (
    <Layout title="Vendor & Third-Party Risk" subtitle="Third-party vendors and apps this org depends on &#8212; exposure, criticality, and compromise monitoring"
      actions={
        <div className="flex items-center gap-2">
          <button onClick={() => setShowApprovalQueue(true)}
            className="h-8 px-3 text-[12px] border border-amber-500/30 hover:bg-amber-500/10 text-amber-300 rounded inline-flex items-center gap-1.5">
            <Sparkle size={14} /> Approval queue
          </button>
          <button onClick={recomputeRisk} disabled={recomputing}
            title="Refresh every vendor's cached risk score/asset count/finding count right now, instead of waiting for the nightly sweep"
            className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] text-slate-300 rounded inline-flex items-center gap-1.5 disabled:opacity-50">
            <ArrowsClockwise size={14} className={recomputing ? "animate-spin" : ""} /> {recomputing ? "Recomputing…" : "Recompute risk"}
          </button>
          <button onClick={() => setShowNew(true)}
            className="h-8 px-3 text-[12px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 text-blue-300 rounded inline-flex items-center gap-1.5">
            <Plus size={14} /> Add vendor
          </button>
        </div>
      }>

      {stats && (
        <>
          <div className="grid grid-cols-4 gap-4 mb-4">
            <StatCard label="Total Vendors" value={stats.total_vendors} />
            <StatCard label="Critical / High Risk" value={(stats.by_band.Critical || 0) + (stats.by_band.High || 0)} tone="red" />
            <StatCard label="Top Exposure" value={stats.top_exposure[0]?.name || "—"} sub={stats.top_exposure[0] ? `${stats.top_exposure[0].critical_high_count} crit/high findings` : undefined} tone="amber" />
            <StatCard label="Categories Tracked" value={Object.keys(stats.by_category).length} />
          </div>
          <div className="grid grid-cols-2 gap-4 mb-5">
            <Panel title="Vendors by Category">
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={categoryData} layout="vertical" margin={{ left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262D" horizontal={false} />
                  <XAxis type="number" tick={{ fill: "#8B949E", fontSize: 10 }} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" tick={{ fill: "#8B949E", fontSize: 11 }} width={110} />
                  <Tooltip contentStyle={{ background: "#161B22", border: "1px solid #30363D", fontSize: 12 }} />
                  <Bar dataKey="count" fill="#60a5fa" radius={[0, 3, 3, 0]} cursor="pointer" onClick={(d) => setCategory(category === d.name ? "" : d.name)} />
                </BarChart>
              </ResponsiveContainer>
            </Panel>
            <Panel title="Vendors by Risk Band">
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={bandData} layout="vertical" margin={{ left: 10 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#21262D" horizontal={false} />
                  <XAxis type="number" tick={{ fill: "#8B949E", fontSize: 10 }} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" tick={{ fill: "#8B949E", fontSize: 11 }} width={70} />
                  <Tooltip contentStyle={{ background: "#161B22", border: "1px solid #30363D", fontSize: 12 }} />
                  <Bar dataKey="count" radius={[0, 3, 3, 0]} cursor="pointer" onClick={(d) => setBand(band === d.name ? "" : d.name)}>
                    {bandData.map((d, i) => <Cell key={i} fill={BAND_COLOR[d.name] || "#8B949E"} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </Panel>
          </div>
          {renewals.length > 0 && (
            <div className="mb-5">
            <Panel title="Upcoming Contract Renewals" actions={<CalendarBlank size={13} className="text-slate-500" />}>
              <div className="space-y-1.5">
                {renewals.map(r => (
                  <div key={r.id} onClick={() => navigate(`/vendors/${r.id}`)}
                    className={`flex items-center justify-between px-2.5 py-1.5 rounded border text-[11.5px] cursor-pointer hover:border-blue-500/30 ${r.overdue ? "border-red-500/30 bg-red-500/5" : "border-[#21262D]"}`}>
                    <div className="flex items-center gap-2 min-w-0">
                      <Buildings size={12} className="text-slate-500 shrink-0" />
                      <span className="text-slate-200 truncate">{r.name}</span>
                      {r.overdue && <Warning size={12} className="text-red-400" />}
                      <Chip color="slate">{DPA_LABEL[r.dpa_status] || r.dpa_status}</Chip>
                      <Chip color="slate">{QUESTIONNAIRE_LABEL[r.security_questionnaire_status] || r.security_questionnaire_status}</Chip>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {r.contract_owner && <span className="text-slate-500">{r.contract_owner}</span>}
                      <span className={`font-mono ${r.overdue ? "text-red-300" : "text-slate-400"}`}>
                        {r.overdue ? "Overdue: " : ""}{new Date(r.renewal_date).toLocaleDateString()}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
            </div>
          )}
        </>
      )}

      <div className="flex items-center gap-2 mb-3 flex-wrap">
        <div className="relative">
          <MagnifyingGlass size={13} className="absolute left-2 top-2.5 text-slate-500" />
          <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search name/domain/tags…"
            className="h-8 w-64 bg-[#161B22] border border-[#30363D] rounded pl-7 pr-2.5 text-[12px] text-slate-200" />
        </div>
        <select value={category} onChange={(e) => setCategory(e.target.value)} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-300">
          <option value="">All categories</option>
          {meta.categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <select value={status} onChange={(e) => setStatus(e.target.value)} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-300">
          <option value="">All statuses</option>
          {STATUS_OPTIONS.map(s => <option key={s} value={s}>{STATUS_LABEL[s]}</option>)}
        </select>
        {band && (
          <span className="text-[11px] text-slate-500">Filtered to <span style={{ color: BAND_COLOR[band] }}>{band}</span> risk <button onClick={() => setBand("")} className="text-slate-500 hover:text-slate-300 ml-1">✕</button></span>
        )}
        {selectedIds.size > 0 && (
          <div className="ml-auto flex items-center gap-2 text-[12px]">
            <span className="text-blue-300">{selectedIds.size} selected</span>
            <button onClick={bulkDelete} className="h-7 px-2.5 border border-red-500/30 hover:bg-red-500/10 text-red-300 rounded inline-flex items-center gap-1.5">
              <Trash size={12} /> Remove selected
            </button>
          </div>
        )}
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead>
            <tr>
              <th className="px-3 w-8">
                <button onClick={toggleSelectAll} className="text-slate-500 hover:text-slate-300">
                  {selectedIds.size > 0 && selectedIds.size === items.length ? <CheckSquare size={14} /> : <Square size={14} />}
                </button>
              </th>
              <th className="text-left">Vendor</th><th>Category</th><th>Org Criticality</th>
              <th>Assets</th><th>Findings</th><th>Risk</th><th>Status</th><th>Monitoring</th>
            </tr>
          </thead>
          <tbody>
            {items.map(v => (
              <tr key={v.id} className="border-t border-[#30363D] hover:bg-slate-800/20 cursor-pointer" onClick={() => navigate(`/vendors/${v.id}`)}>
                <td className="px-3" onClick={(e) => { e.stopPropagation(); toggleSelect(v.id); }}>
                  {selectedIds.has(v.id) ? <CheckSquare size={14} className="text-blue-300" /> : <Square size={14} className="text-slate-500" />}
                </td>
                <td className="max-w-[260px]">
                  <div className="flex items-center gap-1.5">
                    <Buildings size={13} className="text-slate-500 shrink-0" />
                    <div className="text-slate-200 truncate">{v.name}</div>
                  </div>
                  {v.domain && <div className="text-[10.5px] text-slate-500 truncate ml-[19px]">{v.domain}</div>}
                </td>
                <td><Chip color="slate">{v.category}</Chip></td>
                <td className="text-center font-mono text-[12px] text-slate-300">{v.org_criticality}</td>
                <td className="text-center font-mono text-[12px] text-slate-400">{v.asset_count}</td>
                <td className="text-center font-mono text-[12px] text-slate-400">{v.finding_count}</td>
                <td><Chip color={BAND_CHIP[v.risk_band] || "slate"}>{v.risk_band} · {v.risk_score}</Chip></td>
                <td><Chip color={STATUS_CHIP[v.status] || "slate"}>{STATUS_LABEL[v.status] || v.status}</Chip></td>
                <td className="text-center">{v.monitoring_enabled ? <Chip color="green">On</Chip> : <span className="text-slate-600 text-[11px]">Off</span>}</td>
              </tr>
            ))}
            {items.length === 0 && (
              <tr><td colSpan={9} className="text-center text-slate-500 py-6 text-[12px]">No vendors match this view. Try &#8220;Approval queue&#8221; to auto-detect vendors from your asset inventory, or &#8220;Add vendor&#8221;.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {showNew && (
        <NewVendorModal meta={meta} onClose={() => setShowNew(false)}
          onCreated={(v) => { setShowNew(false); refreshAll(); navigate(`/vendors/${v.id}`); }} />
      )}
      {showApprovalQueue && (
        <ApprovalQueueModal onClose={() => setShowApprovalQueue(false)}
          onDecided={refreshAll} />
      )}
    </Layout>
  );
}
