import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Plus, X, Trash, PencilSimple, ArrowsClockwise, CalendarX, CheckCircle, XCircle,
  CircleNotch, CaretRight, MagicWand,
} from "@phosphor-icons/react";

const SEVERITY_COLOR = { Critical: "red", High: "red", Medium: "orange" };

function statusChip(t) {
  const latest = t.latest;
  if (!latest) return <Chip color="slate">Not checked yet</Chip>;
  if (latest.error) return <Chip color="red">Check failed</Chip>;
  if (!latest.severity) return <Chip color="green">Supported</Chip>;
  return <Chip color={SEVERITY_COLOR[latest.severity] || "orange"}>{latest.severity}</Chip>;
}

function bucketOf(t) {
  const latest = t.latest;
  if (!latest) return "unchecked";
  if (latest.severity === "Critical" || latest.severity === "High") return "eol";
  if (latest.severity === "Medium") return "upcoming";
  return "healthy";
}

const EMPTY_FORM = { product: "", cycle: "", label: "", enabled: true };

export default function EolTracking() {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState(null);
  const [checkingAll, setCheckingAll] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [checkingIds, setCheckingIds] = useState(new Set());
  const [statusFilter, setStatusFilter] = useState(null); // null | "eol" | "upcoming" | "healthy" | "unchecked"
  const pollRef = useRef(null);

  const load = async () => {
    try {
      const r = await api.get("/v1/admin/eol/targets");
      setTargets(r.data.items || []);
    } catch (e) {
      toast.error("Failed to load EOL watch targets");
    } finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    pollRef.current = setInterval(load, 20000);
    return () => clearInterval(pollRef.current);
  }, []);

  const checkNow = async (t) => {
    setCheckingIds(prev => new Set(prev).add(t.id));
    try {
      await api.post(`/v1/admin/eol/targets/${t.id}/check-now`);
      toast.success(`${t.product} ${t.cycle}: checked`);
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Check failed");
    } finally {
      setCheckingIds(prev => { const n = new Set(prev); n.delete(t.id); return n; });
    }
  };

  const checkAll = async () => {
    setCheckingAll(true);
    try {
      const r = await api.post("/v1/admin/eol/check-all");
      toast.success(`Checked ${r.data.checked} target(s) — ${r.data.issues} with issues`);
      await load();
    } catch (e) {
      toast.error("Bulk check failed");
    } finally { setCheckingAll(false); }
  };

  const scanAssets = async () => {
    setScanning(true);
    try {
      const r = await api.post("/v1/admin/eol/scan-assets");
      toast.success(
        `Scanned ${r.data.assets_scanned} asset(s): ${r.data.os_strings_matched} matched a trackable OS, ` +
        `${r.data.watch_targets_added} new watch target(s) added`
      );
      await load();
    } catch (e) {
      toast.error("Asset scan failed");
    } finally { setScanning(false); }
  };

  const remove = async (t) => {
    if (!window.confirm(`Stop tracking "${t.product} ${t.cycle}"?`)) return;
    try {
      await api.delete(`/v1/admin/eol/targets/${t.id}`);
      toast.success("Removed");
      load();
    } catch (e) {
      toast.error("Delete failed");
    }
  };

  const toggleEnabled = async (t) => {
    try {
      await api.put(`/v1/admin/eol/targets/${t.id}`, { ...t, enabled: !t.enabled });
      load();
    } catch (e) {
      toast.error("Update failed");
    }
  };

  const summary = targets.reduce((acc, t) => {
    acc[bucketOf(t)]++;
    return acc;
  }, { healthy: 0, eol: 0, upcoming: 0, unchecked: 0 });

  const visibleTargets = statusFilter ? targets.filter(t => bucketOf(t) === statusFilter) : targets;

  return (
    <Layout title="End-of-Life Software" subtitle="Tracks OS/software release cycles against endoflife.date -- catches 'this stopped getting security updates' before a CVE scanner ever has to">
      <div className="grid grid-cols-4 gap-3 mb-5">
        {[
          { key: "healthy", label: "Supported", color: "text-emerald-400" },
          { key: "eol", label: "End-of-Life", color: "text-red-400" },
          { key: "upcoming", label: "EOL ≤90d", color: "text-orange-400" },
          { key: "unchecked", label: "Not Checked", color: "text-slate-400" },
        ].map(({ key, label, color }) => (
          <button key={key} onClick={() => setStatusFilter(prev => prev === key ? null : key)}
            className={`text-left border rounded-md px-4 py-3 transition-colors ${
              statusFilter === key ? "border-blue-500/60 bg-blue-500/5" : "border-[#30363D] bg-[#0D1117] hover:border-[#484F58]"
            }`}>
            <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">{label}</div>
            <div className={`text-[22px] font-mono mt-0.5 ${color}`}>{summary[key]}</div>
          </button>
        ))}
      </div>
      {statusFilter && (
        <div className="mb-3 flex items-center gap-2 text-[11.5px] text-slate-400">
          Showing only <span className="text-slate-200 capitalize">{statusFilter}</span> targets.
          <button onClick={() => setStatusFilter(null)} className="text-blue-300 hover:underline">Clear filter</button>
        </div>
      )}

      <div className="flex justify-between items-center mb-3 flex-wrap gap-2">
        <div className="flex gap-2">
          <button onClick={checkAll} disabled={checkingAll}
            className="h-9 px-3.5 text-[12.5px] bg-[#161B22] hover:bg-[#1c232c] disabled:opacity-40 text-slate-200 rounded inline-flex items-center gap-1.5 border border-[#30363D]">
            {checkingAll ? <CircleNotch size={15} className="animate-spin"/> : <ArrowsClockwise size={15}/>} Check all now
          </button>
          <button onClick={scanAssets} disabled={scanning}
            title="Auto-detects Ubuntu/Debian/CentOS/RHEL from your asset inventory's OS field"
            className="h-9 px-3.5 text-[12.5px] bg-[#161B22] hover:bg-[#1c232c] disabled:opacity-40 text-slate-200 rounded inline-flex items-center gap-1.5 border border-[#30363D]">
            {scanning ? <CircleNotch size={15} className="animate-spin"/> : <MagicWand size={15}/>} Scan assets
          </button>
        </div>
        <button onClick={() => { setEditing(null); setModalOpen(true); }}
          className="h-9 px-3.5 text-[12.5px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
          <Plus size={15}/> Watch a product/cycle
        </button>
      </div>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : targets.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          Nothing being tracked yet. Click "Scan assets" to auto-detect Ubuntu/Debian/CentOS/RHEL hosts, or
          "Watch a product/cycle" to add anything else endoflife.date tracks (Windows Server, PostgreSQL, PHP, etc.).
        </div>
      ) : visibleTargets.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No {statusFilter} targets. <button onClick={() => setStatusFilter(null)} className="text-blue-300 hover:underline">Clear filter</button>
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
          {visibleTargets.map(t => (
            <div key={t.id} className="px-4 py-3 flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <CalendarX size={14} className="text-slate-500"/>
                  <span className="text-[13px] text-slate-100 font-mono">{t.product} {t.cycle}</span>
                  {t.label && <span className="text-[11.5px] text-slate-500">{t.label}</span>}
                  {statusChip(t)}
                  {t.source === "auto" && <Chip color="slate">Auto-detected</Chip>}
                  {!t.enabled && <Chip color="slate">Disabled</Chip>}
                </div>
                {t.latest && (
                  <div className="flex items-center gap-3 mt-1.5 text-[11px] text-slate-500 flex-wrap">
                    {t.latest.error ? (
                      <span className="text-red-400">{t.latest.error}</span>
                    ) : (
                      <>
                        <span>EOL: {t.latest.eol === false ? "not set" : t.latest.eol === true ? "yes (no date)" : t.latest.eol}</span>
                        {t.latest.latest && <span>Latest release: {t.latest.latest}</span>}
                        {t.latest.lts && <span className="text-blue-300">LTS</span>}
                      </>
                    )}
                  </div>
                )}
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <button onClick={() => checkNow(t)} disabled={checkingIds.has(t.id)}
                  className="h-8 px-2.5 text-[11.5px] bg-blue-500/10 hover:bg-blue-500/20 disabled:opacity-40 text-blue-300 rounded inline-flex items-center gap-1.5 border border-blue-500/30">
                  {checkingIds.has(t.id) ? <CircleNotch size={12} className="animate-spin"/> : <ArrowsClockwise size={12}/>} Check now
                </button>
                <button onClick={() => toggleEnabled(t)} title={t.enabled ? "Disable" : "Enable"}
                  className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-slate-200 rounded border border-[#30363D]">
                  {t.enabled ? <CheckCircle size={14}/> : <XCircle size={14}/>}
                </button>
                <button onClick={() => { setEditing(t); setModalOpen(true); }}
                  className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-slate-200 rounded border border-[#30363D]">
                  <PencilSimple size={14}/>
                </button>
                <button onClick={() => remove(t)}
                  className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-red-400 rounded border border-[#30363D]">
                  <Trash size={14}/>
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      {modalOpen && (
        <EolTargetModal
          initial={editing || EMPTY_FORM}
          isEdit={!!editing}
          onClose={() => setModalOpen(false)}
          onSaved={() => { setModalOpen(false); load(); }}
        />
      )}
    </Layout>
  );
}

function EolTargetModal({ initial, isEdit, onClose, onSaved }) {
  const [form, setForm] = useState({
    product: initial.product || "", cycle: initial.cycle || "",
    label: initial.label || "", enabled: initial.enabled ?? true,
  });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!form.product.trim() || !form.cycle.trim()) { toast.error("Product and cycle are both required"); return; }
    setSaving(true);
    try {
      if (isEdit) {
        await api.put(`/v1/admin/eol/targets/${initial.id}`, form);
      } else {
        await api.post(`/v1/admin/eol/targets`, form);
      }
      toast.success(isEdit ? "Updated" : "Now tracking this product/cycle");
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Save failed");
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">{isEdit ? "Edit watch target" : "Watch a product/cycle"}</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Product</label>
            <input value={form.product} onChange={e => setForm({ ...form, product: e.target.value })}
              placeholder="e.g. windows-server, postgresql, php"
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100 font-mono"/>
            <div className="text-[10.5px] text-slate-600 mt-1">Exact identifier from endoflife.date -- browse them at endoflife.date to find the right one.</div>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Cycle</label>
            <input value={form.cycle} onChange={e => setForm({ ...form, cycle: e.target.value })}
              placeholder="e.g. 2019, 15, 8.1"
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100 font-mono"/>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Label (optional)</label>
            <input value={form.label} onChange={e => setForm({ ...form, label: e.target.value })}
              placeholder="Primary domain controller" className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"/>
          </div>
        </div>
        <div className="flex justify-end gap-2 px-5 py-3.5 border-t border-[#30363D]">
          <button onClick={onClose} className="h-9 px-3.5 text-[12.5px] text-slate-400 hover:text-slate-200 rounded">Cancel</button>
          <button onClick={save} disabled={saving}
            className="h-9 px-4 text-[12.5px] bg-blue-500 hover:bg-blue-400 disabled:opacity-40 text-white rounded">
            {saving ? "Saving…" : isEdit ? "Save changes" : "Add"}
          </button>
        </div>
      </div>
    </div>
  );
}
