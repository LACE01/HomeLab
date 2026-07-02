import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Plus, X, Trash, PencilSimple, ArrowsClockwise, Certificate, CheckCircle, XCircle,
  WarningCircle, LockKeyOpen, CircleNotch, MagicWand,
} from "@phosphor-icons/react";

function daysLabel(days) {
  if (days == null) return "—";
  if (days < 0) return `Expired ${Math.abs(days)}d ago`;
  if (days === 0) return "Expires today";
  return `${days}d left`;
}

function statusChip(t) {
  const latest = t.latest;
  if (!latest) return <Chip color="slate">Not checked yet</Chip>;
  if (latest.reachable === false) return <Chip color="red">Unreachable</Chip>;
  const d = latest.days_until_expiry;
  if (d == null) return <Chip color="slate">Unknown</Chip>;
  if (d < 0) return <Chip color="red">Expired</Chip>;
  if (d <= 7) return <Chip color="red">Expires in {d}d</Chip>;
  if (d <= 30) return <Chip color="orange">Expires in {d}d</Chip>;
  if (!latest.trust_valid) return <Chip color="amber">Untrusted</Chip>;
  return <Chip color="green">Healthy</Chip>;
}

const EMPTY_FORM = { hostname: "", port: 443, label: "", enabled: true };

export default function TlsCerts() {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState(null);
  const [checkingAll, setCheckingAll] = useState(false);
  const [checkingIds, setCheckingIds] = useState(new Set());
  const pollRef = useRef(null);

  const load = async () => {
    try {
      const r = await api.get("/v1/admin/certs/targets");
      setTargets(r.data.items || []);
    } catch (e) {
      toast.error("Failed to load certificate targets");
    } finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    pollRef.current = setInterval(load, 15000);
    return () => clearInterval(pollRef.current);
  }, []);

  const checkNow = async (t) => {
    setCheckingIds(prev => new Set(prev).add(t.id));
    try {
      await api.post(`/v1/admin/certs/targets/${t.id}/check-now`);
      toast.success(`${t.hostname}: checked`);
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
      const r = await api.post("/v1/admin/certs/check-all");
      toast.success(`Checked ${r.data.checked} target(s) — ${r.data.issues} with issues`);
      await load();
    } catch (e) {
      toast.error("Bulk check failed");
    } finally { setCheckingAll(false); }
  };

  const importInternetFacing = async () => {
    try {
      const r = await api.post("/v1/admin/certs/targets/import-internet-facing");
      toast.success(r.data.added > 0 ? `Added ${r.data.added} internet-facing asset(s)` : "No new internet-facing assets to add");
      load();
    } catch (e) {
      toast.error("Import failed");
    }
  };

  const remove = async (t) => {
    if (!window.confirm(`Stop monitoring "${t.hostname}:${t.port}"?`)) return;
    try {
      await api.delete(`/v1/admin/certs/targets/${t.id}`);
      toast.success("Removed");
      load();
    } catch (e) {
      toast.error("Delete failed");
    }
  };

  const toggleEnabled = async (t) => {
    try {
      await api.put(`/v1/admin/certs/targets/${t.id}`, { ...t, enabled: !t.enabled });
      load();
    } catch (e) {
      toast.error("Update failed");
    }
  };

  const summary = targets.reduce((acc, t) => {
    const d = t.latest?.days_until_expiry;
    if (t.latest?.reachable === false) acc.unreachable++;
    else if (d != null && d < 0) acc.expired++;
    else if (d != null && d <= 30) acc.expiring++;
    else if (t.latest) acc.healthy++;
    return acc;
  }, { expired: 0, expiring: 0, unreachable: 0, healthy: 0 });

  return (
    <Layout title="TLS Certificates" subtitle="Tracks certificate expiry across your internet-facing services — catches the outage before the calendar does">
      <div className="grid grid-cols-4 gap-3 mb-5">
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3">
          <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Healthy</div>
          <div className="text-[22px] text-emerald-400 font-mono mt-0.5">{summary.healthy}</div>
        </div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3">
          <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Expiring ≤30d</div>
          <div className="text-[22px] text-orange-400 font-mono mt-0.5">{summary.expiring}</div>
        </div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3">
          <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Expired</div>
          <div className="text-[22px] text-red-400 font-mono mt-0.5">{summary.expired}</div>
        </div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3">
          <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Unreachable</div>
          <div className="text-[22px] text-slate-400 font-mono mt-0.5">{summary.unreachable}</div>
        </div>
      </div>

      <div className="flex justify-between items-center mb-3 flex-wrap gap-2">
        <div className="flex gap-2">
          <button onClick={checkAll} disabled={checkingAll}
            className="h-9 px-3.5 text-[12.5px] bg-[#161B22] hover:bg-[#1c232c] disabled:opacity-40 text-slate-200 rounded inline-flex items-center gap-1.5 border border-[#30363D]">
            {checkingAll ? <CircleNotch size={15} className="animate-spin"/> : <ArrowsClockwise size={15}/>} Check all now
          </button>
          <button onClick={importInternetFacing}
            className="h-9 px-3.5 text-[12.5px] bg-[#161B22] hover:bg-[#1c232c] text-slate-200 rounded inline-flex items-center gap-1.5 border border-[#30363D]">
            <MagicWand size={15}/> Import internet-facing assets
          </button>
        </div>
        <button onClick={() => { setEditing(null); setModalOpen(true); }}
          className="h-9 px-3.5 text-[12.5px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
          <Plus size={15}/> Watch a hostname
        </button>
      </div>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : targets.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No certificates being watched yet. Add a hostname or import your internet-facing assets.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
          {targets.map(t => (
            <div key={t.id} className="px-4 py-3 flex items-start justify-between gap-3">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <Certificate size={14} className="text-slate-500"/>
                  <span className="text-[13px] text-slate-100 font-mono">{t.hostname}:{t.port}</span>
                  {t.label && <span className="text-[11.5px] text-slate-500">{t.label}</span>}
                  {statusChip(t)}
                  {!t.enabled && <Chip color="slate">Disabled</Chip>}
                </div>
                {t.latest && (
                  <div className="flex items-center gap-3 mt-1.5 text-[11px] text-slate-500 flex-wrap">
                    {t.latest.reachable === false ? (
                      <span className="text-red-400 inline-flex items-center gap-1"><WarningCircle size={12}/> {t.latest.error}</span>
                    ) : (
                      <>
                        <span>{daysLabel(t.latest.days_until_expiry)}</span>
                        <span>Issuer: {t.latest.issuer}</span>
                        {t.latest.self_signed && <span className="inline-flex items-center gap-1 text-amber-400"><LockKeyOpen size={12}/> Self-signed</span>}
                        {t.latest.trust_valid ? (
                          <span className="inline-flex items-center gap-1 text-emerald-400"><CheckCircle size={12}/> Trusted</span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-amber-400"><XCircle size={12}/> Not trusted</span>
                        )}
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
        <CertTargetModal
          initial={editing || EMPTY_FORM}
          isEdit={!!editing}
          onClose={() => setModalOpen(false)}
          onSaved={() => { setModalOpen(false); load(); }}
        />
      )}
    </Layout>
  );
}

function CertTargetModal({ initial, isEdit, onClose, onSaved }) {
  const [form, setForm] = useState({
    hostname: initial.hostname || "", port: initial.port ?? 443,
    label: initial.label || "", enabled: initial.enabled ?? true,
  });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!form.hostname.trim()) { toast.error("Hostname is required"); return; }
    setSaving(true);
    try {
      if (isEdit) {
        await api.put(`/v1/admin/certs/targets/${initial.id}`, form);
      } else {
        await api.post(`/v1/admin/certs/targets`, form);
      }
      toast.success(isEdit ? "Updated" : "Now watching this hostname");
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Save failed");
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">{isEdit ? "Edit watch target" : "Watch a hostname"}</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Hostname</label>
            <input value={form.hostname} onChange={e => setForm({ ...form, hostname: e.target.value })}
              placeholder="app.example.com" className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100 font-mono"/>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Port</label>
            <input type="number" value={form.port} onChange={e => setForm({ ...form, port: parseInt(e.target.value, 10) || 443 })}
              className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100 font-mono"/>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Label (optional)</label>
            <input value={form.label} onChange={e => setForm({ ...form, label: e.target.value })}
              placeholder="Customer portal" className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"/>
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
