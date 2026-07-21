import { useEffect, useRef, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Plus, X, Trash, PencilSimple, ArrowsClockwise, At, CheckCircle, XCircle,
  WarningCircle, CircleNotch, CaretRight,
} from "@phosphor-icons/react";

const SEVERITY_COLOR = { High: "red", Medium: "orange", Low: "amber" };

function worstSeverity(issues) {
  if (!issues || !issues.length) return null;
  if (issues.some(i => i.severity === "High")) return "High";
  if (issues.some(i => i.severity === "Medium")) return "Medium";
  return "Low";
}

function statusChip(t) {
  const latest = t.latest;
  if (!latest) return <Chip color="slate">Not checked yet</Chip>;
  const worst = worstSeverity(latest.issues);
  if (!worst) return <Chip color="green">Healthy</Chip>;
  return <Chip color={SEVERITY_COLOR[worst]}>{latest.issues.length} issue{latest.issues.length > 1 ? "s" : ""}</Chip>;
}

// Which bucket a single target falls into -- drives both the summary stat
// cards and the "click a card to filter" behavior below, kept in lockstep.
function bucketOf(t) {
  const latest = t.latest;
  if (!latest) return "unchecked";
  const worst = worstSeverity(latest.issues);
  if (worst === "High") return "high";
  if (worst) return "other"; // Medium or Low
  return "healthy";
}

const EMPTY_FORM = { domain: "", label: "", enabled: true };

export default function EmailAuthMonitoring() {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState(null);
  const [checkingAll, setCheckingAll] = useState(false);
  const [checkingIds, setCheckingIds] = useState(new Set());
  const [detailTargetId, setDetailTargetId] = useState(null);
  const [statusFilter, setStatusFilter] = useState(null); // null | "healthy" | "high" | "other" | "unchecked"
  const pollRef = useRef(null);
  const detailTarget = targets.find(t => t.id === detailTargetId) || null;

  const load = async () => {
    try {
      const r = await api.get("/v1/admin/email-auth/targets");
      setTargets(r.data.items || []);
    } catch (e) {
      toast.error("Failed to load domain watch targets");
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
      await api.post(`/v1/admin/email-auth/targets/${t.id}/check-now`);
      toast.success(`${t.domain}: checked`);
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
      const r = await api.post("/v1/admin/email-auth/check-all");
      toast.success(`Checked ${r.data.checked} domain(s) — ${r.data.issues} with issues`);
      await load();
    } catch (e) {
      toast.error("Bulk check failed");
    } finally { setCheckingAll(false); }
  };

  const remove = async (t) => {
    if (!window.confirm(`Stop monitoring "${t.domain}"?`)) return;
    try {
      await api.delete(`/v1/admin/email-auth/targets/${t.id}`);
      toast.success("Removed");
      load();
    } catch (e) {
      toast.error("Delete failed");
    }
  };

  const toggleEnabled = async (t) => {
    try {
      await api.put(`/v1/admin/email-auth/targets/${t.id}`, { ...t, enabled: !t.enabled });
      load();
    } catch (e) {
      toast.error("Update failed");
    }
  };

  const summary = targets.reduce((acc, t) => {
    acc[bucketOf(t)]++;
    return acc;
  }, { healthy: 0, high: 0, other: 0, unchecked: 0 });

  const visibleTargets = statusFilter ? targets.filter(t => bucketOf(t) === statusFilter) : targets;

  return (
    <Layout title="Email Authentication" subtitle="Tracks SPF, DKIM, and DMARC across your mail-sending domains — the first line of defense against phishing that spoofs your name">
      <div className="grid grid-cols-4 gap-3 mb-5">
        {[
          { key: "healthy", label: "Healthy", color: "text-emerald-400" },
          { key: "high", label: "High Severity", color: "text-red-400" },
          { key: "other", label: "Medium/Low Issues", color: "text-orange-400" },
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
          Showing only <span className="text-slate-200 capitalize">{statusFilter}</span> domains.
          <button onClick={() => setStatusFilter(null)} className="text-blue-300 hover:underline">Clear filter</button>
        </div>
      )}

      <div className="flex justify-between items-center mb-3 flex-wrap gap-2">
        <button onClick={checkAll} disabled={checkingAll}
          className="h-9 px-3.5 text-[12.5px] bg-[#161B22] hover:bg-[#1c232c] disabled:opacity-40 text-slate-200 rounded inline-flex items-center gap-1.5 border border-[#30363D]">
          {checkingAll ? <CircleNotch size={15} className="animate-spin"/> : <ArrowsClockwise size={15}/>} Check all now
        </button>
        <button onClick={() => { setEditing(null); setModalOpen(true); }}
          className="h-9 px-3.5 text-[12.5px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
          <Plus size={15}/> Watch a domain
        </button>
      </div>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : targets.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No domains being watched yet. Add a mail-sending domain to check its SPF/DKIM/DMARC posture.
        </div>
      ) : visibleTargets.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No {statusFilter} domains. <button onClick={() => setStatusFilter(null)} className="text-blue-300 hover:underline">Clear filter</button>
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
          {visibleTargets.map(t => (
            <div key={t.id} onClick={() => setDetailTargetId(t.id)}
              className="px-4 py-3 flex items-start justify-between gap-3 cursor-pointer hover:bg-[#161B22] transition-colors">
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <At size={14} className="text-slate-500"/>
                  <span className="text-[13px] text-slate-100 font-mono">{t.domain}</span>
                  {t.label && <span className="text-[11.5px] text-slate-500">{t.label}</span>}
                  {statusChip(t)}
                  {!t.enabled && <Chip color="slate">Disabled</Chip>}
                </div>
                {t.latest && (
                  <div className="flex items-center gap-3 mt-1.5 text-[11px] text-slate-500 flex-wrap">
                    <span className={t.latest.spf?.present ? "text-emerald-400" : "text-red-400"}>SPF {t.latest.spf?.present ? "present" : "missing"}</span>
                    <span className={t.latest.dmarc?.present ? "text-emerald-400" : "text-red-400"}>
                      DMARC {t.latest.dmarc?.present ? `p=${t.latest.dmarc.policy || "?"}` : "missing"}
                    </span>
                    <span className={t.latest.dkim?.found_selectors?.length ? "text-emerald-400" : "text-slate-500"}>
                      DKIM {t.latest.dkim?.found_selectors?.length ? "detected" : "not detected"}
                    </span>
                  </div>
                )}
              </div>
              <div className="flex items-center gap-1.5 shrink-0" onClick={e => e.stopPropagation()}>
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
                <CaretRight size={14} className="text-slate-600 ml-1"/>
              </div>
            </div>
          ))}
        </div>
      )}

      {modalOpen && (
        <DomainTargetModal
          initial={editing || EMPTY_FORM}
          isEdit={!!editing}
          onClose={() => setModalOpen(false)}
          onSaved={() => { setModalOpen(false); load(); }}
        />
      )}

      {detailTarget && (
        <DomainDetailModal target={detailTarget} onClose={() => setDetailTargetId(null)}
          onCheckNow={() => checkNow(detailTarget)} checking={checkingIds.has(detailTarget.id)}/>
      )}
    </Layout>
  );
}

function DetailRow({ label, value, mono }) {
  return (
    <div className="flex justify-between gap-3 py-1.5 border-b border-[#30363D]/50 last:border-0">
      <div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 shrink-0">{label}</div>
      <div className={`text-[12px] text-slate-200 text-right break-all ${mono ? "font-mono" : ""}`}>{value ?? "—"}</div>
    </div>
  );
}

function CheckSection({ title, ok, children }) {
  return (
    <div className="mb-4">
      <div className="flex items-center gap-1.5 mb-1.5">
        {ok ? <CheckCircle size={13} className="text-emerald-400"/> : <WarningCircle size={13} className="text-amber-400"/>}
        <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400">{title}</div>
      </div>
      {children}
    </div>
  );
}

function DomainDetailModal({ target, onClose, onCheckNow, checking }) {
  const c = target.latest;
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-lg max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div>
            <div className="text-[14px] text-slate-100 font-medium font-mono">{target.domain}</div>
            {target.label && <div className="text-[11px] text-slate-500">{target.label}</div>}
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5">
          <div className="flex items-center justify-between mb-3">
            {statusChip(target)}
            <button onClick={onCheckNow} disabled={checking}
              className="h-7 px-2.5 text-[11px] bg-blue-500/10 hover:bg-blue-500/20 disabled:opacity-40 text-blue-300 rounded inline-flex items-center gap-1.5 border border-blue-500/30">
              {checking ? <CircleNotch size={12} className="animate-spin"/> : <ArrowsClockwise size={12}/>} Check now
            </button>
          </div>

          {!c ? (
            <div className="text-[12px] text-slate-500 py-4 text-center">Not checked yet — click "Check now" above.</div>
          ) : (
            <div>
              <CheckSection title="SPF" ok={c.spf?.present}>
                <DetailRow label="Present" value={c.spf?.present ? "Yes" : "No"}/>
                <DetailRow label="Record" value={c.spf?.record} mono/>
                <DetailRow label="Record Count" value={c.spf?.record_count}/>
                <DetailRow label="All Mechanism" value={c.spf?.all_mechanism} mono/>
              </CheckSection>

              <CheckSection title="DMARC" ok={c.dmarc?.present && c.dmarc?.policy !== "none"}>
                <DetailRow label="Present" value={c.dmarc?.present ? "Yes" : "No"}/>
                <DetailRow label="Record" value={c.dmarc?.record} mono/>
                <DetailRow label="Policy" value={c.dmarc?.policy} mono/>
                <DetailRow label="Reporting (rua)" value={c.dmarc?.rua} mono/>
              </CheckSection>

              <CheckSection title="DKIM (best-effort)" ok={!!c.dkim?.found_selectors?.length}>
                <DetailRow label="Selectors Found" value={c.dkim?.found_selectors?.length ? c.dkim.found_selectors.join(", ") : "None"} mono/>
                <div className="text-[10.5px] text-slate-600 mt-1">
                  Checked {c.dkim?.checked_selectors?.length || 0} common selector name(s) — a nonstandard selector wouldn't be detected by this check.
                </div>
              </CheckSection>

              {c.issues?.length > 0 && (
                <div>
                  <div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Issues</div>
                  <div className="space-y-2">
                    {c.issues.map((i, idx) => (
                      <div key={idx} className={`border rounded-md px-3 py-2 text-[11.5px] ${
                        i.severity === "High" ? "border-red-500/30 bg-red-500/5 text-red-300"
                        : i.severity === "Medium" ? "border-orange-500/30 bg-orange-500/5 text-orange-300"
                        : "border-amber-500/30 bg-amber-500/5 text-amber-300"
                      }`}>
                        <span className="font-mono uppercase text-[10px] mr-1.5">[{i.check}/{i.severity}]</span>{i.reason}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="text-[10.5px] text-slate-600 mt-3">Last checked {c.checked_at && new Date(c.checked_at).toLocaleString()}</div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function DomainTargetModal({ initial, isEdit, onClose, onSaved }) {
  const [form, setForm] = useState({
    domain: initial.domain || "", label: initial.label || "", enabled: initial.enabled ?? true,
  });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!form.domain.trim()) { toast.error("Domain is required"); return; }
    setSaving(true);
    try {
      if (isEdit) {
        await api.put(`/v1/admin/email-auth/targets/${initial.id}`, form);
      } else {
        await api.post(`/v1/admin/email-auth/targets`, form);
      }
      toast.success(isEdit ? "Updated" : "Now watching this domain");
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Save failed");
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-md" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">{isEdit ? "Edit watch target" : "Watch a domain"}</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Domain</label>
            <input value={form.domain} onChange={e => setForm({ ...form, domain: e.target.value })}
              placeholder="example.com" className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100 font-mono"/>
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Label (optional)</label>
            <input value={form.label} onChange={e => setForm({ ...form, label: e.target.value })}
              placeholder="Primary mail domain" className="w-full h-9 bg-[#161B22] border border-[#30363D] rounded px-3 text-[12.5px] text-slate-100"/>
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
