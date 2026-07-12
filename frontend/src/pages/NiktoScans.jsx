import { useEffect, useState, useRef } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Plus, X, Trash, PencilSimple, Play, Clock, ShieldWarning, CheckCircle,
  XCircle, CircleNotch, ArrowSquareOut, Globe,
} from "@phosphor-icons/react";

const SCHEDULE_PRESETS = [
  { label: "Manual only", hours: 0 },
  { label: "Every 6 hours", hours: 6 },
  { label: "Daily", hours: 24 },
  { label: "Weekly", hours: 168 },
];

const EMPTY_FORM = {
  name: "", target_url: "", schedule_hours: 0, enabled: true, authorized: false,
  tuning: "", timeout_sec: 600,
};

export default function NiktoScans() {
  const [configs, setConfigs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState(null);
  const [runningIds, setRunningIds] = useState(new Set());
  const pollRef = useRef(null);

  const load = async () => {
    try {
      const r = await api.get("/v1/admin/nikto/configs");
      setConfigs(r.data.items || []);
    } catch (e) {
      toast.error("Failed to load web scan targets");
    } finally { setLoading(false); }
  };

  useEffect(() => {
    load();
    pollRef.current = setInterval(load, 8000);
    return () => clearInterval(pollRef.current);
  }, []);

  const runNow = async (cfg) => {
    setRunningIds(prev => new Set(prev).add(cfg.id));
    try {
      await api.post(`/v1/admin/nikto/configs/${cfg.id}/run-now`);
      toast.success(`${cfg.name}: scan started — this can take a few minutes`);
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to start scan");
    } finally {
      setRunningIds(prev => { const n = new Set(prev); n.delete(cfg.id); return n; });
    }
  };

  // A timed-out scan is a dead end otherwise -- the config keeps whatever timeout_sec
  // it had, and re-running "as is" would just time out again. This bumps the stored
  // timeout (doubled, floored at 900s, capped at the 7200s server-side max) before
  // kicking off another run, so retrying an actually-slow target's scan can succeed
  // without the admin having to go find the edit form themselves.
  const retryWithLongerTimeout = async (cfg) => {
    const nextTimeout = Math.min(7200, Math.max(900, (cfg.timeout_sec || 600) * 2));
    setRunningIds(prev => new Set(prev).add(cfg.id));
    try {
      await api.put(`/v1/admin/nikto/configs/${cfg.id}`, { ...cfg, timeout_sec: nextTimeout });
      await api.post(`/v1/admin/nikto/configs/${cfg.id}/run-now`);
      toast.success(`${cfg.name}: retrying with a ${nextTimeout}s timeout`);
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to retry scan");
    } finally {
      setRunningIds(prev => { const n = new Set(prev); n.delete(cfg.id); return n; });
    }
  };

  const remove = async (cfg) => {
    if (!window.confirm(`Delete web scan target "${cfg.name}"?`)) return;
    try {
      await api.delete(`/v1/admin/nikto/configs/${cfg.id}`);
      toast.success("Deleted");
      load();
    } catch (e) {
      toast.error("Delete failed");
    }
  };

  const toggleEnabled = async (cfg) => {
    try {
      await api.put(`/v1/admin/nikto/configs/${cfg.id}`, { ...cfg, enabled: !cfg.enabled });
      load();
    } catch (e) {
      toast.error("Update failed");
    }
  };

  return (
    <Layout title="Web App Scans" subtitle="Nikto scans against your own web applications — on-demand or on a schedule">
      <div className="border border-orange-500/30 bg-orange-500/5 rounded-md px-3 py-2.5 mb-4 text-[12px] text-orange-200 leading-relaxed flex items-start gap-2 max-w-3xl">
        <ShieldWarning size={16} className="shrink-0 mt-0.5"/>
        <div>
          VulnOps will originate real HTTP requests against whatever URL you configure. Only scan applications
          you're authorized to test — every target requires you to confirm that explicitly. Only one scan runs
          at a time, whether triggered manually or by schedule.
        </div>
      </div>

      <div className="flex justify-end mb-3">
        <button onClick={() => { setEditing(null); setModalOpen(true); }}
          className="h-9 px-3.5 text-[12.5px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
          <Plus size={15}/> New web scan target
        </button>
      </div>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : configs.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No web scan targets yet. Add one to scan an application on demand or on a schedule.
        </div>
      ) : (
        <div className="space-y-2.5">
          {configs.map(cfg => (
            <ScanConfigRow
              key={cfg.id}
              cfg={cfg}
              running={runningIds.has(cfg.id) || cfg.status === "running"}
              onRun={() => runNow(cfg)}
              onEdit={() => { setEditing(cfg); setModalOpen(true); }}
              onDelete={() => remove(cfg)}
              onToggle={() => toggleEnabled(cfg)}
              onRetryLonger={() => retryWithLongerTimeout(cfg)}
            />
          ))}
        </div>
      )}

      {modalOpen && (
        <ScanConfigModal
          initial={editing || EMPTY_FORM}
          isEdit={!!editing}
          onClose={() => setModalOpen(false)}
          onSaved={() => { setModalOpen(false); load(); }}
        />
      )}
    </Layout>
  );
}

function ScanConfigRow({ cfg, running, onRun, onEdit, onDelete, onToggle, onRetryLonger }) {
  const [resultOpen, setResultOpen] = useState(false);
  const scheduleLabel = cfg.schedule_hours === 0
    ? "Manual only"
    : SCHEDULE_PRESETS.find(p => p.hours === cfg.schedule_hours)?.label || `Every ${cfg.schedule_hours}h`;
  const result = cfg.last_result;

  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3.5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[13.5px] text-slate-100 font-medium">{cfg.name}</span>
            {cfg.tuning && <Chip color="purple">Tuning: {cfg.tuning}</Chip>}
            {!cfg.enabled && <Chip color="slate">Disabled</Chip>}
            {running && (
              <span className="inline-flex items-center gap-1 text-[11px] text-blue-300">
                <CircleNotch size={12} className="animate-spin"/> Running…
              </span>
            )}
          </div>
          <div className="text-[11.5px] text-slate-500 font-mono mt-1 truncate flex items-center gap-1.5">
            <Globe size={12}/> {cfg.target_url}
          </div>
          <div className="flex items-center gap-3 mt-1.5 text-[11px] text-slate-500">
            <span className="inline-flex items-center gap-1"><Clock size={12}/> {scheduleLabel}</span>
            {cfg.last_run_at && <span>Last run: {new Date(cfg.last_run_at).toLocaleString()}</span>}
          </div>
          {result && (
            <div className="mt-2 text-[11.5px]">
              {result.ok === false ? (
                <button onClick={() => setResultOpen(true)} className="inline-flex items-center gap-1.5 text-red-400 hover:underline">
                  <XCircle size={13}/> {result.error || "Scan failed"}
                </button>
              ) : (
                <button onClick={() => setResultOpen(true)} className="inline-flex items-center gap-1.5 text-emerald-400 hover:underline">
                  <CheckCircle size={13}/>
                  {result.issues_found} issue(s) found · {result.findings_created} new finding(s)
                </button>
              )}
            </div>
          )}
          {resultOpen && (
            <ScanResultModal cfg={cfg} result={result} onClose={() => setResultOpen(false)}
              onRetryLonger={() => { setResultOpen(false); onRetryLonger(); }}/>
          )}
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <button onClick={onRun} disabled={running}
            className="h-8 px-2.5 text-[11.5px] bg-blue-500/10 hover:bg-blue-500/20 disabled:opacity-40 text-blue-300 rounded inline-flex items-center gap-1.5 border border-blue-500/30">
            <Play size={13}/> Run now
          </button>
          <button onClick={onToggle} title={cfg.enabled ? "Disable schedule" : "Enable schedule"}
            className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-slate-200 rounded border border-[#30363D]">
            {cfg.enabled ? <CheckCircle size={14}/> : <XCircle size={14}/>}
          </button>
          <button onClick={onEdit} className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-slate-200 rounded border border-[#30363D]">
            <PencilSimple size={14}/>
          </button>
          <button onClick={onDelete} className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-red-400 rounded border border-[#30363D]">
            <Trash size={14}/>
          </button>
        </div>
      </div>
    </div>
  );
}

function ScanResultModal({ cfg, result, onClose, onRetryLonger }) {
  // Nikto's own kill message (nikto_scan.py's TimeoutError) always looks like
  // "Nikto scan exceeded <N>s and was killed: <argv>" -- detect that specific shape
  // so a timed-out scan gets a clear explanation and a one-click retry instead of a
  // dead-end raw error/command dump.
  const isTimeout = result?.ok === false && /exceeded \d+s and was killed/.test(result.error || "");
  const nextTimeout = Math.min(7200, Math.max(900, (cfg.timeout_sec || 600) * 2));

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-lg max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">Scan result — {cfg.name}</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-4">
          {result?.ok === false && isTimeout ? (
            <div>
              <div className="border border-amber-500/30 bg-amber-500/5 rounded-md px-3 py-2.5 text-[12.5px] text-amber-200 mb-3">
                This scan didn't finish within its {cfg.timeout_sec}s timeout and was stopped — that's a safety
                limit, not necessarily a problem with the target. Larger sites or a broad tuning spec can
                legitimately take longer than the default.
              </div>
              <button onClick={onRetryLonger}
                className="h-9 px-3 text-[12.5px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
                <Play size={13}/> Retry with a {nextTimeout}s timeout
              </button>
              <details className="mt-3 text-[11px] text-slate-500">
                <summary className="cursor-pointer hover:text-slate-300">Show raw error</summary>
                <div className="mt-1.5 font-mono break-all">{result.error}</div>
              </details>
            </div>
          ) : result?.ok === false ? (
            <div className="border border-red-500/30 bg-red-500/5 rounded-md px-3 py-2.5 text-[12px] text-red-300">
              {result.error || "Scan failed"}
            </div>
          ) : (
            <div>
              <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">
                {result?.issues_found ?? 0} issue(s) · {result?.distinct_issue_types ?? 0} distinct type(s) · {result?.findings_created ?? 0} new finding(s)
              </div>
              {result?.asset_id && (
                <Link to={`/assets/${result.asset_id}`}
                  className="flex items-center justify-between gap-3 px-3 py-2.5 border border-[#30363D] rounded-md hover:bg-[#161B22] transition-colors">
                  <div className="text-[12.5px] text-slate-200 font-mono truncate">{result.hostname}</div>
                  <ArrowSquareOut size={14} className="text-slate-500 shrink-0"/>
                </Link>
              )}
              <div className="text-[11px] text-slate-500 mt-2">
                Findings this scan didn't create new duplicates for (already-open findings from a prior scan of
                the same issue) still count toward "issue(s) found" above but not "new finding(s)".
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function ScanConfigModal({ initial, isEdit, onClose, onSaved }) {
  const [form, setForm] = useState({ ...EMPTY_FORM, ...initial });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!form.name.trim()) { toast.error("Name is required"); return; }
    if (!form.target_url.trim()) { toast.error("Target URL is required"); return; }
    if (!form.authorized) { toast.error("You must confirm you're authorized to scan this target"); return; }
    setSaving(true);
    try {
      const body = { ...form, timeout_sec: Number(form.timeout_sec) || 600, tuning: form.tuning?.trim() || null };
      if (isEdit) await api.put(`/v1/admin/nikto/configs/${initial.id}`, body);
      else await api.post("/v1/admin/nikto/configs", body);
      toast.success(isEdit ? "Target updated" : "Target created");
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Save failed");
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-lg" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">{isEdit ? "Edit web scan target" : "New web scan target"}</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-3.5">
          <div>
            <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Name</label>
            <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
              placeholder="e.g. Customer portal (prod)"
              className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200"/>
          </div>
          <div>
            <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Target URL</label>
            <input value={form.target_url} onChange={e => setForm({ ...form, target_url: e.target.value })}
              placeholder="https://app.example.com"
              className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200 font-mono"/>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Schedule</label>
              <select value={form.schedule_hours} onChange={e => setForm({ ...form, schedule_hours: Number(e.target.value) })}
                className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200">
                {SCHEDULE_PRESETS.map(p => <option key={p.hours} value={p.hours}>{p.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Timeout (sec)</label>
              <input type="number" min={30} max={3600} value={form.timeout_sec}
                onChange={e => setForm({ ...form, timeout_sec: e.target.value })}
                className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200"/>
            </div>
          </div>
          <div>
            <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Tuning (optional)</label>
            <input value={form.tuning || ""} onChange={e => setForm({ ...form, tuning: e.target.value })}
              placeholder="e.g. 1259bcx — leave blank to run all default checks"
              className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200 font-mono"/>
            <div className="text-[10.5px] text-slate-500 mt-1">Nikto's -Tuning codes let you narrow which check categories run. Leave blank for the default full sweep.</div>
          </div>
          <label className="flex items-start gap-2 text-[12px] text-slate-300 pt-1">
            <input type="checkbox" checked={form.authorized} onChange={e => setForm({ ...form, authorized: e.target.checked })} className="mt-0.5"/>
            <span>I'm authorized to run active scans against this target — VulnOps will send real HTTP requests to it.</span>
          </label>
        </div>
        <div className="px-5 py-3.5 border-t border-[#30363D] flex justify-end gap-2">
          <button onClick={onClose} className="h-9 px-3.5 text-[12.5px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={save} disabled={saving}
            className="h-9 px-3.5 text-[12.5px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}
