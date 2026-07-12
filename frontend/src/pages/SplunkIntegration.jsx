import { useEffect, useState, useRef } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Plus, X, Trash, PencilSimple, Play, Clock, CheckCircle,
  XCircle, CircleNotch, Database, Siren,
} from "@phosphor-icons/react";

const SCHEDULE_PRESETS = [
  { label: "Manual only", minutes: 0 },
  { label: "Every 5 minutes", minutes: 5 },
  { label: "Every 15 minutes", minutes: 15 },
  { label: "Hourly", minutes: 60 },
  { label: "Every 6 hours", minutes: 360 },
];

const EMPTY_FORM = {
  name: "", endpoint: "", token: "", search: "", schedule_minutes: 0,
  enabled: true, verify_ssl: true, timeout_sec: 60,
};

export default function SplunkIntegration() {
  const [configs, setConfigs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [modalOpen, setModalOpen] = useState(false);
  const [editing, setEditing] = useState(null);
  const [runningIds, setRunningIds] = useState(new Set());
  const pollRef = useRef(null);

  const load = async () => {
    try {
      const r = await api.get("/v1/admin/splunk/configs");
      setConfigs(r.data.items || []);
    } catch (e) {
      toast.error("Failed to load Splunk connections");
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
      await api.post(`/v1/admin/splunk/configs/${cfg.id}/run-now`);
      toast.success(`${cfg.name}: search started`);
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to start search");
    } finally {
      setRunningIds(prev => { const n = new Set(prev); n.delete(cfg.id); return n; });
    }
  };

  const remove = async (cfg) => {
    if (!window.confirm(`Remove Splunk connection "${cfg.name}"?`)) return;
    await api.delete(`/v1/admin/splunk/configs/${cfg.id}`);
    toast.success("Removed");
    load();
  };

  const toggleEnabled = async (cfg) => {
    await api.put(`/v1/admin/splunk/configs/${cfg.id}`, { ...cfg, enabled: !cfg.enabled });
    load();
  };

  return (
    <Layout title="Splunk" subtitle="Poll a saved SPL search on a schedule and feed matches into Security Alerts"
      actions={
        <button onClick={() => { setEditing(null); setModalOpen(true); }}
          className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
          <Plus size={14}/> Add connection
        </button>
      }>
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 mb-4 text-[12px] text-blue-200 leading-relaxed max-w-3xl">
        Pull-based: VulnOps calls out to Splunk's REST API on the schedule below and normalizes each matching result
        row into a Security Alert -- Splunk never needs to reach in to this app. Uses the "oneshot" search export
        endpoint, so keep the search scoped to a bounded time window (e.g. <span className="font-mono">earliest=-15m</span>).
      </div>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : configs.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No Splunk connections yet. Add one to pull search results into Security Alerts.
        </div>
      ) : (
        <div className="space-y-2.5">
          {configs.map(cfg => (
            <ConfigRow key={cfg.id} cfg={cfg} running={runningIds.has(cfg.id) || cfg.status === "running"}
              onRun={() => runNow(cfg)} onEdit={() => { setEditing(cfg); setModalOpen(true); }}
              onDelete={() => remove(cfg)} onToggle={() => toggleEnabled(cfg)}/>
          ))}
        </div>
      )}

      {modalOpen && (
        <ConfigModal initial={editing || EMPTY_FORM} isEdit={!!editing}
          onClose={() => setModalOpen(false)} onSaved={() => { setModalOpen(false); load(); }}/>
      )}
    </Layout>
  );
}

function ConfigRow({ cfg, running, onRun, onEdit, onDelete, onToggle }) {
  const [resultOpen, setResultOpen] = useState(false);
  const scheduleLabel = cfg.schedule_minutes === 0
    ? "Manual only"
    : SCHEDULE_PRESETS.find(p => p.minutes === cfg.schedule_minutes)?.label || `Every ${cfg.schedule_minutes}min`;
  const result = cfg.last_result;

  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3.5">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-[13.5px] text-slate-100 font-medium">{cfg.name}</span>
            {!cfg.enabled && <Chip color="slate">Disabled</Chip>}
            {running && (
              <span className="inline-flex items-center gap-1 text-[11px] text-blue-300">
                <CircleNotch size={12} className="animate-spin"/> Running…
              </span>
            )}
          </div>
          <div className="text-[11.5px] text-slate-500 font-mono mt-1 truncate flex items-center gap-1.5">
            <Database size={12}/> {cfg.endpoint}
          </div>
          <div className="text-[11px] text-slate-600 font-mono mt-1 truncate">{cfg.search}</div>
          <div className="flex items-center gap-3 mt-1.5 text-[11px] text-slate-500">
            <span className="inline-flex items-center gap-1"><Clock size={12}/> {scheduleLabel}</span>
            {cfg.last_run_at && <span>Last run: {new Date(cfg.last_run_at).toLocaleString()}</span>}
          </div>
          {result && (
            <div className="mt-2 text-[11.5px]">
              {result.ok === false ? (
                <button onClick={() => setResultOpen(true)} className="inline-flex items-center gap-1.5 text-red-400 hover:underline">
                  <XCircle size={13}/> {result.error || "Sync failed"}
                </button>
              ) : (
                <span className="inline-flex items-center gap-1.5 text-emerald-400">
                  <CheckCircle size={13}/> {result.rows_seen} row(s) · {result.events_created} alert(s) created/updated
                  {result.events_created > 0 && (
                    <Link to="/alerts" className="text-blue-300 hover:underline inline-flex items-center gap-0.5 ml-1">
                      <Siren size={11}/> view
                    </Link>
                  )}
                </span>
              )}
            </div>
          )}
          {resultOpen && (
            <div className="mt-2 text-[11px] text-slate-500 font-mono break-all border-t border-[#30363D] pt-2">
              {result.error}
              <button onClick={() => setResultOpen(false)} className="ml-2 text-slate-400 hover:text-slate-200">close</button>
            </div>
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

function ConfigModal({ initial, isEdit, onClose, onSaved }) {
  const [form, setForm] = useState({ ...EMPTY_FORM, ...initial, token: "" });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!form.name.trim()) { toast.error("Name is required"); return; }
    if (!form.endpoint.trim()) { toast.error("Endpoint is required"); return; }
    if (!form.search.trim()) { toast.error("Search query is required"); return; }
    if (!isEdit && !form.token.trim()) { toast.error("An auth token is required"); return; }
    setSaving(true);
    try {
      if (isEdit) await api.put(`/v1/admin/splunk/configs/${initial.id}`, form);
      else await api.post("/v1/admin/splunk/configs", form);
      toast.success(isEdit ? "Connection updated" : "Connection added");
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to save");
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-lg max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] text-slate-100 font-medium">{isEdit ? "Edit" : "Add"} Splunk connection</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-3.5">
          <div>
            <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Name</label>
            <input value={form.name} onChange={e=>setForm({...form, name: e.target.value})}
              className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100"/>
          </div>
          <div>
            <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Endpoint</label>
            <input value={form.endpoint} onChange={e=>setForm({...form, endpoint: e.target.value})}
              placeholder="https://splunk.example.com:8089"
              className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100 font-mono"/>
          </div>
          <div>
            <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Auth Token</label>
            <input type="password" value={form.token} onChange={e=>setForm({...form, token: e.target.value})}
              placeholder={isEdit ? "Leave blank to keep existing" : "Splunk API token"}
              className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100 font-mono"/>
          </div>
          <div>
            <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Search (SPL)</label>
            <textarea value={form.search} onChange={e=>setForm({...form, search: e.target.value})} rows={3}
              placeholder="index=security sourcetype=auth action=failure earliest=-15m"
              className="w-full mt-1 px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100 font-mono"/>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Schedule</label>
              <select value={form.schedule_minutes} onChange={e=>setForm({...form, schedule_minutes: Number(e.target.value)})}
                className="w-full mt-1 h-9 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200">
                {SCHEDULE_PRESETS.map(p => <option key={p.minutes} value={p.minutes}>{p.label}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">Timeout (sec)</label>
              <input type="number" value={form.timeout_sec} onChange={e=>setForm({...form, timeout_sec: Number(e.target.value)})}
                min={5} max={300}
                className="w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[13px] text-slate-100"/>
            </div>
          </div>
          <label className="flex items-center gap-2 text-[12px] text-slate-300">
            <input type="checkbox" checked={form.verify_ssl} onChange={e=>setForm({...form, verify_ssl: e.target.checked})}/>
            Verify TLS certificate
          </label>
        </div>
        <div className="flex justify-end gap-2 px-5 py-3.5 border-t border-[#30363D]">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={save} disabled={saving}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}
