import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Archive, PlayCircle, CircleNotch, DownloadSimple, CheckCircle, XCircle } from "@phosphor-icons/react";

function fmtDate(iso) {
  return iso ? new Date(iso).toLocaleString() : "Never";
}

export default function DataRetention() {
  const [policies, setPolicies] = useState([]);
  const [runs, setRuns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [runningId, setRunningId] = useState(null);
  const [editingDays, setEditingDays] = useState({});

  const load = async () => {
    try {
      const [p, r] = await Promise.all([
        api.get("/v1/admin/retention/policies"),
        api.get("/v1/admin/retention/runs"),
      ]);
      setPolicies(p.data.items || []);
      setRuns(r.data.items || []);
    } catch (e) {
      toast.error("Failed to load retention policies");
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const toggleEnabled = async (policy) => {
    try {
      await api.patch(`/v1/admin/retention/policies/${policy.id}`, { enabled: !policy.enabled });
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to update policy");
    }
  };

  const saveDays = async (policy) => {
    const days = Number(editingDays[policy.id]);
    if (!days || days < 1) { toast.error("Days must be at least 1"); return; }
    try {
      await api.patch(`/v1/admin/retention/policies/${policy.id}`, { days });
      toast.success(`${policy.label}: retention set to ${days} day(s)`);
      setEditingDays(prev => { const n = { ...prev }; delete n[policy.id]; return n; });
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to update policy");
    }
  };

  const runNow = async (policy) => {
    setRunningId(policy.id);
    try {
      const r = await api.post(`/v1/admin/retention/policies/${policy.id}/run-now`);
      toast.success(r.data.purged_count > 0
        ? `${policy.label}: purged ${r.data.purged_count} record(s), archived before deletion`
        : `${policy.label}: nothing older than the retention window to purge`);
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Purge failed");
    } finally { setRunningId(null); }
  };

  const downloadArchive = async (run) => {
    try {
      const r = await api.get(`/v1/admin/retention/runs/${run.id}/download`, { responseType: "blob" });
      const url = window.URL.createObjectURL(new Blob([r.data]));
      const a = document.createElement("a"); a.href = url; a.download = run.filename; a.click();
      window.URL.revokeObjectURL(url);
    } catch (e) {
      toast.error("Archive file not available for this run");
    }
  };

  if (loading) return <Layout title="Data Retention"><div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div></Layout>;

  return (
    <Layout title="Data Retention & Archival" subtitle="Purges old operational records on a schedule -- every purge archives to a compressed JSON file first, so nothing is silently lost">
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 mb-5 text-[12px] text-blue-200 leading-relaxed max-w-3xl">
        Runs automatically once a day for every enabled policy below. Records are archived to a downloadable file before
        being deleted from the live database. Closed IR cases default to off since those often carry their own legal
        retention requirements -- turn that on deliberately if you want it auto-purged too.
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D] mb-6">
        {policies.map(p => (
          <div key={p.id} className="px-4 py-3.5 flex items-center justify-between gap-3 flex-wrap">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-[13px] text-slate-100">{p.label}</span>
                {!p.enabled && <Chip color="slate">Disabled</Chip>}
              </div>
              <div className="text-[11px] text-slate-500 mt-0.5">
                Last run: {fmtDate(p.last_run_at)}
                {p.last_purged_count != null && ` · ${p.last_purged_count} purged`}
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <input type="number" min={1}
                value={editingDays[p.id] ?? p.days}
                onChange={e => setEditingDays(prev => ({ ...prev, [p.id]: e.target.value }))}
                className="w-16 h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100 text-right"/>
              <span className="text-[11px] text-slate-500">days</span>
              {editingDays[p.id] !== undefined && Number(editingDays[p.id]) !== p.days && (
                <button onClick={() => saveDays(p)} className="h-8 px-2 text-[11px] bg-blue-500 hover:bg-blue-400 text-white rounded">
                  Save
                </button>
              )}
              <button onClick={() => toggleEnabled(p)} title={p.enabled ? "Disable" : "Enable"}
                className="h-8 w-8 flex items-center justify-center text-slate-500 hover:text-slate-200 rounded border border-[#30363D]">
                {p.enabled ? <CheckCircle size={14}/> : <XCircle size={14}/>}
              </button>
              <button onClick={() => runNow(p)} disabled={runningId === p.id}
                className="h-8 px-2.5 text-[11.5px] border border-[#30363D] hover:border-blue-500/50 disabled:opacity-50 text-slate-300 rounded inline-flex items-center gap-1.5">
                {runningId === p.id ? <CircleNotch size={13} className="animate-spin"/> : <PlayCircle size={13}/>}
                Run now
              </button>
            </div>
          </div>
        ))}
      </div>

      <div className="text-[13.5px] text-slate-100 font-medium mb-3">Recent purge runs</div>
      {runs.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-8 text-center text-[12.5px] text-slate-500">
          No purge runs yet.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
          {runs.map(r => (
            <div key={r.id} className="px-4 py-2.5 flex items-center justify-between gap-3">
              <div className="min-w-0 flex items-center gap-2">
                <Archive size={13} className="text-slate-500 shrink-0"/>
                <div className="min-w-0">
                  <span className="text-[12px] text-slate-200">{r.policy_label}</span>
                  <span className="text-[11px] text-slate-500 ml-2">{r.purged_count} purged · {fmtDate(r.run_at)} · {r.triggered_by}</span>
                </div>
              </div>
              {r.archived && r.filename ? (
                <button onClick={() => downloadArchive(r)}
                  className="h-7 px-2 text-[11px] border border-[#30363D] hover:border-blue-500/50 text-slate-300 rounded inline-flex items-center gap-1 shrink-0">
                  <DownloadSimple size={12}/> Archive
                </button>
              ) : (
                <span className="text-[11px] text-slate-600 shrink-0">No archive</span>
              )}
            </div>
          ))}
        </div>
      )}
    </Layout>
  );
}
