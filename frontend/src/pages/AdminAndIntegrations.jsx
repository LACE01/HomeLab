import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { fmtDate, fmtRel } from "@/lib/utils-fmt";
import { CheckCircle, WarningCircle, XCircle, GearSix, Lightning, Info, ArrowsClockwise } from "@phosphor-icons/react";
import { toast } from "sonner";

export function Integrations() {
  const [items, setItems] = useState([]);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState({});
  const [testing, setTesting] = useState(null);
  const [qualysScope, setQualysScope] = useState(null);
  const load = () => api.get("/v1/integrations").then(r => setItems(r.data.items));
  const loadScope = () => api.get("/v1/admin/qualys/scope").then(r => setQualysScope(r.data)).catch(() => setQualysScope(null));
  useEffect(() => { load(); loadScope(); }, []);

  const Icon = ({ s }) =>
    s === "healthy" ? <CheckCircle size={16} className="text-emerald-400"/> :
    s === "degraded" ? <WarningCircle size={16} className="text-amber-400"/> :
    s === "not_configured" ? <GearSix size={16} className="text-slate-500"/> :
    <XCircle size={16} className="text-red-400"/>;

  const sync = async (i) => {
    setTesting(i.id);
    try {
      const r = await api.post(`/v1/admin/qualys/sync/run`);
      const s = r.data?.summary || {};
      toast.success(`${i.name}: +${s.created || 0} new · ↻${s.updated || 0} updated · ${s.detections || 0} detections`);
      await load();
      await loadScope();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Sync failed");
    } finally { setTesting(null); }
  };

  const openEdit = (i) => {
    setEditing(i);
    setForm({
      endpoint: i.config?.endpoint || "",
      api_key: "",  // never prefill — masked
      api_secret: "",
      username: i.config?.username || "",
      auth_type: i.config?.auth_type || "api_key",
      enabled: i.config?.enabled !== false,
    });
  };

  const save = async () => {
    const payload = Object.fromEntries(Object.entries(form).filter(([_,v]) => v !== "" && v !== null && v !== undefined));
    try {
      await api.patch(`/v1/integrations/${editing.id}`, payload);
      toast.success(`${editing.name} configuration saved`);
      setEditing(null); await load();
    } catch (e) { toast.error(e.response?.data?.detail || "Save failed"); }
  };

  const test = async (i) => {
    setTesting(i.id);
    try {
      const r = await api.post(`/v1/integrations/${i.id}/test`);
      toast.success(r.data.message);
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Connection test failed");
      await load();
    } finally { setTesting(null); }
  };

  return (
    <Layout title="Integrations" subtitle="Configure scanner connectors and ticketing systems with your API keys">
      {qualysScope?.configured && qualysScope?.role && (
        <div
          data-testid="qualys-scope-banner"
          className={`mb-4 rounded-md border px-4 py-3 flex items-start gap-3 ${
            qualysScope.is_narrow
              ? "border-amber-500/40 bg-amber-500/10"
              : "border-emerald-500/40 bg-emerald-500/10"
          }`}
        >
          <Info size={18} className={qualysScope.is_narrow ? "text-amber-300 shrink-0 mt-0.5" : "text-emerald-300 shrink-0 mt-0.5"}/>
          <div className="flex-1 min-w-0">
            <div className="text-[12.5px] font-medium text-slate-100">
              Qualys API user{" "}
              <span className="font-mono text-blue-300">{qualysScope.username}</span>{" "}
              · role <span className="font-mono">{qualysScope.role}</span>{" "}
              · {qualysScope.host_count} host{qualysScope.host_count === 1 ? "" : "s"} visible
            </div>
            <div className="text-[11.5px] text-slate-400 mt-0.5 leading-relaxed">
              {qualysScope.is_narrow ? (
                <>
                  Your API user is scoped narrowly (Reader role and/or limited Asset Group membership).
                  The legacy <code className="text-slate-300">/api/2.0/fo/asset/host/vm/detection/</code> only
                  returns detections for the {qualysScope.host_count} host{qualysScope.host_count === 1 ? "" : "s"}
                  {" "}assigned to this user. To pull your full subscription, promote{" "}
                  <span className="font-mono">{qualysScope.username}</span> to <strong>Manager</strong> or
                  <strong> Unit Manager</strong> in Qualys → Users, or add all required Asset Groups.
                </>
              ) : (
                <>API user has full access. Live detections sync at full subscription scope.</>
              )}
            </div>
          </div>
          <button
            data-testid="qualys-scope-refresh"
            onClick={loadScope}
            className="h-7 px-2.5 text-[11px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300 shrink-0"
            title="Re-check role and host count"
          >
            <ArrowsClockwise size={12}/> Re-check
          </button>
        </div>
      )}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {items.map(i => (
          <div key={i.id} data-testid={`integration-${i.id}`} className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="flex items-start justify-between">
              <div>
                <div className="text-[14px] font-medium text-slate-100">{i.name}</div>
                <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider mt-0.5">{i.type}</div>
              </div>
              <Icon s={i.status}/>
            </div>

            <div className="mt-3 space-y-1">
              <div className="flex gap-2 items-center"><span className="text-[10px] font-mono text-slate-500 w-16 uppercase">Endpoint</span><span className="text-[11px] font-mono text-slate-300 truncate flex-1">{i.config?.endpoint || <span className="text-slate-600">not set</span>}</span></div>
              <div className="flex gap-2 items-center"><span className="text-[10px] font-mono text-slate-500 w-16 uppercase">API Key</span><span className="text-[11px] font-mono text-slate-300 truncate flex-1">{i.config?.api_key || <span className="text-slate-600">not set</span>}</span></div>
              <div className="flex gap-2 items-center"><span className="text-[10px] font-mono text-slate-500 w-16 uppercase">Auth</span><span className="text-[11px] font-mono text-slate-300">{i.config?.auth_type || "api_key"}</span></div>
            </div>

            <div className="mt-3 pt-3 border-t border-[#30363D] grid grid-cols-2 gap-2">
              <div><div className="text-[10px] uppercase font-mono text-slate-500">Last Sync</div><div className="text-[11.5px]">{fmtRel(i.last_sync_at)}</div></div>
              <div><div className="text-[10px] uppercase font-mono text-slate-500">Errors</div><div className={`text-[11.5px] font-mono ${i.sync_errors>0?"text-red-300":"text-slate-300"}`}>{i.sync_errors}</div></div>
            </div>

            <div className="mt-3 flex items-center justify-between gap-2">
              <Chip color={
                i.status === "healthy" ? "green" :
                i.status === "degraded" ? "amber" :
                i.status === "not_configured" ? "slate" : "red"
              }>{i.status === "not_configured" ? "not configured" : i.status}</Chip>
              <div className="flex gap-1.5">
                {i.name === "Qualys VMDR" && i.status !== "not_configured" && (
                  <button data-testid={`sync-${i.id}`} disabled={testing===i.id} onClick={()=>sync(i)}
                    className="h-7 px-2.5 text-[11px] bg-emerald-500/15 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-500/25 rounded inline-flex items-center gap-1 disabled:opacity-50">
                    <Lightning size={12}/> {testing===i.id ? "Syncing…" : "Sync now"}
                  </button>
                )}
                <button data-testid={`test-${i.id}`} disabled={testing===i.id} onClick={()=>test(i)}
                  className="h-7 px-2.5 text-[11px] border border-[#30363D] hover:border-emerald-500/50 hover:text-emerald-300 rounded inline-flex items-center gap-1 disabled:opacity-50">
                  <Lightning size={12}/> {testing===i.id ? "Testing…" : "Test"}
                </button>
                <button data-testid={`configure-${i.id}`} onClick={()=>openEdit(i)}
                  className="h-7 px-2.5 text-[11px] bg-blue-500/15 border border-blue-500/40 text-blue-300 hover:bg-blue-500/25 rounded inline-flex items-center gap-1">
                  <GearSix size={12}/> Configure
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {editing && (
        <div data-testid="config-modal" className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4 z-50" onClick={()=>setEditing(null)}>
          <div className="w-full max-w-[520px] border border-[#30363D] bg-[#0D1117] rounded-md" onClick={(e)=>e.stopPropagation()}>
            <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
              <h3 className="text-[14px] font-medium text-slate-100">Configure {editing.name}</h3>
              <button onClick={()=>setEditing(null)} className="text-slate-500 hover:text-slate-200">✕</button>
            </div>
            <div className="p-4 space-y-3">
              <div>
                <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Endpoint URL</label>
                <input data-testid="cfg-endpoint" value={form.endpoint} onChange={(e)=>setForm({...form, endpoint:e.target.value})}
                  placeholder="https://qualysapi.qualys.com" className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200"/>
              </div>
              <div>
                <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Auth Type</label>
                <select value={form.auth_type} onChange={(e)=>setForm({...form, auth_type:e.target.value})}
                  className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200">
                  <option value="api_key">API Key</option>
                  <option value="basic">Basic Auth (user + password)</option>
                  <option value="bearer">Bearer Token</option>
                  <option value="oauth">OAuth</option>
                </select>
              </div>
              {form.auth_type === "basic" && (
                <div>
                  <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Username</label>
                  <input data-testid="cfg-username" value={form.username} onChange={(e)=>setForm({...form, username:e.target.value})}
                    className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200"/>
                </div>
              )}
              <div>
                <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">{form.auth_type === "basic" ? "Password" : "API Key / Token"}</label>
                <input data-testid="cfg-api-key" type="password" value={form.api_key} onChange={(e)=>setForm({...form, api_key:e.target.value})}
                  placeholder={editing.config?.api_key ? "•••••• (leave blank to keep existing)" : "Paste credential"}
                  className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200 font-mono"/>
              </div>
              {(form.auth_type === "oauth") && (
                <div>
                  <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Client Secret</label>
                  <input data-testid="cfg-api-secret" type="password" value={form.api_secret} onChange={(e)=>setForm({...form, api_secret:e.target.value})}
                    className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200 font-mono"/>
                </div>
              )}
              <label className="flex items-center gap-2 text-[12px] text-slate-300">
                <input type="checkbox" checked={form.enabled} onChange={(e)=>setForm({...form, enabled:e.target.checked})}/>
                Enabled (sync will run)
              </label>
              <div className="text-[11px] text-slate-500 leading-relaxed pt-2 border-t border-[#30363D]">
                Credentials are stored encrypted server-side. The API key is masked in list responses (first 4 + last 4 only).
              </div>
            </div>
            <div className="px-4 py-3 border-t border-[#30363D] flex justify-end gap-2">
              <button onClick={()=>setEditing(null)} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
              <button data-testid="cfg-save" onClick={save} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Save</button>
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
}

export function ImportJobs() {
  const [items, setItems] = useState([]);
  useEffect(() => { api.get("/v1/import-jobs").then(r => setItems(r.data.items)); }, []);
  return (
    <Layout title="Ingestion Jobs" subtitle="Recent imports, reimports, and API pushes">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead><tr><th className="text-left">Source</th><th>Mode</th><th>Status</th><th>Created</th><th>Updated</th><th>Dedup</th><th>Failed</th><th>Started</th><th>Duration</th><th>Request ID</th></tr></thead>
          <tbody>
            {items.map(j => (
              <tr key={j.id} className="border-t border-[#30363D] hover:bg-slate-800/30">
                <td className="text-slate-200">{j.source_name}</td>
                <td><Chip>{j.mode}</Chip></td>
                <td><Chip color={j.status === "success" ? "green" : "red"}>{j.status}</Chip></td>
                <td className="font-mono text-emerald-300">+{j.created_count}</td>
                <td className="font-mono text-blue-300">↻{j.updated_count}</td>
                <td className="font-mono text-slate-400">{j.deduplicated_count}</td>
                <td className={`font-mono ${j.failed_count>0?"text-red-300":"text-slate-400"}`}>{j.failed_count}</td>
                <td className="font-mono text-[11px]">{fmtDate(j.started_at)}</td>
                <td className="font-mono text-[11px] text-slate-400">{j.finished_at ? `${Math.round((new Date(j.finished_at)-new Date(j.started_at))/60000)}m` : "—"}</td>
                <td className="font-mono text-[10.5px] text-slate-500">{j.request_id}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}

export function Admin() {
  const [users, setUsers] = useState([]);
  const [keys, setKeys] = useState([]);
  const [sla, setSla] = useState({});
  useEffect(() => {
    api.get("/v1/admin/users").then(r => setUsers(r.data.items)).catch(()=>{});
    api.get("/v1/admin/api-keys").then(r => setKeys(r.data.items)).catch(()=>{});
    api.get("/v1/admin/sla-policies").then(r => setSla(r.data.policies)).catch(()=>{});
  }, []);

  return (
    <Layout title="Administration" subtitle="Users, API keys, SLA policies, scoring rules">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
          <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">Users / RBAC</h3></div>
          <table className="dense w-full">
            <thead><tr><th className="text-left">Email</th><th>Name</th><th>Role</th></tr></thead>
            <tbody>{users.map(u => (
              <tr key={u.id} className="border-t border-[#30363D]"><td className="font-mono text-[11.5px]">{u.email}</td><td>{u.name}</td><td><Chip color={u.role==="admin"?"red":u.role==="manager"?"amber":u.role==="executive"?"blue":"slate"}>{u.role}</Chip></td></tr>
            ))}</tbody>
          </table>
        </div>

        <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
          <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">API Keys</h3></div>
          <table className="dense w-full">
            <thead><tr><th className="text-left">Name</th><th className="text-left">Key</th><th>Active</th></tr></thead>
            <tbody>{keys.map(k => (
              <tr key={k.id} className="border-t border-[#30363D]"><td>{k.name}</td><td className="font-mono text-[11.5px] text-blue-300">{k.key}</td><td><Chip color={k.active?"green":"slate"}>{k.active?"yes":"no"}</Chip></td></tr>
            ))}</tbody>
          </table>
          <div className="px-4 py-2 text-[11px] text-slate-500 border-t border-[#30363D]">Use with header <span className="font-mono text-slate-300">X-API-Key</span> against <span className="font-mono text-slate-300">POST /api/v1/ingest/universal</span></div>
        </div>

        <div className="border border-[#30363D] bg-[#0D1117] rounded-md lg:col-span-2">
          <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">SLA Policies (days to remediate)</h3></div>
          <table className="dense w-full">
            <thead><tr><th className="text-left">Severity</th><th>Crown Jewel</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th></tr></thead>
            <tbody>{Object.entries(sla).map(([sev, days]) => (
              <tr key={sev} className="border-t border-[#30363D]"><td>{sev}</td>
                <td className="font-mono">{days.crown_jewel}</td>
                <td className="font-mono">{days.critical}</td>
                <td className="font-mono">{days.high}</td>
                <td className="font-mono">{days.medium}</td>
                <td className="font-mono">{days.low}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </div>
    </Layout>
  );
}
