import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { fmtDate, fmtRel } from "@/lib/utils-fmt";
import { CheckCircle, WarningCircle, XCircle, GearSix, Lightning, Info, ArrowsClockwise, Eye, EyeSlash, Trash, Plus, Warning, ShieldCheck, Target, Bug } from "@phosphor-icons/react";
import { toast } from "sonner";

export function Integrations() {
  const [items, setItems] = useState([]);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState({});
  const [testing, setTesting] = useState(null);
  const [qualysScope, setQualysScope] = useState(null);
  const [tiStatus, setTiStatus] = useState(null);
  const [tiSyncing, setTiSyncing] = useState(null);
  const load = () => api.get("/v1/integrations").then(r => setItems(r.data.items));
  const loadScope = () => api.get("/v1/admin/qualys/scope").then(r => setQualysScope(r.data)).catch(() => setQualysScope(null));
  const loadTi = () => api.get("/v1/admin/threat-intel/status").then(r => setTiStatus(r.data)).catch(() => setTiStatus(null));
  useEffect(() => { load(); loadScope(); loadTi(); }, []);

  const syncFeed = async (feed) => {
    setTiSyncing(feed);
    try {
      const r = await api.post(`/v1/admin/enrich/${feed}`);
      if (r.data.status === "failed") toast.error(`${feed.toUpperCase()} sync failed: ${r.data.error || "unknown error"}`);
      else toast.success(`${feed.toUpperCase()} sync complete.`);
      await loadTi();
    } catch (e) {
      toast.error(e.response?.data?.detail || `${feed} sync failed`);
    } finally { setTiSyncing(null); }
  };

  const Icon = ({ s }) =>
    s === "healthy" ? <CheckCircle size={16} className="text-emerald-400"/> :
    s === "degraded" ? <WarningCircle size={16} className="text-amber-400"/> :
    s === "not_configured" ? <GearSix size={16} className="text-slate-500"/> :
    <XCircle size={16} className="text-red-400"/>;

  const sync = async (i) => {
    setTesting(i.id);
    let toastId;
    try {
      const r = await api.post(`/v1/admin/qualys/sync/run`);
      // Sync now runs async — poll until the latest run completes
      toastId = toast.loading(`${i.name}: sync started — pulling detections…`);
      const startId = r.data?.id;
      const startedAt = Date.now();
      const MAX_MS = 10 * 60 * 1000; // 10 min cap
      while (Date.now() - startedAt < MAX_MS) {
        await new Promise(res => setTimeout(res, 4000));
        const runs = await api.get("/v1/admin/qualys/sync/runs");
        const latest = (runs.data?.items || [])[0];
        // Stop when we see a completed run that's newer than ours OR the same one finished
        if (latest && latest.status !== "running" && latest.id !== startId) {
          const s = latest.summary || {};
          const autoClosed = s.auto_closed?.auto_closed || 0;
          toast.success(
            `${i.name}: +${s.created || 0} new · ↻${s.updated || 0} updated · ${s.detections || 0} detections` +
            (autoClosed ? ` · ${autoClosed} auto-closed (Qualys confirmed fixed)` : ""),
            { id: toastId }
          );
          // Hardware/last-logged-in-user enrichment (GAV/CSAM) is a separate, best-effort,
          // separately-licensed Qualys module -- surfaced as its own info/success toast so
          // a licensing gap there never looks like the main sync failed.
          if (s.asset_inventory_error) {
            toast(`Asset hardware/last-logged-in-user sync skipped: ${s.asset_inventory_error}`, { duration: 10000 });
          } else if (s.asset_inventory?.assets_enriched) {
            toast.success(`Hardware + last-logged-in-user data updated for ${s.asset_inventory.assets_enriched} asset(s).`);
          }
          break;
        }
        if (latest && latest.id === startId && latest.status === "failed") {
          toast.error(`${i.name}: sync failed — ${latest.errors?.[0]?.error || "unknown error"}`, { id: toastId });
          break;
        }
      }
      await load();
      await loadScope();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Sync failed to start", { id: toastId });
    } finally { setTesting(null); }
  };

  // Connectors with real (non-Qualys) sync jobs wired up -- see backend
  // routes/integrations.py's _dispatch_sync for the full list.
  const GENERIC_SYNC_CONNECTORS = ["Shodan", "Censys"];
  const syncGeneric = async (i) => {
    setTesting(i.id);
    try {
      const r = await api.post(`/v1/integrations/${i.id}/sync`);
      const res = r.data?.result || {};
      toast.success(`${i.name}: checked ${res.assets_checked ?? 0} asset(s), enriched ${res.assets_enriched ?? 0}.`);
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || `${i.name} sync failed`);
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
      cf_access_client_id: i.config?.cf_access_client_id || "",
      cf_access_client_secret: "",
    });
  };

  const save = async () => {
    // Trim whitespace client-side too -- a copy-pasted CF-Access token with a
    // trailing newline looks identical in the input box but won't match on
    // Cloudflare's side, and the token will just sit at "not seen" forever.
    const trimmed = Object.fromEntries(Object.entries(form).map(([k, v]) => [k, typeof v === "string" ? v.trim() : v]));
    const payload = Object.fromEntries(Object.entries(trimmed).filter(([_,v]) => v !== "" && v !== null && v !== undefined));
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
      <div className="mb-4 border border-[#30363D] bg-[#0D1117] rounded-md p-4">
        <div className="flex items-center justify-between mb-3">
          <div>
            <div className="text-[13.5px] font-medium text-slate-100">Threat Intel Feeds</div>
            <div className="text-[11px] text-slate-500 mt-0.5">
              Always-on enrichers (no credentials needed) that run automatically every 12h.
              {tiStatus?.last_run_at ? <> Last full pass: {fmtRel(tiStatus.last_run_at)}.</> : " Haven't run yet on this deployment."}
            </div>
          </div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div className="border border-[#30363D] rounded p-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-[12.5px] text-slate-200"><ShieldCheck size={15} className="text-red-400"/> CISA KEV</div>
              <button disabled={tiSyncing==="kev"} onClick={()=>syncFeed("kev")}
                className="h-6 px-2 text-[10.5px] border border-[#30363D] hover:border-emerald-500/50 hover:text-emerald-300 rounded disabled:opacity-50">
                {tiSyncing==="kev" ? "Syncing…" : "Sync now"}
              </button>
            </div>
            <div className="text-[11px] text-slate-500 mt-2">
              {tiStatus?.kev?.findings_flagged ?? 0} finding(s) flagged actively-exploited
              {tiStatus?.kev?.catalog_size ? ` · catalog: ${tiStatus.kev.catalog_size} CVEs` : ""}
            </div>
            {tiStatus?.kev?.error && <div className="text-[10.5px] text-red-400 mt-1">{tiStatus.kev.error}</div>}
          </div>
          <div className="border border-[#30363D] rounded p-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-[12.5px] text-slate-200"><Target size={15} className="text-amber-400"/> EPSS</div>
              <button disabled={tiSyncing==="epss"} onClick={()=>syncFeed("epss")}
                className="h-6 px-2 text-[10.5px] border border-[#30363D] hover:border-emerald-500/50 hover:text-emerald-300 rounded disabled:opacity-50">
                {tiSyncing==="epss" ? "Syncing…" : "Sync now"}
              </button>
            </div>
            <div className="text-[11px] text-slate-500 mt-2">{tiStatus?.epss?.findings_scored ?? 0} finding(s) scored</div>
            {tiStatus?.epss?.error && <div className="text-[10.5px] text-red-400 mt-1">{tiStatus.epss.error}</div>}
            {tiStatus?.epss?.last_result?.chunk_errors?.length > 0 && (
              <div className="text-[10.5px] text-amber-400 mt-1">
                {tiStatus.epss.last_result.chunk_errors.length} of {tiStatus.epss.last_result.lookups} request(s) to FIRST.org failed: {tiStatus.epss.last_result.chunk_errors[0]}
              </div>
            )}
          </div>
          <div className="border border-[#30363D] rounded p-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-[12.5px] text-slate-200"><Bug size={15} className="text-violet-400"/> Exploit-DB</div>
              <button disabled={tiSyncing==="exploitdb"} onClick={()=>syncFeed("exploitdb")}
                className="h-6 px-2 text-[10.5px] border border-[#30363D] hover:border-emerald-500/50 hover:text-emerald-300 rounded disabled:opacity-50">
                {tiSyncing==="exploitdb" ? "Syncing…" : "Sync now"}
              </button>
            </div>
            <div className="text-[11px] text-slate-500 mt-2">
              {tiStatus?.exploitdb?.findings_with_exploits ?? 0} finding(s) with a public PoC
              {tiStatus?.exploitdb?.catalog_cves ? ` · catalog: ${tiStatus.exploitdb.catalog_cves} CVEs` : ""}
            </div>
            {tiStatus?.exploitdb?.error && <div className="text-[10.5px] text-red-400 mt-1">{tiStatus.exploitdb.error}</div>}
          </div>
        </div>
      </div>

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
              {i.name === "OpenCTI" && (
                <div className="flex gap-2 items-center">
                  <span className="text-[10px] font-mono text-slate-500 w-16 uppercase">CF-Access</span>
                  <span className={`text-[11px] font-mono ${i.config?.cf_access_client_id ? "text-emerald-400" : "text-slate-600"}`}>
                    {i.config?.cf_access_client_id ? `configured (...${i.config.cf_access_client_id.slice(-14)})` : "not set — required if OpenCTI sits behind Cloudflare Access"}
                  </span>
                </div>
              )}
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
                {GENERIC_SYNC_CONNECTORS.includes(i.name) && i.status !== "not_configured" && (
                  <button data-testid={`sync-${i.id}`} disabled={testing===i.id} onClick={()=>syncGeneric(i)}
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
              {editing.name === "OpenCTI" && (
                <div className="border-t border-[#30363D] pt-3 mt-1 space-y-3" data-testid="cfg-cf-section">
                  <div className="text-[11px] uppercase font-mono text-slate-400 tracking-wider inline-flex items-center gap-2">
                    Cloudflare Access Service Token
                    <span className="text-[10px] normal-case text-slate-500 font-sans">(only needed if /graphql is behind CF Access)</span>
                  </div>
                  <div>
                    <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">CF-Access-Client-Id</label>
                    <input data-testid="cfg-cf-id" value={form.cf_access_client_id} onChange={(e)=>setForm({...form, cf_access_client_id:e.target.value})}
                      placeholder="e.g. 0f94f6dc….access"
                      className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200 font-mono"/>
                  </div>
                  <div>
                    <label className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">CF-Access-Client-Secret</label>
                    <input data-testid="cfg-cf-secret" type="password" value={form.cf_access_client_secret} onChange={(e)=>setForm({...form, cf_access_client_secret:e.target.value})}
                      placeholder={editing.config?.cf_access_client_secret ? "•••••• (leave blank to keep existing)" : "Paste service-token secret"}
                      className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200 font-mono"/>
                  </div>
                  <div className="text-[10.5px] text-slate-500 leading-relaxed">
                    ⚠ After saving, you MUST add the same service token as an "Include" rule on the CF Access application policy for <span className="font-mono text-slate-300">open.smrtlab.net</span>. Otherwise CF still redirects API calls to the login page.
                  </div>
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
  const [revealedKeys, setRevealedKeys] = useState(new Set());

  const loadKeys = () => api.get("/v1/admin/api-keys").then(r => setKeys(r.data.items)).catch(()=>{});

  useEffect(() => {
    api.get("/v1/admin/users").then(r => setUsers(r.data.items)).catch(()=>{});
    loadKeys();
    api.get("/v1/admin/sla-policies").then(r => setSla(r.data.policies)).catch(()=>{});
  }, []);

  const toggleReveal = (id) => setRevealedKeys(prev => {
    const next = new Set(prev);
    next.has(id) ? next.delete(id) : next.add(id);
    return next;
  });

  const createKey = async () => {
    const name = window.prompt("Name for this key (e.g. 'Splunk ingest')", "Ingestion Key");
    if (!name) return;
    try { await api.post("/v1/admin/api-keys", { name }); toast.success("Key created"); loadKeys(); }
    catch (e) { toast.error(e.response?.data?.detail || "Failed to create key"); }
  };

  const regenerateKey = async (k) => {
    if (!window.confirm(`Regenerate "${k.name}"? Anything using the old value will stop working immediately.`)) return;
    try { await api.post(`/v1/admin/api-keys/${k.id}/regenerate`); toast.success("Key regenerated"); setRevealedKeys(prev => new Set(prev).add(k.id)); loadKeys(); }
    catch (e) { toast.error("Failed to regenerate"); }
  };

  const deleteKey = async (k) => {
    if (!window.confirm(`Delete "${k.name}"? Anything using it will stop working immediately.`)) return;
    try { await api.delete(`/v1/admin/api-keys/${k.id}`); toast.success("Deleted"); loadKeys(); }
    catch (e) { toast.error("Failed to delete"); }
  };

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
          <div className="px-4 py-2 border-b border-[#30363D] flex items-center justify-between">
            <h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">API Keys</h3>
            <button onClick={createKey} className="h-6 px-2 text-[10.5px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 text-blue-300 rounded inline-flex items-center gap-1">
              <Plus size={11}/> New key
            </button>
          </div>
          <table className="dense w-full">
            <thead><tr><th className="text-left">Name</th><th className="text-left">Key</th><th>Active</th><th></th></tr></thead>
            <tbody>{keys.map(k => (
              <tr key={k.id} className="border-t border-[#30363D]">
                <td>
                  {k.name}
                  {k.is_known_demo_value && (
                    <div title="This key's value is a hardcoded string from an older version of this app that shipped in the public repo source -- anyone can find it. Regenerate it before relying on this endpoint."
                      className="inline-flex items-center gap-1 text-amber-400 ml-1.5"><Warning size={11}/></div>
                  )}
                </td>
                <td className="font-mono text-[11.5px] text-blue-300">
                  <span className="inline-flex items-center gap-1.5">
                    {revealedKeys.has(k.id) ? k.key : `${k.key.slice(0, 12)}${"•".repeat(12)}`}
                    <button onClick={() => toggleReveal(k.id)} className="text-slate-500 hover:text-slate-300">
                      {revealedKeys.has(k.id) ? <EyeSlash size={12}/> : <Eye size={12}/>}
                    </button>
                  </span>
                </td>
                <td><Chip color={k.active?"green":"slate"}>{k.active?"yes":"no"}</Chip></td>
                <td>
                  <div className="flex items-center gap-1 justify-end">
                    <button onClick={() => regenerateKey(k)} title="Regenerate" className="text-slate-500 hover:text-slate-200"><ArrowsClockwise size={13}/></button>
                    <button onClick={() => deleteKey(k)} title="Delete" className="text-slate-500 hover:text-red-400"><Trash size={13}/></button>
                  </div>
                </td>
              </tr>
            ))}</tbody>
          </table>
          <div className="px-4 py-2 text-[11px] text-slate-500 border-t border-[#30363D]">
            Used by external tools pushing findings directly (not by any built-in scanner connector — Qualys/Nmap/SBOM/EASM
            have their own auth). Send it as header <span className="font-mono text-slate-300">X-API-Key</span> against{" "}
            <span className="font-mono text-slate-300">POST /api/v1/ingest/universal</span>.
          </div>
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
