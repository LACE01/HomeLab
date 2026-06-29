import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { fmtDate, fmtRel } from "@/lib/utils-fmt";
import { CheckCircle, WarningCircle, XCircle } from "@phosphor-icons/react";

export function Integrations() {
  const [items, setItems] = useState([]);
  useEffect(() => { api.get("/v1/integrations").then(r => setItems(r.data.items)); }, []);
  const Icon = ({ s }) => s === "healthy" ? <CheckCircle size={16} className="text-emerald-400"/> : s === "degraded" ? <WarningCircle size={16} className="text-amber-400"/> : <XCircle size={16} className="text-red-400"/>;
  return (
    <Layout title="Integrations" subtitle="Connector health and synchronization status">
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
            <div className="mt-3 text-[11px] text-slate-500 font-mono">{i.config?.endpoint}</div>
            <div className="mt-3 pt-3 border-t border-[#30363D] grid grid-cols-2 gap-2">
              <div><div className="text-[10px] uppercase font-mono text-slate-500">Last Sync</div><div className="text-[11.5px]">{fmtRel(i.last_sync_at)}</div></div>
              <div><div className="text-[10px] uppercase font-mono text-slate-500">Errors</div><div className={`text-[11.5px] font-mono ${i.sync_errors>0?"text-red-300":"text-slate-300"}`}>{i.sync_errors}</div></div>
            </div>
            <div className="mt-2"><Chip color={i.status === "healthy" ? "green" : i.status === "degraded" ? "amber" : "red"}>{i.status}</Chip></div>
          </div>
        ))}
      </div>
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

export function Reports() {
  const dl = async (path, filename) => {
    const r = await api.get(path, { responseType: "blob" });
    const url = URL.createObjectURL(r.data);
    const a = document.createElement("a"); a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  };
  const Card = ({ title, desc, action, testid }) => (
    <div data-testid={testid} className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
      <div className="text-[14px] font-medium text-slate-100">{title}</div>
      <div className="text-[12px] text-slate-500 mt-1 mb-3">{desc}</div>
      {action}
    </div>
  );
  return (
    <Layout title="Reports" subtitle="Branded executive PDFs, technical CSV exports, and host reports">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        <Card title="Executive PDF" desc="Score, narrative, product breakdown, drivers. Suitable for board reporting."
          testid="rpt-exec-pdf"
          action={<button data-testid="dl-exec-pdf" onClick={()=>dl("/v1/reports/pdf/executive", "executive-report.pdf")} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Download PDF</button>}/>
        <Card title="All Findings CSV" desc="Full export of every finding with risk, asset, owner, and SLA fields."
          testid="rpt-findings-csv"
          action={<button data-testid="dl-findings-csv" onClick={()=>dl("/v1/reports/csv/findings", "findings.csv")} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Download CSV</button>}/>
        <Card title="Critical Findings CSV" desc="Filtered export of Critical-severity findings only."
          testid="rpt-critical-csv"
          action={<button data-testid="dl-critical-csv" onClick={()=>dl("/v1/reports/csv/findings?severity=Critical", "critical-findings.csv")} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Download CSV</button>}/>
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
