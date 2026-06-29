import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { fmtDate, fmtRel } from "@/lib/utils-fmt";
import { Link } from "react-router-dom";

export function Products() {
  const [items, setItems] = useState([]);
  useEffect(() => { api.get("/v1/products").then(r => setItems(r.data.items)); }, []);
  return (
    <Layout title="Products / Business Services" subtitle="Vulnerability exposure grouped by application portfolio">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {items.map(p => (
          <Link key={p.id} to={`/products/${p.id}`} className="block border border-[#30363D] bg-[#0D1117] rounded-md p-4 hover:border-[#484F58]" data-testid={`product-${p.id}`}>
            <div className="flex items-start justify-between"><div className="text-[14px] font-medium text-slate-100">{p.name}</div><Chip color={p.criticality === "crown_jewel" ? "red" : "orange"}>{p.criticality}</Chip></div>
            <div className="text-[12px] text-slate-500 mt-1">{p.description}</div>
            <div className="text-[11px] text-slate-500 mt-2">Owner: <span className="text-slate-300">{p.business_owner}</span></div>
            <div className="grid grid-cols-3 gap-2 mt-3 pt-3 border-t border-[#30363D]">
              <div><div className="text-[10px] uppercase font-mono text-slate-500">Assets</div><div className="text-[18px] font-mono">{p.asset_count}</div></div>
              <div><div className="text-[10px] uppercase font-mono text-slate-500">Open</div><div className="text-[18px] font-mono">{p.open_findings}</div></div>
              <div><div className="text-[10px] uppercase font-mono text-slate-500">Critical</div><div className="text-[18px] font-mono text-red-300">{p.critical_findings}</div></div>
            </div>
          </Link>
        ))}
      </div>
    </Layout>
  );
}

export function Engagements() {
  const [items, setItems] = useState([]);
  useEffect(() => { api.get("/v1/engagements").then(r => setItems(r.data.items)); }, []);
  return (
    <Layout title="Engagements / Scan Runs" subtitle="Recent scanner executions and import jobs">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead><tr><th className="text-left">Name</th><th>Scanner</th><th>Scan Type</th><th>Method</th><th>Status</th><th>Assets</th><th>Created</th><th>Updated</th><th>Started</th></tr></thead>
          <tbody>
            {items.map(e => (
              <tr key={e.id} className="border-t border-[#30363D] hover:bg-slate-800/30">
                <td className="text-slate-200">{e.name}</td>
                <td className="text-slate-400">{e.scanner}</td>
                <td><Chip>{e.scan_type}</Chip></td>
                <td><Chip>{e.scan_method}</Chip></td>
                <td><Chip color="green">{e.status}</Chip></td>
                <td className="font-mono">{e.assets_scanned}</td>
                <td className="font-mono">{e.findings_created}</td>
                <td className="font-mono">{e.findings_updated}</td>
                <td className="font-mono text-[11px]">{fmtDate(e.started_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}

export function Tickets() {
  const [items, setItems] = useState([]);
  useEffect(() => { api.get("/v1/tickets").then(r => setItems(r.data.items)); }, []);
  return (
    <Layout title="Remediation Tickets" subtitle="External tickets synced from Jira, ServiceNow, GitHub">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead><tr><th className="text-left">Ticket</th><th>System</th><th className="text-left">Title</th><th>Assignee</th><th>Status</th><th>Updated</th></tr></thead>
          <tbody>
            {items.map(t => (
              <tr key={t.id} className="border-t border-[#30363D] hover:bg-slate-800/30">
                <td><a href={t.url} target="_blank" rel="noopener noreferrer" className="font-mono text-blue-300 hover:underline" data-testid={`ticket-${t.id}`}>{t.external_id}</a></td>
                <td>{t.system}</td>
                <td className="max-w-[420px]"><Link to={`/findings/${t.finding_id}`} className="text-slate-200 hover:text-blue-300">{t.title}</Link></td>
                <td className="text-slate-400">{t.assignee}</td>
                <td><Chip color={t.status === "done" ? "green" : "amber"}>{t.status}</Chip></td>
                <td className="font-mono text-[11px] text-slate-400">{fmtRel(t.updated_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}

export function Exceptions() {
  const [items, setItems] = useState([]);
  useEffect(() => { api.get("/v1/exceptions").then(r => setItems(r.data.items)); }, []);
  return (
    <Layout title="Risk Acceptances / Exceptions" subtitle="Findings explicitly accepted with rationale and expiration">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead><tr><th className="text-left">Finding</th><th>Severity</th><th>Asset</th><th className="text-left">Rationale</th><th>Approver</th><th>Approved</th><th>Expires</th></tr></thead>
          <tbody>
            {items.map(e => (
              <tr key={e.id} className="border-t border-[#30363D]">
                <td><Link to={`/findings/${e.finding_id}`} className="text-blue-300 hover:underline">{e.finding_title?.slice(0,50)}</Link><div className="text-[10.5px] text-slate-500 font-mono">{e.cve}</div></td>
                <td><Chip color={e.severity === "Critical" ? "red" : "orange"}>{e.severity}</Chip></td>
                <td className="font-mono text-[11px]">{e.asset_hostname}</td>
                <td className="max-w-[360px] text-slate-300">{e.rationale}<div className="mt-1 flex gap-1 flex-wrap">{(e.compensating_controls||[]).map(c=> <Chip key={c} color="blue">{c}</Chip>)}</div></td>
                <td className="text-slate-400 text-[11px]">{e.approver}</td>
                <td className="font-mono text-[11px]">{fmtDate(e.approved_at)}</td>
                <td className="font-mono text-[11px]">{fmtDate(e.expires_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}
