import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { SevBadge, Chip, RiskBar } from "@/components/Badges";
import { fmtDate, fmtRel, isOverdue } from "@/lib/utils-fmt";
import { MagnifyingGlass, ArrowLeft } from "@phosphor-icons/react";

export function Assets() {
  const [items, setItems] = useState([]);
  const [q, setQ] = useState("");
  const [criticality, setCriticality] = useState("");
  useEffect(() => {
    const params = {};
    if (q) params.q = q; if (criticality) params.criticality = criticality;
    api.get("/v1/assets", { params }).then(r => setItems(r.data.items));
  }, [criticality]);
  return (
    <Layout title="Assets" subtitle="Hosts, cloud resources, repositories, and devices under management">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md mb-3 px-3 py-2 flex gap-2 items-center">
        <div className="flex items-center gap-1.5 bg-[#161B22] border border-[#30363D] rounded px-2 h-8 flex-1 min-w-[200px]">
          <MagnifyingGlass size={14} className="text-slate-500" />
          <input data-testid="assets-search" value={q} onChange={(e)=>setQ(e.target.value)} onKeyDown={(e)=>e.key==='Enter'&&api.get("/v1/assets",{params:{q,criticality}}).then(r=>setItems(r.data.items))}
            placeholder="hostname, IP, or FQDN…" className="bg-transparent flex-1 outline-none text-[12.5px] text-slate-200"/>
        </div>
        <select data-testid="assets-criticality" value={criticality} onChange={(e)=>setCriticality(e.target.value)} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px]">
          <option value="">All criticalities</option>
          {["crown_jewel","critical","high","medium","low"].map(s => <option key={s}>{s}</option>)}
        </select>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table data-testid="assets-table" className="dense w-full">
          <thead><tr>
            <th className="text-left">Hostname</th><th className="text-left">IP</th>
            <th className="text-left">Type</th><th className="text-left">Env</th>
            <th className="text-left">Criticality</th><th className="text-left">Exposure</th>
            <th className="text-left">Owner Team</th><th className="text-right">Open Findings</th>
            <th className="text-right">Critical</th><th className="text-left">Ownership</th>
          </tr></thead>
          <tbody>
            {items.map(a => (
              <tr key={a.id} className="border-t border-[#30363D] hover:bg-slate-800/30">
                <td><Link to={`/assets/${a.id}`} data-testid={`asset-${a.id}`} className="text-blue-300 hover:underline font-mono text-[12px]">{a.hostname}</Link></td>
                <td className="font-mono text-[11.5px] text-slate-400">{a.ip || "—"}</td>
                <td className="text-slate-400 text-[11.5px]">{a.asset_type}</td>
                <td className="text-slate-400 capitalize">{a.environment}</td>
                <td><Chip color={a.criticality === "crown_jewel" ? "red" : a.criticality === "critical" ? "orange" : "slate"}>{a.criticality}</Chip></td>
                <td><Chip color={a.exposure === "internet" ? "orange" : "slate"}>{a.exposure}</Chip></td>
                <td className="text-slate-400">{a.owner_team}</td>
                <td className="text-right font-mono">{a.open_findings}</td>
                <td className="text-right font-mono text-red-300">{a.critical_findings}</td>
                <td><div className="flex items-center gap-1.5">
                  <div className="h-1 w-12 bg-slate-800 rounded overflow-hidden">
                    <div className={`h-full ${a.ownership_confidence >= 0.8 ? "bg-emerald-500" : a.ownership_confidence >= 0.6 ? "bg-amber-500" : "bg-red-500"}`} style={{width: `${(a.ownership_confidence||0)*100}%`}}/>
                  </div>
                  <span className="font-mono text-[10.5px] text-slate-400">{((a.ownership_confidence||0)*100).toFixed(0)}%</span>
                </div></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}

export function AssetDetail() {
  const { id } = useParams();
  const [a, setA] = useState(null);
  const [findings, setFindings] = useState([]);
  const [history, setHistory] = useState({activity: [], observations: []});
  useEffect(() => {
    api.get(`/v1/assets/${id}`).then(r => setA(r.data));
    api.get(`/v1/assets/${id}/findings`).then(r => setFindings(r.data.items));
    api.get(`/v1/assets/${id}/history`).then(r => setHistory(r.data));
  }, [id]);
  if (!a) return <Layout title="Asset…"><div className="text-slate-500">Loading…</div></Layout>;

  return (
    <Layout title={a.hostname} subtitle={`${a.platform} · ${a.operating_system} · ${a.environment}`}
      actions={<Link to="/assets" className="h-8 px-3 text-[12px] border border-[#30363D] rounded inline-flex items-center gap-1.5 text-slate-300"><ArrowLeft size={14}/> Back</Link>}>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-3 mb-4">
        <div className="lg:col-span-2 border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500">Asset Profile</div>
          <div className="mt-2 grid grid-cols-2 gap-2 text-[12.5px]">
            <div><span className="text-slate-500">IP:</span> <span className="font-mono">{a.ip || "—"}</span></div>
            <div><span className="text-slate-500">FQDN:</span> <span className="font-mono text-[11px]">{a.fqdn || "—"}</span></div>
            <div><span className="text-slate-500">Type:</span> {a.asset_type}</div>
            <div><span className="text-slate-500">Status:</span> {a.status}</div>
            <div><span className="text-slate-500">Owner Team:</span> {a.owner_team}</div>
            <div><span className="text-slate-500">Product:</span> {a.product_name || "—"}</div>
          </div>
          <div className="mt-3 flex flex-wrap gap-1">{(a.tags||[]).map(t => <Chip key={t}>{t}</Chip>)}</div>
        </div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500">Criticality</div>
          <div className="mt-2"><Chip color={a.criticality === "crown_jewel" ? "red" : "orange"}>{a.criticality}</Chip></div>
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mt-3">Exposure</div>
          <div className="mt-2"><Chip color={a.exposure === "internet" ? "orange" : "slate"}>{a.exposure}</Chip></div>
        </div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500">Ownership Confidence</div>
          <div className="text-[28px] font-mono font-semibold text-blue-300 mt-1">{((a.ownership_confidence||0)*100).toFixed(0)}<span className="text-slate-500 text-[14px]">%</span></div>
          <div className="text-[11px] text-slate-500 mt-1">{a.ownership_rationale}</div>
        </div>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden mb-4">
        <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">Vulnerabilities on this Host ({findings.length})</h3></div>
        <table className="dense w-full">
          <thead><tr><th className="text-left">Risk</th><th>Severity</th><th className="text-left">Title</th><th>CVE</th><th>Status</th><th>First Seen</th><th>Last Seen</th><th>Due</th></tr></thead>
          <tbody>
            {findings.map(f => (
              <tr key={f.id} className="border-t border-[#30363D] hover:bg-slate-800/30">
                <td><RiskBar score={f.risk_score} /></td>
                <td><SevBadge severity={f.severity} /></td>
                <td><Link to={`/findings/${f.id}`} className="text-blue-300 hover:underline">{f.title?.slice(0,70)}</Link></td>
                <td className="font-mono text-[11px]">{f.cve || "—"}</td>
                <td><Chip color={f.status==="Reopened" ? "orange" : f.status?.includes("Fixed") ? "green" : "slate"}>{f.status}</Chip></td>
                <td className="font-mono text-[11px]">{fmtDate(f.first_seen_at)}</td>
                <td className="font-mono text-[11px]">{fmtDate(f.last_seen_at)}</td>
                <td className={isOverdue(f.due_at) ? "text-red-300 text-[11px]" : "text-slate-400 text-[11px]"}>{fmtRel(f.due_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">Detection History</h3></div>
        <table className="dense w-full">
          <thead><tr><th className="text-left">Source</th><th>Method</th><th>Severity</th><th>Observed</th></tr></thead>
          <tbody>
            {history.observations.slice(0,30).map(o => (
              <tr key={o.id} className="border-t border-[#30363D]">
                <td>{o.source_tool}</td><td>{o.agent_or_network}</td>
                <td><SevBadge severity={o.normalized_severity} /></td>
                <td className="font-mono text-[11px]">{fmtDate(o.observed_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Layout>
  );
}
