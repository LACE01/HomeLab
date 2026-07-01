import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip, RiskBar } from "@/components/Badges";
import { Link, useNavigate } from "react-router-dom";
import { Globe, Fire, UserCircle, ShareNetwork } from "@phosphor-icons/react";
import {
  ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid,
} from "recharts";

const Stat = ({ label, value, sub, icon: Icon, tone = "slate", onClick }) => {
  const tones = {
    red: "text-red-300", orange: "text-orange-300", amber: "text-amber-300",
    blue: "text-blue-300", slate: "text-slate-200",
  };
  return (
    <div onClick={onClick}
      className={`border border-[#30363D] bg-[#0D1117] rounded-md p-3.5 hover:border-[#484F58] transition-colors ${onClick ? "cursor-pointer hover:bg-slate-800/20" : ""}`}>
      <div className="flex items-center justify-between mb-1.5">
        <div className="text-[10px] uppercase tracking-wider text-slate-500 font-mono">{label}</div>
        {Icon && <Icon size={14} className="text-slate-600" />}
      </div>
      <div className={`text-[22px] font-semibold font-mono ${tones[tone]}`}>{value}</div>
      {sub && <div className="text-[10.5px] text-slate-500 mt-0.5">{sub}</div>}
    </div>
  );
};

export default function Exposure() {
  const navigate = useNavigate();
  const [d, setD] = useState(null);

  useEffect(() => { api.get("/v1/dashboards/exposure").then(r => setD(r.data)); }, []);

  if (!d) return <Layout title="Exposure" subtitle="Loading…"><div className="text-slate-500">Loading…</div></Layout>;

  const pct = d.total_assets ? Math.round((d.exposed_assets / d.total_assets) * 100) : 0;

  return (
    <Layout title="Exposure" subtitle="What's actually reachable from the internet, and how bad is it">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
        <Stat label="Internet-Facing Assets" value={d.exposed_assets} sub={`${pct}% of ${d.total_assets} total`}
          icon={Globe} tone="blue" />
        <Stat label="Open Findings (Exposed)" value={d.exposed_open} icon={ShareNetwork} tone="slate"
          onClick={()=>navigate("/findings?view=internet_facing_critical")} />
        <Stat label="Exposed Critical/High" value={d.exposed_crit_high} icon={Fire} tone="orange"
          onClick={()=>navigate("/findings?view=internet_facing_critical")} />
        <Stat label="Exposed + KEV" value={d.exposed_kev} icon={Fire} tone="red"
          onClick={()=>navigate("/findings?view=kev")} />
        <Stat label="Exposed + Unassigned" value={d.exposed_unassigned} icon={UserCircle} tone="amber"
          onClick={()=>navigate("/findings?view=unassigned")} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <div className="lg:col-span-2 border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
          <div className="px-4 py-2.5 border-b border-[#30363D] text-[11px] uppercase tracking-wider font-mono text-slate-400">
            Top Exposed Assets — Fix These First
          </div>
          <table className="dense w-full">
            <thead><tr><th className="text-left">Host</th><th>Open</th><th>Critical</th><th>KEV</th><th>Owner</th><th>Risk</th></tr></thead>
            <tbody>
              {d.top_exposed_assets.map(a => (
                <tr key={a.asset_id} className="border-t border-[#30363D] hover:bg-slate-800/30">
                  <td><Link to={`/assets/${a.asset_id}`} className="text-blue-300 hover:underline font-mono text-[12px]">{a.hostname}</Link></td>
                  <td className="text-center font-mono">{a.open_findings}</td>
                  <td className="text-center font-mono text-red-300">{a.critical}</td>
                  <td className="text-center">{a.kev > 0 && <Chip color="red">{a.kev}</Chip>}</td>
                  <td className="text-slate-400 text-[11.5px]">{a.owner_team || <span className="text-amber-400">unassigned</span>}</td>
                  <td className="w-24"><RiskBar score={Math.min(100, a.risk_sum)} /></td>
                </tr>
              ))}
              {d.top_exposed_assets.length === 0 && (
                <tr><td colSpan="6" className="text-center text-slate-500 py-6">No internet-facing findings tracked yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
          <div className="px-4 py-2.5 border-b border-[#30363D] text-[11px] uppercase tracking-wider font-mono text-slate-400">
            Exposed Findings by Environment
          </div>
          <div className="p-3 h-[280px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={d.by_environment} layout="vertical" margin={{ left: 20 }}>
                <CartesianGrid stroke="#30363D" strokeDasharray="2 2"/>
                <XAxis type="number" stroke="#8B949E" fontSize={10}/>
                <YAxis type="category" dataKey="environment" stroke="#8B949E" fontSize={10} width={90}/>
                <Tooltip contentStyle={{ background:"#0D1117", border:"1px solid #30363D", fontSize:12 }}/>
                <Bar dataKey="count" fill="#3b82f6"/>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3 flex items-center justify-between gap-3">
        <div className="text-[12px] text-slate-400">
          Want to see how an exposed host connects further into the network? Attack Path Analysis walks the chain CVE by CVE.
        </div>
        <Link to="/attack-paths" className="h-8 px-3 text-[12px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 text-blue-300 rounded inline-flex items-center gap-1.5 shrink-0">
          <ShareNetwork size={14}/> Open Attack Paths
        </Link>
      </div>
    </Layout>
  );
}
