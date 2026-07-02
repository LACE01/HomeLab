import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip, RiskBar } from "@/components/Badges";
import { Link, useNavigate } from "react-router-dom";
import { Globe, Fire, UserCircle, ShareNetwork, Warning, Info, ArrowsClockwise } from "@phosphor-icons/react";
import { useAuth } from "@/lib/auth";
import { toast } from "sonner";
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
  const { user } = useAuth();
  const [d, setD] = useState(null);
  const [resyncing, setResyncing] = useState(false);

  const load = () => api.get("/v1/dashboards/exposure").then(r => setD(r.data));
  useEffect(() => { load(); }, []); // eslint-disable-line

  const resync = async () => {
    setResyncing(true);
    try {
      const r = await api.post("/v1/admin/exposure/resync");
      toast.success(`Checked ${r.data.assets_checked} assets — updated ${r.data.findings_updated} finding(s) across ${r.data.assets_with_changes} asset(s).`);
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Resync failed");
    } finally { setResyncing(false); }
  };

  if (!d) return <Layout title="Exposure" subtitle="Loading…"><div className="text-slate-500">Loading…</div></Layout>;

  const pct = d.total_assets ? Math.round((d.exposed_assets / d.total_assets) * 100) : 0;

  return (
    <Layout title="Exposure" subtitle="What's actually reachable from the internet, and how bad is it"
      actions={user?.role === "admin" && (
        <button onClick={resync} disabled={resyncing} data-testid="resync-exposure-btn"
          title="Retroactively fixes findings whose internet-facing flag went stale after an asset was reclassified"
          className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 text-slate-400 rounded inline-flex items-center gap-1.5 disabled:opacity-50">
          <ArrowsClockwise size={14} className={resyncing ? "animate-spin" : ""}/> {resyncing ? "Resyncing…" : "Resync exposure flags"}
        </button>
      )}>
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

      {d.exposed_assets > 0 && d.exposed_open === 0 && (
        <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-4 py-3 mb-4 flex items-start gap-2.5">
          <Info size={16} className="text-blue-400 shrink-0 mt-0.5"/>
          <div className="text-[12px] text-blue-200/90 leading-relaxed">
            {d.exposed_assets} internet-facing asset{d.exposed_assets === 1 ? "" : "s"} tracked, but no vulnerability scan has run
            against {d.exposed_assets === 1 ? "it" : "them"} yet — EASM only discovers hosts, it doesn't scan for
            vulnerabilities. Run <Link to="/admin/nmap-scans" className="underline hover:text-blue-100">Nmap</Link> or another
            scanner targeting these assets to populate this view. If some of these assets already had findings from a prior
            scan before being marked internet-facing, use "Resync exposure flags" above to catch those up.
          </div>
        </div>
      )}

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

      {d.exposure_mismatches?.length > 0 && (
        <div className="border border-amber-500/30 bg-amber-500/5 rounded-md overflow-hidden mb-4">
          <div className="px-4 py-2.5 border-b border-amber-500/20 text-[11px] uppercase tracking-wider font-mono text-amber-300 flex items-center gap-2">
            <Warning size={13}/> Exposure Mismatches — {d.exposure_mismatches.length} asset{d.exposure_mismatches.length===1?"":"s"} (from external Nmap scans)
          </div>
          <div className="divide-y divide-amber-500/10">
            {d.exposure_mismatches.map(a => (
              <div key={a.id} className="px-4 py-2.5 flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <Link to={`/assets/${a.id}`} className="text-blue-300 hover:underline font-mono text-[12px]">{a.hostname}</Link>
                  <div className="text-[11px] text-amber-200/80 mt-0.5">{a.exposure_mismatch_note}</div>
                </div>
                <Chip color="amber">marked "{a.exposure}"</Chip>
              </div>
            ))}
          </div>
        </div>
      )}

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
