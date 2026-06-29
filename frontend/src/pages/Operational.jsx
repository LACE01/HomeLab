import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, LineChart, Line } from "recharts";

const Stat = ({ label, value, suffix }) => (
  <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3.5">
    <div className="text-[10px] uppercase tracking-wider text-slate-500 font-mono">{label}</div>
    <div className="text-[22px] font-mono font-semibold text-slate-100">{value}<span className="text-slate-500 text-[14px]">{suffix||""}</span></div>
  </div>
);

const Panel = ({ title, children }) => (
  <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
    <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider text-slate-400 font-mono">{title}</h3></div>
    {children}
  </div>
);

export default function Operational() {
  const [d, setD] = useState(null);
  const [team, setTeam] = useState("");
  useEffect(() => { api.get("/v1/dashboards/operational", { params: team ? {team} : {} }).then(r => setD(r.data)); }, [team]);
  if (!d) return <Layout title="Operational Dashboard"><div className="text-slate-500">Loading…</div></Layout>;

  const agingData = Object.entries(d.aging_buckets).map(([k,v]) => ({bucket:k, count:v}));
  const overdueData = Object.entries(d.overdue_by_severity).map(([k,v]) => ({sev:k, count:v}));

  return (
    <Layout title="Operational Dashboard" subtitle={`Aging, throughput, and team health — ${d.team_scope}`}
      actions={
        <input placeholder="Scope: team name" data-testid="op-team-filter" value={team} onChange={(e)=>setTeam(e.target.value)}
          className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] w-44"/>
      }>
      <div className="grid grid-cols-2 md:grid-cols-6 gap-3 mb-4">
        <Stat label="Open Total" value={d.total_open}/>
        <Stat label="MTTR" value={d.mttr_days} suffix=" d"/>
        <Stat label="Reopen Rate" value={d.reopen_rate} suffix="%"/>
        <Stat label="Reopened Open" value={d.reopened_open}/>
        <Stat label="Scan Coverage" value={d.scan_coverage_pct} suffix="%"/>
        <Stat label="Active Exceptions" value={d.active_exceptions}/>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <Panel title="Aging Buckets (days open)">
          <div className="p-3 h-[220px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={agingData}>
                <CartesianGrid stroke="#30363D" strokeDasharray="2 2"/>
                <XAxis dataKey="bucket" stroke="#8B949E" fontSize={11}/>
                <YAxis stroke="#8B949E" fontSize={11}/>
                <Tooltip contentStyle={{ background:"#0D1117", border:"1px solid #30363D", fontSize:12 }}/>
                <Bar dataKey="count" fill="#f59e0b"/>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Overdue by Severity">
          <div className="p-3 h-[220px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={overdueData}>
                <CartesianGrid stroke="#30363D" strokeDasharray="2 2"/>
                <XAxis dataKey="sev" stroke="#8B949E" fontSize={11}/>
                <YAxis stroke="#8B949E" fontSize={11}/>
                <Tooltip contentStyle={{ background:"#0D1117", border:"1px solid #30363D", fontSize:12 }}/>
                <Bar dataKey="count" fill="#ef4444"/>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Top Assignees / Teams">
          <table className="dense w-full">
            <thead><tr><th className="text-left">Owner</th><th className="text-right">Open</th></tr></thead>
            <tbody>{d.by_assignee.map(b => (
              <tr key={b.assignee} className="border-t border-[#30363D]"><td className="text-slate-200">{b.assignee}</td><td className="text-right font-mono">{b.count}</td></tr>
            ))}</tbody>
          </table>
        </Panel>
      </div>

      <Panel title="Throughput — Opened vs Closed (30 days)">
        <div className="p-3 h-[260px]">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={d.throughput}>
              <CartesianGrid stroke="#30363D" strokeDasharray="2 2"/>
              <XAxis dataKey="date" stroke="#8B949E" fontSize={10} tickFormatter={(s)=>s?.slice(5)}/>
              <YAxis stroke="#8B949E" fontSize={10}/>
              <Tooltip contentStyle={{ background:"#0D1117", border:"1px solid #30363D", fontSize:12 }}/>
              <Legend wrapperStyle={{fontSize:11}}/>
              <Line dataKey="opened" stroke="#ef4444" name="Opened"/>
              <Line dataKey="closed" stroke="#10b981" name="Closed"/>
              <Line dataKey="net" stroke="#2F81F7" name="Net"/>
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Panel>
    </Layout>
  );
}
