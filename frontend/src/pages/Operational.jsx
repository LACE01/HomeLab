import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, LineChart, Line } from "recharts";
import { ArrowLeft, CaretUp, CaretDown } from "@phosphor-icons/react";
import TrendChart from "@/components/TrendChart";

const Stat = ({ label, value, suffix, onClick, tone }) => {
  const tones = { red: "text-red-300", orange: "text-orange-300", amber: "text-amber-300", slate: "text-slate-100" };
  return (
    <div onClick={onClick}
      className={`border border-[#30363D] bg-[#0D1117] rounded-md p-3.5 ${onClick ? "cursor-pointer hover:border-[#484F58] hover:bg-slate-800/20 transition-colors" : ""}`}>
      <div className="text-[10px] uppercase tracking-wider text-slate-500 font-mono">{label}</div>
      <div className={`text-[22px] font-mono font-semibold ${tones[tone] || tones.slate}`}>{value}<span className="text-slate-500 text-[14px]">{suffix||""}</span></div>
    </div>
  );
};

const Panel = ({ title, children }) => (
  <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
    <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider text-slate-400 font-mono">{title}</h3></div>
    {children}
  </div>
);

export default function Operational() {
  const [searchParams] = useSearchParams();
  const initialTeam = searchParams.get("team") || "";
  const [d, setD] = useState(null);
  const [team, setTeam] = useState(initialTeam);
  const [view, setView] = useState(initialTeam ? "team" : "leaderboard"); // "leaderboard" | "team"
  const navigate = useNavigate();
  useEffect(() => {
    if (view !== "team") return;
    api.get("/v1/dashboards/operational", { params: team ? {team} : {} }).then(r => setD(r.data));
  }, [team, view]);

  const openTeam = (teamName) => { setTeam(teamName || ""); setView("team"); };

  if (view === "leaderboard") {
    return <TeamsLeaderboard onOpenTeam={openTeam}/>;
  }
  if (!d) return <Layout title="Operational Dashboard"><div className="text-slate-500">Loading…</div></Layout>;

  const agingData = Object.entries(d.aging_buckets).map(([k,v]) => ({bucket:k, count:v}));
  const overdueData = Object.entries(d.overdue_by_severity).map(([k,v]) => ({sev:k, count:v}));

  // Build /findings deep links, carrying the current team scope along.
  const link = (params) => {
    const p = new URLSearchParams(params);
    if (team) p.set("owner_team", team);
    navigate(`/findings?${p.toString()}`);
  };

  return (
    <Layout title="Operational Dashboard" subtitle={`Aging, throughput, and team health — ${d.team_scope}`}
      actions={
        <>
          <button onClick={()=>setView("leaderboard")} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300">
            <ArrowLeft size={13}/> All teams
          </button>
          <input placeholder="Scope: team name" data-testid="op-team-filter" value={team} onChange={(e)=>setTeam(e.target.value)}
            className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] w-44"/>
        </>
      }>
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-3">
        <Stat label="Open Total" value={d.total_open} onClick={()=>link({})}/>
        <Stat label="Critical Open" value={d.critical_open} tone="red" onClick={()=>link({severity:"Critical"})}/>
        <Stat label="KEV (Exploited)" value={d.kev_open} tone="red" onClick={()=>link({view:"kev"})}/>
        <Stat label="Active Attacks" value={d.active_attacks_open} tone="orange" onClick={()=>link({view:"active_attacks"})}/>
        <Stat label="Unassigned" value={d.unassigned_open} tone="amber" onClick={()=>link({view:"unassigned"})}/>
      </div>
      <div className="grid grid-cols-2 md:grid-cols-7 gap-3 mb-4">
        <Stat label="SLA Compliance" value={d.sla_compliance ?? "—"} suffix={d.sla_compliance != null ? "%" : ""}
          tone={d.sla_compliance == null ? "slate" : d.sla_compliance >= 85 ? "slate" : d.sla_compliance >= 60 ? "amber" : "red"}/>
        <Stat label="MTTR" value={d.mttr_days} suffix=" d"/>
        <Stat label="Reopen Rate" value={d.reopen_rate} suffix="%"/>
        <Stat label="Reopened Open" value={d.reopened_open} onClick={()=>link({view:"reopened"})}/>
        <Stat label="Scan Coverage" value={d.scan_coverage_pct} suffix="%"/>
        <Stat label="Active Exceptions" value={d.active_exceptions}/>
        <Stat label="Overdue" value={Object.values(d.overdue_by_severity).reduce((a,b)=>a+b,0)} tone="red" onClick={()=>link({view:"overdue"})}/>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
        <Panel title="Aging Buckets (days open) — click a bar to drill in">
          <div className="p-3 h-[220px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={agingData} onClick={(e) => {
                const label = e?.activeLabel;
                if (!label) return;
                // Aging buckets aren't a single backend filter -- send the user to the
                // full open-findings view sorted oldest-first, which lands them right
                // where this bucket lives.
                link({ sort: "first_seen_at", order: "asc" });
              }}>
                <CartesianGrid stroke="#30363D" strokeDasharray="2 2"/>
                <XAxis dataKey="bucket" stroke="#8B949E" fontSize={11}/>
                <YAxis stroke="#8B949E" fontSize={11}/>
                <Tooltip contentStyle={{ background:"#0D1117", border:"1px solid #30363D", fontSize:12 }}/>
                <Bar dataKey="count" fill="#f59e0b" cursor="pointer"/>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Overdue by Severity — click a bar to drill in">
          <div className="p-3 h-[220px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={overdueData} onClick={(e) => {
                const sev = e?.activePayload?.[0]?.payload?.sev;
                if (sev) link({ view: "overdue", severity: sev });
              }}>
                <CartesianGrid stroke="#30363D" strokeDasharray="2 2"/>
                <XAxis dataKey="sev" stroke="#8B949E" fontSize={11}/>
                <YAxis stroke="#8B949E" fontSize={11}/>
                <Tooltip contentStyle={{ background:"#0D1117", border:"1px solid #30363D", fontSize:12 }}/>
                <Bar dataKey="count" fill="#ef4444" cursor="pointer"/>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Top Assignees / Teams — click a row to drill in">
          <table className="dense w-full">
            <thead><tr><th className="text-left">Owner</th><th className="text-right">Open</th></tr></thead>
            <tbody>{d.by_assignee.map(b => (
              <tr key={b.assignee} onClick={()=>link({owner_team: b.assignee})}
                className="border-t border-[#30363D] cursor-pointer hover:bg-slate-800/30">
                <td className="text-slate-200">{b.assignee}</td><td className="text-right font-mono">{b.count}</td>
              </tr>
            ))}</tbody>
          </table>
        </Panel>
      </div>

      <div className="mb-4">
        <TrendChart title={`Vulnerabilities Over Time — ${d.team_scope}`} filters={team ? { owner_team: team } : {}} defaultDays={90}/>
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


function TeamsLeaderboard({ onOpenTeam }) {
  const [items, setItems] = useState(null);
  const [sortKey, setSortKey] = useState("overdue");
  const [sortDir, setSortDir] = useState("desc");

  useEffect(() => { api.get("/v1/dashboards/teams-leaderboard").then(r => setItems(r.data.items)); }, []);

  if (!items) return <Layout title="Team Dashboards" subtitle="SLA health across every team"><div className="text-slate-500">Loading…</div></Layout>;

  const sorted = [...items].sort((a, b) => {
    const av = a[sortKey], bv = b[sortKey];
    const an = av == null ? -1 : av, bn = bv == null ? -1 : bv;
    return sortDir === "desc" ? bn - an : an - bn;
  });

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir(d => d === "desc" ? "asc" : "desc");
    else { setSortKey(key); setSortDir("desc"); }
  };

  const Th = ({ label, k }) => (
    <th className="text-right cursor-pointer select-none hover:text-slate-200" onClick={() => toggleSort(k)}>
      <span className="inline-flex items-center gap-0.5">
        {label} {sortKey === k && (sortDir === "desc" ? <CaretDown size={10}/> : <CaretUp size={10}/>)}
      </span>
    </th>
  );

  const slaTone = (v) => v == null ? "text-slate-500" : v >= 85 ? "text-emerald-300" : v >= 60 ? "text-amber-300" : "text-red-300";

  return (
    <Layout title="Team Dashboards" subtitle="SLA compliance, backlog, and exposure — one row per team, click through for the full drill-down">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead>
            <tr>
              <th className="text-left">Team</th>
              <Th label="SLA %" k="sla_compliance"/>
              <Th label="Open" k="open"/>
              <Th label="Overdue" k="overdue"/>
              <Th label="Critical" k="critical_open"/>
              <Th label="KEV" k="kev_open"/>
              <Th label="MTTR (d)" k="mttr_days"/>
              <Th label="Resolved (90d)" k="resolved_90d"/>
            </tr>
          </thead>
          <tbody>
            {sorted.map(row => (
              <tr key={row.team} onClick={() => onOpenTeam(row.team)}
                className="border-t border-[#30363D] cursor-pointer hover:bg-slate-800/30">
                <td className="text-slate-200 font-medium">{row.team}</td>
                <td className={`text-right font-mono ${slaTone(row.sla_compliance)}`}>{row.sla_compliance != null ? `${row.sla_compliance}%` : "—"}</td>
                <td className="text-right font-mono">{row.open}</td>
                <td className={`text-right font-mono ${row.overdue > 0 ? "text-red-300" : ""}`}>{row.overdue}</td>
                <td className={`text-right font-mono ${row.critical_open > 0 ? "text-red-300" : ""}`}>{row.critical_open}</td>
                <td className={`text-right font-mono ${row.kev_open > 0 ? "text-red-300" : ""}`}>{row.kev_open}</td>
                <td className="text-right font-mono">{row.mttr_days ?? "—"}</td>
                <td className="text-right font-mono text-slate-500">{row.resolved_90d}</td>
              </tr>
            ))}
            {sorted.length === 0 && (
              <tr><td colSpan={8} className="text-center text-slate-500 py-8">No findings with an owner_team assigned yet.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      <div className="text-[11px] text-slate-500 mt-2">
        SLA % is the share of each team's last-90-day resolutions that landed on or before their due date — same convention as the
        org-wide score on the Executive dashboard, just scoped per team. Click any row for that team's full aging/throughput drill-down.
      </div>
    </Layout>
  );
}
