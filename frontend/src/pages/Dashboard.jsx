import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import { useAuth } from "@/lib/auth";
import { usePreferences } from "@/lib/usePreferences";
import Layout from "@/components/Layout";
import TimeRangeSelector from "@/components/TimeRangeSelector";
import TilePicker from "@/components/TilePicker";
import { SevBadge, Chip, RiskBar } from "@/components/Badges";
import { fmtRel, isOverdue } from "@/lib/utils-fmt";
import { Link } from "react-router-dom";
import {
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid,
  BarChart, Bar, Cell, PieChart, Pie, Legend,
} from "recharts";
import { Lightning, Fire, Clock, ArrowsClockwise, Warning, UserCircle, ChartLineUp, FileArrowDown } from "@phosphor-icons/react";

const Stat = ({ label, value, icon: Icon, tone = "slate", testid }) => {
  const tones = {
    red: "text-red-300", orange: "text-orange-300", amber: "text-amber-300",
    blue: "text-blue-300", green: "text-emerald-300", slate: "text-slate-200",
  };
  return (
    <div data-testid={testid} className="border border-[#30363D] bg-[#0D1117] rounded-md p-3.5 hover:border-[#484F58] transition-colors duration-150">
      <div className="flex items-center justify-between mb-1.5">
        <div className="text-[10px] uppercase tracking-wider text-slate-500 font-mono">{label}</div>
        {Icon && <Icon size={14} className="text-slate-600" />}
      </div>
      <div className={`text-[22px] font-semibold font-mono ${tones[tone] || tones.slate}`}>{value}</div>
    </div>
  );
};

const Panel = ({ title, children, actions, testid }) => (
  <div data-testid={testid} className="border border-[#30363D] bg-[#0D1117] rounded-md">
    <div className="px-4 py-2.5 border-b border-[#30363D] flex items-center justify-between">
      <h3 className="text-[12px] uppercase tracking-wider text-slate-400 font-mono">{title}</h3>
      {actions}
    </div>
    <div>{children}</div>
  </div>
);

// Catalog of tiles (per tab) for the TilePicker
const TILE_CATALOG = [
  { id: "stat-open", label: "Open Findings", group: "Stats" },
  { id: "stat-triage", label: "Needs Triage", group: "Stats" },
  { id: "stat-kev", label: "KEV (Exploited)", group: "Stats" },
  { id: "stat-rti", label: "Active Attacks", group: "Stats" },
  { id: "stat-overdue", label: "Overdue", group: "Stats" },
  { id: "stat-reopened", label: "Reopened", group: "Stats" },
  { id: "stat-unassigned", label: "Unassigned", group: "Stats" },
  { id: "stat-lowconf", label: "Low-Confidence Owner", group: "Stats" },
  { id: "stat-failedimports", label: "Failed Imports", group: "Stats" },
  { id: "stat-new", label: "New (window)", group: "Stats" },
  { id: "panel-severity", label: "Open Findings by Severity", group: "Panels" },
  { id: "panel-top-findings", label: "Top Risk Findings", group: "Panels" },
  { id: "panel-imports", label: "Recent Imports", group: "Panels" },
  { id: "panel-cwe", label: "CWE Prevalence", group: "Panels" },
];

export default function Dashboard() {
  const { user } = useAuth();
  const role = user?.role || "analyst";
  const { prefs, setSection } = usePreferences();
  const [analyst, setAnalyst] = useState(null);
  const [manager, setManager] = useState(null);
  const [exec, setExec] = useState(null);
  const [sevStats, setSevStats] = useState(null);
  const [cwe, setCwe] = useState([]);
  const [tab, setTab] = useState(role === "executive" ? "exec" : role === "manager" ? "mgr" : "ops");
  const [customRange, setCustomRange] = useState({ start: "", end: "" });

  const range = prefs?.dashboard?.range || "30d";
  const tiles = prefs?.dashboard?.tiles || {};
  const tileOn = (id) => tiles[id] !== false; // default-on

  const rangeParams = useMemo(() => {
    if (range === "custom") {
      return { range: "custom", start: customRange.start, end: customRange.end };
    }
    return { range };
  }, [range, customRange]);

  useEffect(() => {
    // Wait for prefs to load, then refetch when range changes
    if (!prefs) return;
    // Skip custom request until both dates are set
    if (range === "custom" && (!customRange.start || !customRange.end)) return;

    // Debounce: wait 300ms after the last range/prefs change before firing the
    // 5 parallel dashboard requests. Prevents request bursts on rapid clicks.
    let cancelled = false;
    const fire = async () => {
      // Bundle the 5 reads in parallel
      const [a, m, e, s, c] = await Promise.all([
        api.get("/v1/dashboards/analyst",   { params: rangeParams }),
        api.get("/v1/dashboards/manager",   { params: rangeParams }),
        api.get("/v1/dashboards/executive", { params: rangeParams }),
        api.get("/v1/findings/stats"),
        api.get("/v1/cwe-prevalence"),
      ]);
      if (cancelled) return;
      setAnalyst(a.data);
      setManager(m.data);
      setExec(e.data);
      setSevStats(s.data);
      setCwe(c.data.items || []);
    };
    const t = setTimeout(fire, 300);
    return () => { cancelled = true; clearTimeout(t); };
  }, [prefs, range, rangeParams, customRange.start, customRange.end]);

  const setRange = (r) => setSection("dashboard", { range: r });
  const toggleTile = (id) => setSection("dashboard", { tiles: { ...tiles, [id]: !tileOn(id) } });
  const resetTiles = () => setSection("dashboard", { tiles: {} });

  const downloadPdf = async () => {
    const r = await api.get("/v1/reports/pdf/executive", { responseType: "blob" });
    const url = URL.createObjectURL(r.data);
    const a = document.createElement("a"); a.href = url; a.download = "executive-report.pdf"; a.click();
    URL.revokeObjectURL(url);
  };

  const Tab = ({ id, children, testid }) => (
    <button data-testid={testid} onClick={() => setTab(id)}
      className={`px-3 py-1 text-[12px] rounded-sm transition-colors ${tab === id ? "bg-blue-500/15 text-blue-300 border border-blue-500/30" : "text-slate-400 hover:text-slate-200 border border-transparent"}`}>
      {children}
    </button>
  );

  return (
    <Layout title="Dashboard" subtitle="Live security posture across products, assets, and findings"
      actions={<>
        <TimeRangeSelector
          value={range}
          onChange={setRange}
          customStart={customRange.start}
          customEnd={customRange.end}
          onCustomChange={(d) => setCustomRange({ start: d.start || "", end: d.end || "" })}
        />
        <div className="flex items-center gap-1 mr-1">
          <Tab id="ops" testid="tab-analyst">Analyst</Tab>
          <Tab id="mgr" testid="tab-manager">Manager</Tab>
          <Tab id="exec" testid="tab-executive">Executive</Tab>
        </div>
        <TilePicker
          tiles={tiles}
          catalog={TILE_CATALOG}
          onToggle={toggleTile}
          onResetAll={resetTiles}
        />
        <button data-testid="export-exec-pdf" onClick={downloadPdf}
          className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] hover:bg-slate-800/40 rounded inline-flex items-center gap-1.5 text-slate-300">
          <FileArrowDown size={14}/> Export PDF
        </button>
      </>}>

      {tab === "ops" && analyst && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            {tileOn("stat-open") && <Stat label="Open Findings" value={analyst.open_findings} icon={ChartLineUp} testid="stat-open" />}
            {tileOn("stat-triage") && <Stat label="Needs Triage" value={analyst.needs_triage} tone="amber" icon={Warning} testid="stat-triage" />}
            {tileOn("stat-kev") && <Stat label="KEV (Exploited)" value={analyst.kev_findings} tone="red" icon={Fire} testid="stat-kev" />}
            {tileOn("stat-rti") && <Stat label="Active Attacks" value={analyst.rti_findings} tone="orange" icon={Lightning} testid="stat-rti" />}
            {tileOn("stat-overdue") && <Stat label="Overdue" value={analyst.overdue} tone="red" icon={Clock} testid="stat-overdue" />}
            {tileOn("stat-reopened") && <Stat label="Reopened" value={analyst.reopened} tone="amber" icon={ArrowsClockwise} testid="stat-reopened" />}
            {tileOn("stat-unassigned") && <Stat label="Unassigned" value={analyst.unassigned} tone="blue" icon={UserCircle} testid="stat-unassigned" />}
            {tileOn("stat-lowconf") && <Stat label="Low-Confidence Owner" value={analyst.low_confidence_ownership} tone="amber" testid="stat-lowconf" />}
            {tileOn("stat-failedimports") && <Stat label="Failed Imports" value={analyst.failed_imports} tone={analyst.failed_imports > 0 ? "red" : "slate"} testid="stat-failedimports" />}
            {tileOn("stat-new") && <Stat label={`New (${analyst.range || range})`} value={analyst.new_findings} tone="blue" testid="stat-new" />}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 min-w-0">
            {tileOn("panel-severity") && (
              <div className="min-w-0">
              <Panel title="Open Findings by Severity" testid="panel-severity">
                <div className="p-3 h-[260px]">
                  {sevStats && (
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie data={["Critical","High","Medium","Low","Info"].map(s => ({name: s, value: sevStats.by_severity?.[s] || 0}))}
                          cx="50%" cy="50%" innerRadius={50} outerRadius={85} paddingAngle={2} dataKey="value"
                          label={({name, value}) => value > 0 ? `${name}: ${value}` : ""}
                          labelLine={false}>
                          <Cell fill="#ef4444"/><Cell fill="#f97316"/><Cell fill="#f59e0b"/><Cell fill="#3b82f6"/><Cell fill="#64748b"/>
                        </Pie>
                        <Tooltip contentStyle={{ background:"#0D1117", border:"1px solid #30363D", fontSize:12 }}/>
                        <Legend wrapperStyle={{fontSize:11, color:"#94a3b8"}}/>
                      </PieChart>
                    </ResponsiveContainer>
                  )}
                </div>
              </Panel>
              </div>
            )}

            {tileOn("panel-top-findings") && (
              <div className="lg:col-span-2 min-w-0">
                <Panel title="Top Risk Findings" testid="panel-top-findings">
                  <div className="overflow-x-auto">
                    <table className="dense w-full table-fixed">
                      <colgroup>
                        <col className="w-[80px]"/>
                        <col className="w-[80px]"/>
                        <col/>
                        <col className="w-[110px]"/>
                        <col className="w-[110px]"/>
                        <col className="w-[90px]"/>
                      </colgroup>
                      <thead><tr><th className="text-left">Risk</th><th className="text-left">Severity</th><th className="text-left">Title</th><th className="text-left">Asset</th><th className="text-left">Owner</th><th className="text-left">Due</th></tr></thead>
                      <tbody>
                        {analyst.top_findings.map(f => (
                          <tr key={f.id} className="border-t border-[#30363D] hover:bg-slate-800/30">
                            <td><RiskBar score={f.risk_score} /></td>
                            <td><SevBadge severity={f.severity} /></td>
                            <td className="min-w-0">
                              <Link className="text-blue-300 hover:underline block truncate" to={`/findings/${f.id}`} data-testid={`top-finding-${f.id}`} title={f.title}>{f.title}</Link>
                              <div className="flex gap-1 mt-0.5 flex-wrap">
                                {f.kev_flag && <Chip color="red">KEV</Chip>}
                                {f.cve && <Chip color="slate">{f.cve}</Chip>}
                                {f.internet_facing && <Chip color="orange">EXPOSED</Chip>}
                              </div>
                            </td>
                            <td className="font-mono text-[11.5px] truncate" title={f.asset_hostname}>{f.asset_hostname}</td>
                            <td className="text-slate-400 truncate" title={f.owner_team}>{f.owner_team}</td>
                            <td className={isOverdue(f.due_at) ? "text-red-300 text-[11px]" : "text-slate-400 text-[11px]"}>{fmtRel(f.due_at)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Panel>
              </div>
            )}

            {tileOn("panel-imports") && (
              <div className="min-w-0">
              <Panel title="Recent Imports" testid="panel-imports">
                <div className="divide-y divide-[#30363D]">
                  {analyst.recent_imports.map(j => (
                    <div key={j.id} className="px-4 py-2.5">
                      <div className="flex items-center justify-between">
                        <div className="text-[12.5px] text-slate-200 truncate">{j.source_name}</div>
                        <Chip color={j.status === "success" ? "green" : "red"}>{j.status}</Chip>
                      </div>
                      <div className="text-[11px] text-slate-500 mt-0.5 font-mono">
                        +{j.created_count} new · ↻{j.updated_count} updated · {j.deduplicated_count} dedup
                      </div>
                      <div className="text-[10.5px] text-slate-600 mt-0.5">{fmtRel(j.started_at)}</div>
                    </div>
                  ))}
                </div>
              </Panel>
              </div>
            )}
          </div>

          {/* CWE Prevalence — your local systemic weaknesses (KRI methodology) */}
          {tileOn("panel-cwe") && cwe.length > 0 && (
            <Panel title="CWE Prevalence — Local Systemic Weaknesses" testid="panel-cwe">
              <div className="p-3 text-[11px] text-slate-500 mb-1">
                CWEs ranked by frequency in YOUR environment. Higher weight = more recurring → gets a multiplier in KRI scoring.
              </div>
              <table className="dense w-full">
                <thead><tr><th className="text-left">CWE</th><th className="text-left">Sample Title</th><th>Findings</th><th>Local Weight</th></tr></thead>
                <tbody>
                  {cwe.slice(0,10).map(c => (
                    <tr key={c.cwe} className="border-t border-[#30363D]">
                      <td className="font-mono text-[12px] text-blue-300">{c.cwe}</td>
                      <td className="text-slate-300 max-w-[420px] truncate">{c.sample_title || "—"}</td>
                      <td className="text-center font-mono">{c.count ?? 0}</td>
                      <td><div className="flex items-center gap-2">
                        <div className="h-1.5 w-24 bg-slate-800 rounded overflow-hidden">
                          <div className="h-full bg-blue-400" style={{width:`${((c.weight-0.8)/0.7)*100}%`}}/>
                        </div>
                        <span className="font-mono text-[11px]">{c.weight}×</span>
                      </div></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          )}
        </div>
      )}

      {tab === "mgr" && manager && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Panel title={`Risk Score Trend (${manager.range || range})`}>
              <div className="p-3 h-[260px]">
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={manager.snapshots}>
                    <defs>
                      <linearGradient id="g1" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#2F81F7" stopOpacity={0.4}/>
                        <stop offset="100%" stopColor="#2F81F7" stopOpacity={0}/>
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="#30363D" strokeDasharray="2 2" />
                    <XAxis dataKey="date" stroke="#8B949E" fontSize={10} tickFormatter={(d)=>d?.slice(5,10)} />
                    <YAxis stroke="#8B949E" fontSize={10} domain={[40,100]} />
                    <Tooltip contentStyle={{ background:"#0D1117", border:"1px solid #30363D", fontSize:12 }} />
                    <Area dataKey="org_score" stroke="#2F81F7" fill="url(#g1)" />
                  </AreaChart>
                </ResponsiveContainer>
              </div>
            </Panel>
            <Panel title="Findings by Team">
              <table className="dense w-full">
                <thead><tr><th className="text-left">Team</th><th className="text-right">Open</th><th className="text-right">Critical</th><th className="text-right">Overdue</th></tr></thead>
                <tbody>
                  {manager.by_team.map(t => (
                    <tr key={t.team} className="border-t border-[#30363D]">
                      <td className="text-slate-200">{t.team}</td>
                      <td className="text-right font-mono">{t.open}</td>
                      <td className="text-right font-mono text-red-300">{t.critical}</td>
                      <td className="text-right font-mono text-orange-300">{t.overdue}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          </div>
        </div>
      )}

      {tab === "exec" && exec && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 md:col-span-2">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 font-mono mb-1">Security Score</div>
              <div className="flex items-baseline gap-2"><span data-testid="exec-score" className="text-[44px] font-semibold font-mono text-blue-300">{exec.current_score}</span><span className="text-slate-500 text-[14px]">/ 100</span></div>
              <p className="text-[12.5px] text-slate-400 mt-2 leading-relaxed">{exec.narrative}</p>
            </div>
            <Stat label="SLA Compliance" value={`${exec.sla_compliance}%`} tone="green" testid="exec-sla" />
            <Stat label="MTTR (days)" value={exec.mttr_days} tone="amber" testid="exec-mttr" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <Panel title={`Risk Score / SLA Trend (${exec.range || range})`}>
                <div className="p-3 h-[280px]">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={exec.snapshots}>
                      <CartesianGrid stroke="#30363D" strokeDasharray="2 2"/>
                      <XAxis dataKey="date" stroke="#8B949E" fontSize={10} tickFormatter={(d)=>d?.slice(5,10)}/>
                      <YAxis stroke="#8B949E" fontSize={10}/>
                      <Tooltip contentStyle={{ background:"#0D1117", border:"1px solid #30363D", fontSize:12 }}/>
                      <Area dataKey="org_score" stroke="#2F81F7" fill="#2F81F722" name="Score"/>
                      <Area dataKey="sla_compliance" stroke="#f59e0b" fill="#f59e0b22" name="SLA %"/>
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </Panel>
            </div>
            <Panel title="Score Drivers">
              <div className="divide-y divide-[#30363D]">
                {exec.score_factors.map((f, i) => (
                  <div key={i} className="px-4 py-2.5">
                    <div className="flex items-center justify-between">
                      <div className="text-[12.5px] text-slate-200">{f.factor}</div>
                      <Chip color={f.impact?.startsWith("-") ? "red" : "green"}>{f.impact}</Chip>
                    </div>
                    <div className="text-[11px] text-slate-500 mt-0.5">{f.reason}</div>
                  </div>
                ))}
              </div>
            </Panel>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Panel title="Open Critical/High by Product">
              <div className="p-3 h-[240px]">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={exec.by_product} layout="vertical" margin={{left: 100}}>
                    <CartesianGrid stroke="#30363D" strokeDasharray="2 2"/>
                    <XAxis type="number" stroke="#8B949E" fontSize={10}/>
                    <YAxis type="category" dataKey="name" stroke="#8B949E" fontSize={10} width={140}/>
                    <Tooltip contentStyle={{ background:"#0D1117", border:"1px solid #30363D", fontSize:12 }}/>
                    <Bar dataKey="critical_open" fill="#ef4444"/>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </Panel>
            <Panel title="By Environment">
              <table className="dense w-full">
                <thead><tr><th className="text-left">Environment</th><th className="text-right">Open Critical/High</th></tr></thead>
                <tbody>
                  {exec.by_environment.map(e => (
                    <tr key={e.environment} className="border-t border-[#30363D]"><td className="capitalize">{e.environment}</td><td className="text-right font-mono">{e.count}</td></tr>
                  ))}
                </tbody>
              </table>
            </Panel>
          </div>
        </div>
      )}
    </Layout>
  );
}
