import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import {
  ResponsiveContainer, AreaChart, Area, BarChart, Bar, LineChart, Line,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from "recharts";

// Reusable "vulnerabilities over time" chart -- one data source (GET
// /v1/charts/findings-timeseries) and one component, dropped in anywhere a trend
// broken down by severity/status/CWE/source is useful: Asset Detail (scoped to that
// asset), Reports (ad-hoc exploration), Dashboards (team/org scoped). Pass `filters`
// to scope the underlying query (asset_id, owner_team, product_id, severity, status).

const GROUP_BY_OPTIONS = [
  { value: "severity", label: "Severity" },
  { value: "status", label: "Status" },
  { value: "cwe", label: "Weakness (CWE)" },
  { value: "source_tool", label: "Source" },
];

const RANGE_OPTIONS = [
  { value: 30, label: "30 days", granularity: "day" },
  { value: 90, label: "90 days", granularity: "day" },
  { value: 180, label: "6 months", granularity: "week" },
  { value: 365, label: "12 months", granularity: "week" },
];

const CHART_TYPES = [
  { value: "area", label: "Stacked area" },
  { value: "bar", label: "Stacked bar" },
  { value: "line", label: "Lines" },
];

export default function TrendChart({
  filters = {}, title = "Vulnerabilities Over Time", defaultGroupBy = "severity",
  defaultDays = 90, defaultChartType = "area", height = 260, compact = false,
}) {
  const [groupBy, setGroupBy] = useState(defaultGroupBy);
  const [days, setDays] = useState(defaultDays);
  const [chartType, setChartType] = useState(defaultChartType);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    const range = RANGE_OPTIONS.find(r => r.value === days) || RANGE_OPTIONS[1];
    const params = { days, granularity: range.granularity, group_by: groupBy, ...filters };
    api.get("/v1/charts/findings-timeseries", { params })
      .then(r => setData(r.data))
      .catch(() => setData(null))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [groupBy, days, JSON.stringify(filters)]);

  const tickFmt = (s) => s ? s.slice(5) : s;

  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
      <div className="px-4 py-2.5 border-b border-[#30363D] flex items-center justify-between flex-wrap gap-2">
        <h3 className="text-[11px] uppercase tracking-wider text-slate-400 font-mono">{title}</h3>
        <div className="flex items-center gap-1.5">
          <select value={groupBy} onChange={e => setGroupBy(e.target.value)}
            className="h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11px] text-slate-300">
            {GROUP_BY_OPTIONS.map(o => <option key={o.value} value={o.value}>By {o.label}</option>)}
          </select>
          <select value={days} onChange={e => setDays(Number(e.target.value))}
            className="h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11px] text-slate-300">
            {RANGE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>
          {!compact && (
            <select value={chartType} onChange={e => setChartType(e.target.value)}
              className="h-7 bg-[#161B22] border border-[#30363D] rounded px-1.5 text-[11px] text-slate-300">
              {CHART_TYPES.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          )}
        </div>
      </div>
      <div className="p-3" style={{ height }}>
        {loading ? (
          <div className="h-full flex items-center justify-center text-[12px] text-slate-500">Loading…</div>
        ) : !data || data.total === 0 ? (
          <div className="h-full flex items-center justify-center text-[12px] text-slate-500">No findings in this range.</div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            {chartType === "bar" ? (
              <BarChart data={data.series}>
                <CartesianGrid stroke="#30363D" strokeDasharray="2 2"/>
                <XAxis dataKey="date" stroke="#8B949E" fontSize={10} tickFormatter={tickFmt}/>
                <YAxis stroke="#8B949E" fontSize={10}/>
                <Tooltip contentStyle={{ background: "#0D1117", border: "1px solid #30363D", fontSize: 12 }}/>
                {!compact && <Legend wrapperStyle={{ fontSize: 11 }}/>}
                {data.keys.map(k => <Bar key={k} dataKey={k} stackId="s" fill={data.colors[k]}/>)}
              </BarChart>
            ) : chartType === "line" ? (
              <LineChart data={data.series}>
                <CartesianGrid stroke="#30363D" strokeDasharray="2 2"/>
                <XAxis dataKey="date" stroke="#8B949E" fontSize={10} tickFormatter={tickFmt}/>
                <YAxis stroke="#8B949E" fontSize={10}/>
                <Tooltip contentStyle={{ background: "#0D1117", border: "1px solid #30363D", fontSize: 12 }}/>
                {!compact && <Legend wrapperStyle={{ fontSize: 11 }}/>}
                {data.keys.map(k => <Line key={k} type="monotone" dataKey={k} stroke={data.colors[k]} dot={false} strokeWidth={2}/>)}
              </LineChart>
            ) : (
              <AreaChart data={data.series}>
                <CartesianGrid stroke="#30363D" strokeDasharray="2 2"/>
                <XAxis dataKey="date" stroke="#8B949E" fontSize={10} tickFormatter={tickFmt}/>
                <YAxis stroke="#8B949E" fontSize={10}/>
                <Tooltip contentStyle={{ background: "#0D1117", border: "1px solid #30363D", fontSize: 12 }}/>
                {!compact && <Legend wrapperStyle={{ fontSize: 11 }}/>}
                {data.keys.map(k => (
                  <Area key={k} type="monotone" dataKey={k} stackId="s" stroke={data.colors[k]} fill={data.colors[k]} fillOpacity={0.55}/>
                ))}
              </AreaChart>
            )}
          </ResponsiveContainer>
        )}
      </div>
    </div>
  );
}
