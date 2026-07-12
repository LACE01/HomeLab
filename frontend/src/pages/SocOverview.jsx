import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Siren, ShieldWarning, Fingerprint, Binoculars, Database, Virus,
  FirstAidKit, ArrowSquareOut,
} from "@phosphor-icons/react";

const RANGE_OPTIONS = [
  { value: "7d", label: "Last 7 days" },
  { value: "30d", label: "Last 30 days" },
  { value: "90d", label: "Last 90 days" },
];

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "Info"];
const SEVERITY_COLOR = { Critical: "red", High: "orange", Medium: "amber", Low: "blue", Info: "slate" };

export default function SocOverview() {
  const [range, setRange] = useState("7d");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  const load = async (r) => {
    setLoading(true);
    try {
      const resp = await api.get("/v1/dashboards/soc", { params: { range: r } });
      setData(resp.data);
    } catch (e) {
      toast.error("Failed to load SOC overview");
    } finally { setLoading(false); }
  };

  useEffect(() => { load(range); }, [range]);

  return (
    <Layout title="SOC Overview"
      subtitle="One pane across alerts, auth security, UEBA, threat intel, connectors, and IR -- each card links to its full module"
      actions={
        <select value={range} onChange={e => setRange(e.target.value)}
          className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-300">
          {RANGE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
        </select>
      }>
      {loading || !data ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3.5">
          <Card title="Security Alerts" icon={Siren} to="/alerts" iconColor="text-red-400">
            <div className="flex flex-wrap gap-1.5 mb-3">
              {SEVERITY_ORDER.filter(s => data.events.open_by_severity[s]).map(s => (
                <Chip key={s} color={SEVERITY_COLOR[s]}>{s}: {data.events.open_by_severity[s]}</Chip>
              ))}
              {Object.keys(data.events.open_by_severity).length === 0 && (
                <span className="text-[12px] text-slate-500">No open alerts</span>
              )}
            </div>
            <MetricRow label="Correlated (multi-source)" value={data.events.correlated_open} highlight={data.events.correlated_open > 0}/>
            <MetricRow label="New events in range" value={data.events.events_in_range}/>
            <MetricRow label="Avg time to acknowledge" value={data.events.mtta_minutes != null ? `${data.events.mtta_minutes} min` : "—"}/>
            <MetricRow label="Avg time to close" value={data.events.mttr_hours != null ? `${data.events.mttr_hours} hr` : "—"}/>
          </Card>

          <Card title="Auth & Sessions" icon={Fingerprint} to="/security" iconColor="text-blue-400">
            <MetricRow label="Brute-force attempts blocked" value={data.auth.brute_force_events} highlight={data.auth.brute_force_events > 0}/>
            <MetricRow label="Active sessions" value={data.auth.active_sessions}/>
            <MetricRow label="MFA adoption" value={`${data.auth.mfa_adoption_pct}% (${data.auth.mfa_users}/${data.auth.total_users})`}/>
          </Card>

          <Card title="User & Entity Behavior" icon={ShieldWarning} to="/alerts" iconColor="text-amber-400">
            <MetricRow label="Impossible travel flags" value={data.ueba.impossible_travel} highlight={data.ueba.impossible_travel > 0}/>
            <MetricRow label="New-country logins" value={data.ueba.new_country_logins}/>
            <MetricRow label="New-IP logins" value={data.ueba.new_ip_logins}/>
          </Card>

          <Card title="Threat Intel Watchlist" icon={Binoculars} to="/admin/threat-intel" iconColor="text-purple-400">
            <MetricRow label="IOCs tracked" value={data.threat_intel.watchlist_total}/>
            <MetricRow label="IOCs that have matched" value={data.threat_intel.watchlist_with_hits}/>
            <MetricRow label="Matches in range" value={data.threat_intel.matches_in_range} highlight={data.threat_intel.matches_in_range > 0}/>
          </Card>

          <Card title="SIEM Connectors" icon={Database} to="/admin/splunk" iconColor="text-cyan-400">
            <ConnectorRow label="Splunk" health={data.connectors.splunk}/>
            <ConnectorRow label="Wazuh" health={data.connectors.wazuh}/>
          </Card>

          <Card title="YARA File Scanning" icon={Virus} to="/admin/yara" iconColor="text-rose-400">
            <MetricRow label="Scans with a match in range" value={data.yara.matches_in_range} highlight={data.yara.matches_in_range > 0}/>
          </Card>

          <Card title="Incident Response" icon={FirstAidKit} to="/ir/cases" iconColor="text-orange-400">
            <MetricRow label="Open cases" value={data.ir.open_cases} highlight={data.ir.open_cases > 0}/>
            <MetricRow label="Opened in range" value={data.ir.opened_in_range}/>
          </Card>
        </div>
      )}
    </Layout>
  );
}

function Card({ title, icon: Icon, to, iconColor, children }) {
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3.5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Icon size={16} className={iconColor}/>
          <span className="text-[13.5px] text-slate-100 font-medium">{title}</span>
        </div>
        <Link to={to} className="text-slate-500 hover:text-slate-200" title={`Open ${title}`}>
          <ArrowSquareOut size={14}/>
        </Link>
      </div>
      {children}
    </div>
  );
}

function MetricRow({ label, value, highlight }) {
  return (
    <div className="flex items-center justify-between py-1 text-[12.5px]">
      <span className="text-slate-500">{label}</span>
      <span className={highlight ? "text-amber-300 font-medium" : "text-slate-200"}>{value}</span>
    </div>
  );
}

function ConnectorRow({ label, health }) {
  return (
    <div className="flex items-center justify-between py-1 text-[12.5px]">
      <span className="text-slate-500">{label}</span>
      <span className="flex items-center gap-1.5">
        <span className="text-slate-200">{health.enabled}/{health.configured} enabled</span>
        {health.failing > 0 && <Chip color="red">{health.failing} failing</Chip>}
      </span>
    </div>
  );
}
