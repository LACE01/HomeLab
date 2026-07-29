import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Crosshair, ShieldCheck, ArrowsClockwise, CaretDown, CaretRight, Plus, Trash,
  Warning, Prohibit, ArrowRight, Copy, ListChecks,
} from "@phosphor-icons/react";

const SEV_COLOR = { Critical: "red", High: "orange", Medium: "amber", Low: "blue" };
const BLOCKED_ACTIONS = ["block", "drop", "challenge", "managed_challenge", "jschallenge"];

const TABS = [
  { id: "observations", label: "Observations", icon: Crosshair },
  { id: "rules", label: "Drafted WAF Rules", icon: ShieldCheck },
  { id: "indicators", label: "Auto Indicators", icon: Warning },
  { id: "allowlist", label: "Allowlist", icon: ListChecks },
];

export default function AttackTelemetry() {
  const [tab, setTab] = useState("observations");
  const [status, setStatus] = useState(null);
  const [summary, setSummary] = useState(null);
  const [ingesting, setIngesting] = useState(false);

  const load = () => {
    api.get("/v1/attack-telemetry/status").then(r => setStatus(r.data)).catch(() => {});
    api.get("/v1/attack-telemetry/summary").then(r => setSummary(r.data)).catch(() => {});
  };
  useEffect(() => { load(); }, []);

  const ingest = async () => {
    setIngesting(true);
    try {
      const r = await api.post("/v1/attack-telemetry/ingest", { minutes: 60 });
      toast.success(`${r.data.classified} attack(s) classified from ${r.data.firewall_events + r.data.http_requests} request(s)`);
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Ingest failed"); }
    finally { setIngesting(false); }
  };

  return (
    <Layout title="Attack Surface Telemetry"
      subtitle="Live exploitation monitoring from Cloudflare — decoded, classified, correlated against your assets and open findings, and turned into reviewable defenses"
      actions={
        <button onClick={ingest} disabled={ingesting || !status?.configured}
          className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded inline-flex items-center gap-1.5">
          <ArrowsClockwise size={13} className={ingesting ? "animate-spin" : ""}/> {ingesting ? "Polling…" : "Poll now"}
        </button>
      }>

      {status && !status.configured && (
        <div className="border border-amber-500/30 bg-amber-500/5 rounded-md px-3.5 py-3 mb-4 text-[12px] text-amber-200">
          Cloudflare isn&apos;t configured. Add an API token with <span className="font-mono">Analytics:Read</span> on the
          zone, plus the zone ID, under Integrations → Cloudflare. Works on Free and Pro — both the firewall-events
          and HTTP-requests datasets are available to every plan through the GraphQL API.
        </div>
      )}

      {status?.retention && !status.retention.error && (
        <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3.5 py-2.5 mb-4 text-[11.5px] text-blue-200 leading-relaxed">
          Cloudflare keeps firewall events for {status.retention.firewall_events_retention_hours}h and HTTP requests
          for {status.retention.http_requests_retention_hours}h on this zone, so <strong>this database is the system of
          record</strong> — polling every {status.retention.recommended_poll_minutes} minutes builds unlimited history
          from that short window. Records here are kept {status.local_retention_days} days
          (they contain client IPs and full URLs); confirmed and high-risk ones are kept regardless.
        </div>
      )}

      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 mb-4">
          <Stat label="Attack observations" value={summary.observations}/>
          <Stat label="Total hits" value={summary.total_hits}/>
          <Stat label="Reached origin" value={summary.reached_origin_hits} tone={summary.reached_origin_hits ? "red" : null}/>
          <Stat label="Blocked by CF" value={summary.blocked_hits} tone="emerald"/>
          <Stat label="Match an open vuln" value={summary.attacks_matching_open_vulnerability}
            tone={summary.attacks_matching_open_vulnerability ? "red" : null}/>
          <Stat label="High risk (≥70)" value={summary.high_risk} tone={summary.high_risk ? "amber" : null}/>
        </div>
      )}

      <div className="flex items-center gap-1 border-b border-[#30363D] mb-4 overflow-x-auto">
        {TABS.map(t => {
          const Icon = t.icon;
          return (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`h-9 px-3 text-[12.5px] inline-flex items-center gap-1.5 border-b-2 -mb-px whitespace-nowrap ${
                tab === t.id ? "border-blue-500 text-blue-300" : "border-transparent text-slate-400 hover:text-slate-200"}`}>
              <Icon size={14}/> {t.label}
            </button>
          );
        })}
      </div>

      {tab === "observations" && <Observations summary={summary} onChange={load}/>}
      {tab === "rules" && <WafRules onChange={load}/>}
      {tab === "indicators" && <AutoIndicators onChange={load}/>}
      {tab === "allowlist" && <Allowlist onChange={load}/>}
    </Layout>
  );
}

function Stat({ label, value, tone }) {
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-3.5 py-3">
      <div className="text-[10.5px] text-slate-500 uppercase tracking-wider">{label}</div>
      <div className={`text-[20px] font-semibold mt-0.5 ${tone === "red" ? "text-red-300" : tone === "amber" ? "text-amber-300" : tone === "emerald" ? "text-emerald-300" : "text-slate-100"}`}>
        {value ?? 0}
      </div>
    </div>
  );
}

function Observations({ summary, onChange }) {
  const [items, setItems] = useState([]);
  const [filter, setFilter] = useState("all");   // all | origin | blocked | vuln
  const [expanded, setExpanded] = useState(new Set());

  const load = () => {
    const params = {};
    if (filter === "origin") params.reached_origin = true;
    if (filter === "blocked") params.reached_origin = false;
    if (filter === "vuln") params.min_score = 70;
    api.get("/v1/attack-telemetry/observations", { params }).then(r => setItems(r.data.items || []));
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [filter]);

  const setStatus = async (o, status) => {
    await api.patch(`/v1/attack-telemetry/observations/${o.id}`, { status });
    load(); onChange();
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-1.5 flex-wrap">
        {[["all", "All"], ["origin", "Reached origin"], ["blocked", "Blocked by Cloudflare"], ["vuln", "High risk (≥70)"]].map(([id, label]) => (
          <button key={id} onClick={() => setFilter(id)}
            className={`h-7 px-2.5 text-[11.5px] rounded border ${filter === id
              ? "bg-blue-500/15 border-blue-500/40 text-blue-300" : "border-[#30363D] text-slate-400 hover:border-slate-500"}`}>
            {label}
          </button>
        ))}
        {summary?.top_sources?.length > 0 && (
          <span className="text-[11px] text-slate-500 ml-2">
            Top source: <span className="font-mono text-slate-400">{summary.top_sources[0].key}</span> ({summary.top_sources[0].count} hits)
          </span>
        )}
      </div>

      {items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No attack observations yet. Poll Cloudflare to pull the most recent window.
        </div>
      ) : items.map(o => {
        const isOpen = expanded.has(o.id);
        const blocked = BLOCKED_ACTIONS.includes((o.cf_action || "").toLowerCase());
        return (
          <div key={o.id} className="border border-[#30363D] bg-[#0D1117] rounded-md">
            <div className="px-4 py-2.5 cursor-pointer"
              onClick={() => setExpanded(p => { const n = new Set(p); n.has(o.id) ? n.delete(o.id) : n.add(o.id); return n; })}>
              <div className="flex items-center gap-2 flex-wrap">
                {isOpen ? <CaretDown size={12} className="text-slate-500"/> : <CaretRight size={12} className="text-slate-500"/>}
                <Chip color={SEV_COLOR[o.severity] || "slate"}>{o.severity}</Chip>
                <span className="text-[12.5px] text-slate-200">{(o.attack_type || "").replace(/_/g, " ")}</span>
                <span className="font-mono text-[11.5px] text-slate-400">{o.source_ip}</span>
                <ArrowRight size={11} className="text-slate-600"/>
                <span className="font-mono text-[11.5px] text-slate-400 truncate max-w-[280px]">{o.host}{o.path}</span>
                {blocked
                  ? <Chip color="emerald"><Prohibit size={10}/> blocked</Chip>
                  : <Chip color="red">reached origin{o.last_origin_status ? ` (${o.last_origin_status})` : ""}</Chip>}
                {o.has_matching_vulnerability && <Chip color="red">matches an open vuln</Chip>}
                {o.hit_count > 1 && <Chip color="slate">×{o.hit_count}</Chip>}
                <span className="ml-auto text-[12px] text-slate-300 font-mono">{o.business_risk_score}</span>
              </div>
            </div>
            {isOpen && (
              <div className="border-t border-[#30363D] px-4 py-3 space-y-2.5 text-[11.5px]">
                <div className="grid sm:grid-cols-2 gap-2">
                  <Field label="ATT&CK">{o.attack_technique} · {o.attack_tactic}</Field>
                  <Field label="Confidence">{Math.round((o.confidence || 0) * 100)}%{o.was_encoded ? " (payload was encoded)" : ""}</Field>
                  <Field label="Source">{o.source_ip} · AS{o.asn} · {o.country}</Field>
                  <Field label="Cloudflare action">{o.cf_action}{o.cf_rule_id ? ` (${o.cf_rule_id})` : ""}</Field>
                  <Field label="Method / UA">{o.method} · {o.user_agent}</Field>
                  <Field label="First / last seen">
                    {new Date(o.first_seen_at).toLocaleString()} → {new Date(o.last_seen_at).toLocaleString()}
                  </Field>
                </div>
                <div>
                  <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-1">Decoded payload</div>
                  <pre className="text-[11px] text-amber-200 bg-[#161B22] border border-[#30363D] rounded p-2 whitespace-pre-wrap break-all max-h-40 overflow-y-auto">
                    {o.decoded_payload}
                  </pre>
                </div>
                {o.matched_signatures?.length > 0 && (
                  <div className="text-[11px] text-slate-500">
                    Matched: {o.matched_signatures.map((m, i) => (
                      <span key={i} className="font-mono text-slate-400 mr-2">{m.attack_type}:{m.matched}</span>
                    ))}
                  </div>
                )}
                {o.asset_id && (
                  <div>
                    <Link to={`/assets/${o.asset_id}`} className="text-blue-300 hover:underline">
                      Target asset: {o.asset_hostname} ({o.asset_criticality}) →
                    </Link>
                    {o.matching_finding_ids?.length > 0 && (
                      <span className="text-red-300 ml-2">
                        {o.matching_finding_ids.length} open finding(s) on this host match this technique
                      </span>
                    )}
                  </div>
                )}
                {Object.keys(o.source_reputation || {}).length > 0 && (
                  <div className="text-[11px] text-slate-500">
                    Source reputation: {JSON.stringify(o.source_reputation)}
                  </div>
                )}
                <div className="flex gap-1.5">
                  {["investigating", "confirmed", "dismissed"].map(s => (
                    <button key={s} onClick={() => setStatus(o, s)}
                      className={`h-7 px-2.5 text-[11px] rounded border capitalize ${o.status === s
                        ? "bg-blue-500/15 border-blue-500/40 text-blue-300" : "border-[#30363D] text-slate-400"}`}>
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function Field({ label, children }) {
  return (
    <div>
      <span className="text-slate-500">{label}: </span>
      <span className="text-slate-300">{children}</span>
    </div>
  );
}

function WafRules({ onChange }) {
  const [items, setItems] = useState([]);
  const load = () => api.get("/v1/attack-telemetry/waf-rules").then(r => setItems(r.data.items || []));
  useEffect(() => { load(); }, []);

  const decide = async (r, status) => {
    await api.patch(`/v1/attack-telemetry/waf-rules/${r.id}`, { status });
    toast.success(`Rule ${status}`);
    load(); onChange();
  };
  const exportRules = async () => {
    const r = await api.get("/v1/attack-telemetry/waf-rules/export");
    navigator.clipboard.writeText(r.data.text);
    toast.success(`${r.data.count} approved rule(s) copied`);
  };

  return (
    <div className="space-y-3">
      <div className="border border-amber-500/30 bg-amber-500/5 rounded-md px-3.5 py-2.5 text-[12px] text-amber-200 flex items-start justify-between gap-3">
        <div>
          Rules are <strong>drafted, never applied automatically</strong>. Blocking traffic on a classifier match alone
          is how you take your own site offline — a human approves every rule, and approved rules export as
          Cloudflare expressions for you to paste into a custom ruleset.
        </div>
        <button onClick={exportRules}
          className="h-7 px-2.5 text-[11.5px] border border-amber-500/40 text-amber-200 rounded inline-flex items-center gap-1 shrink-0">
          <Copy size={11}/> Export approved
        </button>
      </div>
      {items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No rules drafted yet.
        </div>
      ) : items.map(r => (
        <div key={r.id} className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3">
          <div className="flex items-center gap-2 flex-wrap">
            <Chip color={r.status === "approved" ? "emerald" : r.status === "rejected" ? "slate" : "amber"}>{r.status}</Chip>
            {r.auto_eligible && <Chip color="blue">auto-eligible (still needs a click)</Chip>}
            <span className="font-mono text-[11.5px] text-slate-300">{r.expression}</span>
            <span className="text-[11.5px] text-slate-500">→ {r.action}</span>
            <span className="ml-auto text-[10.5px] text-slate-600">{r.observation_count} observation(s)</span>
          </div>
          <div className="text-[12px] text-slate-400 mt-1">{r.description}</div>
          <div className="text-[10.5px] text-slate-600 mt-0.5">
            {r.rationale?.attack_type} · {r.rationale?.attack_technique} · confidence {r.rationale?.confidence} ·
            {" "}{r.rationale?.prior_observations} prior observation(s) from this source
            {r.rationale?.has_matching_vulnerability ? " · target has a matching open vulnerability" : ""}
          </div>
          {r.decided_by && (
            <div className="text-[10.5px] text-slate-500 mt-1">{r.status} by {r.decided_by} on {new Date(r.decided_at).toLocaleString()}</div>
          )}
          {r.status === "draft" && (
            <div className="flex gap-1.5 mt-2">
              <button onClick={() => decide(r, "approved")}
                className="h-7 px-2.5 text-[11.5px] border border-emerald-500/40 text-emerald-300 rounded">Approve</button>
              <button onClick={() => decide(r, "rejected")}
                className="h-7 px-2.5 text-[11.5px] border border-[#30363D] text-slate-400 rounded">Reject</button>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function AutoIndicators({ onChange }) {
  const [items, setItems] = useState([]);
  const load = () => api.get("/v1/attack-telemetry/auto-indicators").then(r => setItems(r.data.items || []));
  useEffect(() => { load(); }, []);

  const review = async (i, review_status) => {
    const note = review_status === "false_positive"
      ? (window.prompt("Why is this a false positive? (it will be allowlisted)") || "")
      : "";
    if (review_status === "false_positive" && note === null) return;
    await api.post(`/v1/attack-telemetry/auto-indicators/${i.value}/review`, { review_status, note });
    toast.success(review_status === "confirmed" ? "Promoted to a reviewed indicator" : "Removed and allowlisted");
    load(); onChange();
  };

  return (
    <div className="space-y-3">
      <div className="text-[11.5px] text-slate-500 max-w-3xl">
        Source IPs auto-added from exploit-classified requests. Every one is confidence-tagged and carries the full
        reasoning, so a false positive can be downgraded — which also allowlists it so the next poll doesn&apos;t
        re-add it.
      </div>
      {items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          None yet.
        </div>
      ) : items.map(i => (
        <div key={i.id} className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-[12.5px] text-slate-200">{i.value}</span>
            <Chip color={SEV_COLOR[i.severity] || "slate"}>{i.severity}</Chip>
            <Chip color={i.review_status === "confirmed" ? "emerald" : "amber"}>{i.review_status || "unreviewed"}</Chip>
            <span className="text-[11px] text-slate-500">confidence {Math.round((i.confidence || 0) * 100)}%</span>
          </div>
          <div className="text-[11.5px] text-slate-400 mt-1">{i.notes}</div>
          {i.detail && (
            <div className="text-[10.5px] text-slate-500 mt-1">
              {i.detail.attack_type} · {i.detail.attack_technique} · target {i.detail.target_host}{i.detail.target_path} ·
              {" "}observed {i.detail.observed_at ? new Date(i.detail.observed_at).toLocaleString() : "?"}
              {i.detail.decoded_payload && (
                <pre className="mt-1 text-[10.5px] text-amber-200/80 bg-[#161B22] border border-[#30363D] rounded p-1.5 whitespace-pre-wrap break-all max-h-24 overflow-y-auto">
                  {i.detail.decoded_payload}
                </pre>
              )}
            </div>
          )}
          {i.review_status !== "confirmed" && (
            <div className="flex gap-1.5 mt-2">
              <button onClick={() => review(i, "confirmed")}
                className="h-7 px-2.5 text-[11.5px] border border-emerald-500/40 text-emerald-300 rounded">Confirm</button>
              <button onClick={() => review(i, "false_positive")}
                className="h-7 px-2.5 text-[11.5px] border border-[#30363D] text-slate-400 rounded">False positive</button>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function Allowlist({ onChange }) {
  const [items, setItems] = useState([]);
  const [form, setForm] = useState({ value: "", label: "", reason: "" });
  const load = () => api.get("/v1/attack-telemetry/allowlist").then(r => setItems(r.data.items || []));
  useEffect(() => { load(); }, []);

  const add = async () => {
    try {
      await api.post("/v1/attack-telemetry/allowlist", form);
      setForm({ value: "", label: "", reason: "" });
      load(); onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed"); }
  };

  return (
    <div className="space-y-3 max-w-3xl">
      <div className="text-[11.5px] text-slate-500">
        Source IPs and CIDR ranges checked <strong>before</strong> any enrichment or indicator creation — your own
        scanners, partner integrations, and office egress. Traffic from these is still recorded, but never escalated,
        so the platform can&apos;t flag itself.
      </div>
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3.5">
        <div className="grid sm:grid-cols-3 gap-2">
          <input placeholder="203.0.113.7 or 10.0.0.0/8" value={form.value}
            onChange={e => setForm({ ...form, value: e.target.value })}
            className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200 font-mono"/>
          <input placeholder="Label (e.g. office egress)" value={form.label}
            onChange={e => setForm({ ...form, label: e.target.value })}
            className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200"/>
          <input placeholder="Reason" value={form.reason}
            onChange={e => setForm({ ...form, reason: e.target.value })}
            className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200"/>
        </div>
        <button onClick={add} disabled={!form.value.trim()}
          className="mt-2 h-7 px-2.5 text-[11.5px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded inline-flex items-center gap-1">
          <Plus size={11}/> Add
        </button>
      </div>
      {items.map(i => (
        <div key={i.id} className="border border-[#30363D] bg-[#0D1117] rounded px-3 py-2 flex items-center gap-2 text-[12px]">
          <span className="font-mono text-slate-200">{i.value}</span>
          {i.label && <Chip color="slate">{i.label}</Chip>}
          <span className="text-slate-500">{i.reason}</span>
          <button onClick={async () => { await api.delete(`/v1/attack-telemetry/allowlist/${i.id}`); load(); onChange(); }}
            className="ml-auto text-slate-600 hover:text-red-400"><Trash size={12}/></button>
        </div>
      ))}
    </div>
  );
}
