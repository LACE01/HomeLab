import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { SevBadge, Chip, RiskBar } from "@/components/Badges";
import { fmtDate, fmtRel, isOverdue } from "@/lib/utils-fmt";
import { ArrowLeft, ChatCircle, ClockCounterClockwise, Ticket, Shield } from "@phosphor-icons/react";

const Section = ({ title, children, testid }) => (
  <div data-testid={testid} className="border border-[#30363D] bg-[#0D1117] rounded-md">
    <div className="px-4 py-2 border-b border-[#30363D]"><h3 className="text-[11px] uppercase tracking-wider font-mono text-slate-400">{title}</h3></div>
    <div className="p-4">{children}</div>
  </div>
);

const KV = ({ k, v, mono }) => (
  <div className="flex justify-between gap-3 py-1 border-b border-[#30363D]/50 last:border-0">
    <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500">{k}</div>
    <div className={`text-[12.5px] text-slate-200 text-right ${mono ? "font-mono" : ""}`}>{v ?? "—"}</div>
  </div>
);

export default function FindingDetail() {
  const { id } = useParams();
  const [f, setF] = useState(null);
  const [tickets, setTickets] = useState([]);
  const [obs, setObs] = useState([]);
  const [activity, setActivity] = useState([]);
  const [comments, setComments] = useState([]);
  const [newComment, setNewComment] = useState("");
  const [statusVal, setStatusVal] = useState("");
  const [kri, setKri] = useState(null);
  const [intel, setIntel] = useState(null);

  useEffect(() => {
    api.get(`/v1/findings/${id}`).then(r => { setF(r.data); setStatusVal(r.data.status); });
    api.get(`/v1/findings/${id}/tickets`).then(r => setTickets(r.data.items));
    api.get(`/v1/findings/${id}/observations`).then(r => setObs(r.data.items));
    api.get(`/v1/findings/${id}/timeline`).then(r => setActivity(r.data.items));
    api.get(`/v1/findings/${id}/comments`).then(r => setComments(r.data.items));
    api.get(`/v1/findings/${id}/kri`).then(r => setKri(r.data));
  }, [id]);

  useEffect(() => {
    if (f?.cve) api.get(`/v1/threat-intel/${f.cve}`).then(r => setIntel(r.data));
  }, [f?.cve]);

  const updateStatus = async (s) => {
    await api.patch(`/v1/findings/${id}/status`, { status: s });
    setStatusVal(s);
    const r = await api.get(`/v1/findings/${id}/timeline`); setActivity(r.data.items);
  };

  const addComment = async () => {
    if (!newComment.trim()) return;
    await api.post(`/v1/findings/${id}/comments`, { text: newComment });
    setNewComment("");
    const r = await api.get(`/v1/findings/${id}/comments`); setComments(r.data.items);
  };

  if (!f) return <Layout title="Finding…"><div className="text-slate-500">Loading…</div></Layout>;

  return (
    <Layout title={f.title?.slice(0,90)} subtitle={`${f.cve || f.source_native_id} · ${f.source_tool}`}
      actions={<Link to="/findings" className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300"><ArrowLeft size={14}/> Back</Link>}>

      <div className="flex flex-wrap gap-2 mb-4">
        <SevBadge severity={f.severity} />
        {f.kev_flag && <Chip color="red">KEV — actively exploited</Chip>}
        {f.cve && <Chip color="slate">{f.cve}</Chip>}
        {f.cwe && <Chip color="slate">{f.cwe}</Chip>}
        {f.internet_facing && <Chip color="orange">Internet Facing</Chip>}
        {f.patch_available === false && <Chip color="amber">No Patch Available</Chip>}
        {(f.rti || []).map(r => <Chip key={r} color="red">{r.replace(/_/g," ").toUpperCase()}</Chip>)}
        {(f.compliance_scope || []).map(c => <Chip key={c} color="blue">{c}</Chip>)}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 space-y-4">
          <Section title="Description" testid="section-description">
            <div className="text-[13px] text-slate-200 leading-relaxed whitespace-pre-wrap">{f.description}</div>
          </Section>

          <Section title="Consequence if Unpatched" testid="section-consequence">
            <div className="text-[13px] text-slate-300 leading-relaxed">{f.consequence}</div>
          </Section>

          <Section title="Business Impact" testid="section-impact">
            <div className="text-[13px] text-slate-300 leading-relaxed">{f.business_impact}</div>
          </Section>

          <Section title="Remediation Guidance" testid="section-remediation">
            <div className="text-[13px] text-slate-200 leading-relaxed">{f.remediation}</div>
            {f.compensating_controls && <div className="mt-2 text-[12px] text-slate-400">Compensating controls: {f.compensating_controls}</div>}
          </Section>

          <Section title="Detection Logic" testid="section-detection">
            <div className="text-[12.5px] text-slate-300 leading-relaxed font-mono whitespace-pre-wrap">{f.detection_logic}</div>
          </Section>

          <Section title="MITRE ATT&CK Mapping">
            <KV k="Tactic" v={f.mitre_tactic} />
            <KV k="Technique" v={f.mitre_technique} />
          </Section>

          <Section title="Risk Score Breakdown" testid="section-breakdown">
            <div className="flex items-center gap-3 mb-3">
              <div className="text-[36px] font-mono font-semibold text-blue-300">{f.risk_score}</div>
              <div className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">/ 100 risk score</div>
            </div>
            <table className="dense w-full">
              <thead><tr><th className="text-left">Factor</th><th className="text-right">Points</th><th className="text-left">Reason</th></tr></thead>
              <tbody>
                {(f.risk_breakdown || []).map((b, i) => (
                  <tr key={i} className="border-t border-[#30363D]"><td className="text-slate-200">{b.factor}</td><td className="text-right font-mono text-slate-200">+{b.points}</td><td className="text-slate-400">{b.reason}</td></tr>
                ))}
              </tbody>
            </table>
          </Section>

          {kri && (
            <Section title="Empirical Score (KRI / ZDES / BII)" testid="section-empirical">
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-3">
                <div className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                  <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider">Empirical %ile</div>
                  <div className="text-[22px] font-mono font-semibold text-red-300 mt-0.5" data-testid="empirical-pct">{(100-kri.empirical.top_pct).toFixed(1)}%</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Top {kri.empirical.top_pct}%</div>
                </div>
                <div className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                  <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider">KRI</div>
                  <div className="text-[22px] font-mono font-semibold text-blue-300 mt-0.5">{kri.kri_score}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">EPSS × CVSS × CWE</div>
                </div>
                <div className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                  <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider">ZDES</div>
                  <div className="text-[22px] font-mono font-semibold text-amber-300 mt-0.5">{kri.zdes_score}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Zero-day exposure</div>
                </div>
                <div className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                  <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider">BII (Patch ROI)</div>
                  <div className="text-[22px] font-mono font-semibold text-emerald-300 mt-0.5">{kri.bii_score}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">{kri.patch_hours_estimated}h est. effort</div>
                </div>
              </div>
              <div className="flex items-center gap-2 mb-3">
                <span className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">Urgency Tier:</span>
                <Chip color={kri.urgency_tier==="Urgent"?"red":kri.urgency_tier==="Standard"?"amber":"slate"}>{kri.urgency_tier}</Chip>
              </div>
              <div className="text-[11px] font-mono text-slate-500 mb-3 leading-relaxed">
                <span className="text-slate-400">Due basis:</span> {kri.due_basis}
              </div>

              <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider mb-2">Critical Indicators</div>
              <div className="grid grid-cols-2 lg:grid-cols-3 gap-1.5">
                {kri.critical_indicators.map(i => {
                  const sigColor = {high:"red", medium:"amber", low:"slate", none:"slate"}[i.signal];
                  const trendArrow = {up:"↑", down:"↓", flat:"→", unknown:"·"}[i.trend];
                  const trendColor = i.trend==="up"?"text-red-300":i.trend==="down"?"text-emerald-300":"text-slate-500";
                  return (
                    <div key={i.key} className="flex items-center justify-between border border-[#30363D] rounded px-2 py-1.5 bg-[#161B22]">
                      <span className="text-[12px] text-slate-200">{i.label}</span>
                      <div className="flex items-center gap-1.5">
                        <Chip color={sigColor}>{i.signal}</Chip>
                        <span className={`font-mono text-[14px] ${trendColor}`}>{trendArrow}</span>
                      </div>
                    </div>
                  );
                })}
              </div>

              {kri.empirical.distribution?.length > 0 && (
                <div className="mt-4">
                  <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider mb-1">Score Distribution (cohort: same severity)</div>
                  <div className="flex items-end gap-0.5 h-12">
                    {kri.empirical.distribution.map((v, i) => {
                      const max = Math.max(...kri.empirical.distribution, 1);
                      const h = Math.max(2, (v / max) * 100);
                      const myBucket = Math.floor((kri.kri_score * 20) / Math.max(...kri.empirical.distribution.map((_,idx)=>idx+1), 1));
                      return <div key={i} className={`flex-1 ${i===myBucket?"bg-red-400":"bg-slate-700"}`} style={{height:`${h}%`}}/>;
                    })}
                  </div>
                </div>
              )}
            </Section>
          )}

          {f.cve && intel && (
            <Section title="Threat Intelligence (OpenCTI)" testid="section-threat-intel">
              {!intel.configured && (
                <div className="text-[12.5px] text-amber-300 bg-amber-900/10 border border-amber-500/30 rounded p-2.5">
                  {intel.message}
                  <div className="text-[11px] text-slate-400 mt-1">Go to Integrations → OpenCTI → Configure (endpoint + api_key).</div>
                </div>
              )}
              {intel.error && (
                <div className="text-[12px] text-red-300">OpenCTI error: {intel.error}</div>
              )}
              {intel.configured && !intel.error && (
                <div className="space-y-2">
                  <KV k="Threat Actors" v={intel.threat_actors?.join(", ") || "—"}/>
                  <KV k="Intrusion Sets" v={intel.intrusion_sets?.join(", ") || "—"}/>
                  <KV k="Malware Families" v={intel.malware?.join(", ") || "—"}/>
                  <KV k="Campaigns" v={intel.campaigns?.join(", ") || "—"}/>
                  {(intel.external_references||[]).slice(0,8).map((r,i) => (
                    <a key={i} href={r.url} target="_blank" rel="noopener noreferrer" className="block text-[12px] text-blue-300 hover:underline truncate">{r.source} — {r.url}</a>
                  ))}
                </div>
              )}
            </Section>
          )}

          <Section title="Observations / Detection History" testid="section-observations">
            <table className="dense w-full">
              <thead><tr><th className="text-left">Source</th><th className="text-left">Method</th><th className="text-left">Auth</th><th className="text-left">Detected</th><th className="text-left">Record ID</th></tr></thead>
              <tbody>
                {obs.map(o => (
                  <tr key={o.id} className="border-t border-[#30363D]">
                    <td>{o.source_tool}</td><td>{o.agent_or_network}</td><td>{o.auth_state}</td>
                    <td className="font-mono text-[11px]">{fmtDate(o.observed_at)}</td>
                    <td className="font-mono text-[11px] text-slate-500">{o.source_record_id}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Section>

          <Section title="Activity / Timeline" testid="section-timeline">
            <div className="space-y-2">
              {activity.map(a => (
                <div key={a.id} className="flex gap-3 items-start text-[12.5px]">
                  <ClockCounterClockwise size={14} className="text-slate-500 mt-0.5"/>
                  <div className="flex-1">
                    <div className="text-slate-200">{a.action.replace(/_/g," ")} <span className="text-slate-500">— {a.details}</span></div>
                    <div className="text-[10.5px] font-mono text-slate-600">{a.actor} · {fmtDate(a.timestamp)}</div>
                  </div>
                </div>
              ))}
            </div>
          </Section>

          <Section title="Comments" testid="section-comments">
            <div className="space-y-2 mb-3">
              {comments.length === 0 && <div className="text-[12px] text-slate-500">No comments yet.</div>}
              {comments.map(c => (
                <div key={c.id} className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                  <div className="text-[10.5px] font-mono text-slate-500">{c.author} · {fmtDate(c.created_at)}</div>
                  <div className="text-[12.5px] text-slate-200 mt-1">{c.text}</div>
                </div>
              ))}
            </div>
            <div className="flex gap-2">
              <input data-testid="comment-input" value={newComment} onChange={(e)=>setNewComment(e.target.value)} placeholder="Add a triage note…"
                className="flex-1 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"/>
              <button data-testid="comment-add" onClick={addComment} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1">
                <ChatCircle size={14}/> Add
              </button>
            </div>
          </Section>
        </div>

        <div className="space-y-4">
          <Section title="Status & Triage" testid="section-status">
            <select data-testid="status-select" value={statusVal} onChange={(e)=>updateStatus(e.target.value)}
              className="w-full h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px]">
              {["New","Needs triage","Valid","False positive","Duplicate","Mitigated","Accepted risk","Deferred","Fixed pending validation","Fixed validated","Reopened","Out of scope","Closed administratively"].map(s => <option key={s}>{s}</option>)}
            </select>
            <div className="mt-2 grid grid-cols-2 gap-1">
              <KV k="Validation" v={f.validation_status}/>
              <KV k="Reopened" v={f.reopened_count} mono/>
            </div>
          </Section>

          <Section title="Risk Score">
            <RiskBar score={f.risk_score} />
          </Section>

          <Section title="Identifiers">
            <KV k="Internal ID" v={<span className="font-mono text-[10.5px]">{f.id}</span>} />
            <KV k="CVE" v={f.cve} mono/>
            <KV k="CWE" v={f.cwe} mono/>
            <KV k="QID" v={f.qid} mono/>
            <KV k="Plugin ID" v={f.plugin_id} mono/>
            <KV k="Source ID" v={f.source_observation_id} mono/>
          </Section>

          <Section title="Scoring">
            <KV k="CVSS v3" v={f.cvss_score} mono/>
            <KV k="CVSS Vector" v={<span className="font-mono text-[10px] break-all">{f.cvss_v3_vector}</span>} />
            <KV k="EPSS" v={f.epss_score ? (f.epss_score*100).toFixed(2)+"%" : "—"} mono/>
            <KV k="EPSS %ile" v={f.epss_percentile?.toFixed?.(1)} mono/>
          </Section>

          <Section title="Asset">
            <Link to={`/assets/${f.asset_id}`} className="text-blue-300 hover:underline font-mono text-[12.5px]">{f.asset_hostname}</Link>
            <KV k="IP" v={f.asset_ip} mono/>
            <KV k="Criticality" v={f.asset_criticality}/>
            <KV k="Exposure" v={f.asset_exposure}/>
            <KV k="Environment" v={f.asset_environment}/>
            <KV k="Owner Team" v={f.owner_team}/>
            <KV k="Ownership Confidence" v={f.ownership_confidence != null ? `${(f.ownership_confidence*100).toFixed(0)}%` : "—"} mono/>
          </Section>

          <Section title="SLA / Lifecycle">
            <KV k="First Seen" v={fmtDate(f.first_seen_at)} mono/>
            <KV k="Last Seen" v={fmtDate(f.last_seen_at)} mono/>
            <KV k="Due" v={<span className={isOverdue(f.due_at) ? "text-red-300" : "text-slate-200"}>{fmtDate(f.due_at)}</span>} mono/>
            <KV k="SLA (days)" v={f.sla_days} mono/>
            <KV k="Days Open" v={f.days_open} mono/>
          </Section>

          <Section title="Source & Detection">
            <KV k="Source Tool" v={f.source_tool}/>
            <KV k="Tool Type" v={f.source_tool_type}/>
            <KV k="Scan Method" v={f.scan_method}/>
            <KV k="Auth" v={f.scan_authenticated ? "Authenticated" : "Unauth"}/>
            <KV k="Channel" v={f.detection_channel}/>
            <KV k="Parser" v={`${f.parser_type || "—"} v${f.parser_version || "—"}`}/>
          </Section>

          <Section title="Tickets">
            {tickets.length === 0 && <div className="text-[12px] text-slate-500">No linked tickets.</div>}
            {tickets.map(t => (
              <a key={t.id} href={t.url} target="_blank" rel="noopener noreferrer"
                className="flex justify-between gap-2 py-1.5 border-b border-[#30363D]/40 last:border-0 hover:text-blue-300">
                <span className="font-mono text-[12px] text-blue-300">{t.external_id}</span>
                <span className="text-[11px] text-slate-500">{t.system} · {t.status}</span>
              </a>
            ))}
          </Section>

          <Section title="References">
            {(f.advisory_links || []).map(l => <a key={l} href={l} target="_blank" rel="noopener noreferrer" className="block text-[12px] text-blue-300 hover:underline truncate">{l}</a>)}
            {(f.exploit_references || []).map(l => <a key={l} href={l} target="_blank" rel="noopener noreferrer" className="block text-[12px] text-orange-300 hover:underline truncate">{l}</a>)}
          </Section>
        </div>
      </div>
    </Layout>
  );
}
