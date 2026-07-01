import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { SevBadge, Chip, RiskBar } from "@/components/Badges";
import { fmtDate, fmtRel, isOverdue } from "@/lib/utils-fmt";
import { ArrowLeft, ChatCircle, ClockCounterClockwise, Ticket, Shield, BookOpen, CheckCircle, ArrowCounterClockwise, Plus, ShieldCheck, X, Trash } from "@phosphor-icons/react";
import InfoTip from "@/components/InfoTip";
import { toast } from "sonner";

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

function AddMitigationForm({ types, onCancel, onAdded, findingId }) {
  const [controlType, setControlType] = useState(types?.[0] || "Other");
  const [description, setDescription] = useState("");
  const [saving, setSaving] = useState(false);
  const submit = async () => {
    if (!description.trim()) { toast.error("Description is required"); return; }
    setSaving(true);
    try {
      await api.post(`/v1/findings/${findingId}/mitigations`, { control_type: controlType, description });
      toast.success("Mitigation recorded.");
      onAdded();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to add mitigation");
    } finally { setSaving(false); }
  };
  return (
    <div className="border border-[#30363D] rounded p-2.5 bg-[#161B22] space-y-2">
      <select value={controlType} onChange={e=>setControlType(e.target.value)} data-testid="mitigation-type-select"
        className="w-full h-8 bg-[#0D1117] border border-[#30363D] rounded px-2 text-[12px] text-slate-200">
        {(types||[]).map(t => <option key={t} value={t}>{t}</option>)}
      </select>
      <textarea value={description} onChange={e=>setDescription(e.target.value)} rows={2} placeholder="What was done, and where"
        data-testid="mitigation-description" className="w-full bg-[#0D1117] border border-[#30363D] rounded px-2 py-1.5 text-[12px] text-slate-200"/>
      <div className="flex justify-end gap-2">
        <button onClick={onCancel} className="h-7 px-2.5 text-[11px] border border-[#30363D] rounded text-slate-300">Cancel</button>
        <button onClick={submit} disabled={saving} data-testid="mitigation-save"
          className="h-7 px-2.5 text-[11px] bg-blue-500/20 border border-blue-500/40 text-blue-200 rounded disabled:opacity-50">
          {saving ? "Saving…" : "Save"}
        </button>
      </div>
    </div>
  );
}

function ExceptionRequestModal({ findingId, onClose, onDone }) {
  const [justification, setJustification] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [controls, setControls] = useState("");
  const [saving, setSaving] = useState(false);
  const submit = async () => {
    if (!justification.trim() || !expiresAt) { toast.error("Justification and expiry date are required"); return; }
    setSaving(true);
    try {
      await api.post("/v1/exceptions", {
        finding_id: findingId, business_justification: justification,
        expires_at: new Date(expiresAt).toISOString(),
        compensating_controls: controls.split(",").map(s=>s.trim()).filter(Boolean),
      });
      toast.success("Exception requested -- pending approval.");
      onDone();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to request exception");
    } finally { setSaving(false); }
  };
  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-sm" onClick={e=>e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
          <h3 className="text-[13px] font-medium text-slate-100">Request risk exception</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16}/></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Business justification</label>
            <textarea value={justification} onChange={e=>setJustification(e.target.value)} rows={3}
              data-testid="exception-justification" className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200"/>
          </div>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Expires on</label>
            <input type="date" value={expiresAt} onChange={e=>setExpiresAt(e.target.value)} data-testid="exception-expires"
              className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"/>
          </div>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Compensating controls (comma-separated)</label>
            <input value={controls} onChange={e=>setControls(e.target.value)} placeholder="WAF rule, network segmentation"
              className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"/>
          </div>
        </div>
        <div className="px-4 py-3 border-t border-[#30363D] flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={submit} disabled={saving} data-testid="exception-submit"
            className="h-8 px-3 text-[12px] bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/40 text-blue-200 rounded disabled:opacity-50">
            {saving ? "Submitting…" : "Submit request"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function FindingDetail() {
  const { id } = useParams();
  const [f, setF] = useState(null);
  const [tickets, setTickets] = useState([]);
  const [obs, setObs] = useState([]);
  const [activity, setActivity] = useState([]);
  const [comments, setComments] = useState([]);
  const [newComment, setNewComment] = useState("");
  const [attachments, setAttachments] = useState([]);
  const [statusVal, setStatusVal] = useState("");
  const [kri, setKri] = useState(null);
  const [intel, setIntel] = useState(null);
  const [playbook, setPlaybook] = useState(undefined); // undefined = loading, null = none found
  const [playbookBasis, setPlaybookBasis] = useState(null);
  const [mitigations, setMitigations] = useState([]);
  const [mitigationTypes, setMitigationTypes] = useState([]);
  const [showAddMitigation, setShowAddMitigation] = useState(false);
  const [showExceptionForm, setShowExceptionForm] = useState(false);
  const [exceptions, setExceptions] = useState([]);

  const loadMitigations = () => api.get(`/v1/findings/${id}/mitigations`).then(r => { setMitigations(r.data.items); setMitigationTypes(r.data.types); });
  const loadExceptions = () => api.get("/v1/exceptions").then(r => setExceptions(r.data.items.filter(e => e.finding_id === id)));

  useEffect(() => {
    api.get(`/v1/findings/${id}`).then(r => { setF(r.data); setStatusVal(r.data.status); });
    api.get(`/v1/findings/${id}/tickets`).then(r => setTickets(r.data.items));
    api.get(`/v1/findings/${id}/observations`).then(r => setObs(r.data.items));
    api.get(`/v1/findings/${id}/timeline`).then(r => setActivity(r.data.items));
    api.get(`/v1/findings/${id}/comments`).then(r => setComments(r.data.items));
    api.get(`/v1/findings/${id}/kri`).then(r => setKri(r.data));
    api.get(`/v1/findings/${id}/playbook`).then(r => { setPlaybook(r.data.playbook); setPlaybookBasis(r.data.match_basis); });
    loadMitigations();
    loadExceptions();
  }, [id]); // eslint-disable-line

  useEffect(() => {
    if (f?.cve) api.get(`/v1/threat-intel/${f.cve}`).then(r => setIntel(r.data));
  }, [f?.cve]);

  const updateStatus = async (s) => {
    await api.patch(`/v1/findings/${id}/status`, { status: s });
    setStatusVal(s);
    const r = await api.get(`/v1/findings/${id}/timeline`); setActivity(r.data.items);
  };

  const addComment = async () => {
    if (!newComment.trim() && attachments.length === 0) return;
    await api.post(`/v1/findings/${id}/comments`, { text: newComment, attachments });
    setNewComment(""); setAttachments([]);
    const r = await api.get(`/v1/findings/${id}/comments`); setComments(r.data.items);
  };

  const handleFiles = async (files) => {
    const arr = Array.from(files || []);
    const out = [...attachments];
    for (const file of arr) {
      if (!file.type.startsWith("image/") && file.type !== "application/pdf") continue;
      if (file.size > 1_000_000) { alert(`${file.name} > 1MB — skipped`); continue; }
      const reader = new FileReader();
      const data_url = await new Promise((res) => { reader.onload = () => res(reader.result); reader.readAsDataURL(file); });
      out.push({ name: file.name, mime: file.type, data_url });
    }
    setAttachments(out);
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

            <Section title="Remediation Playbook" testid="section-playbook">
              {playbook === undefined && <div className="text-[12px] text-slate-500">Loading…</div>}
              {playbook === null && (
                <div className="text-[12.5px] text-slate-500 flex items-center justify-between gap-3">
                  <span>No playbook yet for {f.cve || (f.cwe ? f.cwe : "this finding")}.</span>
                  <Link to={`/admin/playbooks?new=1&cve=${encodeURIComponent(f.cve||"")}&cwe=${encodeURIComponent(f.cwe||"")}`}
                    className="h-7 px-2.5 text-[11px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 text-blue-300 rounded inline-flex items-center gap-1 shrink-0">
                    <Plus size={11}/> Create one
                  </Link>
                </div>
              )}
              {playbook && (
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <BookOpen size={15} className="text-blue-300"/>
                    <div className="text-[13px] text-slate-100 font-medium">{playbook.title}</div>
                    <Chip color="blue">{playbookBasis === "cve" ? `Exact CVE match` : `CWE match: ${playbook.cwe}`}</Chip>
                  </div>
                  {playbook.description && <div className="text-[11.5px] text-slate-500 mb-3">{playbook.description}</div>}

                  <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider mb-1.5">Steps</div>
                  <ol className="space-y-1.5 mb-3">
                    {playbook.steps.map((s, i) => (
                      <li key={i} className="flex items-start gap-2 text-[12.5px] text-slate-200">
                        <span className="text-blue-300 font-mono text-[11px] mt-0.5 shrink-0">{i+1}.</span>
                        <span>{s}</span>
                      </li>
                    ))}
                  </ol>

                  {playbook.rollback_notes && (
                    <div className="mb-3 border border-amber-500/30 bg-amber-500/5 rounded p-2.5">
                      <div className="text-[10px] uppercase font-mono text-amber-400 tracking-wider mb-1 flex items-center gap-1.5">
                        <ArrowCounterClockwise size={12}/> Rollback notes
                      </div>
                      <div className="text-[12px] text-amber-100/90">{playbook.rollback_notes}</div>
                    </div>
                  )}

                  {playbook.validation_checks?.length > 0 && (
                    <div>
                      <div className="text-[10px] uppercase font-mono text-slate-500 tracking-wider mb-1.5 flex items-center gap-1.5">
                        <CheckCircle size={12}/> Validation checks
                      </div>
                      <ul className="space-y-1">
                        {playbook.validation_checks.map((v, i) => (
                          <li key={i} className="text-[12px] text-slate-300 flex items-start gap-1.5">
                            <span className="text-emerald-400 mt-0.5">✓</span> {v}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}
            </Section>

          <Section title="Compensating Mitigations" testid="section-mitigations">
            <div className="text-[11.5px] text-slate-500 mb-2">Temporary controls applied while a real fix is pending -- separate from a formal risk exception.</div>
            {mitigations.length === 0 && <div className="text-[12px] text-slate-500 mb-2">None recorded yet.</div>}
            <div className="space-y-2 mb-2">
              {mitigations.map(m => (
                <div key={m.id} className="border border-[#30363D] rounded p-2.5 bg-[#161B22] flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-1.5">
                      <Chip color={m.still_in_place ? "green" : "slate"}>{m.control_type}</Chip>
                      {!m.still_in_place && <span className="text-[10px] text-slate-500">removed {fmtDate(m.removed_at)}</span>}
                    </div>
                    <div className="text-[12px] text-slate-300 mt-1">{m.description}</div>
                    <div className="text-[10.5px] text-slate-500 mt-1">by {m.applied_by} · {fmtRel(m.applied_at)}</div>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    {m.still_in_place && (
                      <button onClick={async ()=>{ await api.patch(`/v1/mitigations/${m.id}`, {still_in_place:false}); loadMitigations(); }}
                        className="text-[10.5px] text-slate-400 hover:text-slate-200 border border-[#30363D] rounded px-2 h-6">Mark removed</button>
                    )}
                    <button onClick={async ()=>{ await api.delete(`/v1/mitigations/${m.id}`); loadMitigations(); }} className="text-slate-500 hover:text-red-400"><Trash size={13}/></button>
                  </div>
                </div>
              ))}
            </div>
            {!showAddMitigation ? (
              <button onClick={()=>setShowAddMitigation(true)} data-testid="add-mitigation-btn"
                className="text-[11.5px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1"><Plus size={12}/> Add mitigation</button>
            ) : (
              <AddMitigationForm
                types={mitigationTypes}
                onCancel={()=>setShowAddMitigation(false)}
                onAdded={()=>{ setShowAddMitigation(false); loadMitigations(); }}
                findingId={id}
              />
            )}
          </Section>

                    {kri && (

            <Section title="Empirical Score (KRI / ZDES / BII)" testid="section-empirical">
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-3">
                <div className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                  <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider flex items-center gap-1">
                    Empirical %ile
                    <InfoTip>
                      Where this finding's KRI ranks among every open finding in your environment. "Top 5%" means it's more urgent than 95% of your current backlog — a relative measure, not an absolute score.
                    </InfoTip>
                  </div>
                  <div className="text-[22px] font-mono font-semibold text-red-300 mt-0.5" data-testid="empirical-pct">{(100-kri.empirical.top_pct).toFixed(1)}%</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Top {kri.empirical.top_pct}%</div>
                </div>
                <div className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                  <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider flex items-center gap-1">
                    KRI
                    <InfoTip>
                      Key Risk Indicator = EPSS × CVSS weight × CWE weight. Combines "how likely is this to be exploited in the next 30 days" (EPSS) with how severe it is and how common this weakness class has been in your environment. Higher = more urgent.
                    </InfoTip>
                  </div>
                  <div className="text-[22px] font-mono font-semibold text-blue-300 mt-0.5">{kri.kri_score}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">EPSS × CVSS × CWE</div>
                </div>
                <div className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                  <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider flex items-center gap-1">
                    ZDES
                    <InfoTip>
                      Zero-Day Exposure Score = (1 − KEV) × recency × CVSS weight. Runs high for findings that are severe and freshly discovered but NOT yet confirmed as actively exploited — i.e. your exposure to something that could turn into a zero-day before it's KEV-listed. Drops once CISA confirms active exploitation (KEV), since that risk has already materialized and is tracked elsewhere.
                    </InfoTip>
                  </div>
                  <div className="text-[22px] font-mono font-semibold text-amber-300 mt-0.5">{kri.zdes_score}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">Zero-day exposure</div>
                </div>
                <div className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                  <div className="text-[9px] uppercase font-mono text-slate-500 tracking-wider flex items-center gap-1">
                    BII (Patch ROI)
                    <InfoTip>
                      Business Impact Index = (risk score ÷ estimated patch effort) × asset criticality. Answers "how much risk do I remove per hour of work, on this specific asset." Use it to sort your queue for maximum risk reduction per hour when time is limited, not just by raw severity.
                    </InfoTip>
                  </div>
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
                  {c.text && <div className="text-[12.5px] text-slate-200 mt-1 whitespace-pre-wrap">{c.text}</div>}
                  {(c.attachments || []).length > 0 && (
                    <div className="mt-2 flex flex-wrap gap-2">
                      {c.attachments.map((a, i) => a.mime?.startsWith("image/") ? (
                        <a key={i} href={a.data_url} target="_blank" rel="noopener noreferrer" title={a.name}>
                          <img src={a.data_url} alt={a.name} className="max-h-24 rounded border border-[#30363D] hover:border-blue-500/50"/>
                        </a>
                      ) : (
                        <a key={i} href={a.data_url} download={a.name} className="text-[11.5px] text-blue-300 hover:underline">📎 {a.name}</a>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
            {attachments.length > 0 && (
              <div className="mb-2 flex flex-wrap gap-2">
                {attachments.map((a, i) => (
                  <div key={i} className="flex items-center gap-1.5 px-2 py-1 border border-[#30363D] rounded bg-[#161B22] text-[11px]">
                    {a.mime?.startsWith("image/") && <img src={a.data_url} alt="" className="h-6 w-6 object-cover rounded"/>}
                    <span className="text-slate-300 truncate max-w-[140px]">{a.name}</span>
                    <button onClick={()=>setAttachments(attachments.filter((_,j)=>j!==i))} className="text-red-400 hover:text-red-300">×</button>
                  </div>
                ))}
              </div>
            )}
            <div className="flex gap-2">
              <input data-testid="comment-input" value={newComment} onChange={(e)=>setNewComment(e.target.value)} placeholder="Add a triage note (paste screenshot or attach below)…"
                className="flex-1 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"
                onPaste={(e) => { const items = e.clipboardData?.items; if (items) { const files=[]; for (const it of items) if (it.kind==='file') { const f=it.getAsFile(); if (f) files.push(f); } if (files.length) handleFiles(files); } }}
              />
              <label data-testid="comment-attach" className="h-8 px-2.5 text-[12px] border border-[#30363D] hover:border-blue-500/50 rounded inline-flex items-center gap-1 cursor-pointer text-slate-300">
                📎
                <input type="file" multiple accept="image/*,application/pdf" className="hidden" onChange={(e)=>handleFiles(e.target.files)}/>
              </label>
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

          <Section title="Risk Exception" testid="section-exception">
            {exceptions.length === 0 && (
              <button onClick={()=>setShowExceptionForm(true)} data-testid="request-exception-btn"
                className="w-full h-8 text-[11.5px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 text-slate-300 rounded inline-flex items-center justify-center gap-1.5">
                <ShieldCheck size={13}/> Request exception
              </button>
            )}
            {exceptions.map(e => (
              <div key={e.id} className="text-[12px]">
                <Chip color={{pending_approval:"amber", active:"green", expired:"slate", rejected:"red"}[e.status] || "slate"}>{e.status?.replace("_"," ")}</Chip>
                <div className="text-slate-400 mt-1.5">{e.business_justification || e.rationale}</div>
                <div className="text-[10.5px] text-slate-500 mt-1">Expires {fmtDate(e.expires_at)}</div>
              </div>
            ))}
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
            {(f.advisory_links || []).map((l, i) => {
              const url = typeof l === "string" ? l : l?.url;
              const label = typeof l === "string" ? l : (l?.source || l?.url || "Reference");
              return url ? <a key={i} href={url} target="_blank" rel="noopener noreferrer" className="block text-[12px] text-blue-300 hover:underline truncate">{label}</a> : null;
            })}
            {(f.exploit_references || []).map((l, i) => {
              const url = typeof l === "string" ? l : l?.url;
              const label = typeof l === "string" ? l : (l?.source || l?.url || "Exploit");
              return url ? <a key={`x-${i}`} href={url} target="_blank" rel="noopener noreferrer" className="block text-[12px] text-orange-300 hover:underline truncate">{label}</a> : null;
            })}
            {(f.external_references || []).slice(0, 12).map((r, i) => {
              const url = Array.isArray(r) ? r[0] : (r?.url || (typeof r === "string" ? r : null));
              const label = Array.isArray(r) ? (r[1] || r[0]) : (r?.source || r?.url || "Ref");
              return url ? <a key={`e-${i}`} href={url} target="_blank" rel="noopener noreferrer" className="block text-[12px] text-slate-400 hover:text-blue-300 hover:underline truncate">{label}</a> : null;
            })}
          </Section>
        </div>
      </div>
      {showExceptionForm && (
        <ExceptionRequestModal findingId={id} onClose={()=>setShowExceptionForm(false)} onDone={()=>{setShowExceptionForm(false); loadExceptions();}} />
      )}
    </Layout>
  );
}
