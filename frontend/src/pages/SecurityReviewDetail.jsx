import { useEffect, useState } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  ArrowLeft, CaretDown, CaretRight, CheckCircle, Printer, ArrowRight,
  Warning, ClipboardText, Scales, ListChecks, Gavel, NotePencil, ClockCounterClockwise,
  Users, ShieldCheck, Copy, ArrowsClockwise, LinkSimple, Sparkle, PaperPlaneTilt,
} from "@phosphor-icons/react";

const RISK_COLOR = { Low: "blue", Medium: "amber", High: "orange", Critical: "red" };
const RISK_BG = { Low: "bg-blue-500/15 border-blue-500/40 text-blue-300",
  Medium: "bg-amber-500/15 border-amber-500/40 text-amber-300",
  High: "bg-orange-500/15 border-orange-500/40 text-orange-300",
  Critical: "bg-red-500/15 border-red-500/40 text-red-300" };
const SEV_COLOR = { Critical: "red", High: "orange", Medium: "amber", Low: "blue" };
const STEP_STATUS_COLOR = { "Not started": "slate", "In progress": "blue", "Blocked": "amber", "Done": "emerald", "N/A": "slate" };
const ANSWERS = [["yes", "Yes"], ["no", "No"], ["partial", "Partial"], ["na", "N/A"]];

const TABS = [
  { id: "playbook", label: "Playbook", icon: ListChecks },
  { id: "questionnaire", label: "Questionnaire", icon: ClipboardText },
  { id: "risk", label: "Risk Scoring", icon: Scales },
  { id: "findings", label: "Findings", icon: Warning },
  { id: "decision", label: "Decision", icon: Gavel },
  { id: "interviews", label: "Interviews", icon: Users },
  { id: "checks", label: "External Checks", icon: ShieldCheck },
  { id: "notes", label: "Notes", icon: NotePencil },
  { id: "audit", label: "Audit Log", icon: ClockCounterClockwise },
];

export default function SecurityReviewDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [data, setData] = useState(null);
  const [meta, setMeta] = useState(null);
  const [prior, setPrior] = useState(null);
  const [tab, setTab] = useState("playbook");
  const [reportOpen, setReportOpen] = useState(false);

  const load = async () => {
    const [r, m, p] = await Promise.all([
      api.get(`/v1/security-reviews/${id}`),
      api.get("/v1/security-reviews/meta"),
      api.get(`/v1/security-reviews/${id}/prior-reviews`).catch(() => ({ data: null })),
    ]);
    setData(r.data); setMeta(m.data); setPrior(p.data);
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [id]);

  if (!data || !meta) return <Layout title="Security Review…"><div className="text-slate-500">Loading…</div></Layout>;
  const { review, steps, responses, findings, questionnaire } = data;
  const closed = review.status === "Closed";

  const nextStep = steps.find(s => !["Done", "N/A"].includes(s.status));

  const setStatus = async (s) => {
    try {
      await api.post(`/v1/security-reviews/${id}/status`, { status: s });
      toast.success(`Status: ${s}`);
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Status change failed"); }
  };

  return (
    <Layout
      title={<span><span className="font-mono text-slate-500 mr-2 text-[15px]">{review.review_number}</span>{review.title}</span>}
      subtitle={`${review.review_type}${review.entity_name ? " · " + review.entity_name : ""}`}
      actions={
        <div className="flex items-center gap-2">
          <button onClick={() => navigate(-1)} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300">
            <ArrowLeft size={13}/> Back
          </button>
          <button onClick={() => setReportOpen(true)}
            className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 rounded inline-flex items-center gap-1.5 text-slate-300">
            <Printer size={13}/> Report
          </button>
          {closed && (
            <button onClick={async () => {
              const r = await api.post(`/v1/security-reviews/${id}/revalidate`);
              toast.success(`${r.data.review_number} created — confirm what changed`);
              navigate(`/security-reviews/${r.data.id}`);
            }} className="h-8 px-3 text-[12px] border border-purple-500/40 text-purple-300 rounded inline-flex items-center gap-1.5">
              <ArrowsClockwise size={13}/> Re-validate
            </button>
          )}
          <select value={review.status} onChange={e => setStatus(e.target.value)} disabled={closed}
            className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200 disabled:opacity-60">
            {meta.statuses.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      }>

      {/* Header: risk badges + next-best-action */}
      <div className="flex items-stretch gap-3 mb-4 flex-wrap">
        <RiskBadge label="Risk if adopted as-is" band={review.inherent_risk?.band}/>
        <div className="flex items-center text-slate-600"><ArrowRight size={18}/></div>
        <RiskBadge label="Risk with required controls" band={review.residual_risk?.band}/>
        {review.risk_of_not_adopting?.band && (
          <RiskBadge label="Risk of NOT adopting" band={review.risk_of_not_adopting.band} small/>
        )}
        <div className="flex-1 min-w-[240px] border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-2.5 flex items-center gap-3">
          {closed ? (
            <div className="text-[12.5px] text-slate-400 flex items-center gap-2">
              <CheckCircle size={15} className="text-emerald-400"/> Closed — evidence and responses are locked.
            </div>
          ) : nextStep ? (
            <div className="min-w-0">
              <div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500">Next step</div>
              <div className="text-[12.5px] text-slate-200 truncate">Step {nextStep.order}: {nextStep.title}</div>
            </div>
          ) : (
            <div className="text-[12.5px] text-slate-400">All playbook steps complete — score, decide, and close.</div>
          )}
          {review.sla_paused_at && <Chip color="amber">SLA paused</Chip>}
          {review.data_classifications?.length > 0 && (
            <div className="flex gap-1 flex-wrap ml-auto">
              {review.data_classifications.map(c => <Chip key={c} color="purple">{c}</Chip>)}
            </div>
          )}
        </div>
      </div>

      {/* Prior-review auto-fill panel */}
      {prior && (prior.prior_reviews?.length > 0 || prior.vendor_osint_findings > 0) && (
        <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-4 py-3 mb-4 text-[12px]">
          <div className="text-[10.5px] uppercase tracking-wider font-mono text-blue-300 mb-1.5">
            What we already know <span className="text-slate-500 normal-case">(pulled from platform data, {new Date().toLocaleDateString()})</span>
          </div>
          <div className="space-y-1 text-slate-300">
            {prior.prior_reviews.map(p => (
              <div key={p.id}>
                <Link to={`/security-reviews/${p.id}`} className="text-blue-300 hover:underline font-mono text-[11.5px]">{p.review_number}</Link>
                {" "}— {p.title} · {p.decision_outcome || p.status}
                {p.residual_risk && <> · residual <Chip color={RISK_COLOR[p.residual_risk]}>{p.residual_risk}</Chip></>}
                {prior.expired_approvals.some(x => x.id === p.id) && <Chip color="red">approval expired</Chip>}
              </div>
            ))}
            {prior.unmet_conditions.length > 0 && (
              <div className="text-amber-300">{prior.unmet_conditions.length} unmet condition(s) from prior reviews — verify before relying on precedent.</div>
            )}
            {prior.vendor_osint_findings > 0 && (
              <div>{prior.vendor_osint_findings} OSINT/compromise-monitoring finding(s) already on file for {review.entity_domain} — see the vendor's page for drill-down.</div>
            )}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-[#30363D] mb-4 overflow-x-auto">
        {TABS.map(t => {
          const Icon = t.icon;
          return (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`h-9 px-3 text-[12.5px] inline-flex items-center gap-1.5 border-b-2 -mb-px whitespace-nowrap ${
                tab === t.id ? "border-blue-500 text-blue-300" : "border-transparent text-slate-400 hover:text-slate-200"}`}>
              <Icon size={14}/> {t.label}
              {t.id === "findings" && findings.length > 0 && <span className="text-[10.5px] bg-slate-700/60 rounded-full px-1.5">{findings.length}</span>}
            </button>
          );
        })}
      </div>

      {tab === "playbook" && <PlaybookTab id={id} steps={steps} closed={closed} onChange={load}/>}
      {tab === "questionnaire" && <QuestionnaireTab id={id} questionnaire={questionnaire} responses={responses} review={review} closed={closed} onChange={load}/>}
      {tab === "risk" && <RiskTab id={id} review={review} meta={meta} closed={closed} onChange={load}/>}
      {tab === "findings" && <FindingsTab id={id} findings={findings} closed={closed} onChange={load}/>}
      {tab === "decision" && <DecisionTab id={id} review={review} meta={meta} closed={closed} onChange={load}/>}
      {tab === "interviews" && <InterviewsTab id={id} closed={closed}/>}
      {tab === "checks" && <ExternalChecksTab id={id} review={review} closed={closed} onChange={load}/>}
      {tab === "notes" && <NotesTab id={id} closed={closed}/>}
      {tab === "audit" && <AuditTab id={id}/>}

      {reportOpen && <ReportModal id={id} onClose={() => setReportOpen(false)}/>}
    </Layout>
  );
}

function RiskBadge({ label, band, small }) {
  return (
    <div className={`border rounded-md px-4 ${small ? "py-1.5" : "py-2.5"} text-center min-w-[150px] ${band ? RISK_BG[band] : "border-[#30363D] bg-[#0D1117] text-slate-600"}`}>
      <div className="text-[10px] uppercase tracking-wider font-mono opacity-80">{label}</div>
      <div className={`${small ? "text-[16px]" : "text-[22px]"} font-bold mt-0.5`}>{band || "Not scored"}</div>
    </div>
  );
}

/* ------------------------------ Playbook ------------------------------ */

function PlaybookTab({ id, steps, closed, onChange }) {
  const [open, setOpen] = useState(new Set());
  const [drafts, setDrafts] = useState({});

  const toggle = (sid) => setOpen(prev => {
    const next = new Set(prev);
    next.has(sid) ? next.delete(sid) : next.add(sid);
    return next;
  });

  const patchStep = async (step, body) => {
    try {
      await api.patch(`/v1/security-reviews/${id}/steps/${step.id}`, body);
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to update step"); }
  };

  const setStepStatus = (step, status) => {
    if (status === "N/A") {
      const reason = window.prompt("N/A requires a reason:");
      if (!reason) return;
      patchStep(step, { status, na_reason: reason });
      return;
    }
    if (status === "Blocked") {
      const who = window.prompt("Blocked on (person/vendor):");
      if (who === null) return;
      patchStep(step, { status, blocked_on: who });
      return;
    }
    patchStep(step, { status });
  };

  const saveNotes = (step) => {
    if (drafts[step.id] === undefined) return;
    patchStep(step, { notes: drafts[step.id] });
    toast.success("Notes saved");
  };

  const attachEvidence = async (step, files) => {
    const out = [];
    for (const file of files) {
      const reader = new FileReader();
      const data_url = await new Promise((res) => { reader.onload = () => res(reader.result); reader.readAsDataURL(file); });
      out.push({ name: file.name, mime: file.type, data_url, uploaded_at: new Date().toISOString() });
    }
    if (out.length) patchStep(step, { evidence: out });
  };

  const done = steps.filter(s => ["Done", "N/A"].includes(s.status)).length;

  return (
    <div>
      <div className="text-[11.5px] text-slate-500 mb-3">{done} of {steps.length} steps complete</div>
      <div className="space-y-2">
        {steps.map(s => {
          const isOpen = open.has(s.id);
          return (
            <div key={s.id} className="border border-[#30363D] bg-[#0D1117] rounded-md">
              <div className="px-3.5 py-2.5 flex items-center gap-3 cursor-pointer" onClick={() => toggle(s.id)}>
                {isOpen ? <CaretDown size={13} className="text-slate-500 shrink-0"/> : <CaretRight size={13} className="text-slate-500 shrink-0"/>}
                <span className="font-mono text-[11px] text-slate-500 shrink-0">#{s.order}</span>
                <span className={`text-[13px] flex-1 ${["Done", "N/A"].includes(s.status) ? "text-slate-500 line-through" : "text-slate-200"}`}>{s.title}</span>
                {s.autofill_hook && <Chip color="blue">auto-fill</Chip>}
                {s.conditional_on && <Chip color="purple">conditional</Chip>}
                <Chip color={STEP_STATUS_COLOR[s.status] || "slate"}>{s.status}</Chip>
              </div>
              {isOpen && (
                <div className="border-t border-[#30363D] px-4 py-3 space-y-3">
                  <div className="text-[12.5px] text-slate-300 leading-relaxed">{s.guidance}</div>
                  {s.autofill_hook && <AutofillPanel id={id} hook={s.autofill_hook}/>}
                  {s.expected_output && (
                    <div className="text-[11.5px] text-slate-500"><span className="text-slate-400 font-medium">Expected output:</span> {s.expected_output}</div>
                  )}
                  {s.status === "Blocked" && (
                    <div className="text-[11.5px] text-amber-300">Blocked on: {s.blocked_on || "?"} since {s.blocked_date || "?"}</div>
                  )}
                  {s.status === "N/A" && s.na_reason && (
                    <div className="text-[11.5px] text-slate-500">N/A reason: {s.na_reason}</div>
                  )}
                  {!closed && (
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {["Not started", "In progress", "Blocked", "Done"].concat(s.allows_na || true ? ["N/A"] : []).map(st => (
                        <button key={st} onClick={() => setStepStatus(s, st)}
                          className={`h-7 px-2.5 text-[11.5px] rounded border ${s.status === st
                            ? "bg-blue-500/15 border-blue-500/40 text-blue-300"
                            : "border-[#30363D] text-slate-400 hover:border-slate-500"}`}>
                          {st}
                        </button>
                      ))}
                    </div>
                  )}
                  <div>
                    <div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1">Notes</div>
                    <textarea rows={2} disabled={closed}
                      value={drafts[s.id] !== undefined ? drafts[s.id] : (s.notes || "")}
                      onChange={e => setDrafts(d => ({ ...d, [s.id]: e.target.value }))}
                      onBlur={() => saveNotes(s)}
                      className="w-full px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100 disabled:opacity-60"/>
                  </div>
                  <div>
                    <div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1">Evidence ({(s.evidence || []).length})</div>
                    {(s.evidence || []).map((ev, i) => (
                      <a key={i} href={ev.data_url} download={ev.name}
                        className="inline-flex items-center gap-1 text-[11.5px] text-blue-300 hover:underline mr-3">{ev.name}</a>
                    ))}
                    {!closed && (
                      <input type="file" multiple onChange={e => attachEvidence(s, Array.from(e.target.files || []))}
                        className="block mt-1 text-[11px] text-slate-500"/>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function AutofillPanel({ id, hook }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  const runHook = async () => {
    setLoading(true);
    try {
      const r = await api.get(`/v1/security-reviews/${id}/autofill/${hook}`);
      setData(r.data);
    } catch (e) { toast.error(e.response?.data?.detail || "Auto-fill failed"); }
    finally { setLoading(false); }
  };

  return (
    <div className="border border-blue-500/25 bg-blue-500/5 rounded-md p-3">
      <div className="flex items-center justify-between">
        <div className="text-[10.5px] uppercase tracking-wider font-mono text-blue-300">Auto-fill: {hook}</div>
        <button onClick={runHook} disabled={loading}
          className="h-7 px-2.5 text-[11.5px] border border-blue-500/40 text-blue-300 rounded inline-flex items-center gap-1.5 disabled:opacity-50">
          <Sparkle size={12}/> {loading ? "Pulling…" : data ? "Refresh" : "Pull from platform"}
        </button>
      </div>
      {data && (
        <div className="mt-2 space-y-1.5 text-[11.5px] text-slate-300">
          <div className="text-[10px] text-slate-500 font-mono">{data.source_tag}</div>
          {hook === "prior_reviews_lookup" && null}
          {hook === "asset_inventory_check" && (
            <>
              {data.shadow_deployment && (
                <div className="text-amber-300">Shadow deployment detected — a draft finding was created on the Findings tab.</div>
              )}
              <div>{data.software_hits.length} installed-software match(es), {data.assets.length} matching asset(s), {(data.linked_assets || []).length} linked asset(s).</div>
              {data.linked_assets?.map(a => (
                <div key={a.id} className="text-slate-400">Linked: {a.hostname} · {a.os} · {a.criticality}{a.internet_facing ? " · internet-facing" : ""}</div>
              ))}
            </>
          )}
          {hook === "open_findings_pull" && (
            <>
              <div>{data.total_open} open finding(s) across {data.asset_count} linked asset(s) — {data.overdue} past SLA.</div>
              <div className="flex gap-1.5 flex-wrap">
                {Object.entries(data.severity_counts).map(([sev, n]) => (
                  <Chip key={sev} color={SEV_COLOR[sev] || "slate"}>{sev}: {n}</Chip>
                ))}
              </div>
              {data.top_qids.slice(0, 5).map(t => (
                <div key={t.qid} className="text-slate-400 font-mono text-[10.5px]">QID {t.qid} ×{t.count} — {t.title}</div>
              ))}
            </>
          )}
          {hook === "osint_compromise_pull" && (
            data.hits.length === 0 ? <div>No OSINT/compromise hits on file for this domain.</div> : (
              <div className="space-y-1">
                {data.hits.slice(0, 8).map(h => (
                  <div key={h.id}>
                    <span className="text-amber-300">{h.module_label || h.module}</span> — {h.label}
                    {h.detail && <div className="text-slate-500 text-[10.5px]">{h.detail}</div>}
                  </div>
                ))}
                {data.vendor_id && <a href={`/vendors/${data.vendor_id}`} className="text-blue-300 hover:underline">Open vendor page for full drill-down →</a>}
              </div>
            )
          )}
          {hook === "governance_crosswalk" && (
            <div className="space-y-1">
              {data.items.map((it, i) => (
                <div key={i}><Chip color="purple">{it.classification}</Chip> <span className="ml-1">{it.requirement}</span></div>
              ))}
              {data.items.length === 0 && <div>No classification-driven requirements apply.</div>}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* ---------------------------- Questionnaire ---------------------------- */

function QuestionnaireTab({ id, questionnaire, responses, review, closed, onChange }) {
  const respByOrder = Object.fromEntries((responses || []).map(r => [r.question_order, r]));
  const [evidenceDrafts, setEvidenceDrafts] = useState({});
  const [vendorQ, setVendorQ] = useState(null);
  const [autoAnswering, setAutoAnswering] = useState(false);
  if (!questionnaire) return <div className="text-slate-500 text-[12.5px]">No questionnaire template attached.</div>;

  const activeClassifications = review.data_classifications || [];
  // Cascading conditions: a question can depend on a data classification OR on a
  // prior answer ("q13:yes" = only shown once Q13 is answered yes).
  const condMet = (cond) => {
    if (!cond) return true;
    if (cond.startsWith("q") && cond.includes(":")) {
      const [qref, want] = cond.slice(1).split(":");
      return respByOrder[parseInt(qref, 10)]?.answer === want;
    }
    return activeClassifications.includes(cond);
  };
  const questions = questionnaire.questions.filter(q => condMet(q.conditional_on));

  const autoAnswer = async () => {
    setAutoAnswering(true);
    try {
      const r = await api.post(`/v1/security-reviews/${id}/auto-answer`);
      toast.success(`${r.data.answered.length} question(s) auto-answered from platform data`);
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Auto-answer failed"); }
    finally { setAutoAnswering(false); }
  };

  const loadVendorQ = async () => {
    const r = await api.get(`/v1/security-reviews/${id}/vendor-questionnaire`);
    setVendorQ(r.data);
  };
  const skipped = questionnaire.questions.length - questions.length;
  const domains = [...new Set(questions.map(q => q.domain))];
  const answered = questions.filter(q => respByOrder[q.order]).length;

  const save = async (q, answer, evidence_text) => {
    try {
      await api.put(`/v1/security-reviews/${id}/responses`, {
        question_order: q.order, answer,
        evidence_text: evidence_text !== undefined ? evidence_text : (respByOrder[q.order]?.evidence_text || ""),
      });
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to save answer"); }
  };

  return (
    <div>
      <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
        <div className="text-[11.5px] text-slate-500">
          {answered} of {questions.length} answered
          {skipped > 0 && <span> · {skipped} conditional question(s) hidden</span>}
          <span> · template v{questionnaire.version}</span>
        </div>
        <div className="flex gap-2">
          {!closed && (
            <button onClick={autoAnswer} disabled={autoAnswering}
              className="h-8 px-3 text-[12px] border border-blue-500/40 text-blue-300 rounded inline-flex items-center gap-1.5 disabled:opacity-50">
              <Sparkle size={13}/> {autoAnswering ? "Answering…" : "Auto-answer from platform data"}
            </button>
          )}
          <button onClick={loadVendorQ}
            className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-slate-500 text-slate-300 rounded inline-flex items-center gap-1.5">
            <PaperPlaneTilt size={13}/> Vendor questionnaire
          </button>
        </div>
      </div>
      {vendorQ && <VendorQuestionnairePanel id={id} vendorQ={vendorQ} closed={closed} onChange={() => { loadVendorQ(); onChange(); }}/>}
      <div className="space-y-4">
        {domains.map(domain => (
          <div key={domain} className="border border-[#30363D] bg-[#0D1117] rounded-md">
            <div className="px-4 py-2 border-b border-[#30363D] text-[11px] uppercase tracking-wider font-mono text-slate-400">{domain}</div>
            <div className="divide-y divide-[#30363D]">
              {questions.filter(q => q.domain === domain).map(q => {
                const resp = respByOrder[q.order];
                return (
                  <div key={q.order} className="px-4 py-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="text-[12.5px] text-slate-200 leading-relaxed">
                        <span className="font-mono text-[11px] text-slate-500 mr-1.5">Q{q.order}.</span>
                        {q.text}
                        <span className="text-[10.5px] text-slate-500 ml-2">[CIS {q.cis_mapping}] · weight {q.risk_weight}{q.vendor_facing ? " · vendor-facing" : ""}</span>
                      </div>
                      <div className="flex gap-1 shrink-0">
                        {ANSWERS.map(([val, label]) => (
                          <button key={val} disabled={closed} onClick={() => save(q, val)}
                            className={`h-7 px-2 text-[11.5px] rounded border disabled:opacity-60 ${resp?.answer === val
                              ? (val === "no" ? "bg-red-500/15 border-red-500/40 text-red-300"
                                 : val === "partial" ? "bg-amber-500/15 border-amber-500/40 text-amber-300"
                                 : val === "yes" ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-300"
                                 : "bg-slate-500/15 border-slate-500/40 text-slate-300")
                              : "border-[#30363D] text-slate-400 hover:border-slate-500"}`}>
                            {label}
                          </button>
                        ))}
                      </div>
                    </div>
                    {resp?.auto_answered && (
                      <div className="text-[10.5px] text-blue-300 mt-1 inline-flex items-center gap-1">
                        <Sparkle size={10}/> Auto-answered — {resp.source_tag} (override by picking a different answer)
                      </div>
                    )}
                    {resp?.analyst_overridden && (
                      <div className="text-[10.5px] text-amber-300 mt-1">Analyst override of an auto answer (recorded in audit log)</div>
                    )}
                    {resp && (
                      <input placeholder="Evidence / notes…" disabled={closed}
                        value={evidenceDrafts[q.order] !== undefined ? evidenceDrafts[q.order] : (resp.evidence_text || "")}
                        onChange={e => setEvidenceDrafts(d => ({ ...d, [q.order]: e.target.value }))}
                        onBlur={e => save(q, resp.answer, e.target.value)}
                        className="w-full mt-2 h-8 px-3 bg-[#161B22] border border-[#30363D] rounded text-[11.5px] text-slate-300 disabled:opacity-60"/>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function VendorQuestionnairePanel({ id, vendorQ, closed, onChange }) {
  const track = async (what) => {
    try {
      await api.post(`/v1/security-reviews/${id}/vendor-questionnaire/track`, { [what]: true });
      toast.success(what === "sent" ? "Marked sent — SLA clock paused while awaiting the vendor" : "Marked received — SLA clock resumed");
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Tracking failed"); }
  };
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 mb-4">
      <div className="flex items-center justify-between mb-2 flex-wrap gap-2">
        <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400">
          Vendor-facing questionnaire ({vendorQ.questions.length} questions)
        </div>
        <div className="flex gap-2 items-center">
          <button onClick={() => { navigator.clipboard.writeText(vendorQ.text); toast.success("Copied"); }}
            className="h-7 px-2.5 text-[11.5px] border border-[#30363D] text-slate-300 rounded inline-flex items-center gap-1"><Copy size={12}/> Copy</button>
          {!closed && !vendorQ.sent_at && (
            <button onClick={() => track("sent")}
              className="h-7 px-2.5 text-[11.5px] border border-blue-500/40 text-blue-300 rounded">Mark sent</button>
          )}
          {!closed && vendorQ.sent_at && !vendorQ.received_at && (
            <button onClick={() => track("received")}
              className="h-7 px-2.5 text-[11.5px] border border-emerald-500/40 text-emerald-300 rounded">Mark received</button>
          )}
        </div>
      </div>
      <div className="text-[10.5px] text-slate-500 mb-2">
        {vendorQ.sent_at ? `Sent ${new Date(vendorQ.sent_at).toLocaleDateString()}` : "Not sent yet"}
        {vendorQ.received_at && ` · received ${new Date(vendorQ.received_at).toLocaleDateString()}`}
        {vendorQ.sent_at && !vendorQ.received_at && " · SLA paused · chase at 10 business days"}
      </div>
      <pre className="text-[11px] text-slate-400 bg-[#161B22] border border-[#30363D] rounded p-3 max-h-56 overflow-y-auto whitespace-pre-wrap">{vendorQ.text}</pre>
    </div>
  );
}

function InterviewsTab({ id, closed }) {
  const [items, setItems] = useState([]);
  const [form, setForm] = useState({ who: "", role: "", when: "", summary: "" });
  const load = () => api.get(`/v1/security-reviews/${id}/interviews`).then(r => setItems(r.data.items || []));
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [id]);

  const add = async () => {
    if (!form.who.trim()) { toast.error("Who was interviewed?"); return; }
    await api.post(`/v1/security-reviews/${id}/interviews`, { ...form, when: form.when || null });
    setForm({ who: "", role: "", when: "", summary: "" });
    load();
  };

  return (
    <div className="max-w-2xl space-y-3">
      <div className="text-[11px] text-slate-500">Stakeholder input — renders into the technical appendix.</div>
      {!closed && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 space-y-2.5">
          <div className="grid grid-cols-3 gap-2">
            <input placeholder="Who" value={form.who} onChange={e => setForm({ ...form, who: e.target.value })}
              className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200"/>
            <input placeholder="Role" value={form.role} onChange={e => setForm({ ...form, role: e.target.value })}
              className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200"/>
            <input type="date" value={form.when} onChange={e => setForm({ ...form, when: e.target.value })}
              className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200"/>
          </div>
          <textarea rows={2} placeholder="Summary of what they said…" value={form.summary}
            onChange={e => setForm({ ...form, summary: e.target.value })}
            className="w-full px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/>
          <button onClick={add} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Capture interview</button>
        </div>
      )}
      {items.map(it => (
        <div key={it.id} className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-2.5">
          <div className="text-[12.5px] text-slate-200">{it.who} <span className="text-slate-500">({it.role || "—"}) · {it.when}</span></div>
          {it.summary && <div className="text-[12px] text-slate-400 mt-1">{it.summary}</div>}
        </div>
      ))}
      {items.length === 0 && <div className="text-[12px] text-slate-500">No interviews captured yet.</div>}
    </div>
  );
}

const CHECK_STATUS_META = {
  ok: { color: "emerald", label: "OK" },
  attention: { color: "amber", label: "Needs attention" },
  manual: { color: "slate", label: "Check manually" },
};

function ExternalChecksTab({ id, review, closed, onChange }) {
  const [running, setRunning] = useState(false);
  const checks = review.external_checks;

  const runChecks = async () => {
    setRunning(true);
    try {
      await api.post(`/v1/security-reviews/${id}/external-checks`);
      toast.success("External checks complete");
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Checks failed"); }
    finally { setRunning(false); }
  };

  return (
    <div className="max-w-2xl space-y-3">
      <div className="text-[11px] text-slate-500">
        Best-effort automated checks against the vendor: TLS/security headers, breach-history signal, NVD CVE lookup.
        Failed checks degrade to manual steps — they never block the review.
      </div>
      {!closed && (
        <button onClick={runChecks} disabled={running}
          className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded inline-flex items-center gap-1.5">
          <ShieldCheck size={13}/> {running ? "Running…" : checks ? "Re-run checks" : "Run external checks"}
        </button>
      )}
      {checks && (
        <div className="space-y-2">
          <div className="text-[10.5px] text-slate-500 font-mono">Last run {new Date(checks.ran_at).toLocaleString()}</div>
          {checks.results.map((c, i) => {
            const meta_ = CHECK_STATUS_META[c.status] || CHECK_STATUS_META.manual;
            return (
              <div key={i} className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3">
                <div className="flex items-center justify-between">
                  <div className="text-[12px] text-slate-200 font-mono">{c.check}</div>
                  <Chip color={meta_.color}>{meta_.label}</Chip>
                </div>
                <div className="text-[12px] text-slate-400 mt-1">{c.summary}</div>
                <div className="text-[10px] text-slate-600 font-mono mt-1">{c.source_tag}</div>
              </div>
            );
          })}
        </div>
      )}
      {!checks && <div className="text-[12px] text-slate-500">Not run yet.</div>}
    </div>
  );
}

/* ------------------------------ Risk Scoring ------------------------------ */

function ScoreGrid({ label, likelihood, impacts, setLikelihood, setImpact, dims, disabled }) {
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
      <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-3">{label}</div>
      <div className="mb-3">
        <div className="text-[11.5px] text-slate-500 mb-1">Likelihood (1–5)</div>
        <div className="flex gap-1">
          {[1, 2, 3, 4, 5].map(n => (
            <button key={n} disabled={disabled} onClick={() => setLikelihood(n)}
              className={`h-8 w-8 text-[12.5px] rounded border disabled:opacity-60 ${likelihood === n
                ? "bg-blue-500/20 border-blue-500/50 text-blue-300" : "border-[#30363D] text-slate-400 hover:border-slate-500"}`}>
              {n}
            </button>
          ))}
        </div>
      </div>
      <div className="space-y-2">
        {dims.map(d => (
          <div key={d} className="flex items-center justify-between gap-2">
            <div className="text-[11.5px] text-slate-400 capitalize">{d.replace("_", "/")}</div>
            <div className="flex gap-1">
              {[1, 2, 3, 4, 5].map(n => (
                <button key={n} disabled={disabled} onClick={() => setImpact(d, n)}
                  className={`h-6 w-6 text-[11px] rounded border disabled:opacity-60 ${impacts[d] === n
                    ? "bg-purple-500/20 border-purple-500/50 text-purple-300" : "border-[#30363D] text-slate-500 hover:border-slate-500"}`}>
                  {n}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function Matrix5x5({ points }) {
  // points: [{likelihood, impact, label, color}]
  const cellBand = (l, i) => {
    const s = l * i;
    if (s <= 4) return "bg-blue-500/10";
    if (s <= 9) return "bg-amber-500/10";
    if (s <= 16) return "bg-orange-500/15";
    return "bg-red-500/20";
  };
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
      <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">5×5 Matrix (Impact → / Likelihood ↑)</div>
      <div className="grid grid-cols-6 gap-0.5 text-[10px]">
        {[5, 4, 3, 2, 1].map(l => (
          [<div key={`l${l}`} className="flex items-center justify-center text-slate-500 h-9">{l}</div>,
            ...[1, 2, 3, 4, 5].map(i => {
              const here = points.filter(p => p.likelihood === l && p.impact === i);
              return (
                <div key={`${l}-${i}`} className={`h-9 rounded-sm border border-[#30363D]/50 flex items-center justify-center gap-0.5 ${cellBand(l, i)}`}>
                  {here.map((p, j) => (
                    <span key={j} title={p.label} className={`h-3.5 w-3.5 rounded-full ${p.color} border border-white/40`}/>
                  ))}
                </div>
              );
            })]
        ))}
        <div/>
        {[1, 2, 3, 4, 5].map(i => <div key={`i${i}`} className="text-center text-slate-500">{i}</div>)}
      </div>
      <div className="flex gap-3 mt-2 text-[10.5px] text-slate-500">
        <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-red-400 inline-block"/> inherent</span>
        <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-emerald-400 inline-block"/> residual</span>
        <span className="inline-flex items-center gap-1"><span className="h-2.5 w-2.5 rounded-full bg-slate-400 inline-block"/> not adopting</span>
      </div>
    </div>
  );
}

function RiskTab({ id, review, meta, closed, onChange }) {
  const dims = meta.impact_dimensions;
  const blank = Object.fromEntries(dims.map(d => [d, 0]));
  const [inhLik, setInhLik] = useState(review.inherent_risk?.likelihood || 0);
  const [inhImp, setInhImp] = useState({ ...blank, ...(review.inherent_risk?.impacts || {}) });
  const [resLik, setResLik] = useState(review.residual_risk?.likelihood || 0);
  const [resImp, setResImp] = useState({ ...blank, ...(review.residual_risk?.impacts || {}) });
  const [notLik, setNotLik] = useState(review.risk_of_not_adopting?.likelihood || 0);
  const [notImp, setNotImp] = useState({ ...blank, ...(review.risk_of_not_adopting?.impacts || {}) });
  const [controls, setControls] = useState(review.compensating_controls || "");
  const [override, setOverride] = useState(review.analyst_override_justification || "");
  const [saving, setSaving] = useState(false);
  const [suggestion, setSuggestion] = useState(null);

  useEffect(() => {
    api.get(`/v1/security-reviews/${review.id}/suggested-risk`).then(r => setSuggestion(r.data)).catch(() => {});
    // eslint-disable-next-line
  }, [review.id]);

  const acceptSuggestion = () => {
    if (!suggestion) return;
    setInhLik(suggestion.likelihood);
    setInhImp(prev => ({ ...prev, ...suggestion.impacts }));
    toast.success("Suggestion applied to the inherent score — adjust as needed");
  };

  const save = async () => {
    if (!inhLik || !Object.values(inhImp).some(Boolean)) {
      toast.error("Score inherent likelihood and at least one impact dimension first");
      return;
    }
    setSaving(true);
    try {
      await api.put(`/v1/security-reviews/${id}/risk-score`, {
        inherent_likelihood: inhLik, inherent_impacts: inhImp,
        suggested_band: suggestion?.band || null,
        residual_likelihood: resLik || null, residual_impacts: resLik ? resImp : null,
        not_adopting_likelihood: notLik || null, not_adopting_impacts: notLik ? notImp : null,
        compensating_controls: controls, override_justification: override,
      });
      toast.success("Risk scoring saved");
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to save risk scoring"); }
    finally { setSaving(false); }
  };

  const maxOf = (imp) => Math.max(...Object.values(imp).map(v => v || 0), 0);
  const points = [];
  if (inhLik && maxOf(inhImp)) points.push({ likelihood: inhLik, impact: maxOf(inhImp), label: "Inherent", color: "bg-red-400" });
  if (resLik && maxOf(resImp)) points.push({ likelihood: resLik, impact: maxOf(resImp), label: "Residual", color: "bg-emerald-400" });
  if (notLik && maxOf(notImp)) points.push({ likelihood: notLik, impact: maxOf(notImp), label: "Not adopting", color: "bg-slate-400" });

  return (
    <div className="space-y-4">
      {suggestion && suggestion.band && (
        <div className="border border-purple-500/30 bg-purple-500/5 rounded-md px-4 py-3 flex items-start justify-between gap-3 flex-wrap">
          <div>
            <div className="text-[10.5px] uppercase tracking-wider font-mono text-purple-300 mb-1">
              Suggested inherent risk <span className="text-slate-500 normal-case">— {suggestion.source_tag}</span>
            </div>
            <div className="flex items-center gap-2">
              <Chip color={RISK_COLOR[suggestion.band]}>{suggestion.band}</Chip>
              <span className="text-[11.5px] text-slate-400">likelihood {suggestion.likelihood} × max impact {Math.max(...Object.values(suggestion.impacts))}</span>
            </div>
            <ul className="mt-1.5 text-[11.5px] text-slate-400 list-disc ml-4">
              {suggestion.rationale.map((r2, i) => <li key={i}>{r2}</li>)}
            </ul>
            <div className="text-[10.5px] text-slate-500 mt-1">Never auto-finalized — accept it, or score differently with a justification.</div>
          </div>
          {!closed && (
            <button onClick={acceptSuggestion}
              className="h-8 px-3 text-[12px] border border-purple-500/40 text-purple-300 rounded shrink-0">Apply suggestion</button>
          )}
        </div>
      )}
      <div className="grid md:grid-cols-3 gap-3">
        <ScoreGrid label="Inherent (adopted as-is)" likelihood={inhLik} impacts={inhImp}
          setLikelihood={setInhLik} setImpact={(d, n) => setInhImp(p => ({ ...p, [d]: n }))} dims={dims} disabled={closed}/>
        <ScoreGrid label="Residual (with required controls)" likelihood={resLik} impacts={resImp}
          setLikelihood={setResLik} setImpact={(d, n) => setResImp(p => ({ ...p, [d]: n }))} dims={dims} disabled={closed}/>
        <ScoreGrid label="Risk of NOT adopting (optional)" likelihood={notLik} impacts={notImp}
          setLikelihood={setNotLik} setImpact={(d, n) => setNotImp(p => ({ ...p, [d]: n }))} dims={dims} disabled={closed}/>
      </div>
      <div className="grid md:grid-cols-2 gap-3">
        <Matrix5x5 points={points}/>
        <div className="space-y-3">
          <div>
            <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-1">Compensating controls (drives residual)</div>
            <textarea rows={4} value={controls} onChange={e => setControls(e.target.value)} disabled={closed}
              placeholder="SSO/MFA enforcement, segmentation, DLP, contract terms, data minimization…"
              className="w-full px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100 disabled:opacity-60"/>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-1">Override justification (required if final rating differs from suggested)</div>
            <textarea rows={2} value={override} onChange={e => setOverride(e.target.value)} disabled={closed}
              className="w-full px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100 disabled:opacity-60"/>
          </div>
          {!closed && (
            <button onClick={save} disabled={saving}
              className="h-9 px-4 text-[12.5px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
              {saving ? "Saving…" : "Save risk scoring"}
            </button>
          )}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------ Findings ------------------------------ */

function FindingsTab({ id, findings, closed, onChange }) {
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState({ description: "", severity: "Medium", category: "General",
    recommendation: "", owner: "", due_date: "", is_condition_of_approval: false, condition_deadline: "" });

  const add = async () => {
    if (!form.description.trim()) { toast.error("Description required"); return; }
    try {
      await api.post(`/v1/security-reviews/${id}/findings`, {
        ...form, due_date: form.due_date || null, condition_deadline: form.condition_deadline || null,
      });
      setAdding(false);
      setForm({ description: "", severity: "Medium", category: "General", recommendation: "", owner: "", due_date: "", is_condition_of_approval: false, condition_deadline: "" });
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to add finding"); }
  };

  const patch = async (f, body) => {
    try { await api.patch(`/v1/security-reviews/${id}/findings/${f.id}`, body); onChange(); }
    catch (e) { toast.error(e.response?.data?.detail || "Update failed"); }
  };

  const promote = async (f) => {
    try {
      const r = await api.post(`/v1/security-reviews/${id}/findings/${f.id}/promote`);
      toast.success("Promoted to Risk Register");
      onChange();
      return r;
    } catch (e) { toast.error(e.response?.data?.detail || "Promotion failed"); }
  };

  const remove = async (f) => {
    if (!window.confirm("Delete this finding?")) return;
    try { await api.delete(`/v1/security-reviews/${id}/findings/${f.id}`); onChange(); }
    catch (e) { toast.error(e.response?.data?.detail || "Delete failed"); }
  };

  return (
    <div className="space-y-3">
      {!closed && !adding && (
        <button onClick={() => setAdding(true)}
          className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">+ Add finding</button>
      )}
      {adding && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 space-y-3">
          <textarea rows={2} placeholder="Finding description…" value={form.description}
            onChange={e => setForm({ ...form, description: e.target.value })}
            className="w-full px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
          <div className="flex gap-2 flex-wrap items-center">
            <select value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })}
              className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200">
              {["Critical", "High", "Medium", "Low"].map(s => <option key={s}>{s}</option>)}
            </select>
            <input placeholder="Owner" value={form.owner} onChange={e => setForm({ ...form, owner: e.target.value })}
              className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200 w-40"/>
            <input type="date" value={form.due_date} onChange={e => setForm({ ...form, due_date: e.target.value })}
              className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200"/>
            <label className="text-[12px] text-slate-300 inline-flex items-center gap-1.5">
              <input type="checkbox" checked={form.is_condition_of_approval}
                onChange={e => setForm({ ...form, is_condition_of_approval: e.target.checked })}/>
              Condition of approval
            </label>
            {form.is_condition_of_approval && (
              <input type="date" title="Condition deadline" value={form.condition_deadline}
                onChange={e => setForm({ ...form, condition_deadline: e.target.value })}
                className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200"/>
            )}
          </div>
          <textarea rows={2} placeholder="Recommendation…" value={form.recommendation}
            onChange={e => setForm({ ...form, recommendation: e.target.value })}
            className="w-full px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
          <div className="flex gap-2">
            <button onClick={add} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Add</button>
            <button onClick={() => setAdding(false)} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          </div>
        </div>
      )}
      {findings.length === 0 && !adding && (
        <div className="text-[12.5px] text-slate-500 border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-6 text-center">No findings recorded yet.</div>
      )}
      {findings.map(f => (
        <div key={f.id} className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <Chip color={SEV_COLOR[f.severity]}>{f.severity}</Chip>
                {f.status === "draft" && <Chip color="blue">Draft — auto-generated{f.source_tag ? ` · ${f.source_tag}` : ""}</Chip>}
                {f.is_condition_of_approval && (
                  <Chip color={f.condition_met === "met" ? "emerald" : f.condition_met === "not_met" ? "red" : "amber"}>
                    Condition {f.condition_met || "pending"}{f.condition_deadline ? ` · due ${f.condition_deadline}` : ""}
                  </Chip>
                )}
                {f.promoted_to_risk_register_id && (
                  <Link to={`/risk-register/${f.promoted_to_risk_register_id}`}><Chip color="purple">In Risk Register ↗</Chip></Link>
                )}
                {f.status === "resolved" && <Chip color="emerald">Resolved</Chip>}
              </div>
              <div className="text-[12.5px] text-slate-200 mt-1.5">{f.description}</div>
              {f.recommendation && <div className="text-[11.5px] text-slate-400 mt-1">Recommendation: {f.recommendation}</div>}
              <div className="text-[10.5px] text-slate-500 mt-1">
                {f.owner && <>Owner: {f.owner} · </>}{f.due_date && <>Due: {f.due_date} · </>}Added {new Date(f.created_at).toLocaleDateString()}
              </div>
            </div>
            {!closed && (
              <div className="flex flex-col gap-1 shrink-0 items-end">
                {f.status === "draft" && (
                  <button onClick={() => patch(f, { status: "open" })}
                    className="h-7 px-2 text-[11px] border border-blue-500/40 text-blue-300 rounded">Accept draft</button>
                )}
                {f.is_condition_of_approval && f.condition_met !== "met" && (
                  <button onClick={() => patch(f, { condition_met: "met" })}
                    className="h-7 px-2 text-[11px] border border-emerald-500/40 text-emerald-300 rounded">Mark condition met</button>
                )}
                {!f.promoted_to_risk_register_id && (
                  <button onClick={() => promote(f)}
                    className="h-7 px-2 text-[11px] border border-purple-500/40 text-purple-300 rounded">Promote to Risk Register</button>
                )}
                {f.status !== "resolved" && (
                  <button onClick={() => patch(f, { status: "resolved" })}
                    className="h-7 px-2 text-[11px] border border-[#30363D] text-slate-400 rounded">Resolve</button>
                )}
                <button onClick={() => remove(f)} className="h-7 px-2 text-[11px] border border-[#30363D] text-slate-500 hover:text-red-400 rounded">Delete</button>
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------ Decision ------------------------------ */

function DecisionTab({ id, review, meta, closed, onChange }) {
  const d = review.decision;
  const [form, setForm] = useState({
    outcome: d?.outcome || meta.decision_outcomes[0], rationale: d?.rationale || "",
    decision_maker: d?.decision_maker || "", expiration_date: d?.expiration_date || "",
    requestor_acknowledged: d?.requestor_acknowledged || false,
  });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    setSaving(true);
    try {
      await api.put(`/v1/security-reviews/${id}/decision`, {
        ...form, expiration_date: form.expiration_date || null,
      });
      toast.success("Decision recorded");
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to record decision"); }
    finally { setSaving(false); }
  };

  return (
    <div className="max-w-2xl space-y-3">
      {d && (
        <div className="border border-emerald-500/30 bg-emerald-500/5 rounded-md px-4 py-3 text-[12.5px] text-slate-200">
          <span className="font-medium">{d.outcome}</span> by {d.decision_maker} on {new Date(d.decision_date).toLocaleDateString()}
          {d.expiration_date && <> · expires {d.expiration_date.slice(0, 10)}</>}
          {d.requestor_acknowledged && <> · requestor acknowledged</>}
        </div>
      )}
      {!closed && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-1">Outcome</div>
              <select value={form.outcome} onChange={e => setForm({ ...form, outcome: e.target.value })}
                className="w-full h-9 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200">
                {meta.decision_outcomes.map(o => <option key={o}>{o}</option>)}
              </select>
            </div>
            <div>
              <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-1">Decision maker</div>
              <input value={form.decision_maker} onChange={e => setForm({ ...form, decision_maker: e.target.value })}
                className="w-full h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200"/>
            </div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-1">Rationale</div>
            <textarea rows={3} value={form.rationale} onChange={e => setForm({ ...form, rationale: e.target.value })}
              className="w-full px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
          </div>
          <div className="flex items-center gap-4">
            <div>
              <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-1">Approval expiration</div>
              <input type="date" value={form.expiration_date?.slice(0, 10) || ""}
                onChange={e => setForm({ ...form, expiration_date: e.target.value })}
                className="h-9 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200"/>
            </div>
            <label className="text-[12.5px] text-slate-300 inline-flex items-center gap-1.5 mt-4">
              <input type="checkbox" checked={form.requestor_acknowledged}
                onChange={e => setForm({ ...form, requestor_acknowledged: e.target.checked })}/>
              Requestor acknowledged conditions
            </label>
          </div>
          <button onClick={save} disabled={saving}
            className="h-9 px-4 text-[12.5px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
            {saving ? "Saving…" : d ? "Update decision" : "Record decision"}
          </button>
        </div>
      )}
    </div>
  );
}

/* ------------------------------ Notes / Audit ------------------------------ */

function NotesTab({ id, closed }) {
  const [items, setItems] = useState([]);
  const [text, setText] = useState("");
  const load = () => api.get(`/v1/security-reviews/${id}/notes`).then(r => setItems(r.data.items || []));
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [id]);

  const add = async () => {
    if (!text.trim()) return;
    await api.post(`/v1/security-reviews/${id}/notes`, { text });
    setText(""); load();
  };

  return (
    <div className="max-w-2xl space-y-3">
      <div className="text-[11px] text-slate-500">Internal working notes — never rendered into shared reports.</div>
      {!closed && (
        <div className="flex gap-2">
          <input value={text} onChange={e => setText(e.target.value)} onKeyDown={e => e.key === "Enter" && add()}
            placeholder="Add a note…" className="flex-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
          <button onClick={add} className="h-9 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Add</button>
        </div>
      )}
      {items.map(n => (
        <div key={n.id} className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-2.5">
          <div className="text-[12.5px] text-slate-200">{n.text}</div>
          <div className="text-[10.5px] text-slate-500 mt-1">{n.author} · {new Date(n.at).toLocaleString()}</div>
        </div>
      ))}
    </div>
  );
}

function AuditTab({ id }) {
  const [items, setItems] = useState([]);
  useEffect(() => { api.get(`/v1/security-reviews/${id}/audit`).then(r => setItems(r.data.items || [])); }, [id]);
  return (
    <div className="max-w-3xl space-y-1">
      {items.map(a => (
        <div key={a.id} className="flex items-start gap-3 text-[12px] border-b border-[#30363D]/60 py-2">
          <span className="font-mono text-[10.5px] text-slate-500 shrink-0 w-36">{new Date(a.at).toLocaleString()}</span>
          <Chip color="slate">{a.action}</Chip>
          <span className="text-slate-300">{a.details}</span>
          <span className="text-slate-500 ml-auto shrink-0">{a.actor}</span>
        </div>
      ))}
    </div>
  );
}

/* ------------------------------ Report ------------------------------ */

function PrintRiskBadge({ label, band, colors }) {
  return (
    <div className="text-center px-7 py-4 rounded-lg border-2"
      style={{ borderColor: colors[band] || "#94a3b8", background: (colors[band] || "#94a3b8") + "18" }}>
      <div className="text-[10px] uppercase tracking-wide text-slate-600">{label}</div>
      <div className="text-[26px] font-extrabold" style={{ color: colors[band] || "#64748b" }}>{band || "Not scored"}</div>
    </div>
  );
}

function ReportModal({ id, onClose }) {
  const [data, setData] = useState(null);
  useEffect(() => { api.get(`/v1/security-reviews/${id}/report-data`).then(r => setData(r.data)); }, [id]);
  const [shareUrl, setShareUrl] = useState(null);
  if (!data) return null;
  const { review, findings, responses, questionnaire, generated_at, interviews, executive_summary } = data;
  const visibleFindings = findings.filter(f => f.status !== "draft");

  const makeShareLink = async () => {
    try {
      const r = await api.post(`/v1/security-reviews/${id}/share-link`, { expires_days: 30 });
      const url = `${window.location.origin}/shared-report/${r.data.token}`;
      setShareUrl(url);
      navigator.clipboard.writeText(url);
      toast.success("Share link created and copied — expires in 30 days");
    } catch (e) { toast.error(e.response?.data?.detail || "Share link failed"); }
  };
  const d = review.decision;
  const conditions = findings.filter(f => f.is_condition_of_approval && f.status !== "draft");
  const respByOrder = Object.fromEntries((responses || []).map(r => [r.question_order, r]));
  const RISK_PRINT = { Low: "#3b82f6", Medium: "#f59e0b", High: "#f97316", Critical: "#ef4444" };

  return (
    <div className="fixed inset-0 bg-black/70 z-50 overflow-y-auto p-6 print:p-0 print:bg-white" onClick={onClose}>
      <div className="bg-white text-slate-900 max-w-3xl mx-auto rounded print:rounded-none print:max-w-none" onClick={e => e.stopPropagation()}>
        <div className="px-8 py-6 print:px-10" id="sr-report">
          {/* Header */}
          <div className="border-b-2 border-slate-800 pb-3 mb-4 flex items-end justify-between">
            <div>
              <div className="text-[20px] font-bold">Security Review Report</div>
              <div className="text-[12px] text-slate-600">
                {review.review_number} · {new Date(generated_at).toLocaleDateString()} · Reviewer: {review.assignee}
                {review.requestor_name && <> · Requestor: {review.requestor_name} ({review.requestor_department})</>}
              </div>
            </div>
            <div className="print:hidden flex gap-2">
              <button onClick={makeShareLink} className="h-8 px-3 text-[12px] border border-slate-400 text-slate-700 rounded inline-flex items-center gap-1"><LinkSimple size={13}/> Share link</button>
              <button onClick={() => window.print()} className="h-8 px-3 text-[12px] bg-slate-800 text-white rounded">Print / PDF</button>
            </div>
          </div>

          {shareUrl && (
            <div className="print:hidden text-[11px] text-blue-700 bg-blue-50 border border-blue-200 rounded px-3 py-2 mb-3 break-all">
              Read-only link (copied): {shareUrl}
            </div>
          )}
          <div className="text-[13px] mb-4">
            <span className="font-semibold">What was reviewed:</span> {review.entity_name || review.title} — {review.title}
          </div>

          {/* Risk verdict panel */}
          <div className="flex items-center justify-center gap-4 my-5">
            <PrintRiskBadge label="Risk if adopted as-is" band={review.inherent_risk?.band} colors={RISK_PRINT}/>
            <div className="text-[26px] text-slate-400">→</div>
            <PrintRiskBadge label="Risk with required controls" band={review.residual_risk?.band} colors={RISK_PRINT}/>
            {review.risk_of_not_adopting?.band && (
              <div className="text-center px-4 py-2.5 rounded-lg border" style={{ borderColor: RISK_PRINT[review.risk_of_not_adopting.band] }}>
                <div className="text-[9px] uppercase tracking-wide text-slate-600">Risk of not adopting</div>
                <div className="text-[16px] font-bold" style={{ color: RISK_PRINT[review.risk_of_not_adopting.band] }}>{review.risk_of_not_adopting.band}</div>
              </div>
            )}
          </div>

          {/* Plain-English summary */}
          <div className="text-[13px] leading-relaxed mb-4">
            {executive_summary || review.scope_statement || "See technical appendix for full assessment detail."}
          </div>

          {/* Key findings */}
          {visibleFindings.length > 0 && (
            <div className="mb-4">
              <div className="text-[13px] font-semibold mb-1.5">Key findings</div>
              <ul className="space-y-1">
                {visibleFindings.slice(0, 5).map(f => (
                  <li key={f.id} className="text-[12.5px] flex items-start gap-2">
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded mt-0.5 text-white shrink-0"
                      style={{ background: RISK_PRINT[f.severity] || "#64748b" }}>{f.severity}</span>
                    <span>{f.description}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Decision box */}
          <div className="border-2 border-slate-800 rounded p-3.5 mb-4">
            <div className="text-[13px] font-semibold">Decision: {d?.outcome || "Pending"}</div>
            {d?.rationale && <div className="text-[12px] text-slate-700 mt-1">{d.rationale}</div>}
            {conditions.length > 0 && (
              <div className="mt-2">
                <div className="text-[12px] font-medium">Conditions of approval:</div>
                <ul className="list-disc ml-5 text-[12px] text-slate-700">
                  {conditions.map(c => (
                    <li key={c.id}>{c.description}{c.condition_deadline && <> — due {c.condition_deadline}</>}{c.owner && <> (owner: {c.owner})</>}</li>
                  ))}
                </ul>
              </div>
            )}
            {d?.expiration_date && <div className="text-[11.5px] text-slate-600 mt-1.5">Approval expires: {d.expiration_date.slice(0, 10)}</div>}
          </div>

          {/* Data & systems touched */}
          <div className="mb-5">
            <div className="text-[13px] font-semibold mb-1">Data &amp; systems touched</div>
            <div className="flex gap-1.5 flex-wrap">
              {(review.data_classifications || []).map(c => (
                <span key={c} className="text-[11px] px-2 py-0.5 rounded-full bg-slate-200 text-slate-800">{c}</span>
              ))}
              {review.entity_domain && <span className="text-[11px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-600">{review.entity_domain}</span>}
            </div>
          </div>

          {/* Technical appendix */}
          {questionnaire && responses.length > 0 && (
            <div className="border-t border-slate-300 pt-4 mb-4 break-before-page">
              <div className="text-[14px] font-bold mb-2">Technical appendix — questionnaire responses</div>
              {questionnaire.questions.filter(q => respByOrder[q.order]).map(q => {
                const r = respByOrder[q.order];
                return (
                  <div key={q.order} className="text-[11.5px] mb-1.5">
                    <span className="font-medium">Q{q.order}.</span> {q.text}
                    <span className="ml-2 font-semibold uppercase" style={{ color: r.answer === "no" ? "#ef4444" : r.answer === "partial" ? "#f59e0b" : "#16a34a" }}>{r.answer}</span>
                    <span className="text-slate-500 ml-2">[CIS {q.cis_mapping}]</span>
                    {r.evidence_text && <div className="text-slate-600 ml-4">{r.evidence_text}</div>}
                  </div>
                );
              })}
            </div>
          )}

          {interviews && interviews.length > 0 && (
            <div className="border-t border-slate-300 pt-3 mb-4">
              <div className="text-[13px] font-semibold mb-1.5">Stakeholder input</div>
              {interviews.map(it => (
                <div key={it.id} className="text-[11.5px] mb-1">
                  <span className="font-medium">{it.who}</span> ({it.role || "—"}, {it.when}): {it.summary}
                </div>
              ))}
            </div>
          )}

          {/* Footer */}
          <div className="border-t border-slate-300 pt-2 text-[10.5px] text-slate-500">
            {review.review_number} · Playbook {review.playbook_key} v{review.playbook_version} · Template {review.template_key} v{review.template_version} · Generated {new Date(generated_at).toLocaleString()} · Technical appendix included above
          </div>
        </div>
      </div>
    </div>
  );
}
