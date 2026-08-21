import { useEffect, useState, useRef } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { renderBlocks, ReportLayoutEditor } from "@/components/ReportBlocks";
import {
  ArrowLeft, CaretDown, CaretRight, CheckCircle, Printer, ArrowRight,
  Warning, ClipboardText, Scales, ListChecks, Gavel, NotePencil, ClockCounterClockwise,
  Users, ShieldCheck, Copy, ArrowsClockwise, LinkSimple, Sparkle, PaperPlaneTilt,
  TextB, TextItalic, TextUnderline, Code, Highlighter, FileDoc, UserSwitch, Trash, X, Plus,
  HardDrives, Paperclip, PencilSimple, FloppyDisk, DownloadSimple,
} from "@phosphor-icons/react";

const RISK_COLOR = { Low: "blue", Medium: "amber", High: "orange", Critical: "red" };
// 5×5 banding, mirrors backend risk_band(): score = likelihood × impact (each 1-5).
const calcBand = (likelihood, impact) => {
  const score = Math.max(1, Math.min(5, likelihood || 1)) * Math.max(1, Math.min(5, impact || 1));
  return score <= 4 ? "Low" : score <= 9 ? "Medium" : score <= 16 ? "High" : "Critical";
};
const RISK_BG = { Low: "bg-blue-500/15 border-blue-500/40 text-blue-300",
  Medium: "bg-amber-500/15 border-amber-500/40 text-amber-300",
  High: "bg-orange-500/15 border-orange-500/40 text-orange-300",
  Critical: "bg-red-500/15 border-red-500/40 text-red-300" };
const SEV_COLOR = { Critical: "red", High: "orange", Medium: "amber", Low: "blue" };
const STEP_STATUS_COLOR = { "Not started": "slate", "In progress": "blue", "Blocked": "amber", "Done": "emerald", "N/A": "slate" };
const ANSWERS = [["yes", "Yes"], ["no", "No"], ["partial", "Partial"], ["na", "N/A"]];
// Highlight swatches. Deliberately light tones: highlighted text is forced to a
// dark colour (see .sr-richtext in index.css) so it stays readable, which only
// works against a light background.
const HIGHLIGHTS = ["#fde68a", "#bbf7d0", "#bfdbfe", "#fecaca", "#e9d5ff"];

const TABS = [
  { id: "playbook", label: "Playbook", icon: ListChecks },
  { id: "questionnaire", label: "Questionnaire", icon: ClipboardText },
  { id: "risk", label: "Risk Scoring", icon: Scales },
  { id: "findings", label: "Findings", icon: Warning },
  { id: "recommendation", label: "Recommendation", icon: NotePencil },
  { id: "decision", label: "Decision", icon: Gavel },
  { id: "assets", label: "In-Scope Assets", icon: HardDrives },
  { id: "attachments", label: "Documents", icon: Paperclip },
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
  const applicableQuestions = data.applicable_questions;
  const questionnaireScoring = data.questionnaire_scoring;
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
          <ReassignControl id={id} review={review} closed={closed} onChange={load}/>
          <select value={review.status} onChange={e => setStatus(e.target.value)} disabled={closed}
            className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200 disabled:opacity-60">
            {meta.statuses.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      }>

      {/* Header: risk badges + next-best-action */}
      <div className="flex items-stretch gap-3 mb-4 flex-wrap">
        <RiskBadge label="Risk if adopted as-is" band={review.inherent_risk?.band} rating={review.inherent_risk}/>
        <div className="flex items-center text-slate-600"><ArrowRight size={18}/></div>
        <RiskBadge label="Risk with required controls" band={review.residual_risk?.band} rating={review.residual_risk}/>
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
      {tab === "questionnaire" && <QuestionnaireTab id={id} questionnaire={questionnaire} responses={responses}
        review={review} closed={closed} onChange={load} meta={meta}
        applicableQuestions={applicableQuestions} scoring={questionnaireScoring}/>}
      {tab === "risk" && <RiskTab id={id} review={review} meta={meta} closed={closed} onChange={load}/>}
      {tab === "findings" && <FindingsTab id={id} findings={findings} closed={closed} onChange={load}/>}
      {tab === "recommendation" && <RecommendationTab id={id} review={review} closed={closed} onChange={load}/>}
      {tab === "decision" && <DecisionTab id={id} review={review} meta={meta} closed={closed} onChange={load}/>}
      {tab === "assets" && <AssetsTab id={id} closed={closed} onChange={load}/>}
      {tab === "attachments" && <AttachmentsTab id={id} closed={closed}/>}
      {tab === "interviews" && <InterviewsTab id={id} closed={closed}/>}
      {tab === "checks" && <ExternalChecksTab id={id} review={review} closed={closed} onChange={load}/>}
      {tab === "notes" && <NotesTab id={id} closed={closed}/>}
      {tab === "audit" && <AuditTab id={id}/>}

      {reportOpen && <ReportModal id={id} onClose={() => setReportOpen(false)}/>}
    </Layout>
  );
}

function RiskBadge({ label, band, small, rating }) {
  const adjustedFrom = rating?.overridden ? rating.calculated_band : null;
  return (
    <div className={`border rounded-md px-4 ${small ? "py-1.5" : "py-2.5"} text-center min-w-[150px] ${band ? RISK_BG[band] : "border-[#30363D] bg-[#0D1117] text-slate-600"}`}>
      <div className="text-[10px] uppercase tracking-wider font-mono opacity-80">{label}</div>
      <div className={`${small ? "text-[16px]" : "text-[22px]"} font-bold mt-0.5`}>{band || "Not scored"}</div>
      {adjustedFrom && (
        <div className="text-[9.5px] uppercase tracking-wider font-mono opacity-70 mt-0.5" title="Manually overridden from the calculated 5×5 score">
          adjusted from {adjustedFrom}
        </div>
      )}
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

function CapabilityProfile({ id, review, meta, closed, onChange }) {
  const flags = meta?.capability_flags || [];
  const [caps, setCaps] = useState(review.capabilities || {});
  const [saving, setSaving] = useState(false);
  const [open, setOpen] = useState(false);

  const toggle = (key) => setCaps(prev => ({ ...prev, [key]: !prev[key] }));

  const save = async () => {
    setSaving(true);
    try {
      const r = await api.put(`/v1/security-reviews/${id}/capabilities`, { capabilities: caps });
      toast.success(`Profile saved — ${r.data.applicable_count} question(s) now apply`);
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Save failed"); }
    finally { setSaving(false); }
  };

  const onCount = flags.filter(f => caps[f.key]).length;

  return (
    <div className="border border-purple-500/30 bg-purple-500/5 rounded-md mb-4">
      <div className="px-4 py-2.5 flex items-center gap-2 cursor-pointer" onClick={() => setOpen(!open)}>
        {open ? <CaretDown size={13} className="text-purple-300"/> : <CaretRight size={13} className="text-purple-300"/>}
        <span className="text-[12.5px] text-purple-200 font-medium">Section 0 — Capability Profile</span>
        <span className="text-[11px] text-slate-500">{onCount} of {flags.length} set · decides which modules apply</span>
      </div>
      {open && (
        <div className="border-t border-purple-500/20 px-4 py-3">
          <div className="text-[11.5px] text-slate-400 mb-2.5">
            What <em>is</em> this thing? These flags gate whole questionnaire modules, so a question that
            doesn't apply is never asked instead of being asked and N/A'd. Pre-seeded from the playbook type — override freely.
          </div>
          <div className="grid sm:grid-cols-2 gap-1.5">
            {flags.map(f => (
              <button key={f.key} disabled={closed} onClick={() => toggle(f.key)} title={f.help}
                className={`text-left border rounded px-2.5 py-2 disabled:opacity-60 ${caps[f.key]
                  ? "border-purple-500/50 bg-purple-500/15" : "border-[#30363D] hover:border-slate-500"}`}>
                <div className="flex items-center gap-2">
                  <span className={`h-3.5 w-3.5 rounded-sm border shrink-0 ${caps[f.key]
                    ? "bg-purple-400 border-purple-400" : "border-slate-600"}`}/>
                  <span className="text-[12px] text-slate-200">{f.label}</span>
                </div>
                <div className="text-[10.5px] text-slate-500 mt-0.5 ml-5.5">{f.help}</div>
              </button>
            ))}
          </div>
          {!closed && (
            <button onClick={save} disabled={saving}
              className="mt-3 h-8 px-3 text-[12px] bg-purple-500 hover:bg-purple-400 disabled:opacity-50 text-white rounded">
              {saving ? "Applying…" : "Apply profile"}
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function QuestionnaireTab({ id, questionnaire, responses, review, closed, onChange, meta,
                            applicableQuestions, scoring }) {
  const respByOrder = Object.fromEntries((responses || []).map(r => [r.question_order, r]));
  const [evidenceDrafts, setEvidenceDrafts] = useState({});
  const [vendorQ, setVendorQ] = useState(null);
  const [autoAnswering, setAutoAnswering] = useState(false);
  const [naPicker, setNaPicker] = useState(null);   // question order awaiting a reason code
  const [customOpen, setCustomOpen] = useState(false);
  const [customForm, setCustomForm] = useState({ text: "", domain: "Custom", risk_weight: 3 });
  if (!questionnaire) return <div className="text-slate-500 text-[12.5px]">No questionnaire template attached.</div>;

  const adaptive = questionnaire.engine === "capability_gated";
  const naCodes = meta?.na_reason_codes || {};
  const activeClassifications = review.data_classifications || [];

  const condMet = (cond) => {
    if (!cond) return true;
    if (cond.startsWith("q") && cond.includes(":")) {
      const [qref, want] = cond.slice(1).split(":");
      return respByOrder[parseInt(qref, 10)]?.answer === want;
    }
    return activeClassifications.includes(cond);
  };
  const questions = adaptive
    ? (applicableQuestions || [])
    : questionnaire.questions.filter(q => condMet(q.conditional_on));

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

  const save = async (q, answer, evidence_text, na_reason_code) => {
    if (answer === "na" && !na_reason_code) { setNaPicker(q.order); return; }
    try {
      await api.put(`/v1/security-reviews/${id}/responses`, {
        question_order: q.order, answer, na_reason_code: na_reason_code || null,
        evidence_text: evidence_text !== undefined ? evidence_text : (respByOrder[q.order]?.evidence_text || ""),
      });
      setNaPicker(null);
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to save answer"); }
  };

  const addCustom = async () => {
    if (!customForm.text.trim()) { toast.error("Question text required"); return; }
    try {
      await api.post(`/v1/security-reviews/${id}/custom-questions`, customForm);
      setCustomForm({ text: "", domain: "Custom", risk_weight: 3 });
      setCustomOpen(false);
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed"); }
  };

  const promote = async (q) => {
    if (!window.confirm("Promote this question into the template as a new version?")) return;
    try {
      const r = await api.post(`/v1/security-reviews/${id}/custom-questions/${q.id}/promote`);
      toast.success(`Added to template v${r.data.version} — existing reviews keep their version`);
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Promotion failed"); }
  };

  const domains = [...new Set(questions.map(q => q.domain))];
  const answered = questions.filter(q => respByOrder[q.order]).length;

  return (
    <div>
      {adaptive && <CapabilityProfile id={id} review={review} meta={meta} closed={closed} onChange={onChange}/>}

      <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
        <div className="text-[11.5px] text-slate-500">
          {answered} of {questions.length} answered
          {adaptive && <span> · adaptive: only applicable modules shown</span>}
          <span> · template v{questionnaire.version}</span>
        </div>
        <div className="flex gap-2">
          {!closed && (
            <button onClick={() => setCustomOpen(!customOpen)}
              className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-slate-500 text-slate-300 rounded inline-flex items-center gap-1.5">
              <Plus size={13}/> Custom question
            </button>
          )}
          {!closed && (
            <button onClick={autoAnswer} disabled={autoAnswering}
              className="h-8 px-3 text-[12px] border border-blue-500/40 text-blue-300 rounded inline-flex items-center gap-1.5 disabled:opacity-50">
              <Sparkle size={13}/> {autoAnswering ? "Answering…" : "Auto-answer"}
            </button>
          )}
          <button onClick={loadVendorQ}
            className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-slate-500 text-slate-300 rounded inline-flex items-center gap-1.5">
            <PaperPlaneTilt size={13}/> Vendor questionnaire
          </button>
        </div>
      </div>

      {scoring && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-2.5 mb-3 flex items-center gap-4 flex-wrap text-[12px]">
          <span className="text-slate-400">Confidence</span>
          <div className="flex-1 min-w-[120px] h-2 bg-slate-800 rounded overflow-hidden">
            <div className={`h-full ${scoring.confidence_pct >= 80 ? "bg-emerald-500" : scoring.confidence_pct >= 50 ? "bg-amber-500" : "bg-red-500"}`}
              style={{ width: `${scoring.confidence_pct}%` }}/>
          </div>
          <span className="text-slate-200 font-medium">{scoring.confidence_pct}%</span>
          {scoring.unknown_count > 0 && <Chip color="amber">{scoring.unknown_count} unknown</Chip>}
          {scoring.pending_vendor_count > 0 && <Chip color="blue">{scoring.pending_vendor_count} pending vendor</Chip>}
          {scoring.unanswered_count > 0 && <Chip color="slate">{scoring.unanswered_count} unanswered</Chip>}
        </div>
      )}

      {customOpen && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 mb-3 space-y-2">
          <textarea rows={2} placeholder="Question specific to this review…" value={customForm.text}
            onChange={e => setCustomForm({ ...customForm, text: e.target.value })}
            className="w-full px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
          <div className="flex gap-2 items-center">
            <input placeholder="Module" value={customForm.domain}
              onChange={e => setCustomForm({ ...customForm, domain: e.target.value })}
              className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200 w-48"/>
            <select value={customForm.risk_weight} onChange={e => setCustomForm({ ...customForm, risk_weight: parseInt(e.target.value, 10) })}
              className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200">
              {[0, 1, 2, 3, 4, 5].map(w => <option key={w} value={w}>weight {w}</option>)}
            </select>
            <button onClick={addCustom} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Add</button>
          </div>
        </div>
      )}

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
                        <span className="text-[10.5px] text-slate-500 ml-2">
                          {q.cis_mapping ? `[CIS ${q.cis_mapping}] · ` : ""}weight {q.risk_weight}
                          {q.vendor_facing ? " · vendor-facing" : ""}
                        </span>
                        {q.custom && (
                          <span className="ml-2 inline-flex items-center gap-1">
                            <Chip color="purple">custom</Chip>
                            {!closed && !q.promoted_to_version && (
                              <button onClick={() => promote(q)} className="text-[10px] text-purple-300 hover:underline">promote to template</button>
                            )}
                            {q.promoted_to_version && <span className="text-[10px] text-slate-500">in template v{q.promoted_to_version}</span>}
                          </span>
                        )}
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

                    {naPicker === q.order && (
                      <div className="mt-2 border border-amber-500/30 bg-amber-500/5 rounded p-2.5">
                        <div className="text-[11px] text-amber-200 mb-1.5">Why is this N/A? "Doesn't apply" and "we don't know" are opposite signals.</div>
                        <div className="flex gap-1.5 flex-wrap">
                          {Object.entries(naCodes).map(([code, m]) => (
                            <button key={code} onClick={() => save(q, "na", undefined, code)} title={m.help}
                              className="h-7 px-2.5 text-[11.5px] border border-[#30363D] hover:border-amber-500/40 text-slate-300 rounded">
                              {m.label}
                            </button>
                          ))}
                          <button onClick={() => setNaPicker(null)} className="h-7 px-2 text-[11px] text-slate-500">cancel</button>
                        </div>
                      </div>
                    )}

                    {resp?.answer === "na" && resp?.na_reason_code && (
                      <div className={`text-[10.5px] mt-1 ${naCodes[resp.na_reason_code]?.counts_against_confidence ? "text-amber-300" : "text-slate-500"}`}>
                        {naCodes[resp.na_reason_code]?.label || resp.na_reason_code}
                        {naCodes[resp.na_reason_code]?.counts_against_confidence ? " — counts against confidence" : " — excluded from scoring"}
                      </div>
                    )}
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
                        onBlur={e => save(q, resp.answer, e.target.value, resp.na_reason_code)}
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

function AssetsTab({ id, closed, onChange }) {
  const [linked, setLinked] = useState([]);
  const [picker, setPicker] = useState(null);
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState("individual");   // individual | team | tag
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState(new Set());
  const [bulkTeams, setBulkTeams] = useState(new Set());
  const [bulkTags, setBulkTags] = useState(new Set());
  const [busy, setBusy] = useState(false);
  const [selRemove, setSelRemove] = useState(new Set());   // in-scope rows checked for mass-remove

  const load = () => api.get(`/v1/security-reviews/${id}/assets`)
    .then(r => { setLinked(r.data.items || []); setSelRemove(new Set()); });
  const loadPicker = (search) => api.get("/v1/security-reviews/asset-picker",
    { params: search ? { q: search } : {} }).then(r => setPicker(r.data));
  useEffect(() => { load(); loadPicker(); /* eslint-disable-next-line */ }, [id]);

  const toggle = (set, setter, v) => {
    const n = new Set(set);
    n.has(v) ? n.delete(v) : n.add(v);
    setter(n);
  };

  const link = async () => {
    const body = {
      asset_ids: mode === "individual" ? Array.from(selected) : [],
      teams: mode === "team" ? Array.from(bulkTeams) : [],
      tags: mode === "tag" ? Array.from(bulkTags) : [],
    };
    if (!body.asset_ids.length && !body.teams.length && !body.tags.length) {
      toast.error("Nothing selected"); return;
    }
    setBusy(true);
    try {
      const r = await api.post(`/v1/security-reviews/${id}/assets`, body);
      toast.success(`${r.data.added} asset(s) added — ${r.data.linked_total} in scope`);
      setSelected(new Set()); setBulkTeams(new Set()); setBulkTags(new Set());
      setOpen(false); load(); onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Link failed"); }
    finally { setBusy(false); }
  };

  // "Remove" here means UNLINK from this review's scope only. It never deletes the
  // host or its findings from inventory -- the backend only edits this review's
  // linked_asset_ids. The confirm copy says so explicitly so no one mistakes the
  // trash icon for a destructive delete.
  const removeFromScope = async (ids, labels) => {
    if (!ids.length) return;
    const what = ids.length === 1
      ? `"${labels[0]}"`
      : `${ids.length} assets`;
    if (!window.confirm(
      `Remove ${what} from this review's scope?\n\n` +
      `This only unlinks ${ids.length === 1 ? "it" : "them"} from this review — ` +
      `the host and its findings stay in inventory and are not deleted.`)) return;
    setBusy(true);
    try {
      const r = await api.post(`/v1/security-reviews/${id}/assets/unlink`, { asset_ids: ids });
      toast.success(`${ids.length} asset(s) removed from scope — ${r.data.linked_total} still in scope`);
      load(); onChange();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Remove failed");
    } finally { setBusy(false); }
  };
  const unlink = (a) => removeFromScope([a.id], [a.hostname]);
  const removeSelected = () => {
    const ids = linked.filter(a => selRemove.has(a.id)).map(a => a.id);
    const labels = linked.filter(a => selRemove.has(a.id)).map(a => a.hostname);
    removeFromScope(ids, labels);
  };
  const allChecked = linked.length > 0 && selRemove.size === linked.length;
  const toggleAll = () => setSelRemove(allChecked ? new Set() : new Set(linked.map(a => a.id)));

  const totalCritHigh = linked.reduce((n, a) => n + (a.critical_high_findings || 0), 0);

  return (
    <div className="space-y-3">
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3.5 py-2.5 text-[12px] text-blue-200">
        Assets this review touches. Add them individually, or pull in a whole team&apos;s or tag&apos;s worth at once —
        bulk selections resolve to a fixed list at link time, so the scope stays reproducible even if someone
        re-tags a host later. This list is what the auto-fill hooks read for environment health.
        <span className="block mt-1 text-blue-300/80">Removing an asset only takes it out of this review&apos;s scope —
        it does not delete the host or its findings from inventory.</span>
      </div>

      <div className="flex items-center justify-between flex-wrap gap-2">
        <div className="text-[12px] text-slate-400">
          {linked.length} asset(s) in scope
          {totalCritHigh > 0 && <span className="text-red-300"> · {totalCritHigh} open Critical/High finding(s) across them</span>}
        </div>
        <div className="flex items-center gap-2">
          {!closed && selRemove.size > 0 && (
            <button onClick={removeSelected} disabled={busy}
              className="h-8 px-3 text-[12px] bg-red-500/15 border border-red-500/40 text-red-300 hover:bg-red-500/25 disabled:opacity-50 rounded inline-flex items-center gap-1.5">
              <Trash size={13}/> Remove {selRemove.size} from scope
            </button>
          )}
          {!closed && (
            <button onClick={() => setOpen(!open)}
              className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
              <Plus size={13}/> Add assets
            </button>
          )}
        </div>
      </div>

      {open && picker && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 space-y-3">
          <div className="inline-flex rounded border border-[#30363D] overflow-hidden">
            {[["individual", "Individual"], ["team", "By team"], ["tag", "By tag"]].map(([m, label], i) => (
              <button key={m} onClick={() => setMode(m)}
                className={`h-7 px-3 text-[11.5px] ${i > 0 ? "border-l border-[#30363D]" : ""} ${
                  mode === m ? "bg-blue-500/15 text-blue-300" : "text-slate-400 hover:text-slate-200"}`}>
                {label}
              </button>
            ))}
          </div>

          {mode === "individual" && (
            <>
              <input value={q} onChange={e => { setQ(e.target.value); loadPicker(e.target.value); }}
                placeholder="Search hostname or IP…"
                className="w-full h-8 px-3 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100"/>
              <div className="max-h-64 overflow-y-auto border border-[#30363D] rounded divide-y divide-[#30363D]">
                {picker.items.map(a => (
                  <label key={a.id} className="flex items-center gap-2 px-3 py-1.5 text-[12px] cursor-pointer hover:bg-slate-800/30">
                    <input type="checkbox" checked={selected.has(a.id)}
                      onChange={() => toggle(selected, setSelected, a.id)}/>
                    <span className="text-slate-200 font-mono">{a.hostname}</span>
                    <span className="text-slate-500">{a.ip}</span>
                    {a.owner_team && <Chip color="slate">{a.owner_team}</Chip>}
                    {a.criticality && <Chip color="blue">{a.criticality}</Chip>}
                    {a.internet_facing && <Chip color="amber">internet-facing</Chip>}
                  </label>
                ))}
                {picker.items.length === 0 && <div className="px-3 py-3 text-[12px] text-slate-500">No matches.</div>}
              </div>
              <div className="text-[11px] text-slate-500">{selected.size} selected</div>
            </>
          )}

          {mode === "team" && (
            <div className="flex gap-1.5 flex-wrap">
              {picker.teams.map(t => (
                <button key={t} onClick={() => toggle(bulkTeams, setBulkTeams, t)}
                  className={`h-7 px-2.5 text-[11.5px] rounded border ${bulkTeams.has(t)
                    ? "bg-blue-500/15 border-blue-500/40 text-blue-300" : "border-[#30363D] text-slate-400"}`}>
                  {t}
                </button>
              ))}
              {picker.teams.length === 0 && <div className="text-[12px] text-slate-500">No teams on any asset yet.</div>}
            </div>
          )}

          {mode === "tag" && (
            <div className="flex gap-1.5 flex-wrap">
              {picker.tags.map(t => (
                <button key={t} onClick={() => toggle(bulkTags, setBulkTags, t)}
                  className={`h-7 px-2.5 text-[11.5px] rounded border ${bulkTags.has(t)
                    ? "bg-blue-500/15 border-blue-500/40 text-blue-300" : "border-[#30363D] text-slate-400"}`}>
                  {t}
                </button>
              ))}
              {picker.tags.length === 0 && <div className="text-[12px] text-slate-500">No tags on any asset yet.</div>}
            </div>
          )}

          <button onClick={link} disabled={busy}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
            {busy ? "Adding…" : "Add to scope"}
          </button>
        </div>
      )}

      {linked.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-8 text-center text-[12.5px] text-slate-500">
          No assets linked yet.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr className="border-b border-[#30363D] text-left text-slate-500 text-[11px] uppercase tracking-wider">
                {!closed && <th className="pl-4 pr-1 py-2 font-medium w-8">
                  <input type="checkbox" checked={allChecked} onChange={toggleAll}
                    title="Select all" className="align-middle"/>
                </th>}
                <th className="px-4 py-2 font-medium">Asset</th>
                <th className="px-4 py-2 font-medium">Team</th>
                <th className="px-4 py-2 font-medium">Criticality</th>
                <th className="px-4 py-2 font-medium">Open findings</th>
                <th className="px-4 py-2 font-medium"></th>
              </tr>
            </thead>
            <tbody>
              {linked.map(a => (
                <tr key={a.id} className="border-b border-[#30363D] last:border-0">
                  {!closed && <td className="pl-4 pr-1 py-2 w-8">
                    <input type="checkbox" checked={selRemove.has(a.id)}
                      onChange={() => toggle(selRemove, setSelRemove, a.id)} className="align-middle"/>
                  </td>}
                  <td className="px-4 py-2">
                    <Link to={`/assets/${a.id}`} className="text-blue-300 hover:underline font-mono">{a.hostname}</Link>
                    <span className="text-slate-500 ml-2">{a.ip}</span>
                  </td>
                  <td className="px-4 py-2 text-slate-400">{a.owner_team || "—"}</td>
                  <td className="px-4 py-2 text-slate-400">{a.criticality || "—"}</td>
                  <td className="px-4 py-2">
                    <span className="text-slate-300">{a.open_findings}</span>
                    {a.critical_high_findings > 0 && <Chip color="red">{a.critical_high_findings} crit/high</Chip>}
                  </td>
                  <td className="px-4 py-2 text-right">
                    {!closed && <button onClick={() => unlink(a)} title="Remove from this review's scope (does not delete the host)" className="text-slate-600 hover:text-red-400"><Trash size={13}/></button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const ATTACHMENT_CATEGORIES = ["supporting", "contract", "certificate", "questionnaire", "screenshot"];

function AttachmentsTab({ id, closed }) {
  const [items, setItems] = useState([]);
  const [category, setCategory] = useState("supporting");
  const [description, setDescription] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () => api.get(`/v1/security-reviews/${id}/attachments`).then(r => setItems(r.data.items || []));
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [id]);

  const upload = async (files) => {
    setBusy(true);
    try {
      for (const file of files) {
        const reader = new FileReader();
        const data_url = await new Promise(res => { reader.onload = () => res(reader.result); reader.readAsDataURL(file); });
        await api.post(`/v1/security-reviews/${id}/attachments`, {
          name: file.name, mime: file.type, data_url, description, category });
      }
      setDescription("");
      toast.success(`${files.length} document(s) attached`);
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Upload failed"); }
    finally { setBusy(false); }
  };

  const remove = async (a) => {
    if (!window.confirm(`Delete "${a.name}"?`)) return;
    await api.delete(`/v1/security-reviews/${id}/attachments/${a.id}`);
    load();
  };

  const download = async (a) => {
    // data_url is stripped from the list payload to keep it light; fetch on demand
    const r = await api.get(`/v1/security-reviews/${id}/attachments`);
    const full = (r.data.items || []).find(x => x.id === a.id);
    const url = full?.data_url || a.data_url;
    if (!url) { toast.error("File content unavailable"); return; }
    const link = document.createElement("a");
    link.href = url; link.download = a.name;
    document.body.appendChild(link); link.click(); link.remove();
  };

  return (
    <div className="space-y-3 max-w-3xl">
      <div className="text-[11.5px] text-slate-500">
        Supporting documents for the review as a whole — contracts, SOC 2 reports, vendor questionnaire responses,
        screenshots. (Evidence tied to one playbook step still lives on that step.) These are listed in the report&apos;s
        technical appendix.
      </div>
      {!closed && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 space-y-2">
          <div className="flex gap-2 flex-wrap">
            <select value={category} onChange={e => setCategory(e.target.value)}
              className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200 capitalize">
              {ATTACHMENT_CATEGORIES.map(c => <option key={c} value={c}>{c}</option>)}
            </select>
            <input placeholder="Description (optional)" value={description}
              onChange={e => setDescription(e.target.value)}
              className="flex-1 h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200"/>
          </div>
          <input type="file" multiple disabled={busy}
            onChange={e => upload(Array.from(e.target.files || []))}
            className="block text-[11.5px] text-slate-500"/>
          <div className="text-[10.5px] text-slate-600">10 MB per file.</div>
        </div>
      )}
      {items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-8 text-center text-[12.5px] text-slate-500">
          No documents attached yet.
        </div>
      ) : items.map(a => (
        <div key={a.id} className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-2.5 flex items-center gap-3">
          <Paperclip size={14} className="text-slate-500 shrink-0"/>
          <div className="min-w-0 flex-1">
            <div className="text-[12.5px] text-slate-200 truncate">{a.name}</div>
            <div className="text-[10.5px] text-slate-500">
              <span className="capitalize">{a.category}</span>
              {a.description ? ` · ${a.description}` : ""} · {Math.round((a.size_bytes || 0) / 1024)} KB ·
              {" "}{a.uploaded_by} · {new Date(a.uploaded_at).toLocaleDateString()}
            </div>
          </div>
          <button onClick={() => download(a)} className="text-slate-500 hover:text-blue-300"><DownloadSimple size={14}/></button>
          {!closed && <button onClick={() => remove(a)} className="text-slate-600 hover:text-red-400"><Trash size={13}/></button>}
        </div>
      ))}
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
  not_configured: { color: "blue", label: "Not configured" },
};

const CHECK_LABELS = {
  corporate_registration: "Corporate registration",
  breach_reputation: "Breach & incident reputation",
  certification_status: "Certification status (SOC 2 / ISO)",
  viability_signals: "Viability signals",
  tls_security_headers: "TLS & security headers",
  cve_lookup: "Known CVEs (NVD)",
  email_authentication: "Email authentication (SPF/DKIM/DMARC)",
  shodan_exposure: "Internet exposure (Shodan)",
  certificate_transparency: "Certificate transparency",
  dns_whois: "DNS & WHOIS hygiene",
  typosquat: "Lookalike domains",
};

function CheckRow({ c }) {
  const [open, setOpen] = useState(false);
  const meta_ = CHECK_STATUS_META[c.status] || CHECK_STATUS_META.manual;
  const hasDetail = c.detail && (typeof c.detail !== "object" || Object.keys(c.detail).length > 0);
  // Executives read the question and the plain-English status; analysts expand
  // for the raw evidence.
  const title = c.label || CHECK_LABELS[c.check] || c.check;
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
      <div className="px-4 py-2.5 cursor-pointer" onClick={() => setOpen(!open)}>
        <div className="flex items-start justify-between gap-2">
          <span className="text-[12.5px] text-slate-200 inline-flex items-start gap-1.5">
            {open ? <CaretDown size={11} className="text-slate-500 mt-1"/> : <CaretRight size={11} className="text-slate-500 mt-1"/>}
            {title}
          </span>
          <Chip color={meta_.color}>{c.status_plain || meta_.label}</Chip>
        </div>
        <div className="text-[12px] text-slate-400 mt-1 ml-4">{c.summary}</div>
      </div>
      {open && (
        <div className="border-t border-[#30363D] px-4 py-2.5 space-y-2">
          {c.what_it_means && (
            <div className="text-[11.5px] text-slate-400">
              <span className="text-slate-500">What we checked: </span>{c.what_it_means}
            </div>
          )}
          {c.why_it_matters && (
            <div className="text-[11.5px] text-slate-400">
              <span className="text-slate-500">Why it matters: </span>{c.why_it_matters}
            </div>
          )}
          <div className="text-[10px] text-slate-600 font-mono">{c.source_tag}</div>
          {hasDetail && (
            <details>
              <summary className="text-[11px] text-blue-300 cursor-pointer">Raw evidence</summary>
              <pre className="mt-1 text-[10.5px] text-slate-400 whitespace-pre-wrap break-all max-h-64 overflow-y-auto">
                {JSON.stringify(c.detail, null, 2)}
              </pre>
            </details>
          )}
        </div>
      )}
    </div>
  );
}

function EntityPrereqEditor({ id, review, onChange }) {
  const [form, setForm] = useState({ legal_name: "", domain: review.entity_domain || "", jurisdiction: "" });
  const [saving, setSaving] = useState(false);
  const save = async () => {
    setSaving(true);
    try {
      const body = Object.fromEntries(Object.entries(form).filter(([, v]) => v));
      await api.patch(`/v1/security-reviews/${id}/entity`, body);
      toast.success("Entity updated");
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Update failed"); }
    finally { setSaving(false); }
  };
  return (
    <div className="border border-amber-500/30 bg-amber-500/5 rounded-md p-3.5 space-y-2">
      <div className="text-[12px] text-amber-200">
        These checks key off the reviewed entity. Fill in what's missing to unlock them.
      </div>
      <div className="grid sm:grid-cols-3 gap-2">
        <input placeholder="Legal company name" value={form.legal_name}
          onChange={e => setForm({ ...form, legal_name: e.target.value })}
          className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200"/>
        <input placeholder="Primary domain" value={form.domain}
          onChange={e => setForm({ ...form, domain: e.target.value })}
          className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200 font-mono"/>
        <input placeholder="Jurisdiction (e.g. us_co)" value={form.jurisdiction}
          onChange={e => setForm({ ...form, jurisdiction: e.target.value })}
          className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200"/>
      </div>
      <button onClick={save} disabled={saving}
        className="h-7 px-2.5 text-[11.5px] border border-amber-500/40 text-amber-200 rounded">
        {saving ? "Saving…" : "Save entity details"}
      </button>
    </div>
  );
}

function ExternalChecksTab({ id, review, closed, onChange }) {
  const [running, setRunning] = useState(null);
  const checks = review.external_checks;

  const runChecks = async (panel) => {
    setRunning(panel || "both");
    try {
      await api.post(`/v1/security-reviews/${id}/external-checks`, null,
        { params: panel ? { panel } : {} });
      toast.success("External checks complete");
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Checks failed"); }
    finally { setRunning(null); }
  };

  const Panel = ({ title, blurb, data, panelKey }) => (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div>
          <div className="text-[12.5px] text-slate-200 font-medium">{title}</div>
          <div className="text-[11px] text-slate-500">{blurb}</div>
        </div>
        {!closed && (
          <button onClick={() => runChecks(panelKey)} disabled={!!running}
            className="h-7 px-2.5 text-[11.5px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 text-slate-300 rounded inline-flex items-center gap-1 disabled:opacity-50 shrink-0">
            <ArrowsClockwise size={12} className={running === panelKey ? "animate-spin" : ""}/> Run
          </button>
        )}
      </div>
      {data ? (
        <>
          {data.summary && (
            <div className={`rounded-md px-3 py-2.5 text-[12px] border ${
              data.summary.verdict === "attention" ? "border-amber-500/30 bg-amber-500/5 text-amber-100"
              : data.summary.verdict === "ok" ? "border-emerald-500/30 bg-emerald-500/5 text-emerald-100"
              : "border-[#30363D] bg-[#161B22] text-slate-300"}`}>
              {data.summary.headline}
            </div>
          )}
          <div className="text-[10px] text-slate-600 font-mono">Last run {new Date(data.ran_at).toLocaleString()}</div>
          {data.results.map((c, i) => <CheckRow key={i} c={c}/>)}
        </>
      ) : (
        <div className="text-[12px] text-slate-500 border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-4">Not run yet.</div>
      )}
    </div>
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="text-[11px] text-slate-500 max-w-2xl">
          Best-effort automated checks against the reviewed entity. Every check reports its own status, so one
          failure degrades that check alone and never blocks the review. Sources are shared with the CTI hub
          rather than duplicated here.
        </div>
        {!closed && (
          <button onClick={() => runChecks(null)} disabled={!!running}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded inline-flex items-center gap-1.5">
            <ShieldCheck size={13}/> {running === "both" ? "Running…" : "Run all checks"}
          </button>
        )}
      </div>

      {checks?.prerequisites?.length > 0 && !closed && (
        <EntityPrereqEditor id={id} review={review} onChange={onChange}/>
      )}
      {checks?.prerequisites?.length > 0 && (
        <ul className="text-[11.5px] text-amber-300 list-disc ml-5">
          {checks.prerequisites.map((p, i) => <li key={i}>{p}</li>)}
        </ul>
      )}

      <div className="grid lg:grid-cols-2 gap-4">
        <Panel title="Company Posture" panelKey="company"
          blurb="Is this a real, stable company we can hold to a contract?"
          data={checks?.company_posture}/>
        <Panel title="Technical Posture" panelKey="technical"
          blurb="Is what they actually run secure?"
          data={checks?.technical_posture}/>
      </div>
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
  const [inhBand, setInhBand] = useState(review.inherent_risk?.overridden ? review.inherent_risk.band : "");
  const [resBand, setResBand] = useState(review.residual_risk?.overridden ? review.residual_risk.band : "");
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
        inherent_override_band: inhBand || null, residual_override_band: resBand || null,
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
            <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-1">Manual band override (optional — overrides the calculated 5×5)</div>
            <div className="grid grid-cols-2 gap-2">
              {[["Inherent", inhLik, inhImp, inhBand, setInhBand],
                ["Residual", resLik, resImp, resBand, setResBand]].map(([lbl, lik, imp, val, setter]) => {
                const calc = (lik && maxOf(imp)) ? calcBand(lik, maxOf(imp)) : null;
                return (
                  <div key={lbl}>
                    <div className="text-[10.5px] text-slate-500 mb-0.5">{lbl}{calc && <span className="text-slate-600"> · 5×5 = {calc}</span>}</div>
                    <select value={val} onChange={e => setter(e.target.value)} disabled={closed}
                      className="w-full h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-100 disabled:opacity-60">
                      <option value="">Use calculated{calc ? ` (${calc})` : ""}</option>
                      {["Low", "Medium", "High", "Critical"].map(b => <option key={b} value={b}>{b}</option>)}
                    </select>
                    {val && calc && val !== calc && (
                      <div className="text-[10px] text-amber-300 mt-0.5">adjusted from {calc} → {val}</div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
          <div>
            <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-1">Override justification (required if final rating differs from the suggested or calculated band)</div>
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
  const [editing, setEditing] = useState(null);
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
      {findings.map(f => (editing === f.id ? (
        <FindingEditor key={f.id} id={id} finding={f}
          onCancel={() => setEditing(null)}
          onSaved={() => { setEditing(null); onChange(); }}/>
      ) : (
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
                <button onClick={() => setEditing(f.id)}
                  className="h-7 px-2 text-[11px] border border-[#30363D] text-slate-300 rounded inline-flex items-center gap-1">
                  <PencilSimple size={11}/> Edit
                </button>
                <button onClick={() => remove(f)} className="h-7 px-2 text-[11px] border border-[#30363D] text-slate-500 hover:text-red-400 rounded">Delete</button>
              </div>
            )}
          </div>
        </div>
      )))}
    </div>
  );
}

function FindingEditor({ id, finding, onCancel, onSaved }) {
  const [form, setForm] = useState({
    description: finding.description || "",
    severity: finding.severity || "Medium",
    category: finding.category || "General",
    affected_component: finding.affected_component || "",
    cis_mapping: finding.cis_mapping || "",
    recommendation: finding.recommendation || "",
    owner: finding.owner || "",
    due_date: finding.due_date || "",
    is_condition_of_approval: !!finding.is_condition_of_approval,
    condition_deadline: finding.condition_deadline || "",
  });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    if (!form.description.trim()) { toast.error("Description required"); return; }
    setSaving(true);
    try {
      await api.patch(`/v1/security-reviews/${id}/findings/${finding.id}`, {
        ...form,
        due_date: form.due_date || null,
        condition_deadline: form.condition_deadline || null,
      });
      toast.success("Finding updated");
      onSaved();
    } catch (e) { toast.error(e.response?.data?.detail || "Save failed"); }
    finally { setSaving(false); }
  };

  const inp = "h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200";
  return (
    <div className="border border-blue-500/40 bg-[#0D1117] rounded-md px-4 py-3 space-y-2.5">
      <div className="text-[11px] uppercase tracking-wider font-mono text-blue-300">Editing finding</div>
      <textarea rows={2} value={form.description}
        onChange={e => setForm({ ...form, description: e.target.value })}
        className="w-full px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
      <div className="flex gap-2 flex-wrap items-center">
        <select value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })} className={inp}>
          {["Critical", "High", "Medium", "Low"].map(x => <option key={x}>{x}</option>)}
        </select>
        <input placeholder="Category" value={form.category}
          onChange={e => setForm({ ...form, category: e.target.value })} className={`${inp} w-36`}/>
        <input placeholder="Affected component" value={form.affected_component}
          onChange={e => setForm({ ...form, affected_component: e.target.value })} className={`${inp} w-44`}/>
        <input placeholder="CIS mapping" value={form.cis_mapping}
          onChange={e => setForm({ ...form, cis_mapping: e.target.value })} className={`${inp} w-28`}/>
      </div>
      <textarea rows={2} placeholder="Recommendation" value={form.recommendation}
        onChange={e => setForm({ ...form, recommendation: e.target.value })}
        className="w-full px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
      <div className="flex gap-2 flex-wrap items-center">
        <input placeholder="Owner" value={form.owner}
          onChange={e => setForm({ ...form, owner: e.target.value })} className={`${inp} w-40`}/>
        <input type="date" title="Due date" value={form.due_date}
          onChange={e => setForm({ ...form, due_date: e.target.value })} className={inp}/>
        <label className="text-[12px] text-slate-300 inline-flex items-center gap-1.5">
          <input type="checkbox" checked={form.is_condition_of_approval}
            onChange={e => setForm({ ...form, is_condition_of_approval: e.target.checked })}/>
          Condition of approval
        </label>
        {form.is_condition_of_approval && (
          <input type="date" title="Condition deadline" value={form.condition_deadline}
            onChange={e => setForm({ ...form, condition_deadline: e.target.value })} className={inp}/>
        )}
      </div>
      <div className="flex gap-2">
        <button onClick={save} disabled={saving}
          className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded inline-flex items-center gap-1.5">
          <FloppyDisk size={13}/> {saving ? "Saving…" : "Save changes"}
        </button>
        <button onClick={onCancel} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
      </div>
    </div>
  );
}

function ReassignControl({ id, review, closed, onChange }) {
  const [open, setOpen] = useState(false);
  const [users, setUsers] = useState([]);
  const [pick, setPick] = useState("");

  const openPicker = async () => {
    setOpen(true);
    try {
      const r = await api.get("/v1/security-reviews/assignable-users");
      setUsers(r.data.items || []);
    } catch { setUsers([]); }
  };

  const save = async () => {
    if (!pick) return;
    try {
      await api.post(`/v1/security-reviews/${id}/reassign`, { assignee: pick });
      toast.success(`Reassigned to ${pick}`);
      setOpen(false); onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Reassign failed"); }
  };

  if (closed) return null;
  return (
    <>
      <button onClick={openPicker} title={`Reviewer: ${review.assignee || "unassigned"}`}
        className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 rounded inline-flex items-center gap-1.5 text-slate-300">
        <UserSwitch size={13}/> {review.assignee ? review.assignee.split("@")[0] : "Assign"}
      </button>
      {open && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => setOpen(false)}>
          <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-sm" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
              <div className="text-[14px] text-slate-100 font-medium">Reassign reviewer</div>
              <button onClick={() => setOpen(false)} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
            </div>
            <div className="p-5 space-y-3">
              <div className="text-[11.5px] text-slate-500">Currently: {review.assignee || "unassigned"}</div>
              <select value={pick} onChange={e => setPick(e.target.value)}
                className="w-full h-9 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-200">
                <option value="">Select a reviewer…</option>
                {users.map(u => <option key={u.id} value={u.email}>{u.name ? `${u.name} (${u.email})` : u.email}</option>)}
              </select>
              <div className="text-[10.5px] text-slate-600">Only users whose role has access to Security Reviews are listed. The change is recorded in the audit log.</div>
            </div>
            <div className="flex justify-end gap-2 px-5 py-3.5 border-t border-[#30363D]">
              <button onClick={() => setOpen(false)} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
              <button onClick={save} disabled={!pick} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">Reassign</button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function RecommendationTab({ id, review, closed, onChange }) {
  const rec = review.recommendation || {};
  const [form, setForm] = useState({
    what_was_reviewed: rec.what_was_reviewed || "",
    why: rec.why || "",
    recommendation: rec.recommendation || "",
    rationale: rec.rationale || "",
  });
  const [saving, setSaving] = useState(false);

  const save = async () => {
    setSaving(true);
    try {
      await api.put(`/v1/security-reviews/${id}/recommendation`, form);
      toast.success("Recommendation saved");
      onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Save failed"); }
    finally { setSaving(false); }
  };

  const L = ({ children }) => <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-1">{children}</div>;
  const ta = "w-full px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100 disabled:opacity-60";

  return (
    <div className="max-w-2xl space-y-3">
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 text-[12px] text-blue-200">
        This is the <strong>reviewer's proposed path</strong> — deliberately separate from the Decision tab, which records
        what leadership actually chose. Both appear in the report, so a decision that diverges from the recommendation
        stays visible instead of being overwritten.
      </div>
      <div>
        <L>What was reviewed</L>
        <textarea rows={2} disabled={closed} value={form.what_was_reviewed}
          onChange={e => setForm({ ...form, what_was_reviewed: e.target.value })}
          placeholder="The product/change under review, in one or two plain sentences." className={ta}/>
      </div>
      <div>
        <L>Why (what problem prompted this)</L>
        <textarea rows={2} disabled={closed} value={form.why}
          onChange={e => setForm({ ...form, why: e.target.value })}
          placeholder="The business driver — why this came to review at all." className={ta}/>
      </div>
      <div>
        <L>Recommendation</L>
        <input disabled={closed} value={form.recommendation}
          onChange={e => setForm({ ...form, recommendation: e.target.value })}
          placeholder="e.g. Approve with conditions / Do not adopt / Defer pending vendor response"
          className="w-full h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100 disabled:opacity-60"/>
      </div>
      <div>
        <L>Rationale</L>
        <textarea rows={4} disabled={closed} value={form.rationale}
          onChange={e => setForm({ ...form, rationale: e.target.value })}
          placeholder="Why this is the right call given the residual risk and required controls." className={ta}/>
      </div>
      {rec.authored_by && (
        <div className="text-[10.5px] text-slate-600">Last saved by {rec.authored_by} on {new Date(rec.authored_at).toLocaleString()}</div>
      )}
      {!closed && (
        <button onClick={save} disabled={saving}
          className="h-9 px-4 text-[12.5px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
          {saving ? "Saving…" : "Save recommendation"}
        </button>
      )}
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

function RichTextEditor({ value, onChange, placeholder, minHeight = 90 }) {
  // Item 22 -- a real rich-text editor (bold/italic/underline/highlight, font
  // size, code block, lists) without pulling in a heavyweight dependency:
  // contentEditable + execCommand, which every browser we target still
  // supports. Emits HTML; the caller also keeps a plain-text copy for search.
  const ref = useRef(null);
  const [swatches, setSwatches] = useState(false);

  useEffect(() => {
    if (ref.current && value !== undefined && ref.current.innerHTML !== value) {
      ref.current.innerHTML = value || "";
    }
    // eslint-disable-next-line
  }, []);

  const exec = (cmd, arg) => {
    document.execCommand(cmd, false, arg);
    ref.current?.focus();
    emit();
  };
  const emit = () => {
    if (!ref.current) return;
    onChange({ html: ref.current.innerHTML, text: ref.current.innerText });
  };
  const codeBlock = () => {
    document.execCommand("formatBlock", false, "pre");
    ref.current?.focus();
    emit();
  };

  const Btn = ({ onClick, title, children }) => (
    <button type="button" onMouseDown={e => e.preventDefault()} onClick={onClick} title={title}
      className="h-7 w-7 inline-flex items-center justify-center border border-[#30363D] rounded text-slate-300 hover:border-slate-500 hover:text-slate-100">
      {children}
    </button>
  );

  return (
    <div className="border border-[#30363D] rounded bg-[#161B22]">
      <div className="flex items-center gap-1 px-2 py-1.5 border-b border-[#30363D] flex-wrap">
        <Btn onClick={() => exec("bold")} title="Bold (Ctrl+B)"><TextB size={13}/></Btn>
        <Btn onClick={() => exec("italic")} title="Italic (Ctrl+I)"><TextItalic size={13}/></Btn>
        <Btn onClick={() => exec("underline")} title="Underline (Ctrl+U)"><TextUnderline size={13}/></Btn>
        <span className="relative inline-flex">
          <Btn onClick={() => setSwatches(v => !v)} title="Highlight"><Highlighter size={13}/></Btn>
          {swatches && (
            <span className="absolute top-8 left-0 z-20 flex gap-1 bg-[#0D1117] border border-[#30363D] rounded p-1">
              {HIGHLIGHTS.map(c => (
                <button key={c} type="button" onMouseDown={e => e.preventDefault()}
                  onClick={() => { exec("hiliteColor", c); setSwatches(false); }}
                  title={`Highlight ${c}`} style={{ background: c }}
                  className="h-5 w-5 rounded border border-black/30"/>
              ))}
              <button type="button" onMouseDown={e => e.preventDefault()}
                onClick={() => { exec("hiliteColor", "transparent"); setSwatches(false); }}
                title="Remove highlight"
                className="h-5 w-5 rounded border border-[#30363D] text-slate-400 text-[10px] leading-none">✕</button>
            </span>
          )}
        </span>
        <Btn onClick={codeBlock} title="Code block"><Code size={13}/></Btn>
        <span className="w-px h-5 bg-[#30363D] mx-1"/>
        <select onChange={e => { exec("fontSize", e.target.value); e.target.value = ""; }} defaultValue=""
          title="Font size"
          className="h-7 px-1 bg-[#0D1117] border border-[#30363D] rounded text-[11px] text-slate-300">
          <option value="" disabled>Size</option>
          <option value="1">Small</option>
          <option value="3">Normal</option>
          <option value="5">Large</option>
          <option value="7">Huge</option>
        </select>
        <Btn onClick={() => exec("insertUnorderedList")} title="Bullet list">•</Btn>
        <Btn onClick={() => exec("removeFormat")} title="Clear formatting">✕</Btn>
      </div>
      <div ref={ref} contentEditable={true} suppressContentEditableWarning
        onInput={emit} data-placeholder={placeholder}
        style={{ minHeight }}
        className="px-3 py-2 text-[12.5px] text-slate-100 outline-none sr-richtext"/>
    </div>
  );
}

function NotesTab({ id, closed }) {
  const [items, setItems] = useState([]);
  const [draft, setDraft] = useState({ html: "", text: "" });
  const [saving, setSaving] = useState(false);
  const inFlight = useRef(false);
  const editorKey = useRef(0);

  const load = () => api.get(`/v1/security-reviews/${id}/notes`).then(r => setItems(r.data.items || []));
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [id]);

  const add = async () => {
    // Item 21 -- the double-submit fix. A ref guard (not state) because state
    // updates are async and two rapid events could both read the stale `false`
    // before either render lands. The backend also de-dupes identical notes
    // within 5s as a backstop.
    if (inFlight.current) return;
    if (!draft.text.trim()) return;
    inFlight.current = true;
    setSaving(true);
    try {
      await api.post(`/v1/security-reviews/${id}/notes`, { text: draft.text, html: draft.html });
      setDraft({ html: "", text: "" });
      editorKey.current += 1;
      await load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to add note");
    } finally {
      inFlight.current = false;
      setSaving(false);
    }
  };

  return (
    <div className="max-w-2xl space-y-3">
      <div className="text-[11px] text-slate-500">Internal working notes — never rendered into shared reports.</div>
      {!closed && (
        <div className="space-y-2">
          <RichTextEditor key={editorKey.current} value={draft.html} onChange={setDraft}
            placeholder="Add a note…"/>
          <button onClick={add} disabled={saving || !draft.text.trim()}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
            {saving ? "Adding…" : "Add note"}
          </button>
        </div>
      )}
      {items.map(n => (
        <div key={n.id} className="border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-2.5">
          {n.html
            ? <div className="text-[12.5px] text-slate-200 sr-richtext" dangerouslySetInnerHTML={{ __html: n.html }}/>
            : <div className="text-[12.5px] text-slate-200 whitespace-pre-wrap">{n.text}</div>}
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

function ShareDialog({ id, review, onClose }) {
  const [mode, setMode] = useState("email");
  const [email, setEmail] = useState("");
  const [userEmail, setUserEmail] = useState("");
  const [users, setUsers] = useState([]);
  const [grants, setGrants] = useState([]);
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);

  const loadGrants = () => api.get(`/v1/security-reviews/${id}/shares`).then(r => setGrants(r.data.items || []));
  useEffect(() => {
    loadGrants();
    api.get("/v1/security-reviews/assignable-users").then(r => setUsers(r.data.items || [])).catch(() => {});
    // eslint-disable-next-line
  }, [id]);

  const share = async () => {
    setBusy(true);
    try {
      const body = mode === "email" ? { email, expires_days: 30 } : { platform_user_email: userEmail, expires_days: 30 };
      const r = await api.post(`/v1/security-reviews/${id}/share`, body);
      setResult({ ...r.data, url: `${window.location.origin}/shared-report/${r.data.token}` });
      loadGrants();
      toast.success(mode === "email"
        ? (r.data.code_emailed ? "Access code emailed to the recipient" : "Grant created — email wasn't configured, hand the code over yourself")
        : "Shared with that platform user");
    } catch (e) { toast.error(e.response?.data?.detail || "Share failed"); }
    finally { setBusy(false); }
  };

  const revoke = async (g) => {
    await api.delete(`/v1/security-reviews/${id}/shares/${g.id}`);
    loadGrants();
  };

  return (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-[60] p-4 print:hidden" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-lg text-slate-200" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div className="text-[14px] font-medium">Share report — {review.review_number}</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-4">
          <div className="border border-amber-500/30 bg-amber-500/5 rounded px-3 py-2 text-[11.5px] text-amber-200">
            Links are no longer viewable by anyone who has them. Every share is scoped to one named recipient,
            expires, and records each view.
          </div>
          <div className="flex gap-2">
            <button onClick={() => setMode("email")}
              className={`flex-1 border rounded p-2.5 text-left ${mode === "email" ? "border-blue-500/50 bg-blue-500/10" : "border-[#30363D]"}`}>
              <div className="text-[12.5px]">External email</div>
              <div className="text-[10.5px] text-slate-500 mt-0.5">One-time code emailed to them; required to open the report.</div>
            </button>
            <button onClick={() => setMode("user")}
              className={`flex-1 border rounded p-2.5 text-left ${mode === "user" ? "border-blue-500/50 bg-blue-500/10" : "border-[#30363D]"}`}>
              <div className="text-[12.5px]">Platform user</div>
              <div className="text-[10.5px] text-slate-500 mt-0.5">Must be signed in as that user to view.</div>
            </button>
          </div>
          {mode === "email" ? (
            <input value={email} onChange={e => setEmail(e.target.value)} placeholder="recipient@example.com"
              className="w-full h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[12.5px]"/>
          ) : (
            <select value={userEmail} onChange={e => setUserEmail(e.target.value)}
              className="w-full h-9 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px]">
              <option value="">Select a user…</option>
              {users.map(u => <option key={u.id} value={u.email}>{u.name ? `${u.name} (${u.email})` : u.email}</option>)}
            </select>
          )}
          <button onClick={share} disabled={busy || (mode === "email" ? !email : !userEmail)}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
            {busy ? "Sharing…" : "Create share"}
          </button>
          {result && (
            <div className="border border-[#30363D] rounded p-3 space-y-1.5">
              <div className="text-[11.5px] text-slate-300 break-all">Link: {result.url}</div>
              <button onClick={() => { navigator.clipboard.writeText(result.url); toast.success("Copied"); }}
                className="h-7 px-2 text-[11px] border border-[#30363D] rounded inline-flex items-center gap-1"><Copy size={11}/> Copy link</button>
              {result.code && (
                <div className="text-[11.5px] text-amber-300">Access code (email wasn't sent — share this separately): <span className="font-mono">{result.code}</span></div>
              )}
            </div>
          )}
          {grants.length > 0 && (
            <div>
              <div className="text-[10.5px] uppercase tracking-wider font-mono text-slate-500 mb-1.5">Active shares</div>
              {grants.map(g => (
                <div key={g.id} className="flex items-center gap-2 py-1 text-[11.5px]">
                  <span className={g.revoked ? "text-slate-600 line-through" : "text-slate-300"}>{g.recipient}</span>
                  <Chip color="slate">{g.mode === "email_code" ? "code" : "platform user"}</Chip>
                  <span className="text-slate-600">{g.view_count} view(s)</span>
                  <span className="text-slate-600 ml-auto">exp {g.expires_at?.slice(0, 10)}</span>
                  {!g.revoked && <button onClick={() => revoke(g)} className="text-slate-600 hover:text-red-400"><Trash size={12}/></button>}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


function ReportModal({ id, onClose }) {
  const [data, setData] = useState(null);
  const [shareOpen, setShareOpen] = useState(false);
  const [layoutOpen, setLayoutOpen] = useState(false);

  const load = () => api.get(`/v1/security-reviews/${id}/report-data`).then(r => setData(r.data));
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [id]);
  if (!data) return null;
  const { review, generated_at, template } = data;

  const downloadDocx = async () => {
    try {
      const r = await api.get(`/v1/security-reviews/${id}/export.docx`, { responseType: "blob" });
      const url = window.URL.createObjectURL(new Blob([r.data]));
      const a = document.createElement("a");
      a.href = url;
      a.download = `${review.review_number}-report.docx`;
      document.body.appendChild(a); a.click(); a.remove();
      window.URL.revokeObjectURL(url);
    } catch (e) { toast.error("Word export failed"); }
  };

  return (
    <div className="fixed inset-0 bg-black/70 z-50 overflow-y-auto p-6 print:p-0 print:bg-white" onClick={onClose}>
      <div className="bg-white text-slate-900 max-w-3xl mx-auto rounded print:rounded-none print:max-w-none"
        onClick={e => e.stopPropagation()}>
        <div className="px-8 py-6 print:px-10" id="sr-report">
          <div className="print:hidden flex justify-end gap-2 mb-3">
            <button onClick={() => setLayoutOpen(true)}
              className="h-8 px-3 text-[12px] border border-slate-400 text-slate-700 rounded inline-flex items-center gap-1">
              <NotePencil size={13}/> Edit layout
            </button>
            <button onClick={() => setShareOpen(true)}
              className="h-8 px-3 text-[12px] border border-slate-400 text-slate-700 rounded inline-flex items-center gap-1">
              <LinkSimple size={13}/> Share
            </button>
            <button onClick={downloadDocx}
              className="h-8 px-3 text-[12px] border border-slate-400 text-slate-700 rounded inline-flex items-center gap-1">
              <FileDoc size={13}/> Word
            </button>
            <button onClick={() => window.print()}
              className="h-8 px-3 text-[12px] bg-slate-800 text-white rounded">Print / PDF</button>
          </div>

          {/* The whole report body renders from the saved layout, so the
              on-screen view, the shared copy and the Word export can't drift. */}
          {renderBlocks(data)}

          <div className="border-t border-slate-300 pt-2 mt-4 text-[10.5px] text-slate-500">
            {review.review_number} · Playbook {review.playbook_key} v{review.playbook_version} ·
            Template {review.template_key} v{review.template_version}
            {template && <> · Layout {template.name} v{template.version}</>} ·
            Generated {new Date(generated_at).toLocaleString()}
          </div>

          {shareOpen && <ShareDialog id={id} review={review} onClose={() => setShareOpen(false)}/>}
          {layoutOpen && <ReportLayoutEditor onClose={() => setLayoutOpen(false)} onSaved={load}/>}
        </div>
      </div>
    </div>
  );
}
