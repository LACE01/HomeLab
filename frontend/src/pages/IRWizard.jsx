import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "@/lib/api";
import { AsyncState } from "@/components/AsyncState";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { FirstAidKit, Warning, CheckCircle, ArrowRight, ArrowCounterClockwise, Wrench } from "@phosphor-icons/react";
import { toast } from "sonner";

const CLASSIFICATION_COLOR = {
  Critical: "red", Significant: "orange", Moderate: "amber", Minor: "blue", Negligible: "slate",
};

export default function IRWizard() {
  const navigate = useNavigate();
  const [cfg, setCfg] = useState(null);
  const [loadError, setLoadError] = useState(null);
  const [answers, setAnswers] = useState({}); // question_id -> option_id
  const [title, setTitle] = useState("");
  const [reporterContact, setReporterContact] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState(null);

  useEffect(() => {
    // The toast disappears; the page then sits on "Loading…" forever with nothing
    // on screen saying it failed. Keep the error so the page can render it.
    setLoadError(null);
    api.get("/v1/ir/wizard").then(r => setCfg(r.data)).catch(e => setLoadError(e));
  }, []);

  const answeredCount = Object.keys(answers).length;
  const totalQuestions = cfg?.questions?.length || 0;

  const submit = async () => {
    if (answeredCount < totalQuestions) {
      toast.error(`Answer all ${totalQuestions} questions first (${answeredCount} done)`);
      return;
    }
    setSubmitting(true);
    try {
      const body = {
        title: title.trim() || null,
        reporter_contact: reporterContact.trim() || null,
        answers: Object.entries(answers).map(([question_id, option_id]) => ({ question_id, option_id })),
      };
      const r = await api.post("/v1/ir/wizard/submit", body);
      setResult(r.data);
      toast.success(`Case ${r.data.case.case_number} opened — security team alerted.`);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to submit");
    } finally {
      setSubmitting(false);
    }
  };

  const reset = () => { setAnswers({}); setTitle(""); setReporterContact(""); setResult(null); };

  if (!cfg) return (
    <Layout title="Incident Triage Wizard">
      <AsyncState loading={!loadError} error={loadError} label="the triage wizard"
                  onRetry={() => window.location.reload()}>
        <span/>
      </AsyncState>
    </Layout>
  );

  if (result) {
    const { result: r, action_plan, recommended_tools, case: c } = result;
    return (
      <Layout title="Incident Triage Wizard" subtitle="Here's what your answers point to">
        <div className="max-w-2xl mx-auto space-y-4">
          {r.immediate_containment && (
            <div className="border border-red-500/40 bg-red-900/20 rounded-md p-4 flex items-start gap-3">
              <Warning size={20} className="text-red-400 shrink-0 mt-0.5"/>
              <div>
                <div className="text-[13.5px] font-medium text-red-300">Isolate affected systems now</div>
                <div className="text-[12.5px] text-red-300/80 mt-0.5">One of your answers indicates active spread (ransomware/malware). Disconnect affected devices from the network immediately, without powering them off, before doing anything else below.</div>
              </div>
            </div>
          )}

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-5">
            <div className="flex items-center justify-between flex-wrap gap-2 mb-3">
              <div className="text-[15px] font-medium text-slate-100">{r.category_label}</div>
              <div className="flex items-center gap-2">
                <Chip color={CLASSIFICATION_COLOR[r.classification] || "slate"}>{r.classification}</Chip>
                <Chip color="blue">{r.confidence_pct}% confidence</Chip>
              </div>
            </div>
            <div className="h-1.5 bg-slate-800 rounded overflow-hidden mb-4">
              <div className="h-full bg-blue-500" style={{ width: `${r.confidence_pct}%` }}/>
            </div>

            <div className="text-[11px] uppercase font-mono text-slate-500 mb-1.5">Recommended immediate actions</div>
            <ul className="space-y-1.5 mb-4">
              {(action_plan.immediate_actions || []).map((a, i) => (
                <li key={i} className="flex items-start gap-2 text-[12.5px] text-slate-300">
                  <CheckCircle size={14} className="text-emerald-400 mt-0.5 shrink-0"/> {a}
                </li>
              ))}
            </ul>

            {recommended_tools?.length > 0 && (
              <>
                <div className="text-[11px] uppercase font-mono text-slate-500 mb-1.5">Tools/resources that may help</div>
                <div className="space-y-1.5 mb-4">
                  {recommended_tools.map(t => (
                    <div key={t.id} className="flex items-start gap-2 text-[12.5px] text-slate-300">
                      <Wrench size={14} className="text-slate-500 mt-0.5 shrink-0"/>
                      <div><span className="text-slate-200">{t.name}</span>{t.description && <span className="text-slate-500"> — {t.description}</span>}{t.location && <div className="text-[11px] text-blue-300/80">{t.location}</div>}</div>
                    </div>
                  ))}
                </div>
              </>
            )}

            <div className="text-[12px] text-slate-500 border-t border-[#30363D] pt-3">
              A case has been opened and the security team has been alerted: <span className="text-slate-300 font-mono">{c.case_number}</span>
            </div>
          </div>

          <div className="flex justify-between">
            <button onClick={reset} className="h-9 px-3 text-[12.5px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300">
              <ArrowCounterClockwise size={14}/> Start another
            </button>
            <button onClick={() => navigate(`/ir/cases/${c.id}`)} className="h-9 px-3 text-[12.5px] bg-blue-500/20 border border-blue-500/40 text-blue-200 rounded inline-flex items-center gap-1.5">
              Open the case <ArrowRight size={14}/>
            </button>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout title="Incident Triage Wizard" subtitle="Answer what you know — no cybersecurity background needed. You'll get a likely category, a confidence score, and next steps.">
      <div className="max-w-2xl mx-auto space-y-4">
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 flex items-center gap-3">
          <FirstAidKit size={22} className="text-blue-400 shrink-0"/>
          <div className="text-[12.5px] text-slate-400">Not sure about an answer? Pick "Not sure" rather than guessing — it won't hurt the result.</div>
        </div>

        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Short title (optional)</label>
            <input value={title} onChange={e=>setTitle(e.target.value)} placeholder="e.g. Suspicious email to finance team"
              className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"/>
          </div>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Your contact info (optional)</label>
            <input value={reporterContact} onChange={e=>setReporterContact(e.target.value)} placeholder="email or phone"
              className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"/>
          </div>
        </div>

        {cfg.questions.map((q, qi) => (
          <div key={q.id} className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="text-[13px] text-slate-200 mb-0.5">{qi + 1}. {q.text}</div>
            {q.help_text && <div className="text-[11.5px] text-slate-500 mb-2">{q.help_text}</div>}
            <div className="flex flex-wrap gap-1.5 mt-2">
              {q.options.map(opt => {
                const active = answers[q.id] === opt.id;
                return (
                  <button key={opt.id} onClick={() => setAnswers({ ...answers, [q.id]: opt.id })}
                    className={`h-8 px-2.5 rounded text-[12px] border text-left ${active ? "bg-blue-500/20 border-blue-500/50 text-blue-200" : "border-[#30363D] text-slate-400 hover:border-[#484F58]"}`}>
                    {opt.label}
                  </button>
                );
              })}
            </div>
          </div>
        ))}

        <div className="sticky bottom-4 flex items-center justify-between border border-[#30363D] bg-[#0D1117]/95 backdrop-blur rounded-md p-3">
          <div className="text-[12px] text-slate-500">{answeredCount} / {totalQuestions} answered</div>
          <button data-testid="ir-wizard-submit" onClick={submit} disabled={submitting}
            className="h-9 px-4 text-[12.5px] bg-blue-500/20 border border-blue-500/40 text-blue-200 rounded disabled:opacity-50">
            {submitting ? "Submitting…" : "Get my results"}
          </button>
        </div>
      </div>
    </Layout>
  );
}
