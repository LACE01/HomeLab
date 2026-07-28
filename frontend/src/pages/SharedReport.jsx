import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { API } from "@/lib/api";

// PUBLIC page -- resolves a tokenized share link to a read-only Security Review
// report. No app account needed; the backend endpoint is unauthenticated and the
// token is the capability. Uses plain fetch (not the app's api client) so no
// auth interceptor ever redirects a logged-out stakeholder to /login.

const RISK_PRINT = { Low: "#3b82f6", Medium: "#f59e0b", High: "#f97316", Critical: "#ef4444" };

function Badge({ label, band }) {
  return (
    <div className="text-center px-7 py-4 rounded-lg border-2"
      style={{ borderColor: RISK_PRINT[band] || "#94a3b8", background: (RISK_PRINT[band] || "#94a3b8") + "18" }}>
      <div className="text-[10px] uppercase tracking-wide text-slate-600">{label}</div>
      <div className="text-[26px] font-extrabold" style={{ color: RISK_PRINT[band] || "#64748b" }}>{band || "Not scored"}</div>
    </div>
  );
}

export default function SharedReport() {
  const { token } = useParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch(`${API}/v1/shared/security-review/${token}`)
      .then(async r => {
        if (!r.ok) throw new Error((await r.json()).detail || "Link invalid");
        setData(await r.json());
      })
      .catch(e => setError(e.message));
  }, [token]);

  if (error) {
    return (
      <div className="min-h-screen bg-slate-100 flex items-center justify-center p-6">
        <div className="bg-white rounded shadow p-8 text-center max-w-md">
          <div className="text-[16px] font-semibold text-slate-800">This report link is invalid or has expired.</div>
          <div className="text-[13px] text-slate-500 mt-2">Ask the review team for a fresh link.</div>
        </div>
      </div>
    );
  }
  if (!data) return <div className="min-h-screen bg-slate-100 flex items-center justify-center text-slate-500">Loading…</div>;

  const { review, findings, responses, questionnaire, interviews, executive_summary, generated_at } = data;
  const d = review.decision;
  const conditions = findings.filter(f => f.is_condition_of_approval);
  const respByOrder = Object.fromEntries((responses || []).map(r => [r.question_order, r]));

  return (
    <div className="min-h-screen bg-slate-100 py-8 print:py-0 print:bg-white">
      <div className="bg-white text-slate-900 max-w-3xl mx-auto rounded shadow print:shadow-none print:rounded-none px-8 py-6 print:px-10">
        <div className="border-b-2 border-slate-800 pb-3 mb-4 flex items-end justify-between">
          <div>
            <div className="text-[20px] font-bold">Security Review Report</div>
            <div className="text-[12px] text-slate-600">
              {review.review_number} · {new Date(generated_at).toLocaleDateString()} · Reviewer: {review.assignee || "—"}
              {review.requestor_name && <> · Requestor: {review.requestor_name}{review.requestor_department ? ` (${review.requestor_department})` : ""}</>}
            </div>
          </div>
          <button onClick={() => window.print()} className="print:hidden h-8 px-3 text-[12px] bg-slate-800 text-white rounded">Print / PDF</button>
        </div>

        <div className="text-[13px] mb-4">
          <span className="font-semibold">What was reviewed:</span> {review.entity_name || review.title} — {review.title}
        </div>

        <div className="flex items-center justify-center gap-4 my-5">
          <Badge label="Risk if adopted as-is" band={review.inherent_risk?.band}/>
          <div className="text-[26px] text-slate-400">→</div>
          <Badge label="Risk with required controls" band={review.residual_risk?.band}/>
        </div>

        <div className="text-[13px] leading-relaxed mb-4">{executive_summary}</div>

        {findings.length > 0 && (
          <div className="mb-4">
            <div className="text-[13px] font-semibold mb-1.5">Key findings</div>
            <ul className="space-y-1">
              {findings.slice(0, 5).map(f => (
                <li key={f.id} className="text-[12.5px] flex items-start gap-2">
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded mt-0.5 text-white shrink-0"
                    style={{ background: RISK_PRINT[f.severity] || "#64748b" }}>{f.severity}</span>
                  <span>{f.description}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

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

        <div className="mb-5">
          <div className="text-[13px] font-semibold mb-1">Data &amp; systems touched</div>
          <div className="flex gap-1.5 flex-wrap">
            {(review.data_classifications || []).map(c => (
              <span key={c} className="text-[11px] px-2 py-0.5 rounded-full bg-slate-200 text-slate-800">{c}</span>
            ))}
            {review.entity_domain && <span className="text-[11px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-600">{review.entity_domain}</span>}
          </div>
        </div>

        {questionnaire && responses.length > 0 && (
          <div className="border-t border-slate-300 pt-4 mb-4">
            <div className="text-[14px] font-bold mb-2">Technical appendix — questionnaire responses</div>
            {questionnaire.questions.filter(q => respByOrder[q.order]).map(q => {
              const r = respByOrder[q.order];
              return (
                <div key={q.order} className="text-[11.5px] mb-1.5">
                  <span className="font-medium">Q{q.order}.</span> {q.text}
                  <span className="ml-2 font-semibold uppercase"
                    style={{ color: r.answer === "no" ? "#ef4444" : r.answer === "partial" ? "#f59e0b" : "#16a34a" }}>{r.answer}</span>
                  {r.auto_answered && <span className="text-slate-400 ml-1">[{r.source_tag}]</span>}
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

        <div className="border-t border-slate-300 pt-2 text-[10.5px] text-slate-500">
          {review.review_number} · Playbook {review.playbook_key} v{review.playbook_version} · Template {review.template_key} v{review.template_version} · Generated {new Date(generated_at).toLocaleString()} · Read-only shared report
        </div>
      </div>
    </div>
  );
}
