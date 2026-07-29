import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { API } from "@/lib/api";

// PUBLIC page -- resolves a tokenized share grant to a read-only Security Review
// report. Item 26: the link ALONE is never enough. Either the recipient enters
// the one-time code emailed to them, or they're signed in as the platform user
// the report was shared with. Uses plain fetch (not the app's api client) so a
// signed-out external recipient is never bounced to /login by the auth
// interceptor -- but credentials are included so the platform-user mode can
// authenticate off the existing session.

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

function Matrix({ points }) {
  const cellFill = (l, i) => {
    const s = l * i;
    if (s <= 4) return "#dbeafe";
    if (s <= 9) return "#fef3c7";
    if (s <= 16) return "#ffedd5";
    return "#fee2e2";
  };
  return (
    <div className="mb-4">
      <div className="text-[13px] font-semibold mb-1.5">Risk matrix (likelihood × impact)</div>
      <table className="border-collapse">
        <tbody>
          {[5, 4, 3, 2, 1].map(l => (
            <tr key={l}>
              <td className="text-[9px] text-slate-500 pr-1 text-right">{l}</td>
              {[1, 2, 3, 4, 5].map(i => {
                const here = points.filter(p => p.likelihood === l && p.impact === i);
                return (
                  <td key={i} style={{ background: cellFill(l, i) }}
                    className="w-14 h-9 border border-slate-300 text-center align-middle">
                    {here.map((p, j) => (
                      <span key={j} className="text-[8px] font-bold px-0.5"
                        style={{ color: RISK_PRINT[p.band] || "#334155" }}>{p.label}</span>
                    ))}
                  </td>
                );
              })}
            </tr>
          ))}
          <tr><td/>{[1, 2, 3, 4, 5].map(i => <td key={i} className="text-[9px] text-slate-500 text-center">{i}</td>)}</tr>
        </tbody>
      </table>
      <div className="text-[9px] text-slate-500 mt-0.5">Impact →, likelihood ↑</div>
    </div>
  );
}

export default function SharedReport() {
  const { token } = useParams();
  const [data, setData] = useState(null);
  const [meta, setMeta] = useState(null);
  const [error, setError] = useState(null);
  const [code, setCode] = useState("");
  const [verifying, setVerifying] = useState(false);

  const tryFetch = async () => {
    const r = await fetch(`${API}/v1/shared/security-review/${token}`, { credentials: "include" });
    if (r.ok) { setData(await r.json()); return true; }
    if (r.status === 404) { setError((await r.json()).detail || "This link is invalid or expired."); return true; }
    return false; // 401/403 -> needs the gate
  };

  useEffect(() => {
    (async () => {
      try {
        const m = await fetch(`${API}/v1/shared/security-review/${token}/meta`);
        if (!m.ok) { setError((await m.json()).detail || "This link is invalid or expired."); return; }
        const metaJson = await m.json();
        setMeta(metaJson);
        await tryFetch();
      } catch {
        setError("Could not reach the server.");
      }
    })();
    // eslint-disable-next-line
  }, [token]);

  const verify = async () => {
    setVerifying(true);
    try {
      const r = await fetch(`${API}/v1/shared/security-review/${token}/verify`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      if (!r.ok) { setError(null); alert((await r.json()).detail || "Incorrect code"); return; }
      setData(await r.json());
    } finally { setVerifying(false); }
  };

  if (error) {
    return (
      <div className="min-h-screen bg-slate-100 flex items-center justify-center p-6">
        <div className="bg-white rounded shadow p-8 text-center max-w-md">
          <div className="text-[16px] font-semibold text-slate-800">{error}</div>
          <div className="text-[13px] text-slate-500 mt-2">Ask the review team for a fresh link.</div>
        </div>
      </div>
    );
  }

  if (!data) {
    if (meta?.mode === "email_code") {
      return (
        <div className="min-h-screen bg-slate-100 flex items-center justify-center p-6">
          <div className="bg-white rounded shadow p-8 max-w-sm w-full">
            <div className="text-[16px] font-semibold text-slate-800">Enter your access code</div>
            <div className="text-[13px] text-slate-500 mt-1">
              We emailed a 6-digit code to {meta.recipient_hint}. It's required to open this report.
            </div>
            <input value={code} onChange={e => setCode(e.target.value)} onKeyDown={e => e.key === "Enter" && verify()}
              placeholder="123456" maxLength={6}
              className="w-full mt-4 h-10 px-3 border border-slate-300 rounded text-[16px] tracking-[0.3em] text-center font-mono"/>
            <button onClick={verify} disabled={verifying || code.length < 6}
              className="w-full mt-3 h-9 bg-slate-800 disabled:opacity-50 text-white rounded text-[13px]">
              {verifying ? "Checking…" : "View report"}
            </button>
          </div>
        </div>
      );
    }
    if (meta?.mode === "platform_user") {
      return (
        <div className="min-h-screen bg-slate-100 flex items-center justify-center p-6">
          <div className="bg-white rounded shadow p-8 text-center max-w-md">
            <div className="text-[16px] font-semibold text-slate-800">Sign in required</div>
            <div className="text-[13px] text-slate-500 mt-2">
              This report was shared with a specific platform user ({meta.recipient_hint}). Sign in as that
              user, then reopen this link.
            </div>
            <a href="/login" className="inline-block mt-4 h-9 px-4 leading-9 bg-slate-800 text-white rounded text-[13px]">Sign in</a>
          </div>
        </div>
      );
    }
    return <div className="min-h-screen bg-slate-100 flex items-center justify-center text-slate-500">Loading…</div>;
  }

  const { review, findings, responses, questionnaire, interviews, executive_summary, generated_at,
          matrix_points, compensating_controls, recommendation } = data;
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

        {compensating_controls && (
          <div className="border border-slate-300 rounded p-3 mb-4 bg-slate-50">
            <div className="text-[12px] font-semibold mb-1">Compensating controls (what moves inherent → residual)</div>
            <div className="text-[12px] text-slate-700 whitespace-pre-wrap">{compensating_controls}</div>
          </div>
        )}

        {matrix_points?.length > 0 && <Matrix points={matrix_points}/>}

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

        {recommendation && (recommendation.recommendation || recommendation.why) && (
          <div className="border border-blue-300 bg-blue-50/60 rounded p-3.5 mb-3">
            <div className="text-[13px] font-semibold text-blue-900">Reviewer recommendation</div>
            {recommendation.what_was_reviewed && <div className="text-[12px] text-slate-700 mt-1"><span className="font-medium">What was reviewed:</span> {recommendation.what_was_reviewed}</div>}
            {recommendation.why && <div className="text-[12px] text-slate-700"><span className="font-medium">Why:</span> {recommendation.why}</div>}
            {recommendation.recommendation && <div className="text-[12.5px] text-blue-900 font-semibold mt-1.5">{recommendation.recommendation}</div>}
            {recommendation.rationale && <div className="text-[12px] text-slate-700 mt-1">{recommendation.rationale}</div>}
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
                  {r.na_reason_code && <span className="text-slate-500 ml-1">({r.na_reason_code.replace(/_/g, " ")})</span>}
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
