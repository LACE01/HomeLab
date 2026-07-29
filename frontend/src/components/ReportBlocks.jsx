import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import {
  ArrowUp, ArrowDown, Eye, EyeSlash, ArrowCounterClockwise, FloppyDisk, Plus, X,
} from "@phosphor-icons/react";

// Shared report rendering + the layout editor.
//
// The report is CONFIGURATION, not code: `renderBlocks` walks the resolved block
// list from the server and draws each one, so the in-app print view and the
// public shared view render identically from the same template, and the Word
// exporter reads the same list server-side. Reordering, renaming, or hiding a
// section is a template edit, not a deploy.

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

export function ReportMatrix({ points, showLegend = true }) {
  const cellFill = (l, i) => {
    const s = l * i;
    if (s <= 4) return "#dbeafe";
    if (s <= 9) return "#fef3c7";
    if (s <= 16) return "#ffedd5";
    return "#fee2e2";
  };
  return (
    <div className="mb-4">
      <table className="border-collapse">
        <tbody>
          {[5, 4, 3, 2, 1].map(l => (
            <tr key={l}>
              <td className="text-[9px] text-slate-500 pr-1 text-right">{l}</td>
              {[1, 2, 3, 4, 5].map(i => {
                const here = (points || []).filter(p => p.likelihood === l && p.impact === i);
                return (
                  <td key={i} style={{ background: cellFill(l, i) }}
                    className="w-16 h-11 border border-slate-300 text-center align-middle p-0.5">
                    {here.map((p, j) => (
                      <span key={j} className="block text-[9px] font-bold leading-tight rounded px-1 py-0.5 mb-0.5 text-white"
                        style={{ background: RISK_PRINT[p.band] || "#334155" }}>{p.label}</span>
                    ))}
                  </td>
                );
              })}
            </tr>
          ))}
          <tr><td/>{[1, 2, 3, 4, 5].map(i => <td key={i} className="text-[9px] text-slate-500 text-center">{i}</td>)}</tr>
        </tbody>
      </table>
      {showLegend && (
        <div className="text-[10px] text-slate-600 mt-1">
          Impact increases left → right, likelihood increases bottom → top.{" "}
          {(points || []).map(p => `${p.label}: likelihood ${p.likelihood} × impact ${p.impact} = ${p.band}`).join(" · ")}
        </div>
      )}
    </div>
  );
}

function H(level, children) {
  const cls = level === 1 ? "text-[16px] font-bold" : level === 2 ? "text-[13px] font-semibold" : "text-[12px] font-medium";
  return <div className={`${cls} mb-1.5`}>{children}</div>;
}

/** Draw one block. Returns null for blocks with nothing to show, so an empty
 *  section never leaves a dangling heading. */
function renderBlock(block, data) {
  const o = block.options || {};
  const { review = {}, findings = [], responses = [], questionnaire, interviews = [],
          notes = [], attachments = [], linked_assets = [], external_checks,
          matrix_points, compensating_controls, recommendation, executive_summary,
          questionnaire_scoring, audit_trail = [], generated_at } = data;
  const decision = review.decision;
  const realFindings = findings.filter(f => f.status !== "draft");
  const title = block.title;

  switch (block.type) {
    case "page_break":
      return <div className="break-before-page"/>;

    case "section_heading":
      return (
        <div className="border-b-2 border-slate-300 pb-1.5 mb-3 mt-5">
          {H(1, title)}
          {o.subtitle && <div className="text-[11.5px] text-slate-600">{o.subtitle}</div>}
        </div>
      );

    case "header":
      return (
        <div className="border-b-2 border-slate-800 pb-3 mb-4">
          <div className="text-[20px] font-bold">{title}</div>
          <div className="text-[12px] text-slate-600">
            {review.review_number} · {new Date(generated_at).toLocaleDateString()} · Reviewer: {review.assignee || "—"}
            {review.requestor_name && <> · Requestor: {review.requestor_name}
              {review.requestor_department ? ` (${review.requestor_department})` : ""}</>}
          </div>
        </div>
      );

    case "what_reviewed":
      return (
        <div className="text-[13px] mb-4">
          <span className="font-semibold">{title}:</span>{" "}
          {review.entity_name || review.title} — {review.title}
        </div>
      );

    case "risk_verdict":
      return (
        <div className="my-5">
          <div className="flex items-center justify-center gap-4">
            <Badge label="Risk if adopted as-is" band={review.inherent_risk?.band}/>
            <div className="text-[26px] text-slate-400">→</div>
            <Badge label="Risk with required controls" band={review.residual_risk?.band}/>
            {o.show_not_adopting !== false && review.risk_of_not_adopting?.band && (
              <div className="text-center px-4 py-2.5 rounded-lg border"
                style={{ borderColor: RISK_PRINT[review.risk_of_not_adopting.band] }}>
                <div className="text-[9px] uppercase tracking-wide text-slate-600">Risk of not adopting</div>
                <div className="text-[16px] font-bold" style={{ color: RISK_PRINT[review.risk_of_not_adopting.band] }}>
                  {review.risk_of_not_adopting.band}
                </div>
              </div>
            )}
          </div>
          {review.analyst_override_justification && (
            <div className="text-[11px] text-slate-600 italic mt-2 text-center">
              Rating override: {review.analyst_override_justification}
            </div>
          )}
        </div>
      );

    case "confidence":
      if (!questionnaire_scoring) return null;
      return (
        <div className="text-[11.5px] text-slate-700 mb-3">
          <span className="font-medium">{title}:</span> {questionnaire_scoring.confidence_pct}% — based on
          {" "}{questionnaire_scoring.applicable_questions} applicable question(s)
          {questionnaire_scoring.unknown_count > 0 && `, ${questionnaire_scoring.unknown_count} unknown`}
          {questionnaire_scoring.pending_vendor_count > 0 && `, ${questionnaire_scoring.pending_vendor_count} awaiting vendor`}.
          {questionnaire_scoring.confidence_pct < 70 && " Treat the ratings above as provisional until the gaps are closed."}
        </div>
      );

    case "compensating_controls":
      if (!compensating_controls) return null;
      return (
        <div className="border border-slate-300 rounded p-3 mb-4 bg-slate-50">
          {H(3, title)}
          <div className="text-[12px] text-slate-700 whitespace-pre-wrap">{compensating_controls}</div>
        </div>
      );

    case "risk_matrix":
      if (!matrix_points?.length) return null;
      return <div className="mb-4">{H(2, title)}<ReportMatrix points={matrix_points} showLegend={o.show_legend !== false}/></div>;

    case "executive_summary":
      return <div className="mb-4">{H(2, title)}<div className="text-[13px] leading-relaxed">{executive_summary}</div></div>;

    case "recommendation":
      if (!recommendation || !(recommendation.recommendation || recommendation.why || recommendation.what_was_reviewed)) return null;
      return (
        <div className="border border-blue-300 bg-blue-50/60 rounded p-3.5 mb-3">
          <div className="text-[13px] font-semibold text-blue-900">{title}</div>
          {recommendation.what_was_reviewed && <div className="text-[12px] text-slate-700 mt-1"><span className="font-medium">What was reviewed:</span> {recommendation.what_was_reviewed}</div>}
          {recommendation.why && <div className="text-[12px] text-slate-700"><span className="font-medium">Why:</span> {recommendation.why}</div>}
          {recommendation.recommendation && <div className="text-[12.5px] text-blue-900 font-semibold mt-1.5">{recommendation.recommendation}</div>}
          {recommendation.rationale && <div className="text-[12px] text-slate-700 mt-1">{recommendation.rationale}</div>}
        </div>
      );

    case "decision": {
      const conditions = realFindings.filter(f => f.is_condition_of_approval);
      return (
        <div className="border-2 border-slate-800 rounded p-3.5 mb-4">
          <div className="text-[13px] font-semibold">{title}: {decision?.outcome || "Pending"}</div>
          {decision?.rationale && <div className="text-[12px] text-slate-700 mt-1">{decision.rationale}</div>}
          {recommendation?.recommendation && decision?.outcome &&
            !decision.outcome.toLowerCase().includes(recommendation.recommendation.trim().toLowerCase()) && (
            <div className="text-[11.5px] text-amber-700 italic mt-1">
              Note: the decision differs from the reviewer&apos;s recommendation.
            </div>
          )}
          {o.show_conditions !== false && conditions.length > 0 && (
            <div className="mt-2">
              <div className="text-[12px] font-medium">Conditions of approval:</div>
              <ul className="list-disc ml-5 text-[12px] text-slate-700">
                {conditions.map(c => (
                  <li key={c.id}>{c.description}{c.condition_deadline && <> — due {c.condition_deadline}</>}{c.owner && <> (owner: {c.owner})</>}</li>
                ))}
              </ul>
            </div>
          )}
          {decision?.expiration_date && <div className="text-[11.5px] text-slate-600 mt-1.5">Approval expires: {String(decision.expiration_date).slice(0, 10)}</div>}
        </div>
      );
    }

    case "key_findings":
      if (!realFindings.length) return null;
      return (
        <div className="mb-4">
          {H(2, title)}
          <ul className="space-y-1">
            {realFindings.slice(0, o.limit || 5).map(f => (
              <li key={f.id} className="text-[12.5px]">
                <div className="flex items-start gap-2">
                  <span className="text-[10px] font-bold px-1.5 py-0.5 rounded mt-0.5 text-white shrink-0"
                    style={{ background: RISK_PRINT[f.severity] || "#64748b" }}>{f.severity}</span>
                  <span>{f.description}</span>
                </div>
                {o.show_recommendations !== false && f.recommendation && (
                  <div className="text-[11.5px] text-slate-600 ml-8">Recommendation: {f.recommendation}</div>
                )}
              </li>
            ))}
          </ul>
        </div>
      );

    case "data_touched":
      return (
        <div className="mb-5">
          {H(2, title)}
          <div className="flex gap-1.5 flex-wrap">
            {(review.data_classifications || []).map(c => (
              <span key={c} className="text-[11px] px-2 py-0.5 rounded-full bg-slate-200 text-slate-800">{c}</span>
            ))}
            {review.entity_domain && <span className="text-[11px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-600">{review.entity_domain}</span>}
          </div>
          {review.scope_statement && <div className="text-[12px] text-slate-700 mt-1.5">{review.scope_statement}</div>}
        </div>
      );

    case "linked_assets":
      if (!linked_assets.length) return null;
      return (
        <div className="mb-4">
          {H(2, `${title} (${linked_assets.length})`)}
          <table className="w-full text-[11.5px] border-collapse">
            <thead>
              <tr className="border-b border-slate-300 text-left">
                <th className="py-1 pr-2">Host</th><th className="py-1 pr-2">Team</th>
                <th className="py-1 pr-2">Criticality</th>
                {o.show_finding_counts !== false && <th className="py-1">Open findings</th>}
              </tr>
            </thead>
            <tbody>
              {linked_assets.map(a => (
                <tr key={a.id} className="border-b border-slate-200">
                  <td className="py-1 pr-2 font-mono">{a.hostname}</td>
                  <td className="py-1 pr-2">{a.owner_team || "—"}</td>
                  <td className="py-1 pr-2">{a.criticality || "—"}</td>
                  {o.show_finding_counts !== false && (
                    <td className="py-1">
                      {a.open_findings}
                      {a.critical_high_findings > 0 && <span className="text-red-600 font-medium"> ({a.critical_high_findings} crit/high)</span>}
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );

    case "external_checks": {
      if (!external_checks || (!external_checks.company_posture && !external_checks.technical_posture)) return null;
      const panels = ["company_posture", "technical_posture"].filter(k =>
        external_checks[k] && (o.panels === "both" || !o.panels || k.includes(o.panels)));
      if (!panels.length) return null;
      return (
        <div className="mb-4">
          {H(2, title)}
          {panels.map(key => {
            const panel = external_checks[key];
            return (
              <div key={key} className="mb-2.5">
                <div className="text-[12px] font-medium">{key === "company_posture" ? "Company posture" : "Technical posture"}</div>
                {panel.summary && <div className="text-[11.5px] text-slate-700 mb-1">{panel.summary.headline}</div>}
                <ul className="text-[11.5px] space-y-0.5">
                  {panel.results.map((c, i) => (
                    <li key={i}>
                      <span className="font-medium">{c.label || c.check}:</span>{" "}
                      <span style={{ color: c.status === "attention" ? "#b45309" : c.status === "ok" ? "#15803d" : "#64748b" }}>
                        {c.status_plain || c.status}
                      </span> — {c.summary}
                      {o.show_why_it_matters !== false && c.why_it_matters && (
                        <div className="text-slate-600 ml-4">Why it matters: {c.why_it_matters}</div>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      );
    }

    case "interviews":
      if (!interviews.length) return null;
      return (
        <div className="mb-4">
          {H(2, title)}
          {interviews.map(it => (
            <div key={it.id} className="text-[11.5px] mb-1">
              <span className="font-medium">{it.who}</span> ({it.role || "—"}, {it.when}): {it.summary}
            </div>
          ))}
        </div>
      );

    case "attachments":
      if (!attachments.length) return null;
      return (
        <div className="mb-4">
          {H(2, `${title} (${attachments.length})`)}
          <ul className="text-[11.5px] list-disc ml-5">
            {attachments.map(a => (
              <li key={a.id}>
                <span className="font-medium">{a.name}</span>
                <span className="text-slate-600"> — {a.category}{a.description ? `, ${a.description}` : ""}
                  {" "}({Math.round((a.size_bytes || 0) / 1024)} KB, uploaded {new Date(a.uploaded_at).toLocaleDateString()})</span>
              </li>
            ))}
          </ul>
        </div>
      );

    case "questionnaire": {
      if (!questionnaire || !responses.length) return null;
      const byOrder = Object.fromEntries(responses.map(r => [r.question_order, r]));
      const qs = (questionnaire.questions || []).filter(q => o.answered_only === false || byOrder[q.order]);
      if (!qs.length) return null;
      return (
        <div className="mb-4">
          {H(2, title)}
          {qs.map(q => {
            const r = byOrder[q.order];
            return (
              <div key={q.order} className="text-[11.5px] mb-1.5">
                <span className="font-medium">Q{q.order}.</span> {q.text}
                {r && (
                  <span className="ml-2 font-semibold uppercase"
                    style={{ color: r.answer === "no" ? "#ef4444" : r.answer === "partial" ? "#f59e0b" : "#16a34a" }}>
                    {r.answer}
                  </span>
                )}
                {r?.na_reason_code && <span className="text-slate-500 ml-1">({String(r.na_reason_code).replace(/_/g, " ")})</span>}
                {q.cis_mapping && <span className="text-slate-500 ml-1">[CIS {q.cis_mapping}]</span>}
                {o.show_evidence !== false && r?.evidence_text && <div className="text-slate-600 ml-4">{r.evidence_text}</div>}
              </div>
            );
          })}
        </div>
      );
    }

    case "notes":
      if (!notes.length) return null;
      return (
        <div className="mb-4">
          {H(2, title)}
          <div className="text-[10.5px] text-slate-500 mb-1.5">
            Internal audit package only — never included in a shared report.
          </div>
          {notes.map(n => (
            <div key={n.id} className="text-[11.5px] mb-1.5">
              <div className="text-slate-500">{n.author} · {new Date(n.at).toLocaleString()}</div>
              {n.html
                ? <div className="sr-richtext-print" dangerouslySetInnerHTML={{ __html: n.html }}/>
                : <div className="whitespace-pre-wrap">{n.text}</div>}
            </div>
          ))}
        </div>
      );

    case "audit_trail":
      if (!audit_trail.length) return null;
      return (
        <div className="mb-4">
          {H(2, title)}
          {audit_trail.slice(0, o.limit || 50).map(a => (
            <div key={a.id} className="text-[10.5px] text-slate-600">
              {new Date(a.at).toLocaleString()} · {a.action} · {a.actor}{a.details ? ` — ${a.details}` : ""}
            </div>
          ))}
        </div>
      );

    default:
      return null;
  }
}

export function renderBlocks(data) {
  const layout = data?.layout;
  if (!layout?.length) return null;
  return layout.map(b => <div key={b.id}>{renderBlock(b, data)}</div>);
}

/* ------------------------------ Layout editor ------------------------------ */

export function ReportLayoutEditor({ onClose, onSaved }) {
  const [catalog, setCatalog] = useState(null);
  const [blocks, setBlocks] = useState([]);
  const [name, setName] = useState("Security Review Report");
  const [adding, setAdding] = useState(false);
  const [saving, setSaving] = useState(false);
  const [version, setVersion] = useState(null);

  const load = async () => {
    const [c, t] = await Promise.all([
      api.get("/v1/report-templates/blocks"),
      api.get("/v1/report-templates"),
    ]);
    setCatalog(c.data.blocks);
    const active = t.data.active;
    setBlocks(active?.blocks || c.data.default_layout);
    setName(active?.name || "Security Review Report");
    setVersion(active?.version);
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  const move = (i, dir) => {
    const j = i + dir;
    if (j < 0 || j >= blocks.length) return;
    const next = [...blocks];
    [next[i], next[j]] = [next[j], next[i]];
    setBlocks(next);
  };
  const update = (i, patch) => setBlocks(bs => bs.map((b, idx) => idx === i ? { ...b, ...patch } : b));
  const remove = (i) => setBlocks(bs => bs.filter((_, idx) => idx !== i));
  const add = (type) => {
    const base = catalog.find(c => c.type === type);
    setBlocks(bs => [...bs, {
      id: `new-${Date.now()}`, type, title: base.default_title,
      visible: true, options: { ...base.options },
    }]);
    setAdding(false);
  };

  const save = async () => {
    setSaving(true);
    try {
      const r = await api.post("/v1/report-templates", { name, blocks });
      toast.success(`Saved as version ${r.data.version} — reports render with this layout from now on`);
      onSaved?.();
      onClose();
    } catch (e) { toast.error(e.response?.data?.detail || "Save failed"); }
    finally { setSaving(false); }
  };

  const reset = async () => {
    if (!window.confirm("Reset to the stock layout? This saves a new version; nothing is lost.")) return;
    const r = await api.post("/v1/report-templates/reset");
    setBlocks(r.data.blocks);
    toast.success("Reset to the default layout");
  };

  if (!catalog) return null;
  const meta = (type) => catalog.find(c => c.type === type) || {};

  return (
    <div className="fixed inset-0 bg-black/70 z-[70] flex items-center justify-center p-4 print:hidden" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-3xl max-h-[90vh] flex flex-col text-slate-200"
        onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
          <div>
            <div className="text-[14px] font-medium">Report layout</div>
            <div className="text-[11px] text-slate-500">
              Reorder, rename, hide or add sections. Applies to the on-screen report, the shared copy, and the Word export.
              {version ? ` Currently on version ${version}.` : ""}
            </div>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>

        <div className="px-5 py-3 border-b border-[#30363D]">
          <input value={name} onChange={e => setName(e.target.value)}
            className="w-full h-8 px-3 bg-[#161B22] border border-[#30363D] rounded text-[12.5px]"/>
        </div>

        <div className="flex-1 overflow-y-auto p-5 space-y-2">
          {blocks.map((b, i) => {
            const m = meta(b.type);
            return (
              <div key={b.id} className={`border rounded-md px-3 py-2.5 ${b.visible === false
                ? "border-[#30363D] bg-[#0D1117] opacity-50" : "border-[#30363D] bg-[#161B22]"}`}>
                <div className="flex items-center gap-2">
                  <div className="flex flex-col">
                    <button onClick={() => move(i, -1)} disabled={i === 0}
                      className="text-slate-500 hover:text-slate-200 disabled:opacity-20"><ArrowUp size={12}/></button>
                    <button onClick={() => move(i, 1)} disabled={i === blocks.length - 1}
                      className="text-slate-500 hover:text-slate-200 disabled:opacity-20"><ArrowDown size={12}/></button>
                  </div>
                  {b.type === "page_break" ? (
                    <span className="flex-1 text-[11.5px] text-slate-500 italic">— page break —</span>
                  ) : (
                    <input value={b.title} onChange={e => update(i, { title: e.target.value })}
                      className="flex-1 h-7 px-2 bg-[#0D1117] border border-[#30363D] rounded text-[12px]"/>
                  )}
                  {m.internal_only && (
                    <span className="text-[10px] text-amber-300 border border-amber-500/40 rounded px-1.5 py-0.5 shrink-0"
                      title="Never included in a shared/external report, whatever the layout says">internal only</span>
                  )}
                  <button onClick={() => update(i, { visible: b.visible === false })}
                    title={b.visible === false ? "Hidden — click to show" : "Visible — click to hide"}
                    className="text-slate-500 hover:text-slate-200">
                    {b.visible === false ? <EyeSlash size={13}/> : <Eye size={13}/>}
                  </button>
                  {m.removable !== false && (
                    <button onClick={() => remove(i)} className="text-slate-600 hover:text-red-400"><X size={13}/></button>
                  )}
                </div>
                <div className="text-[10.5px] text-slate-500 mt-1 ml-6">{m.description}</div>
                {b.type === "section_heading" && (
                  <input value={b.options?.subtitle || ""} placeholder="Subtitle (optional)"
                    onChange={e => update(i, { options: { ...b.options, subtitle: e.target.value } })}
                    className="w-full mt-1.5 ml-6 h-7 px-2 bg-[#0D1117] border border-[#30363D] rounded text-[11.5px]"
                    style={{ width: "calc(100% - 1.5rem)" }}/>
                )}
                {b.type === "key_findings" && (
                  <div className="ml-6 mt-1.5 flex items-center gap-2 text-[11px] text-slate-400">
                    Show
                    <input type="number" min={1} max={50} value={b.options?.limit ?? 5}
                      onChange={e => update(i, { options: { ...b.options, limit: parseInt(e.target.value, 10) || 5 } })}
                      className="h-6 w-16 px-1.5 bg-[#0D1117] border border-[#30363D] rounded text-[11px]"/>
                    findings
                    <label className="inline-flex items-center gap-1 ml-2">
                      <input type="checkbox" checked={b.options?.show_recommendations !== false}
                        onChange={e => update(i, { options: { ...b.options, show_recommendations: e.target.checked } })}/>
                      with recommendations
                    </label>
                  </div>
                )}
                {b.type === "external_checks" && (
                  <div className="ml-6 mt-1.5 flex items-center gap-2 text-[11px] text-slate-400">
                    <select value={b.options?.panels || "both"}
                      onChange={e => update(i, { options: { ...b.options, panels: e.target.value } })}
                      className="h-6 px-1.5 bg-[#0D1117] border border-[#30363D] rounded text-[11px]">
                      <option value="both">Both panels</option>
                      <option value="company">Company posture only</option>
                      <option value="technical">Technical posture only</option>
                    </select>
                    <label className="inline-flex items-center gap-1">
                      <input type="checkbox" checked={b.options?.show_why_it_matters !== false}
                        onChange={e => update(i, { options: { ...b.options, show_why_it_matters: e.target.checked } })}/>
                      include &quot;why it matters&quot;
                    </label>
                  </div>
                )}
                {b.type === "risk_matrix" && (
                  <label className="ml-6 mt-1.5 flex items-center gap-1 text-[11px] text-slate-400">
                    <input type="checkbox" checked={b.options?.show_legend !== false}
                      onChange={e => update(i, { options: { ...b.options, show_legend: e.target.checked } })}/>
                    show the how-to-read legend
                  </label>
                )}
                {b.type === "questionnaire" && (
                  <div className="ml-6 mt-1.5 flex items-center gap-3 text-[11px] text-slate-400">
                    <label className="inline-flex items-center gap-1">
                      <input type="checkbox" checked={b.options?.answered_only !== false}
                        onChange={e => update(i, { options: { ...b.options, answered_only: e.target.checked } })}/>
                      answered questions only
                    </label>
                    <label className="inline-flex items-center gap-1">
                      <input type="checkbox" checked={b.options?.show_evidence !== false}
                        onChange={e => update(i, { options: { ...b.options, show_evidence: e.target.checked } })}/>
                      include evidence text
                    </label>
                  </div>
                )}
              </div>
            );
          })}

          {adding ? (
            <div className="border border-blue-500/40 rounded-md p-3 space-y-1">
              <div className="text-[11px] text-slate-400 mb-1">Add a section</div>
              {catalog.map(c => (
                <button key={c.type} onClick={() => add(c.type)}
                  className="w-full text-left px-2 py-1.5 rounded hover:bg-slate-800/50">
                  <div className="text-[12px] text-slate-200">{c.name}
                    {c.internal_only && <span className="text-[10px] text-amber-300 ml-1.5">internal only</span>}
                  </div>
                  <div className="text-[10.5px] text-slate-500">{c.description}</div>
                </button>
              ))}
              <button onClick={() => setAdding(false)} className="text-[11px] text-slate-500 mt-1">Cancel</button>
            </div>
          ) : (
            <button onClick={() => setAdding(true)}
              className="w-full h-8 border border-dashed border-[#30363D] rounded text-[12px] text-slate-400 hover:border-slate-500 inline-flex items-center justify-center gap-1.5">
              <Plus size={13}/> Add a section
            </button>
          )}
        </div>

        <div className="flex justify-between gap-2 px-5 py-3.5 border-t border-[#30363D]">
          <button onClick={reset}
            className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-400 inline-flex items-center gap-1.5">
            <ArrowCounterClockwise size={13}/> Reset to default
          </button>
          <div className="flex gap-2">
            <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
            <button onClick={save} disabled={saving}
              className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded inline-flex items-center gap-1.5">
              <FloppyDisk size={13}/> {saving ? "Saving…" : "Save layout"}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
