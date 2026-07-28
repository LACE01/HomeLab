import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Plus, X, MagnifyingGlass, ClipboardText, Clock, ChartBar, Wrench, CaretDown, CaretRight } from "@phosphor-icons/react";

const RISK_COLOR = { Low: "blue", Medium: "amber", High: "orange", Critical: "red" };
const STATUS_COLOR = {
  "Requested": "slate", "Scoped": "blue", "In Assessment": "blue", "Pending Info": "amber",
  "Risk Rated": "purple", "Report Drafted": "purple", "Decision Issued": "emerald",
  "Closed": "slate", "In Follow-up": "amber",
};

function slaDays(seconds) {
  if (seconds == null) return null;
  return Math.floor(seconds / 86400);
}

export default function SecurityReviews() {
  const [items, setItems] = useState([]);
  const [meta, setMeta] = useState(null);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [riskFilter, setRiskFilter] = useState("");
  const [q, setQ] = useState("");
  const [intakeOpen, setIntakeOpen] = useState(false);
  const [view, setView] = useState("list"); // list | dashboard | admin
  const [dash, setDash] = useState(null);

  const loadDash = async () => {
    const r = await api.get("/v1/security-reviews/dashboard");
    setDash(r.data);
  };
  useEffect(() => { if (view === "dashboard") loadDash(); /* eslint-disable-next-line */ }, [view]);

  const load = async () => {
    try {
      const params = {};
      if (statusFilter) params.status = statusFilter;
      if (typeFilter) params.review_type = typeFilter;
      if (riskFilter) params.risk = riskFilter;
      if (q.trim()) params.q = q.trim();
      const [r, m] = await Promise.all([
        api.get("/v1/security-reviews", { params }),
        meta ? Promise.resolve({ data: meta }) : api.get("/v1/security-reviews/meta"),
      ]);
      setItems(r.data.items || []);
      if (!meta) setMeta(m.data);
    } catch (e) {
      toast.error("Failed to load security reviews");
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); /* eslint-disable-next-line */ }, [statusFilter, typeFilter, riskFilter]);

  return (
    <Layout title="Security Reviews"
      subtitle='Guided investigations for "we want to buy/enable/change X — is it secure, what&apos;s the risk?" — intake to decision, with a shareable executive report'
      actions={
        <div className="flex items-center gap-2">
          <button onClick={() => setView(view === "dashboard" ? "list" : "dashboard")}
            className={`h-8 px-3 text-[12px] border rounded inline-flex items-center gap-1.5 ${view === "dashboard" ? "border-blue-500/40 text-blue-300 bg-blue-500/10" : "border-[#30363D] text-slate-300 hover:border-slate-500"}`}>
            <ChartBar size={14}/> Dashboard
          </button>
          <button onClick={() => setView(view === "admin" ? "list" : "admin")}
            className={`h-8 px-3 text-[12px] border rounded inline-flex items-center gap-1.5 ${view === "admin" ? "border-blue-500/40 text-blue-300 bg-blue-500/10" : "border-[#30363D] text-slate-300 hover:border-slate-500"}`}>
            <Wrench size={14}/> Templates
          </button>
          <button onClick={() => setIntakeOpen(true)}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1.5">
            <Plus size={14}/> New review
          </button>
        </div>
      }>
      {view === "dashboard" && <DashboardView dash={dash}/>}
      {view === "admin" && <TemplatesAdmin/>}
      {view === "list" && (<>

      <form onSubmit={(e) => { e.preventDefault(); load(); }} className="flex items-center gap-2 mb-3 flex-wrap">
        <div className="relative flex-1 max-w-sm min-w-[220px]">
          <MagnifyingGlass size={14} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500"/>
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search title, SR number, vendor…"
            className="w-full h-8 pl-8 pr-3 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
        </div>
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
          className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-300">
          <option value="">All statuses</option>
          {(meta?.statuses || []).map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
          className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-300 max-w-[260px]">
          <option value="">All types</option>
          {(meta?.review_types || []).map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <select value={riskFilter} onChange={e => setRiskFilter(e.target.value)}
          className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-300">
          <option value="">All risk bands</option>
          {["Low", "Medium", "High", "Critical"].map(b => <option key={b} value={b}>{b}</option>)}
        </select>
        <button type="submit" className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Search</button>
      </form>

      {loading ? (
        <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>
      ) : items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-12 text-center">
          <ClipboardText size={28} className="text-slate-600 mx-auto mb-2"/>
          <div className="text-[13px] text-slate-400">No security reviews yet.</div>
          <div className="text-[12px] text-slate-500 mt-1">Start one when someone asks "can we buy/enable/change X?"</div>
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr className="border-b border-[#30363D] text-left text-slate-500 text-[11px] uppercase tracking-wider">
                <th className="px-4 py-2.5 font-medium">Review</th>
                <th className="px-4 py-2.5 font-medium">Type</th>
                <th className="px-4 py-2.5 font-medium">Status</th>
                <th className="px-4 py-2.5 font-medium">Inherent</th>
                <th className="px-4 py-2.5 font-medium">Residual</th>
                <th className="px-4 py-2.5 font-medium">Assignee</th>
                <th className="px-4 py-2.5 font-medium">Age</th>
              </tr>
            </thead>
            <tbody>
              {items.map(r => {
                const days = slaDays(r.sla_elapsed_seconds);
                return (
                  <tr key={r.id} className="border-b border-[#30363D] last:border-0 hover:bg-slate-800/20">
                    <td className="px-4 py-2.5">
                      <Link to={`/security-reviews/${r.id}`} className="text-blue-300 hover:underline">
                        <span className="font-mono text-[11.5px] text-slate-500 mr-2">{r.review_number}</span>
                        {r.title}
                      </Link>
                      {r.entity_name && <div className="text-[11px] text-slate-500 mt-0.5">{r.entity_name}</div>}
                    </td>
                    <td className="px-4 py-2.5 text-slate-400 text-[11.5px] max-w-[180px] truncate" title={r.review_type}>{r.review_type}</td>
                    <td className="px-4 py-2.5"><Chip color={STATUS_COLOR[r.status] || "slate"}>{r.status}</Chip></td>
                    <td className="px-4 py-2.5">
                      {r.inherent_risk?.band
                        ? <Chip color={RISK_COLOR[r.inherent_risk.band]}>{r.inherent_risk.band}</Chip>
                        : <span className="text-slate-600">—</span>}
                    </td>
                    <td className="px-4 py-2.5">
                      {r.residual_risk?.band
                        ? <Chip color={RISK_COLOR[r.residual_risk.band]}>{r.residual_risk.band}</Chip>
                        : <span className="text-slate-600">—</span>}
                    </td>
                    <td className="px-4 py-2.5 text-slate-400 text-[11.5px]">{r.assignee || "—"}</td>
                    <td className="px-4 py-2.5 text-slate-500 text-[11.5px]">
                      {days != null ? (
                        <span className={`inline-flex items-center gap-1 ${days > 30 ? "text-amber-400" : ""}`}>
                          <Clock size={11}/> {days}d{r.sla_paused_at ? " (paused)" : ""}
                        </span>
                      ) : "closed"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      </>)}

      {intakeOpen && meta && (
        <IntakeModal meta={meta} onClose={() => setIntakeOpen(false)}
          onSaved={() => { setIntakeOpen(false); load(); }}/>
      )}
    </Layout>
  );
}

function DashStat({ label, value, tone }) {
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-3.5 py-3">
      <div className="text-[10.5px] text-slate-500 uppercase tracking-wider">{label}</div>
      <div className={`text-[20px] font-semibold mt-0.5 ${tone === "amber" ? "text-amber-300" : tone === "red" ? "text-red-300" : "text-slate-100"}`}>{value ?? "—"}</div>
    </div>
  );
}

function DashboardView({ dash }) {
  if (!dash) return <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-2.5">
        <DashStat label="Open reviews" value={dash.open_total}/>
        <DashStat label="Aging > 30 days" value={dash.aging_over_30_days} tone={dash.aging_over_30_days ? "amber" : undefined}/>
        <DashStat label="Blocked > 14 days" value={dash.blocked_over_14_days.length} tone={dash.blocked_over_14_days.length ? "amber" : undefined}/>
        <DashStat label="Conditions overdue" value={dash.conditions_overdue.length} tone={dash.conditions_overdue.length ? "red" : undefined}/>
        <DashStat label="Avg days to decision" value={dash.avg_days_to_decision_excl_paused}/>
        <DashStat label="% approved w/ conditions" value={dash.pct_approved_with_conditions != null ? `${dash.pct_approved_with_conditions}%` : "—"}/>
      </div>
      <div className="grid md:grid-cols-2 gap-3">
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">Open by status</div>
          {Object.entries(dash.by_status).map(([s, n]) => (
            <div key={s} className="flex justify-between text-[12.5px] py-0.5"><span className="text-slate-300">{s}</span><span className="text-slate-500">{n}</span></div>
          ))}
          {Object.keys(dash.by_status).length === 0 && <div className="text-[12px] text-slate-500">Nothing open.</div>}
        </div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">Risk distribution (decided reviews)</div>
          {Object.entries(dash.risk_distribution).map(([b, n]) => (
            <div key={b} className="flex justify-between text-[12.5px] py-0.5">
              <Chip color={RISK_COLOR[b] || "slate"}>{b}</Chip><span className="text-slate-500">{n}</span>
            </div>
          ))}
          {Object.keys(dash.risk_distribution).length === 0 && <div className="text-[12px] text-slate-500">No decided reviews yet.</div>}
        </div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">Conditions due in 30 days</div>
          {dash.conditions_due_30_days.map((c, i) => (
            <div key={i} className="text-[12px] text-slate-300 py-0.5">
              {c.description?.slice(0, 90)} <span className="text-amber-300">due {c.condition_deadline}</span>
            </div>
          ))}
          {dash.conditions_due_30_days.length === 0 && <div className="text-[12px] text-slate-500">None coming due.</div>}
        </div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">Re-reviews & expiring certifications</div>
          {dash.upcoming_rereviews.map(e => (
            <div key={e.id} className="text-[12px] text-slate-300 py-0.5">{e.name} — re-review by {e.next_review_date}</div>
          ))}
          {dash.expiring_certifications.map((c, i) => (
            <div key={`c${i}`} className="text-[12px] text-amber-300 py-0.5">{c.entity}: {c.name} expires {c.expires_at}</div>
          ))}
          {dash.upcoming_rereviews.length === 0 && dash.expiring_certifications.length === 0 &&
            <div className="text-[12px] text-slate-500">Nothing upcoming within 90 days.</div>}
        </div>
      </div>
      {dash.blocked_over_14_days.length > 0 && (
        <div className="border border-amber-500/30 bg-amber-500/5 rounded-md p-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-amber-300 mb-2">Blocked &gt; 14 days — needs a nudge</div>
          {dash.blocked_over_14_days.map((b, i) => (
            <div key={i} className="text-[12px] text-slate-300 py-0.5">
              <Link to={`/security-reviews/${b.review_id}`} className="text-blue-300 hover:underline">{b.title}</Link>
              {" "}— blocked on {b.blocked_on || "?"} since {b.blocked_date}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function TemplatesAdmin() {
  const [playbooks, setPlaybooks] = useState([]);
  const [questionnaires, setQuestionnaires] = useState([]);
  const [editing, setEditing] = useState(null); // {kind, key, name, json}
  const [expanded, setExpanded] = useState(new Set());

  const load = async () => {
    const [p, q] = await Promise.all([api.get("/v1/review-playbooks"), api.get("/v1/review-questionnaires")]);
    setPlaybooks(p.data.items || []); setQuestionnaires(q.data.items || []);
  };
  useEffect(() => { load(); }, []);

  const startEdit = (kind, doc) => {
    const payload = kind === "playbook"
      ? { review_types: doc.review_types, steps: doc.steps }
      : { questions: doc.questions };
    setEditing({ kind, key: doc.key, name: doc.name, json: JSON.stringify(payload, null, 2) });
  };

  const saveVersion = async () => {
    let parsed;
    try { parsed = JSON.parse(editing.json); } catch { toast.error("Invalid JSON"); return; }
    try {
      const path = editing.kind === "playbook" ? "/v1/review-playbooks" : "/v1/review-questionnaires";
      const r = await api.post(path, { key: editing.key, name: editing.name, ...parsed });
      toast.success(`Saved as version ${r.data.version} — existing reviews keep their pinned version`);
      setEditing(null); load();
    } catch (e) { toast.error(e.response?.data?.detail || "Save failed"); }
  };

  const latestByKey = (items) => {
    const seen = new Set();
    return items.filter(i => { if (seen.has(i.key)) return false; seen.add(i.key); return true; });
  };

  const Row = ({ kind, doc, items }) => {
    const isOpen = expanded.has(doc.key);
    const versions = items.filter(i => i.key === doc.key).map(i => i.version).sort((a, b) => b - a);
    return (
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
        <div className="px-4 py-2.5 flex items-center gap-3 cursor-pointer"
          onClick={() => setExpanded(prev => { const n = new Set(prev); n.has(doc.key) ? n.delete(doc.key) : n.add(doc.key); return n; })}>
          {isOpen ? <CaretDown size={13} className="text-slate-500"/> : <CaretRight size={13} className="text-slate-500"/>}
          <span className="text-[13px] text-slate-200 flex-1">{doc.name}</span>
          <span className="text-[11px] text-slate-500 font-mono">v{versions.join(", v")}</span>
          <button onClick={(e) => { e.stopPropagation(); startEdit(kind, doc); }}
            className="h-7 px-2.5 text-[11.5px] border border-[#30363D] text-slate-300 rounded hover:border-slate-500">New version</button>
        </div>
        {isOpen && (
          <div className="border-t border-[#30363D] px-4 py-3 text-[11.5px] text-slate-400 space-y-1">
            {kind === "playbook"
              ? doc.steps.map(s => <div key={s.order}>#{s.order} {s.title}{s.autofill_hook ? ` (auto-fill: ${s.autofill_hook})` : ""}</div>)
              : doc.questions.map(q => <div key={q.order}>Q{q.order}. {q.text.slice(0, 100)} <span className="text-slate-600">[CIS {q.cis_mapping} · w{q.risk_weight}]</span></div>)}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-4">
      <div className="text-[12px] text-slate-500 max-w-2xl">
        Playbooks and questionnaires are versioned records — "New version" clones the latest into an editor and saves as
        the next version. Reviews already in flight keep the exact version they started with.
      </div>
      <div>
        <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">Playbooks</div>
        <div className="space-y-2">{latestByKey(playbooks).map(p => <Row key={p.id} kind="playbook" doc={p} items={playbooks}/>)}</div>
      </div>
      <div>
        <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">Questionnaires</div>
        <div className="space-y-2">{latestByKey(questionnaires).map(q => <Row key={q.id} kind="questionnaire" doc={q} items={questionnaires}/>)}</div>
      </div>
      {editing && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={() => setEditing(null)}>
          <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-3xl max-h-[90vh] flex flex-col" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D]">
              <div className="text-[14px] text-slate-100 font-medium">New version — {editing.name}</div>
              <button onClick={() => setEditing(null)} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
            </div>
            <textarea value={editing.json} onChange={e => setEditing({ ...editing, json: e.target.value })}
              className="flex-1 m-4 p-3 bg-[#161B22] border border-[#30363D] rounded text-[11.5px] text-slate-200 font-mono min-h-[400px]"/>
            <div className="flex justify-end gap-2 px-5 py-3.5 border-t border-[#30363D]">
              <button onClick={() => setEditing(null)} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
              <button onClick={saveVersion} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Save as next version</button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function IntakeModal({ meta, onClose, onSaved }) {
  const [form, setForm] = useState({
    title: "", review_type: meta.review_types[0], requestor_name: "", requestor_department: "",
    business_justification: "", urgency: "Normal", target_decision_date: "",
    data_classifications: [], scope_statement: "", entity_name: "", entity_domain: "",
  });
  const [saving, setSaving] = useState(false);
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }));

  const toggleClassification = (c) => {
    set("data_classifications", form.data_classifications.includes(c)
      ? form.data_classifications.filter(x => x !== c)
      : [...form.data_classifications, c]);
  };

  const save = async () => {
    if (!form.title.trim()) { toast.error("Title is required"); return; }
    setSaving(true);
    try {
      const body = { ...form, target_decision_date: form.target_decision_date || null };
      const r = await api.post("/v1/security-reviews", body);
      toast.success(`${r.data.review_number} created`);
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to create review");
    } finally { setSaving(false); }
  };

  const L = ({ children }) => <label className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">{children}</label>;
  const inputCls = "w-full mt-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100";

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-2xl max-h-[90vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[#30363D] sticky top-0 bg-[#0D1117]">
          <div className="text-[14px] text-slate-100 font-medium">New Security Review — Intake</div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200"><X size={18}/></button>
        </div>
        <div className="p-5 space-y-4">
          <div>
            <L>Title</L>
            <input value={form.title} onChange={e => set("title", e.target.value)}
              placeholder='e.g. "Acme Scheduling SaaS for HR"' className={inputCls}/>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <L>Review type</L>
              <select value={form.review_type} onChange={e => set("review_type", e.target.value)} className={inputCls}>
                {meta.review_types.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
            <div>
              <L>Urgency</L>
              <select value={form.urgency} onChange={e => set("urgency", e.target.value)} className={inputCls}>
                {meta.urgencies.map(u => <option key={u} value={u}>{u}</option>)}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <L>Requestor name</L>
              <input value={form.requestor_name} onChange={e => set("requestor_name", e.target.value)} className={inputCls}/>
            </div>
            <div>
              <L>Requestor department</L>
              <input value={form.requestor_department} onChange={e => set("requestor_department", e.target.value)} className={inputCls}/>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <L>Vendor / product / system under review</L>
              <input value={form.entity_name} onChange={e => set("entity_name", e.target.value)}
                placeholder="Acme Corp" className={inputCls}/>
            </div>
            <div>
              <L>Vendor domain (for OSINT checks)</L>
              <input value={form.entity_domain} onChange={e => set("entity_domain", e.target.value)}
                placeholder="acme.com" className={inputCls}/>
            </div>
          </div>
          <div>
            <L>Business justification</L>
            <textarea value={form.business_justification} onChange={e => set("business_justification", e.target.value)}
              rows={2} className="w-full mt-1 px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
          </div>
          <div>
            <L>Scope (what data goes in it, who uses it, how it's accessed)</L>
            <textarea value={form.scope_statement} onChange={e => set("scope_statement", e.target.value)}
              rows={3} className="w-full mt-1 px-3 py-2 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100"/>
          </div>
          <div>
            <L>Data classifications (select all that apply — when in doubt, classify up)</L>
            <div className="flex flex-wrap gap-1.5 mt-1.5">
              {meta.data_classifications.map(c => (
                <button key={c} type="button" onClick={() => toggleClassification(c)}
                  className={`h-7 px-2.5 text-[11.5px] rounded border ${form.data_classifications.includes(c)
                    ? "bg-blue-500/15 border-blue-500/40 text-blue-300"
                    : "border-[#30363D] text-slate-400 hover:border-slate-500"}`}>
                  {c}
                </button>
              ))}
            </div>
          </div>
          <div>
            <L>Target decision date (optional)</L>
            <input type="date" value={form.target_decision_date} onChange={e => set("target_decision_date", e.target.value)}
              className={inputCls}/>
          </div>
        </div>
        <div className="flex justify-end gap-2 px-5 py-3.5 border-t border-[#30363D] sticky bottom-0 bg-[#0D1117]">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={save} disabled={saving}
            className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded">
            {saving ? "Creating…" : "Create review"}
          </button>
        </div>
      </div>
    </div>
  );
}
