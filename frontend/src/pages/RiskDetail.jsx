import { useEffect, useState, useCallback } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { fmtDate } from "@/lib/utils-fmt";
import {
  ArrowLeft, ChatCircle, ClockCounterClockwise, CheckCircle, PencilSimple,
  Trash, FloppyDisk, X, Warning, LinkSimple, ShieldCheck, Plus,
} from "@phosphor-icons/react";

const BAND_COLOR = { Critical: "#f87171", High: "#fb923c", Medium: "#fbbf24", Low: "#60a5fa" };
const BAND_CHIP = { Critical: "red", High: "orange", Medium: "amber", Low: "blue" };
const STATUS_CHIP = { Open: "slate", "In Treatment": "blue", Monitoring: "amber", Accepted: "purple", Closed: "green" };

const ACTION_LABEL = {
  risk_created: "Created", risk_updated: "Updated", risk_status_changed: "Status changed",
  risk_note_added: "Note added", risk_reviewed: "Reviewed", risk_deleted: "Deleted",
};

export default function RiskDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [risk, setRisk] = useState(null);
  const [meta, setMeta] = useState({ categories: [], strategies: [], statuses: [], cadences: [] });
  const [comments, setComments] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [newNote, setNewNote] = useState("");
  const [editing, setEditing] = useState(false);
  const [linkedExceptions, setLinkedExceptions] = useState([]);
  const [showLinkException, setShowLinkException] = useState(false);
  const [allExceptions, setAllExceptions] = useState([]);
  const [exceptionSearch, setExceptionSearch] = useState("");
  const [form, setForm] = useState(null);
  const [saving, setSaving] = useState(false);

  const load = useCallback(async () => {
    try {
      const [riskR, metaR, commentsR, timelineR] = await Promise.all([
        api.get(`/v1/risk-register/${id}`),
        api.get("/v1/risk-register/meta"),
        api.get(`/v1/risk-register/${id}/comments`),
        api.get(`/v1/risk-register/${id}/timeline`),
      ]);
      setRisk(riskR.data);
      setForm(riskR.data);
      setMeta(metaR.data);
      setComments(commentsR.data);
      setTimeline(timelineR.data);
      if (riskR.data.linked_exception_ids?.length > 0) {
        const excs = await Promise.all(
          riskR.data.linked_exception_ids.map(eid => api.get(`/v1/exceptions/${eid}`).then(r => r.data).catch(() => null))
        );
        setLinkedExceptions(excs.filter(Boolean));
      } else {
        setLinkedExceptions([]);
      }
    } catch (e) {
      toast.error("Couldn't load this risk");
    }
  }, [id]);

  const openLinkException = async () => {
    setShowLinkException(true);
    if (allExceptions.length === 0) {
      try {
        const r = await api.get("/v1/exceptions");
        setAllExceptions(r.data.items || []);
      } catch (e) { /* non-fatal */ }
    }
  };

  const linkExisting = async (exceptionId) => {
    try {
      const next = [...new Set([...(risk.linked_exception_ids || []), exceptionId])];
      await api.patch(`/v1/risk-register/${id}`, { linked_exception_ids: next });
      toast.success("Linked");
      setShowLinkException(false);
      setExceptionSearch("");
      load();
    } catch (e) {
      toast.error("Failed to link");
    }
  };

  const unlinkException = async (exceptionId) => {
    try {
      const next = (risk.linked_exception_ids || []).filter(eid => eid !== exceptionId);
      await api.patch(`/v1/risk-register/${id}`, { linked_exception_ids: next });
      load();
    } catch (e) {
      toast.error("Failed to unlink");
    }
  };

  useEffect(() => { load(); }, [load]);

  const addNote = async () => {
    if (!newNote.trim()) return;
    try {
      await api.post(`/v1/risk-register/${id}/comments`, { text: newNote });
      setNewNote("");
      load();
    } catch (e) {
      toast.error("Failed to add note");
    }
  };

  const markReviewed = async () => {
    try {
      const r = await api.post(`/v1/risk-register/${id}/review`);
      toast.success(`Marked reviewed. Next review ${r.data.next_review_date ? new Date(r.data.next_review_date).toLocaleDateString() : "n/a"}.`);
      load();
    } catch (e) {
      toast.error("Failed to mark reviewed");
    }
  };

  const saveEdits = async () => {
    setSaving(true);
    try {
      await api.patch(`/v1/risk-register/${id}`, {
        title: form.title, description: form.description, category: form.category,
        likelihood: Number(form.likelihood), impact: Number(form.impact),
        treatment_strategy: form.treatment_strategy, treatment_plan: form.treatment_plan,
        residual_likelihood: form.residual_likelihood ? Number(form.residual_likelihood) : null,
        residual_impact: form.residual_impact ? Number(form.residual_impact) : null,
        owner: form.owner, status: form.status, review_cadence: form.review_cadence,
      });
      toast.success("Saved");
      setEditing(false);
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to save");
    } finally { setSaving(false); }
  };

  const remove = async () => {
    if (!window.confirm("Delete this risk from the register? This can't be undone.")) return;
    try {
      await api.delete(`/v1/risk-register/${id}`);
      toast.success("Risk deleted");
      navigate("/risk-register");
    } catch (e) {
      toast.error("Failed to delete");
    }
  };

  if (!risk || !form) {
    return <Layout title="Risk Register"><div className="text-slate-500 text-[13px]">Loading…</div></Layout>;
  }

  const overdue = risk.next_review_date && risk.next_review_date < new Date().toISOString() && risk.status !== "Closed";
  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }));

  return (
    <Layout title={risk.title} subtitle={`Risk Register · ${risk.category}`}
      actions={
        <div className="flex items-center gap-2">
          <button onClick={() => navigate(-1)} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-[#484F58] rounded inline-flex items-center gap-1.5 text-slate-300">
            <ArrowLeft size={14} /> Back
          </button>
          {!editing ? (
            <button onClick={() => setEditing(true)} className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-blue-500/40 hover:text-blue-300 rounded inline-flex items-center gap-1.5 text-slate-300">
              <PencilSimple size={14} /> Edit
            </button>
          ) : (
            <>
              <button onClick={() => { setEditing(false); setForm(risk); }} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
              <button onClick={saveEdits} disabled={saving} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-40 text-white rounded inline-flex items-center gap-1.5">
                <FloppyDisk size={14} /> {saving ? "Saving…" : "Save"}
              </button>
            </>
          )}
          <button onClick={remove} className="h-8 px-3 text-[12px] border border-red-500/30 hover:bg-red-500/10 text-red-300 rounded inline-flex items-center gap-1.5">
            <Trash size={14} /> Delete
          </button>
        </div>
      }>
      <div className="grid grid-cols-3 gap-4">
        <div className="col-span-2 space-y-4">
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            {editing ? (
              <div className="space-y-3">
                <div>
                  <label className="text-[11px] uppercase font-mono text-slate-500">Title</label>
                  <input value={form.title} onChange={set("title")} className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200" />
                </div>
                <div>
                  <label className="text-[11px] uppercase font-mono text-slate-500">Description</label>
                  <textarea value={form.description} onChange={set("description")} rows={3} className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200" />
                </div>
              </div>
            ) : (
              <>
                <div className="flex items-center gap-2 flex-wrap mb-2">
                  <Chip color={BAND_CHIP[risk.inherent_band]}>{risk.inherent_band} · inherent {risk.inherent_score}</Chip>
                  {risk.residual_band && <Chip color={BAND_CHIP[risk.residual_band]}>{risk.residual_band} · residual {risk.residual_score}</Chip>}
                  <Chip color={STATUS_CHIP[risk.status]}>{risk.status}</Chip>
                  <Chip color="slate">{risk.category}</Chip>
                </div>
                <div className="text-[13px] text-slate-200 leading-relaxed whitespace-pre-wrap">{risk.description || "No description."}</div>
              </>
            )}
          </div>

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="text-[13px] font-medium text-slate-100 mb-3">Risk Scoring</div>
            {editing ? (
              <div className="grid grid-cols-2 gap-3">
                <div><label className="text-[11px] uppercase font-mono text-slate-500">Likelihood (1-5)</label>
                  <input type="number" min={1} max={5} value={form.likelihood} onChange={set("likelihood")} className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200" /></div>
                <div><label className="text-[11px] uppercase font-mono text-slate-500">Impact (1-5)</label>
                  <input type="number" min={1} max={5} value={form.impact} onChange={set("impact")} className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200" /></div>
                <div><label className="text-[11px] uppercase font-mono text-slate-500">Residual likelihood</label>
                  <input type="number" min={1} max={5} value={form.residual_likelihood || ""} onChange={set("residual_likelihood")} className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200" /></div>
                <div><label className="text-[11px] uppercase font-mono text-slate-500">Residual impact</label>
                  <input type="number" min={1} max={5} value={form.residual_impact || ""} onChange={set("residual_impact")} className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200" /></div>
              </div>
            ) : (
              <div className="grid grid-cols-4 gap-3 text-[12px]">
                <div><div className="text-slate-500 uppercase font-mono text-[10px]">Likelihood</div><div className="text-slate-300 mt-0.5">{risk.likelihood} / 5</div></div>
                <div><div className="text-slate-500 uppercase font-mono text-[10px]">Impact</div><div className="text-slate-300 mt-0.5">{risk.impact} / 5</div></div>
                <div><div className="text-slate-500 uppercase font-mono text-[10px]">Residual likelihood</div><div className="text-slate-300 mt-0.5">{risk.residual_likelihood || "—"}</div></div>
                <div><div className="text-slate-500 uppercase font-mono text-[10px]">Residual impact</div><div className="text-slate-300 mt-0.5">{risk.residual_impact || "—"}</div></div>
              </div>
            )}
          </div>

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="text-[13px] font-medium text-slate-100 mb-3">Treatment Plan</div>
            {editing ? (
              <div className="space-y-3">
                <div>
                  <label className="text-[11px] uppercase font-mono text-slate-500">Strategy</label>
                  <select value={form.treatment_strategy} onChange={set("treatment_strategy")} className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200">
                    {meta.strategies.map(s => <option key={s}>{s}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-[11px] uppercase font-mono text-slate-500">Plan</label>
                  <textarea value={form.treatment_plan} onChange={set("treatment_plan")} rows={3} className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200" />
                </div>
              </div>
            ) : (
              <>
                <Chip color="blue">{risk.treatment_strategy}</Chip>
                <div className="text-[12.5px] text-slate-300 leading-relaxed whitespace-pre-wrap mt-2">{risk.treatment_plan || "No treatment plan documented."}</div>
              </>
            )}
          </div>

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="text-[13px] font-medium text-slate-100 mb-3">Notes / Updates</div>
            <div className="space-y-2 mb-3">
              {comments.length === 0 && <div className="text-[12px] text-slate-500">No notes yet.</div>}
              {comments.map(c => (
                <div key={c.id} className="border border-[#30363D] rounded p-2.5 bg-[#161B22]">
                  <div className="text-[10.5px] font-mono text-slate-500">{c.author} · {fmtDate(c.created_at)}</div>
                  <div className="text-[12.5px] text-slate-200 mt-1 whitespace-pre-wrap">{c.text}</div>
                </div>
              ))}
            </div>
            <div className="flex gap-2">
              <input value={newNote} onChange={e => setNewNote(e.target.value)} placeholder="Add an update…"
                onKeyDown={e => e.key === "Enter" && addNote()}
                className="flex-1 h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200" />
              <button onClick={addNote} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded inline-flex items-center gap-1">
                <ChatCircle size={14} /> Add
              </button>
            </div>
          </div>

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="text-[13px] font-medium text-slate-100 mb-3 flex items-center gap-1.5"><ClockCounterClockwise size={15} /> Activity Timeline</div>
            <div className="space-y-2">
              {timeline.map(e => (
                <div key={e.id} className="flex gap-3 text-[12px]">
                  <div className="text-slate-500 font-mono w-32 shrink-0">{fmtDate(e.timestamp)}</div>
                  <div className="flex-1">
                    <span className="text-slate-200">{ACTION_LABEL[e.action] || e.action}</span>
                    <span className="text-slate-500"> — {e.details}</span>
                    <div className="text-[10.5px] text-slate-600">{e.actor}</div>
                  </div>
                </div>
              ))}
              {timeline.length === 0 && <div className="text-[12px] text-slate-500">No activity yet.</div>}
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="text-[13px] font-medium text-slate-100 mb-3">Ownership & Review</div>
            {editing ? (
              <div className="space-y-3">
                <div><label className="text-[11px] uppercase font-mono text-slate-500">Owner</label>
                  <input value={form.owner || ""} onChange={set("owner")} className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200" /></div>
                <div><label className="text-[11px] uppercase font-mono text-slate-500">Status</label>
                  <select value={form.status} onChange={set("status")} className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200">
                    {meta.statuses.map(s => <option key={s}>{s}</option>)}
                  </select></div>
                <div><label className="text-[11px] uppercase font-mono text-slate-500">Category</label>
                  <select value={form.category} onChange={set("category")} className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200">
                    {meta.categories.map(c => <option key={c}>{c}</option>)}
                  </select></div>
                <div><label className="text-[11px] uppercase font-mono text-slate-500">Review cadence</label>
                  <select value={form.review_cadence} onChange={set("review_cadence")} className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200">
                    {meta.cadences.map(c => <option key={c}>{c}</option>)}
                  </select></div>
              </div>
            ) : (
              <div className="space-y-3 text-[12px]">
                <div><div className="text-slate-500 uppercase font-mono text-[10px]">Owner</div><div className="text-slate-300 mt-0.5">{risk.owner || "Unassigned"}</div></div>
                <div><div className="text-slate-500 uppercase font-mono text-[10px]">Review cadence</div><div className="text-slate-300 mt-0.5">{risk.review_cadence}</div></div>
                <div><div className="text-slate-500 uppercase font-mono text-[10px]">Last reviewed</div><div className="text-slate-300 mt-0.5">{risk.last_reviewed_at ? `${fmtDate(risk.last_reviewed_at)} by ${risk.last_reviewed_by}` : "Never"}</div></div>
                <div>
                  <div className="text-slate-500 uppercase font-mono text-[10px]">Next review</div>
                  <div className={`mt-0.5 flex items-center gap-1.5 ${overdue ? "text-amber-300" : "text-slate-300"}`}>
                    {risk.next_review_date ? new Date(risk.next_review_date).toLocaleDateString() : "—"}
                    {overdue && <Warning size={13} />}
                  </div>
                </div>
                <button onClick={markReviewed} className="w-full h-8 mt-1 text-[12px] bg-emerald-500/15 border border-emerald-500/40 hover:bg-emerald-500/25 text-emerald-300 rounded inline-flex items-center justify-center gap-1.5">
                  <CheckCircle size={14} /> Mark reviewed
                </button>
              </div>
            )}
          </div>

          {(risk.linked_finding_ids?.length > 0 || risk.linked_asset_ids?.length > 0) && (
            <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
              <div className="text-[13px] font-medium text-slate-100 mb-2">Linked Items</div>
              <div className="space-y-1.5 text-[12px]">
                {(risk.linked_finding_ids || []).map(fid => <Link key={fid} to={`/findings/${fid}`} className="block text-blue-300 hover:underline">Finding {fid.slice(0, 8)}</Link>)}
                {(risk.linked_asset_ids || []).map(aid => <Link key={aid} to={`/assets/${aid}`} className="block text-blue-300 hover:underline">Asset {aid.slice(0, 8)}</Link>)}
              </div>
            </div>
          )}

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="flex items-center justify-between mb-2">
              <div className="text-[13px] font-medium text-slate-100 flex items-center gap-1.5"><ShieldCheck size={15} /> Linked Exceptions</div>
              <button onClick={openLinkException} className="text-[11px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1"><LinkSimple size={11} /> Link existing</button>
            </div>
            <div className="space-y-1.5 text-[12px] mb-2">
              {linkedExceptions.map(exc => (
                <div key={exc.id} className="flex items-center justify-between border border-[#21262D] rounded px-2 py-1.5">
                  <Link to={`/exceptions/${exc.id}`} className="text-blue-300 hover:underline truncate">{exc.finding_title || exc.target_value || exc.id.slice(0, 8)}</Link>
                  <div className="flex items-center gap-2 shrink-0">
                    <Chip color="slate">{exc.status}</Chip>
                    <button onClick={() => unlinkException(exc.id)} className="text-slate-500 hover:text-red-400"><X size={12} /></button>
                  </div>
                </div>
              ))}
              {linkedExceptions.length === 0 && <div className="text-slate-500">No exceptions linked yet.</div>}
            </div>
            {risk.linked_finding_ids?.length > 0 && (
              <Link to={`/exceptions/new?finding_id=${risk.linked_finding_ids[0]}`}
                className="text-[11px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1">
                <Plus size={11} /> Request a new exception for the linked finding
              </Link>
            )}
          </div>
        </div>
      </div>

      {showLinkException && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4" onClick={() => setShowLinkException(false)}>
          <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-md max-h-[70vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between sticky top-0 bg-[#0D1117]">
              <h3 className="text-[13px] font-medium text-slate-100">Link an existing exception</h3>
              <button onClick={() => setShowLinkException(false)} className="text-slate-500 hover:text-slate-300"><X size={16} /></button>
            </div>
            <div className="p-3">
              <input value={exceptionSearch} onChange={e => setExceptionSearch(e.target.value)} placeholder="Search by finding, asset, or CVE…"
                className="w-full h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200 mb-2" />
              <div className="space-y-1">
                {allExceptions
                  .filter(e => !exceptionSearch || `${e.finding_title} ${e.asset_hostname} ${e.cve}`.toLowerCase().includes(exceptionSearch.toLowerCase()))
                  .filter(e => !(risk.linked_exception_ids || []).includes(e.id))
                  .slice(0, 30)
                  .map(e => (
                    <button key={e.id} onClick={() => linkExisting(e.id)}
                      className="w-full text-left px-2.5 py-1.5 border border-[#21262D] hover:border-blue-500/40 rounded text-[12px] text-slate-300">
                      <div className="truncate">{e.finding_title || e.target_value}</div>
                      <div className="text-[10.5px] text-slate-500 font-mono">{e.asset_hostname} · {e.status}</div>
                    </button>
                  ))}
                {allExceptions.length === 0 && <div className="text-[12px] text-slate-500 text-center py-4">No exceptions found.</div>}
              </div>
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
}
