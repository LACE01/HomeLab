import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Plus, X, Warning, ClockCounterClockwise } from "@phosphor-icons/react";

const BAND_COLOR = { Critical: "#f87171", High: "#fb923c", Medium: "#fbbf24", Low: "#60a5fa" };
const BAND_CHIP = { Critical: "red", High: "orange", Medium: "amber", Low: "blue" };
const STATUS_CHIP = { Open: "slate", "In Treatment": "blue", Monitoring: "amber", Accepted: "purple", Closed: "green" };

function cellColor(count) {
  if (!count) return "#0D1117";
  if (count >= 4) return "#7f1d1d";
  if (count >= 2) return "#b45309";
  return "#1e3a5f";
}

function RiskMatrix({ cells, onCellClick }) {
  // Impact rows 5->1 (top to bottom), likelihood columns 1->5 (left to right) --
  // standard 5x5 orientation with the highest-risk corner top-right.
  return (
    <div className="inline-block">
      <div className="flex">
        <div className="w-16" />
        <div className="flex-1 text-center text-[10px] uppercase tracking-wider text-slate-500 mb-1">Likelihood →</div>
      </div>
      {[5, 4, 3, 2, 1].map(impact => (
        <div key={impact} className="flex items-center">
          {impact === 3 && <div className="w-4 -rotate-90 text-[10px] uppercase tracking-wider text-slate-500 whitespace-nowrap" style={{ marginLeft: "-2.2rem", marginRight: "0.6rem" }}>Impact →</div>}
          <div className="w-8 text-right pr-2 text-[11px] text-slate-500 font-mono">{impact}</div>
          <div className="flex gap-1 my-0.5">
            {[1, 2, 3, 4, 5].map(likelihood => {
              const key = `${likelihood}-${impact}`;
              const count = cells[key] || 0;
              return (
                <div key={key} onClick={() => count > 0 && onCellClick?.(likelihood, impact)}
                  className={`w-11 h-11 rounded flex items-center justify-center text-[13px] font-semibold text-white border border-black/20 ${count > 0 ? "cursor-pointer hover:opacity-80" : ""}`}
                  style={{ background: cellColor(count) }}>
                  {count > 0 ? count : ""}
                </div>
              );
            })}
          </div>
        </div>
      ))}
      <div className="flex">
        <div className="w-8" />
        <div className="flex gap-1">
          {[1, 2, 3, 4, 5].map(n => <div key={n} className="w-11 text-center text-[11px] text-slate-500 font-mono">{n}</div>)}
        </div>
      </div>
    </div>
  );
}

function NewRiskModal({ meta, onClose, onCreated }) {
  const [form, setForm] = useState({
    title: "", description: "", category: "Technical", likelihood: 3, impact: 3,
    treatment_strategy: "Mitigate", treatment_plan: "", owner: "", status: "Open", review_cadence: "Quarterly",
  });
  const [saving, setSaving] = useState(false);
  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }));

  const submit = async () => {
    if (!form.title.trim()) { toast.error("Title is required"); return; }
    setSaving(true);
    try {
      const r = await api.post("/v1/risk-register", { ...form, likelihood: Number(form.likelihood), impact: Number(form.impact) });
      toast.success("Risk added to register");
      onCreated(r.data);
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to create risk");
    } finally { setSaving(false); }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-lg max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between sticky top-0 bg-[#0D1117]">
          <h3 className="text-[13px] font-medium text-slate-100">New risk</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16} /></button>
        </div>
        <div className="p-4 space-y-3">
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Title</label>
            <input value={form.title} onChange={set("title")} placeholder="e.g. Single vendor dependency for payroll processing"
              className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200" />
          </div>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Description</label>
            <textarea value={form.description} onChange={set("description")} rows={2}
              className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] uppercase font-mono text-slate-500">Category</label>
              <select value={form.category} onChange={set("category")} className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200">
                {meta.categories.map(c => <option key={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[11px] uppercase font-mono text-slate-500">Owner</label>
              <input value={form.owner} onChange={set("owner")} placeholder="email"
                className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] uppercase font-mono text-slate-500">Likelihood (1-5)</label>
              <input type="number" min={1} max={5} value={form.likelihood} onChange={set("likelihood")}
                className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200" />
            </div>
            <div>
              <label className="text-[11px] uppercase font-mono text-slate-500">Impact (1-5)</label>
              <input type="number" min={1} max={5} value={form.impact} onChange={set("impact")}
                className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200" />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] uppercase font-mono text-slate-500">Treatment strategy</label>
              <select value={form.treatment_strategy} onChange={set("treatment_strategy")} className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200">
                {meta.strategies.map(s => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label className="text-[11px] uppercase font-mono text-slate-500">Review cadence</label>
              <select value={form.review_cadence} onChange={set("review_cadence")} className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200">
                {meta.cadences.map(c => <option key={c}>{c}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Treatment plan</label>
            <textarea value={form.treatment_plan} onChange={set("treatment_plan")} rows={2}
              placeholder="What's being done to reduce this risk, and by when?"
              className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200" />
          </div>
        </div>
        <div className="px-4 py-3 border-t border-[#30363D] flex justify-end gap-2 sticky bottom-0 bg-[#0D1117]">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={submit} disabled={saving} className="h-8 px-3 text-[12px] bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/40 text-blue-200 rounded disabled:opacity-50">
            {saving ? "Adding…" : "Add risk"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function RiskRegister() {
  const navigate = useNavigate();
  const [items, setItems] = useState([]);
  const [matrix, setMatrix] = useState(null);
  const [meta, setMeta] = useState({ categories: [], strategies: [], statuses: [], cadences: [] });
  const [status, setStatus] = useState("");
  const [band, setBand] = useState("");
  const [q, setQ] = useState("");
  const [showNew, setShowNew] = useState(false);
  const [matrixFilter, setMatrixFilter] = useState(null);

  const loadAll = async () => {
    const [metaR, matrixR] = await Promise.all([
      api.get("/v1/risk-register/meta"),
      api.get("/v1/risk-register/matrix"),
    ]);
    setMeta(metaR.data);
    setMatrix(matrixR.data);
  };

  const loadItems = async () => {
    const params = {};
    if (status) params.status = status;
    if (band) params.band = band;
    if (q) params.q = q;
    const r = await api.get("/v1/risk-register", { params });
    setItems(r.data);
  };

  useEffect(() => { loadAll(); }, []);
  useEffect(() => { loadItems(); }, [status, band, q]);

  const visibleItems = matrixFilter
    ? items.filter(i => i.likelihood === matrixFilter.likelihood && i.impact === matrixFilter.impact)
    : items;

  return (
    <Layout title="Risk Register" subtitle="Likelihood × impact risk matrix, treatment plans, ownership, and review cadence"
      actions={<button onClick={() => setShowNew(true)}
        className="h-8 px-3 text-[12px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 text-blue-300 rounded inline-flex items-center gap-1.5">
        <Plus size={14} /> New risk
      </button>}>

      {matrix && (
        <div className="grid grid-cols-3 gap-4 mb-5">
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 col-span-1">
            <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-3">Open Risks by Severity Band</div>
            <div className="space-y-2">
              {["Critical", "High", "Medium", "Low"].map(b => (
                <button key={b} onClick={() => setBand(band === b ? "" : b)}
                  className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded border text-[12px] ${band === b ? "border-blue-500/50 bg-blue-500/10" : "border-[#21262D]"}`}>
                  <span style={{ color: BAND_COLOR[b] }}>{b}</span>
                  <span className="text-slate-300 font-mono">{matrix.band_counts[b] || 0}</span>
                </button>
              ))}
            </div>
            {matrix.overdue_reviews > 0 && (
              <div className="mt-3 flex items-center gap-1.5 text-[11.5px] text-amber-300 border border-amber-500/30 bg-amber-500/5 rounded px-2.5 py-2">
                <Warning size={13} /> {matrix.overdue_reviews} review{matrix.overdue_reviews === 1 ? "" : "s"} overdue
              </div>
            )}
          </div>
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 col-span-2 flex items-center justify-center">
            <div>
              <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500 mb-3 text-center">Inherent Risk Matrix (open risks)</div>
              <RiskMatrix cells={matrix.inherent_cells} onCellClick={(likelihood, impact) => setMatrixFilter(m => (m?.likelihood === likelihood && m?.impact === impact) ? null : { likelihood, impact })} />
              {matrixFilter && (
                <button onClick={() => setMatrixFilter(null)} className="mt-2 text-[11px] text-blue-300 hover:text-blue-200">
                  Clear cell filter (L{matrixFilter.likelihood} × I{matrixFilter.impact})
                </button>
              )}
            </div>
          </div>
        </div>
      )}

      <div className="flex items-center gap-2 mb-3">
        <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title/description…"
          className="h-8 w-64 bg-[#161B22] border border-[#30363D] rounded px-2.5 text-[12px] text-slate-200" />
        <select value={status} onChange={(e) => setStatus(e.target.value)} className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-300">
          <option value="">All statuses</option>
          {meta.statuses.map(s => <option key={s} value={s}>{s}</option>)}
        </select>
        {band && (
          <span className="text-[11px] text-slate-500">Filtered to <span style={{ color: BAND_COLOR[band] }}>{band}</span> <button onClick={() => setBand("")} className="text-slate-500 hover:text-slate-300 ml-1">✕</button></span>
        )}
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead>
            <tr>
              <th className="text-left">Risk</th><th>Category</th><th>Inherent</th><th>Residual</th>
              <th>Treatment</th><th>Owner</th><th>Status</th><th>Next Review</th>
            </tr>
          </thead>
          <tbody>
            {visibleItems.map(r => (
              <tr key={r.id} className="border-t border-[#30363D] hover:bg-slate-800/20 cursor-pointer" onClick={() => navigate(`/risk-register/${r.id}`)}>
                <td className="max-w-[280px]">
                  <div className="text-slate-200 truncate">{r.title}</div>
                  <div className="text-[10.5px] text-slate-500 truncate">{r.description}</div>
                </td>
                <td><Chip color="slate">{r.category}</Chip></td>
                <td><Chip color={BAND_CHIP[r.inherent_band] || "slate"}>{r.inherent_band} · {r.inherent_score}</Chip></td>
                <td>{r.residual_band ? <Chip color={BAND_CHIP[r.residual_band] || "slate"}>{r.residual_band} · {r.residual_score}</Chip> : <span className="text-slate-600">—</span>}</td>
                <td className="text-[11.5px] text-slate-400">{r.treatment_strategy}</td>
                <td className="text-[11.5px] text-slate-400">{r.owner || "—"}</td>
                <td><Chip color={STATUS_CHIP[r.status] || "slate"}>{r.status}</Chip></td>
                <td className="font-mono text-[11px] text-slate-400 whitespace-nowrap">
                  {r.next_review_date ? new Date(r.next_review_date).toLocaleDateString() : "—"}
                  {r.next_review_date && r.next_review_date < new Date().toISOString() && r.status !== "Closed" && (
                    <span className="text-amber-400 ml-1" title="Review overdue"><ClockCounterClockwise size={11} className="inline" /></span>
                  )}
                </td>
              </tr>
            ))}
            {visibleItems.length === 0 && (
              <tr><td colSpan={8} className="text-center text-slate-500 py-6 text-[12px]">No risks match this view. Click "New risk" to add one.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      {showNew && (
        <NewRiskModal meta={meta} onClose={() => setShowNew(false)}
          onCreated={(r) => { setShowNew(false); loadAll(); loadItems(); navigate(`/risk-register/${r.id}`); }} />
      )}
    </Layout>
  );
}
