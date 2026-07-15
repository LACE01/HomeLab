import { useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import { X, LinkSimple } from "@phosphor-icons/react";

/* Shared "create a Risk Register entry" modal -- used standalone from the Risk
 * Register list page, and pre-filled from other modules (an Albert alert, an
 * Exception) that want to spin up a tracked risk without re-typing context.
 * `prefill` merges into the initial form state; `contextLabel` (if present) is
 * shown as a read-only banner describing what this risk is being linked from --
 * the actual linked_*_ids fields travel silently in the form state and get
 * submitted as-is, they're not user-editable here (that's what the Risk Detail
 * page's own link pickers are for).
 */
export default function NewRiskModal({ onClose, onCreated, prefill = {} }) {
  const [meta, setMeta] = useState(null);
  const [form, setForm] = useState({
    title: "", description: "", category: "Technical", likelihood: 3, impact: 3,
    treatment_strategy: "Mitigate", treatment_plan: "", owner: "", status: "Open", review_cadence: "Quarterly",
    external_reference: "", linked_finding_ids: [], linked_asset_ids: [], linked_exception_ids: [], linked_albert_alert_ids: [],
    tags: [],
    ...prefill,
  });
  const [saving, setSaving] = useState(false);
  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }));

  useEffect(() => {
    api.get("/v1/risk-register/meta").then(r => setMeta(r.data)).catch(() => setMeta({ categories: ["Technical"], strategies: ["Mitigate"], statuses: ["Open"], cadences: ["Quarterly"] }));
  }, []);

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

  if (!meta) return null;

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-lg max-h-[85vh] overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between sticky top-0 bg-[#0D1117]">
          <h3 className="text-[13px] font-medium text-slate-100">New risk</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16} /></button>
        </div>
        <div className="p-4 space-y-3">
          {prefill.contextLabel && (
            <div className="text-[11.5px] text-blue-300 bg-blue-500/5 border border-blue-500/30 rounded px-2.5 py-2 flex items-center gap-1.5">
              <LinkSimple size={12} /> {prefill.contextLabel}
            </div>
          )}
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
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Device / domain / website (if not a tracked asset)</label>
            <input value={form.external_reference} onChange={set("external_reference")} placeholder="e.g. co-eagle-PRO-Albert-2, or vendor-portal.example.com"
              className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200" />
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
