import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Plus, Trash, ArrowsClockwise, Info } from "@phosphor-icons/react";
import { toast } from "sonner";

function MultiValueInput({ values, onChange, placeholder }) {
  const [input, setInput] = useState("");
  const commit = () => {
    const v = input.trim();
    if (!v) return;
    if (!values.includes(v)) onChange([...values, v]);
    setInput("");
  };
  const remove = (v) => onChange(values.filter(x => x !== v));
  return (
    <div className="min-h-8 bg-[#161B22] border border-[#30363D] rounded px-1.5 py-1 flex flex-wrap gap-1 items-center">
      {values.map(v => (
        <span key={v} className="inline-flex items-center gap-1 px-1.5 py-0.5 bg-blue-500/15 border border-blue-500/30 rounded text-[10.5px] text-blue-200 whitespace-nowrap">
          {v}
          <button type="button" onClick={() => remove(v)} className="text-blue-300 hover:text-blue-100">×</button>
        </span>
      ))}
      <input value={input} onChange={e => setInput(e.target.value)}
        onKeyDown={e => {
          if (e.key === "Enter" || e.key === ",") { e.preventDefault(); commit(); }
          else if (e.key === "Backspace" && !input && values.length) onChange(values.slice(0, -1));
        }}
        onBlur={commit}
        placeholder={values.length ? "+ add" : (placeholder || "Value(s) — Enter to add each")}
        className="flex-1 min-w-[100px] bg-transparent outline-none text-[12px] text-slate-200 h-6"/>
    </div>
  );
}

const EMPTY_DRAFT = { name: "", field: "port", values: [], points: 10, enabled: true };

export default function CriticalityScoring() {
  const [rules, setRules] = useState([]);
  const [fieldMeta, setFieldMeta] = useState({});
  const [thresholds, setThresholds] = useState(null);
  const [draft, setDraft] = useState(EMPTY_DRAFT);
  const [editingId, setEditingId] = useState(null);
  const [recomputing, setRecomputing] = useState(false);

  const load = () => api.get("/v1/admin/criticality-rules").then(r => { setRules(r.data.items); setFieldMeta(r.data.field_meta); });
  const loadThresholds = () => api.get("/v1/admin/criticality-thresholds").then(r => setThresholds(r.data.thresholds));
  useEffect(() => { load(); loadThresholds(); }, []);

  const save = async () => {
    if (!draft.name.trim()) { toast.error("Name is required"); return; }
    if (draft.values.length === 0) { toast.error("At least one value is required"); return; }
    try {
      if (editingId) await api.put(`/v1/admin/criticality-rules/${editingId}`, draft);
      else await api.post("/v1/admin/criticality-rules", draft);
      toast.success(editingId ? "Rule updated" : "Rule added");
      setDraft(EMPTY_DRAFT); setEditingId(null);
      load();
    } catch (e) { toast.error(e.response?.data?.detail || "Save failed"); }
  };

  const edit = (r) => { setDraft({ name: r.name, field: r.field, values: r.values, points: r.points, enabled: r.enabled }); setEditingId(r.id); };
  const cancelEdit = () => { setDraft(EMPTY_DRAFT); setEditingId(null); };

  const remove = async (id) => {
    if (!window.confirm("Delete this rule?")) return;
    await api.delete(`/v1/admin/criticality-rules/${id}`);
    load();
  };

  const toggleEnabled = async (r) => {
    await api.put(`/v1/admin/criticality-rules/${r.id}`, { name: r.name, field: r.field, values: r.values, points: r.points, enabled: !r.enabled });
    load();
  };

  const resetDefaults = async () => {
    if (!window.confirm("This replaces all current rules with the starter set. Continue?")) return;
    await api.post("/v1/admin/criticality-rules/reset-defaults");
    toast.success("Reset to starter rules");
    load();
  };

  const recomputeAll = async () => {
    setRecomputing(true);
    try {
      const r = await api.post("/v1/admin/assets/recompute-criticality");
      toast.success(`Checked ${r.data.checked} asset(s), ${r.data.changed} tier(s) changed (${r.data.skipped_locked} manually locked and skipped).`);
    } catch (e) { toast.error("Recompute failed"); }
    finally { setRecomputing(false); }
  };

  const saveThresholds = async () => {
    try {
      await api.put("/v1/admin/criticality-thresholds", thresholds);
      toast.success("Thresholds saved");
      loadThresholds();
    } catch (e) { toast.error(e.response?.data?.detail || "Save failed"); }
  };

  return (
    <Layout title="Asset Criticality Scoring" subtitle="Auto-score asset criticality from what's actually detected running on it — fully adjustable per your org"
      actions={
        <button onClick={recomputeAll} disabled={recomputing}
          className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded inline-flex items-center gap-1.5">
          <ArrowsClockwise size={13} className={recomputing ? "animate-spin" : ""}/> {recomputing ? "Recomputing…" : "Recompute all assets"}
        </button>
      }>
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 mb-4 text-[12px] text-blue-200 leading-relaxed flex items-start gap-2 max-w-3xl">
        <Info size={16} className="shrink-0 mt-0.5"/>
        <div>
          Every asset's criticality score is the sum of points from every enabled rule below that matches it (open ports/services from
          Nmap, asset type from Nikto, exposure, environment, tags), recomputed automatically after every scan. Locking an asset's
          criticality manually (from its Asset Detail page) makes it ignore these rules until unlocked. This entire rule set — and the
          thresholds below — is just a starting point; tune it or replace it for how your org actually defines "crown jewel."
        </div>
      </div>

      {thresholds && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 mb-4 max-w-2xl">
          <div className="text-[12.5px] text-slate-200 font-medium mb-3">Score thresholds</div>
          <div className="grid grid-cols-4 gap-2.5">
            {["crown_jewel", "critical", "high", "medium"].map(tier => (
              <div key={tier}>
                <label className="text-[10px] uppercase font-mono text-slate-500">{tier.replace("_", " ")} ≥</label>
                <input type="number" value={thresholds[tier]} onChange={e => setThresholds({ ...thresholds, [tier]: Number(e.target.value) })}
                  className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200"/>
              </div>
            ))}
          </div>
          <div className="text-[10.5px] text-slate-500 mt-2">Anything below the "medium" threshold scores "low". Each tier's threshold must be higher than the one below it.</div>
          <button onClick={saveThresholds} className="mt-3 h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">Save thresholds</button>
        </div>
      )}

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 mb-4 max-w-3xl">
        <div className="text-[12.5px] text-slate-200 font-medium mb-3">{editingId ? "Edit rule" : "Add a rule"}</div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-2.5">
          <div className="md:col-span-2">
            <label className="text-[10px] uppercase font-mono text-slate-500">Name</label>
            <input value={draft.name} onChange={e => setDraft({ ...draft, name: e.target.value })}
              placeholder="e.g. Database ports"
              className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200"/>
          </div>
          <div>
            <label className="text-[10px] uppercase font-mono text-slate-500">Condition</label>
            <select value={draft.field} onChange={e => setDraft({ ...draft, field: e.target.value, values: [] })}
              className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200">
              {Object.entries(fieldMeta).map(([k, m]) => <option key={k} value={k}>{m.label}</option>)}
            </select>
          </div>
          <div>
            <label className="text-[10px] uppercase font-mono text-slate-500">Points</label>
            <input type="number" value={draft.points} onChange={e => setDraft({ ...draft, points: Number(e.target.value) })}
              className="w-full mt-1 h-9 bg-[#161B22] border border-[#30363D] rounded px-2 text-[13px] text-slate-200"/>
          </div>
        </div>
        <div className="mt-2.5">
          <label className="text-[10px] uppercase font-mono text-slate-500">Values (matches ANY)</label>
          <div className="mt-1">
            <MultiValueInput values={draft.values} onChange={v => setDraft({ ...draft, values: v })} placeholder={fieldMeta[draft.field]?.placeholder}/>
          </div>
        </div>
        <div className="mt-3 flex gap-2">
          <button onClick={save} className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 text-white rounded">{editingId ? "Save changes" : "Add rule"}</button>
          {editingId && <button onClick={cancelEdit} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>}
        </div>
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <table className="dense w-full">
          <thead><tr><th className="text-left">Rule</th><th className="text-left">Condition</th><th className="text-right">Points</th><th className="text-center">Enabled</th><th></th></tr></thead>
          <tbody>
            {rules.map(r => (
              <tr key={r.id} className={`border-t border-[#30363D] ${!r.enabled ? "opacity-50" : ""}`}>
                <td className="text-slate-200">{r.name}</td>
                <td className="text-[11.5px] text-slate-400 font-mono">{fieldMeta[r.field]?.label || r.field}: {r.values.join(", ")}</td>
                <td className="text-right font-mono">{r.points >= 0 ? "+" : ""}{r.points}</td>
                <td className="text-center">
                  <input type="checkbox" checked={r.enabled} onChange={() => toggleEnabled(r)}/>
                </td>
                <td className="flex gap-2 justify-end pr-2 py-1.5">
                  <button onClick={() => edit(r)} className="text-blue-300 hover:text-blue-200 text-[11.5px]">Edit</button>
                  <button onClick={() => remove(r.id)} className="text-red-400 hover:text-red-300"><Trash size={13}/></button>
                </td>
              </tr>
            ))}
            {rules.length === 0 && <tr><td colSpan={5} className="text-center text-slate-500 py-8">No rules yet.</td></tr>}
          </tbody>
        </table>
      </div>
      <div className="mt-3">
        <button onClick={resetDefaults} className="text-[11.5px] text-slate-500 hover:text-slate-300 underline">Reset to starter rules</button>
      </div>
    </Layout>
  );
}
