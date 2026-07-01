import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  Plus, X, Trash, PencilSimple, Play, Eye, Robot, Power, ClockCounterClockwise,
} from "@phosphor-icons/react";
import { toast } from "sonner";

function ConditionRow({ fields, cond, onChange, onRemove }) {
  const field = fields.find(f => f.field === cond.field) || fields[0];
  return (
    <div className="flex items-center gap-1.5">
      <select value={cond.field} onChange={e => onChange({ field: e.target.value, value: cond.value })}
        className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200">
        {fields.map(f => <option key={f.field} value={f.field}>{f.label}</option>)}
      </select>
      {field?.type === "enum" && (
        <select value={cond.value ?? ""} onChange={e => onChange({ field: cond.field, value: e.target.value })}
          className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200 flex-1">
          <option value="">Select…</option>
          {field.values.map(v => <option key={v} value={v}>{v}</option>)}
        </select>
      )}
      {field?.type === "bool" && (
        <select value={String(cond.value ?? true)} onChange={e => onChange({ field: cond.field, value: e.target.value === "true" })}
          className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200 flex-1">
          <option value="true">True</option>
          <option value="false">False</option>
        </select>
      )}
      {field?.type === "number" && (
        <input type="number" step="0.01" value={cond.value ?? ""} onChange={e => onChange({ field: cond.field, value: parseFloat(e.target.value) })}
          className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200 flex-1"/>
      )}
      {field?.type === "text" && (
        <input value={cond.value ?? ""} onChange={e => onChange({ field: cond.field, value: e.target.value })}
          placeholder="value" className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200 flex-1"/>
      )}
      {field?.type === "unassigned" && (
        <div className="h-8 flex items-center px-2 text-[11px] text-slate-500 flex-1">has no owner team</div>
      )}
      <button onClick={onRemove} className="text-slate-500 hover:text-red-400 shrink-0"><X size={14}/></button>
    </div>
  );
}

function ActionRow({ actionTypes, channels, action, onChange, onRemove }) {
  const meta = actionTypes.find(a => a.type === action.type) || actionTypes[0];
  return (
    <div className="flex items-center gap-1.5">
      <select value={action.type} onChange={e => onChange({ type: e.target.value })}
        className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200">
        {actionTypes.map(a => <option key={a.type} value={a.type}>{a.label}</option>)}
      </select>
      {meta.params.includes("team") && (
        <input value={action.team || ""} onChange={e => onChange({ ...action, team: e.target.value })}
          placeholder="Team name" className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200 flex-1"/>
      )}
      {meta.params.includes("tag") && (
        <input value={action.tag || ""} onChange={e => onChange({ ...action, tag: e.target.value })}
          placeholder="Tag" className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200 flex-1"/>
      )}
      {meta.params.includes("status") && (
        <input value={action.status || ""} onChange={e => onChange({ ...action, status: e.target.value })}
          placeholder="e.g. Needs triage" className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200 flex-1"/>
      )}
      {meta.params.includes("channel_id") && (
        <select value={action.channel_id || ""} onChange={e => onChange({ ...action, channel_id: e.target.value })}
          className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200 flex-1">
          <option value="">Select channel…</option>
          {channels.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
      )}
      {meta.params.includes("note") && (
        <input value={action.note || ""} onChange={e => onChange({ ...action, note: e.target.value })}
          placeholder="Note text" className="h-8 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12px] text-slate-200 flex-1"/>
      )}
      <button onClick={onRemove} className="text-slate-500 hover:text-red-400 shrink-0"><X size={14}/></button>
    </div>
  );
}

function RuleFormModal({ meta, initial, onClose, onSaved }) {
  const [form, setForm] = useState(initial || {
    name: "", description: "", trigger: "scheduled_sweep", enabled: true,
    conditions: {}, actions: [],
  });
  const [condList, setCondList] = useState(
    Object.entries(form.conditions || {}).map(([field, value]) => ({ field, value }))
  );
  const [saving, setSaving] = useState(false);
  const isEdit = !!initial?.id;

  const save = async () => {
    if (!form.name.trim()) { toast.error("Name is required"); return; }
    const conditions = {};
    condList.forEach(c => { if (c.field && c.value !== undefined && c.value !== "") conditions[c.field] = c.value; });
    const body = { ...form, conditions, actions: form.actions.filter(a => a.type) };
    setSaving(true);
    try {
      if (isEdit) await api.put(`/v1/automation/rules/${initial.id}`, body);
      else await api.post("/v1/automation/rules", body);
      toast.success(isEdit ? "Rule updated." : "Rule created.");
      onSaved();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Failed to save rule");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4 py-8 overflow-y-auto" onClick={onClose}>
      <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-2xl my-auto" onClick={e=>e.stopPropagation()}>
        <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
          <h3 className="text-[13px] font-medium text-slate-100">{isEdit ? "Edit rule" : "New automation rule"}</h3>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-300"><X size={16}/></button>
        </div>
        <div className="p-4 space-y-3.5 max-h-[70vh] overflow-y-auto">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] uppercase font-mono text-slate-500">Name</label>
              <input value={form.name} onChange={e=>setForm({...form, name:e.target.value})}
                className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200"/>
            </div>
            <div>
              <label className="text-[11px] uppercase font-mono text-slate-500">Trigger (label only)</label>
              <select value={form.trigger} onChange={e=>setForm({...form, trigger:e.target.value})}
                className="w-full h-8 mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 text-[12.5px] text-slate-200">
                {meta.triggers.map(t => <option key={t.id} value={t.id}>{t.label}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Description</label>
            <textarea value={form.description} onChange={e=>setForm({...form, description:e.target.value})}
              rows={2} className="w-full mt-1 bg-[#161B22] border border-[#30363D] rounded px-2 py-1.5 text-[12.5px] text-slate-200"/>
          </div>

          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Conditions (all must match)</label>
            <div className="space-y-1.5 mt-1.5">
              {condList.map((c, i) => (
                <ConditionRow key={i} fields={meta.condition_fields} cond={c}
                  onChange={(nc)=>setCondList(condList.map((x,idx)=>idx===i?nc:x))}
                  onRemove={()=>setCondList(condList.filter((_,idx)=>idx!==i))}/>
              ))}
              <button onClick={()=>setCondList([...condList, { field: meta.condition_fields[0].field, value: "" }])}
                className="text-[11px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1"><Plus size={12}/> Add condition</button>
              {condList.length === 0 && <div className="text-[11px] text-slate-600">No conditions — this matches every open finding. Careful.</div>}
            </div>
          </div>

          <div>
            <label className="text-[11px] uppercase font-mono text-slate-500">Actions</label>
            <div className="space-y-1.5 mt-1.5">
              {form.actions.map((a, i) => (
                <ActionRow key={i} actionTypes={meta.action_types} channels={meta.channels} action={a}
                  onChange={(na)=>setForm({...form, actions: form.actions.map((x,idx)=>idx===i?na:x)})}
                  onRemove={()=>setForm({...form, actions: form.actions.filter((_,idx)=>idx!==i)})}/>
              ))}
              <button onClick={()=>setForm({...form, actions:[...form.actions, { type: meta.action_types[0].type }]})}
                className="text-[11px] text-blue-300 hover:text-blue-200 inline-flex items-center gap-1"><Plus size={12}/> Add action</button>
            </div>
          </div>

          <label className="flex items-center gap-2 text-[12px] text-slate-300">
            <input type="checkbox" checked={form.enabled} onChange={e=>setForm({...form, enabled:e.target.checked})}/>
            Enabled — runs automatically on the nightly sweep
          </label>
        </div>
        <div className="px-4 py-3 border-t border-[#30363D] flex justify-end gap-2">
          <button onClick={onClose} className="h-8 px-3 text-[12px] border border-[#30363D] rounded text-slate-300">Cancel</button>
          <button onClick={save} disabled={saving}
            className="h-8 px-3 text-[12px] bg-blue-500/20 hover:bg-blue-500/30 border border-blue-500/40 text-blue-200 rounded disabled:opacity-50">
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default function Automation() {
  const [rules, setRules] = useState([]);
  const [meta, setMeta] = useState(null);
  const [runs, setRuns] = useState([]);
  const [showForm, setShowForm] = useState(false);
  const [editing, setEditing] = useState(null);
  const [preview, setPreview] = useState(null);

  const load = () => {
    api.get("/v1/automation/rules").then(r => setRules(r.data.items));
    api.get("/v1/automation/runs", { params: { limit: 30 } }).then(r => setRuns(r.data.items));
  };
  useEffect(() => {
    api.get("/v1/automation/meta").then(r => setMeta(r.data));
    load();
  }, []);

  const toggleEnabled = async (rule) => {
    await api.put(`/v1/automation/rules/${rule.id}`, { ...rule, enabled: !rule.enabled });
    load();
  };

  const remove = async (rule) => {
    if (!window.confirm(`Delete rule "${rule.name}"?`)) return;
    await api.delete(`/v1/automation/rules/${rule.id}`);
    toast.success("Rule deleted.");
    load();
  };

  const runNow = async (rule) => {
    const t = toast.loading(`Running "${rule.name}"…`);
    try {
      const r = await api.post(`/v1/automation/rules/${rule.id}/run`);
      toast.success(`Applied to ${r.data.matched} finding(s).`, { id: t });
      load();
    } catch (e) {
      toast.error(e.response?.data?.detail || "Run failed", { id: t });
    }
  };

  const runPreview = async (rule) => {
    const r = await api.post(`/v1/automation/rules/${rule.id}/preview`);
    setPreview({ rule, ...r.data });
  };

  if (!meta) return <Layout title="Automation" subtitle="Loading…"><div className="text-[12.5px] text-slate-500">Loading…</div></Layout>;

  return (
    <Layout title="Automation" subtitle="Condition-based rules that assign, tag, notify, and re-status findings automatically"
      actions={<button onClick={()=>{setEditing(null); setShowForm(true);}}
        className="h-8 px-3 text-[12px] bg-blue-500/15 border border-blue-500/40 hover:bg-blue-500/25 text-blue-300 rounded inline-flex items-center gap-1.5">
        <Plus size={14}/> New rule
      </button>}>

      <div className="text-[11.5px] text-slate-500 border border-[#30363D] bg-[#0D1117] rounded-md px-3 py-2.5 mb-3 flex items-center gap-2">
        <Robot size={15} className="text-blue-300 shrink-0"/>
        Rules run automatically once a day alongside rescoring, or on demand with "Run now". Each rule only acts on a given finding once — re-running never double-applies.
      </div>

      {rules.length === 0 && (
        <div className="text-[12.5px] text-slate-500 border border-[#30363D] bg-[#0D1117] rounded-md p-6 text-center mb-3">
          No automation rules yet. Create one to auto-assign, tag, notify, or re-status findings that match a condition set.
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 mb-4">
        {rules.map(rule => (
          <div key={rule.id} className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <div className="text-[13.5px] font-medium text-slate-100 truncate">{rule.name}</div>
                  <Chip color={rule.enabled ? "green" : "slate"}>{rule.enabled ? "Enabled" : "Disabled"}</Chip>
                </div>
                <div className="text-[11px] text-slate-500 mt-0.5">{meta.triggers.find(t=>t.id===rule.trigger)?.label || rule.trigger}</div>
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <button onClick={()=>toggleEnabled(rule)} title="Enable/disable" className="text-slate-500 hover:text-emerald-400"><Power size={14}/></button>
                <button onClick={()=>runPreview(rule)} title="Preview matches" className="text-slate-500 hover:text-blue-300"><Eye size={14}/></button>
                <button onClick={()=>runNow(rule)} title="Run now" className="text-slate-500 hover:text-emerald-400"><Play size={14}/></button>
                <button onClick={()=>{setEditing(rule); setShowForm(true);}} className="text-slate-500 hover:text-slate-200"><PencilSimple size={14}/></button>
                <button onClick={()=>remove(rule)} className="text-slate-500 hover:text-red-400"><Trash size={14}/></button>
              </div>
            </div>
            {rule.description && <div className="text-[12px] text-slate-500 mt-1.5">{rule.description}</div>}
            <div className="flex flex-wrap gap-1.5 mt-2">
              {Object.entries(rule.conditions || {}).map(([k, v]) => (
                <Chip key={k} color="blue">{k}: {String(v)}</Chip>
              ))}
              {Object.keys(rule.conditions || {}).length === 0 && <Chip color="slate">no conditions (all open findings)</Chip>}
            </div>
            <div className="flex flex-wrap gap-1.5 mt-1.5">
              {(rule.actions || []).map((a, i) => (
                <Chip key={i}>{meta.action_types.find(x=>x.type===a.type)?.label || a.type}</Chip>
              ))}
            </div>
            <div className="text-[10.5px] text-slate-600 mt-2 font-mono">
              {rule.run_count || 0} finding(s) touched · last run {rule.last_run_at ? rule.last_run_at.slice(0,16).replace("T"," ") : "never"}
            </div>
          </div>
        ))}
      </div>

      <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
        <div className="px-3 py-2 border-b border-[#30363D] text-[11px] uppercase tracking-wider font-mono text-slate-400 flex items-center gap-2">
          <ClockCounterClockwise size={13}/> Recent Automation Activity
        </div>
        {runs.length === 0 ? (
          <div className="p-4 text-[12px] text-slate-500">Nothing has run yet.</div>
        ) : (
          <table className="dense w-full">
            <thead><tr><th className="text-left">Rule</th><th className="text-left">Finding</th><th className="text-left">Actions</th><th className="text-left">When</th></tr></thead>
            <tbody>
              {runs.map(r => (
                <tr key={r.id} className="border-t border-[#30363D]">
                  <td className="text-slate-200">{r.rule_name}</td>
                  <td className="text-slate-400 max-w-[280px] truncate" title={r.finding_title}>{r.finding_title}</td>
                  <td className="text-slate-400 text-[11px]">{(r.actions_applied || []).join(", ")}</td>
                  <td className="text-slate-500 text-[11px] font-mono">{r.ran_at?.slice(0,16).replace("T"," ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {showForm && (
        <RuleFormModal meta={meta} initial={editing}
          onClose={()=>{setShowForm(false); setEditing(null);}}
          onSaved={()=>{setShowForm(false); setEditing(null); load();}}/>
      )}

      {preview && (
        <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 px-4 py-8" onClick={()=>setPreview(null)}>
          <div className="bg-[#0D1117] border border-[#30363D] rounded-md w-full max-w-lg" onClick={e=>e.stopPropagation()}>
            <div className="px-4 py-3 border-b border-[#30363D] flex items-center justify-between">
              <h3 className="text-[13px] font-medium text-slate-100">Preview — {preview.rule.name}</h3>
              <button onClick={()=>setPreview(null)} className="text-slate-500 hover:text-slate-300"><X size={16}/></button>
            </div>
            <div className="p-4">
              <div className="text-[12.5px] text-slate-300 mb-2">{preview.matched} finding(s) would be matched (dry run — nothing applied).</div>
              <div className="space-y-1.5 max-h-64 overflow-y-auto">
                {preview.sample?.map(f => (
                  <div key={f.id} className="text-[11.5px] text-slate-400 border-b border-[#30363D]/50 pb-1.5">
                    <Chip color={f.severity==="Critical"?"red":"orange"}>{f.severity}</Chip> {f.title} <span className="text-slate-600">· {f.asset}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
}
